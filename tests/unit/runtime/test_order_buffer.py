"""Unit test OrderBuffer dan integrasinya dengan coordinator."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from src.contracts.raw_alert import CanonicalRawAlert
from src.runtime.live_coordinator import LiveIngestionCoordinator
from src.runtime.live_source import WazuhIndexerLivePoller
from src.runtime.order_buffer import BufferedRelease, OrderBuffer


def make_alert(idx: int, ts: datetime) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"buf_{idx:03d}",
        timestamp=ts,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        rule_level=3,
        rule_id="5501",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1,
    )


T0 = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)


def test_release_ordered_despite_random_arrival():
    buf = OrderBuffer(
        hold_window=timedelta(seconds=60),
        max_hold=timedelta(minutes=5),
        max_items=100,
    )
    # Datang teracak di sekitar T0..T0+40 detik; tidak boleh ada yang dilepas sampai watermark bergerak.
    shuffled = [make_alert(i, T0 + timedelta(seconds=s)) for i, s in [(3, 30), (1, 10), (2, 20), (0, 0)]]
    released = buf.add(shuffled, now=T0 + timedelta(seconds=40))
    assert released == []  # semua masih dalam hold_window dari maksimum teramati (T0+30 detik)
    assert buf.status()["size"] == 4

    # Event yang lebih baru mendorong watermark melewati event yang lebih lama.
    newer = [make_alert(4, T0 + timedelta(seconds=200))]
    released = buf.add(newer, now=T0 + timedelta(seconds=200))
    keys = [(r.alert.timestamp, r.alert.wazuh_alert_id) for r in released]
    assert keys == sorted(keys)
    assert [r.alert.wazuh_alert_id for r in released] == [
        "buf_000",
        "buf_001",
        "buf_002",
        "buf_003",
    ]
    assert all(r.late is False for r in released)


def test_late_alert_never_dropped_and_flagged():
    buf = OrderBuffer(
        hold_window=timedelta(seconds=60),
        max_hold=timedelta(minutes=5),
        max_items=100,
    )
    buf.add([make_alert(9, T0 + timedelta(seconds=300))], now=T0 + timedelta(seconds=300))
    buf.flush()  # drain; watermark tetap di T0+300 detik

    latecomer = make_alert(0, T0)  # lebih tua dari watermark (T0+300 detik - 60 detik)
    released = buf.add([latecomer], now=T0 + timedelta(seconds=310))
    assert len(released) == 1
    assert isinstance(released[0], BufferedRelease)
    assert released[0].alert.wazuh_alert_id == "buf_000"
    assert released[0].late is True
    assert buf.status()["late_total"] == 1


def test_max_hold_forces_release_without_newer_events():
    buf = OrderBuffer(
        hold_window=timedelta(hours=1),
        max_hold=timedelta(seconds=30),
        max_items=100,
    )
    held = buf.add([make_alert(1, T0)], now=T0)
    assert held == []
    released = buf.add([], now=T0 + timedelta(seconds=31))
    assert [r.alert.wazuh_alert_id for r in released] == ["buf_001"]
    assert released[0].late is False


def test_full_buffer_backpressure_without_drop():
    buf = OrderBuffer(
        hold_window=timedelta(hours=1),
        max_hold=timedelta(hours=1),
        max_items=2,
    )
    assert buf.add([make_alert(1, T0)], now=T0) == []
    assert buf.add([make_alert(2, T0 + timedelta(seconds=1))], now=T0) == []
    assert buf.status()["size"] == 2

    refused_release = buf.add([make_alert(3, T0 + timedelta(seconds=2))], now=T0)
    assert refused_release == []
    st = buf.status()
    assert st["backpressure_count"] == 1
    assert st["buffer_dropped"] == 0
    assert st["size"] == 2

    # Tidak ada yang ditahan yang hilang; alert yang ditolak dikembalikan untuk dicoba ulang, bukan dibuang.
    rest = buf.flush()
    assert sorted(r.alert.wazuh_alert_id for r in rest) == ["buf_001", "buf_002"]
    refused = buf.pop_refused()
    assert [a.wazuh_alert_id for a in refused] == ["buf_003"]
    assert buf.pop_refused() == []


def test_checkpoint_roundtrip_preserves_buffer_and_watermark():
    buf = OrderBuffer(
        hold_window=timedelta(seconds=60),
        max_hold=timedelta(minutes=5),
        max_items=10,
    )
    buf.add([make_alert(2, T0 + timedelta(seconds=20))], now=T0 + timedelta(seconds=20))
    buf.add([make_alert(1, T0 + timedelta(seconds=10))], now=T0 + timedelta(seconds=20))
    snap = buf.to_checkpoint()
    assert snap["max_observed_event_time"] == (T0 + timedelta(seconds=20)).isoformat()
    assert snap["late_total"] == 0

    restored = OrderBuffer.from_checkpoint(snap)
    assert restored.status()["size"] == 2
    released = restored.add([make_alert(9, T0 + timedelta(seconds=500))], now=T0 + timedelta(seconds=500))
    assert [r.alert.wazuh_alert_id for r in released] == ["buf_001", "buf_002"]


def _make_coordinator(tmp_path: Path, **kwargs):
    from datetime import timedelta as _td

    from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
    from src.runners.batch_runner import BatchResearchRunner
    from src.runtime.durable_state import DurableStateManager
    from src.runtime.service import LiveRBTAService

    base_t = datetime(2026, 8, 28, 8, 0, 0, tzinfo=timezone.utc)
    sample = [
        make_alert(i, base_t + timedelta(minutes=i * 20)) for i in range(30)
    ]
    # Variasikan severity seperti di tests/unit/runtime/test_live_coordinator.py agar
    # kalibrasi reference tidak degenerate.
    varied = [
        CanonicalRawAlert(
            wazuh_alert_id=a.wazuh_alert_id,
            timestamp=a.timestamp,
            agent_id=a.agent_id,
            agent_name=a.agent_name,
            rule_group_primary=a.rule_group_primary,
            rule_level=(i % 12) + 1,
            rule_id=a.rule_id,
            mitre_tactics=a.mitre_tactics,
            srcip=a.srcip,
            agent_criticality=a.agent_criticality,
        )
        for i, a in enumerate(sample)
    ]
    batch_res = BatchResearchRunner(base_delta_t=_td(minutes=15), adaptive=False).run(varied)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="buf-test-v1")
    service = LiveRBTAService(
        scoring_pipeline=ScoringPipeline(bundle),
        state_manager=DurableStateManager(tmp_path / "buf_coord_state.json"),
        base_delta_t=_td(minutes=15),
        adaptive=False,
    )
    poller = MagicMock(spec=WazuhIndexerLivePoller)
    poller.poll_recent.return_value = []
    poller.poll_reconciliation.return_value = []
    poller.poll_full_reconciliation.return_value = []
    return service, LiveIngestionCoordinator(service=service, poller=poller, **kwargs)


def test_coordinator_default_off_preserves_legacy_behavior(tmp_path: Path):
    service, coord = _make_coordinator(tmp_path)
    assert coord.order_buffer is None

    t_now = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    a1 = make_alert(1, t_now - timedelta(minutes=2))
    a2 = make_alert(2, t_now - timedelta(minutes=1))
    coord.poller.poll_recent.return_value = [a1, a2]
    result = coord.run_cycle(current_time=t_now, force_recent_reconciliation=True)
    assert result.submitted_candidates == 2
    assert result.processed_new_ids == 2
    assert service.is_seen("buf_001") and service.is_seen("buf_002")


def test_coordinator_buffer_enabled_defers_and_releases_across_cycles(tmp_path: Path):
    service, coord = _make_coordinator(
        tmp_path,
        order_buffer_enabled=True,
        order_buffer_hold_window=timedelta(seconds=60),
        order_buffer_max_hold=timedelta(minutes=5),
        order_buffer_max_items=100,
    )
    assert coord.order_buffer is not None

    t1 = datetime(2026, 8, 28, 10, 30, 0, tzinfo=timezone.utc)
    early = [make_alert(1, t1), make_alert(2, t1 + timedelta(seconds=10))]
    coord.poller.poll_recent.return_value = early
    res1 = coord.run_cycle(current_time=t1 + timedelta(seconds=10), force_recent_reconciliation=True)
    # Ditahan di buffer: belum ada yang di-ingest, tidak ada yang hilang.
    assert res1.submitted_candidates == 0
    assert not service.is_seen("buf_001")

    late_newer = [make_alert(9, t1 + timedelta(seconds=600))]
    coord.poller.poll_recent.return_value = late_newer
    res2 = coord.run_cycle(current_time=t1 + timedelta(seconds=600), force_recent_reconciliation=True)
    assert res2.submitted_candidates == 2  # buf_001 + buf_002 dilepas oleh watermark
    assert service.is_seen("buf_001") and service.is_seen("buf_002")


# Batas toleransi masa depan + helper partisi.

def test_future_alert_clamped_to_late_passthrough_with_counter():
    """Event-time yang melewati now+future_tolerance tidak pernah menggeser watermark."""
    from src.runtime.order_buffer import partition_unseen

    buf = OrderBuffer(
        hold_window=timedelta(seconds=60),
        max_hold=timedelta(minutes=5),
        max_items=100,
        future_tolerance=timedelta(minutes=5),
    )
    far_future = make_alert(7, T0 + timedelta(hours=6))
    released = buf.add([far_future], now=T0)
    assert len(released) == 1
    assert released[0].late is True
    st = buf.status()
    assert st["future_anomalies"] == 1
    assert st["late_total"] == 1
    # Watermark tidak boleh melompat: alert normal sesudahnya ditahan, bukan dianggap terlambat.
    normal = buf.add([make_alert(1, T0)], now=T0)
    assert normal == []
    assert buf.status()["size"] == 1
    assert partition_unseen is not None  # helper bisa di-import (didefinisikan di bawah)


def test_partition_unseen_splits_candidates():
    """partition_unseen(candidates, is_seen_fn) -> (unseen, seen), urutan dipertahankan."""
    from src.runtime.order_buffer import partition_unseen

    a = [make_alert(1, T0), make_alert(2, T0), make_alert(3, T0)]
    seen_ids = {"buf_002"}
    unseen, seen = partition_unseen(a, lambda aid: aid in seen_ids)
    assert [x.wazuh_alert_id for x in unseen] == ["buf_001", "buf_003"]
    assert [x.wazuh_alert_id for x in seen] == ["buf_002"]
    assert partition_unseen([], lambda aid: False) == ([], [])
