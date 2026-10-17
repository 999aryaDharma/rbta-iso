"""Unit test koordinasi LiveRBTAService, idle flush, dan shutdown terkendali."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import pytest
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.durable_state import DurableStateManager
from src.runtime.service import LiveRBTAService


def make_alert(idx: int, ts: datetime, group: str = "pam", level: int = 3, crit: int = 1) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"alert_{idx}",
        timestamp=ts,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary=group,
        rule_level=level,
        rule_id=f"550{idx % 5}",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=crit,
    )


def test_concurrent_ingress_serializes_core_mutations_and_recovers_all_ids(tmp_path, monkeypatch):
    service = LiveRBTAService(None, state_manager=DurableStateManager(tmp_path / "state.json"))
    first_entered = Event()
    second_requested = Event()
    overlapped = Event()
    process = service.engine.process
    active = False

    def guarded_process(alert):
        nonlocal active
        if active:
            overlapped.set()
        active = True
        if alert.wazuh_alert_id == "alert_1":
            first_entered.set()
            assert second_requested.wait(2)
            overlapped.wait(0.2)
        result = process(alert)
        active = False
        return result

    monkeypatch.setattr(service.engine, "process", guarded_process)
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)

    def second():
        second_requested.set()
        service.ingest_alert(make_alert(2, now))

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(service.ingest_alert, make_alert(1, now))
        assert first_entered.wait(2)
        other = pool.submit(second)
        first.result(timeout=5)
        other.result(timeout=5)
    assert not overlapped.is_set()
    recovered = LiveRBTAService(None, state_manager=DurableStateManager(tmp_path / "state.json"))
    assert recovered.engine._active_buckets[("001", "pam")].wazuh_alert_ids == ["alert_1", "alert_2"]
    assert recovered.is_seen("alert_1") and recovered.is_seen("alert_2")


def test_live_service_ingestion_scoring_and_idle_flush(tmp_path: Path):
    """Live service memfinalkan setiap skor tetapi hanya mengantrekan record pengiriman yang perlu ditindaklanjuti."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Latih bundle model.
    sample_alerts = [
        make_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1)
        for i in range(30)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="live-v1")
    scoring_pipe = ScoringPipeline(bundle)

    state_mgr = DurableStateManager(tmp_path / "service_state.json")
    service = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    # Ingest alert pukul 10:00.
    a1 = make_alert(1, base_t)
    out1 = service.ingest_alert(a1)
    assert out1 == []  # masih teragregasi di bucket aktif

    # Picu idle flush pukul 10:10 (idle 10m <= delta_t 15m -> masih boleh merge -> TIDAK flush).
    flushed_10 = service.check_idle_flush(base_t + timedelta(minutes=10))
    assert flushed_10 == []

    # Picu idle flush pukul 10:16 (idle 16m > delta_t 15m -> FLUSH).
    flushed_16 = service.check_idle_flush(base_t + timedelta(minutes=16))
    assert len(flushed_16) == 1
    assert isinstance(flushed_16[0], ScoredMetaAlert)
    assert flushed_16[0].meta_id == 1

    # Skor low-context ini tetap di history tetapi tidak masuk outbox pengiriman.
    outbox = service.get_outbox()
    assert flushed_16[0].action != "ESCALATE"
    assert outbox == []
    assert len(service.get_history()) == 1  # history tetap ada setelah ACK
    assert service.get_meta_detail(1) is not None


def test_live_service_controlled_shutdown_and_restart_recovery(tmp_path: Path):
    """Shutdown service menyimpan state; instance service baru memulihkan bucket aktif dan outbox."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [
        make_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1)
        for i in range(30)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="live-v1")
    scoring_pipe = ScoringPipeline(bundle)

    state_mgr = DurableStateManager(tmp_path / "service_state.json")
    service1 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    # Ingest alert 1 ke bucket aktif.
    service1.ingest_alert(make_alert(1, base_t))
    # Flush agar ada satu di history.
    service1.check_idle_flush(base_t + timedelta(minutes=20))

    # Shutdown terkendali (tanpa drain, bucket aktif dan history dipertahankan).
    service1.shutdown(drain=False)

    # Jalankan service2 baru dengan state manager yang sama.
    service2 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    assert len(service2.get_history()) == 1  # history tetap ada setelah restart

    # Ingest alert 2 pukul 10:25 -> bucket aktif baru.
    a2 = make_alert(2, base_t + timedelta(minutes=25))
    service2.ingest_alert(a2)

    # Shutdown dengan drain -> menghasilkan satu meta-alert final lagi.
    drained = service2.shutdown(drain=True)
    assert len(drained) == 1
    assert drained[0].alert_count == 1
    assert drained[0].source_alert_ids == ("alert_2",)
    assert len(service2.get_history()) == 2


def test_live_service_scoring_failure_durable_recovery(tmp_path: Path):
    """Bila scoring gagal, MetaAlert disimpan di antrean pending_scoring yang durable dan dipulihkan saat restart."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [
        make_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1)
        for i in range(30)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="live-v1")
    scoring_pipe = ScoringPipeline(bundle)

    state_mgr = DurableStateManager(tmp_path / "failing_service_state.json")
    service1 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    # Ingest alert 1.
    service1.ingest_alert(make_alert(1, base_t))

    # Mock scoring untuk menyimulasikan kegagalan di hilir saat idle flush.
    with patch.object(scoring_pipe, "score_single", side_effect=RuntimeError("Model inference service unavailable")):
        with pytest.raises(RuntimeError, match="Model inference service unavailable"):
            service1.check_idle_flush(base_t + timedelta(minutes=20))

    # pending_scoring tidak kosong dan tersimpan di disk.
    assert len(service1.pending_scoring) == 1
    assert service1.pending_scoring[0].meta_id == 1
    assert len(service1.get_outbox()) == 0

    # Jalankan service2 dengan scoring pipeline yang sehat.
    service2 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    # Service2 harus otomatis memulihkan dan menskor meta-alert yang tertunda.
    assert len(service2.pending_scoring) == 0
    assert service2.get_outbox() == []
    assert len(service2.get_history()) == 1


def test_non_escalate_scored_alert_is_history_not_actionable_outbox(tmp_path: Path):
    """Outbox pengiriman hanya boleh berisi record dengan action ESCALATE."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [
        make_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1)
        for i in range(30)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    scoring_pipe = ScoringPipeline(train_reference_pipeline(batch_res.meta_alerts, model_version="outbox-v1"))
    service = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=DurableStateManager(tmp_path / "state.json"),
        adaptive=False,
    )
    meta = batch_res.meta_alerts[0]
    suppressed = ScoredMetaAlert(
        meta_id=meta.meta_id,
        agent_id=meta.agent_id,
        agent_name=meta.agent_name,
        rule_group_primary=meta.rule_group_primary,
        start_time=meta.start_time,
        end_time=meta.end_time,
        alert_count=meta.alert_count,
        max_severity=meta.max_severity,
        mitre_tactics=meta.mitre_tactics_unique,
        seven_features={
            "max_severity": float(meta.max_severity),
            "mitre_tactic_count": 0.0,
            "critical_mitre_tactic_present": 0.0,
            "alert_count_log": 0.0,
            "rule_diversity_shannon": 0.0,
            "severity_dispersion": 0.0,
            "agent_criticality": float(meta.agent_criticality),
        },
        raw_model_score=0.1,
        anomaly_score=0.1,
        threshold_used=0.5,
        decision="NOISE",
        action="SUPPRESS",
        escalate=False,
        model_version="outbox-v1",
        feature_schema_version="1.0",
        score_calibration_version="minmax-v1",
        source_alert_ids=meta.wazuh_alert_ids,
    )
    service.pending_scoring.append(meta)

    with patch.object(scoring_pipe, "score_single", return_value=suppressed):
        result = service._drain_pending_scoring()

    assert result == [suppressed]
    assert service.get_outbox() == []
    assert service.get_history() == [suppressed]


def test_seen_id_memory_is_bounded_by_sqlite_duplicate_index(tmp_path: Path):
    base_t = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)
    alerts = [make_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1) for i in range(30)]
    metas = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(alerts).meta_alerts
    pipeline = ScoringPipeline(train_reference_pipeline(metas, model_version="seen-v1"))
    service = LiveRBTAService(pipeline, DurableStateManager(tmp_path / "state.json"), adaptive=False)

    first = make_alert(999, base_t)
    service.ingest_alert(first)
    assert len(service.engine._seen_alert_ids) <= 10_000
    assert service.is_seen(first.wazuh_alert_id)
    before = len(service.engine._active_buckets)
    assert service.ingest_alert(first) == []
    assert len(service.engine._active_buckets) == before
