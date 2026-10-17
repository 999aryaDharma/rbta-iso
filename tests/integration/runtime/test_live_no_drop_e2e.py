"""Integration test ingestion live tanpa drop, pemulihan crash, dan pending scoring."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.durable_state import DurableStateManager
from src.runtime.live_coordinator import LiveIngestionCoordinator
from src.runtime.live_source import WazuhIndexerLivePoller
from src.runtime.service import LiveRBTAService


def make_raw_alert(
    idx: int,
    ts: datetime,
    group: str = "pam",
    level: int = 3,
    crit: int = 1,
) -> CanonicalRawAlert:
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


def test_live_no_drop_service_restart_and_reconciliation_recovery(tmp_path: Path):
    """Restart service memulihkan ID seen dan pending scoring; scan rekonsiliasi menemukan ID baru tanpa menduplikasi yang lama."""
    base_t = datetime(2026, 8, 28, 8, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [
        make_raw_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1)
        for i in range(30)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="live-nodrop-v1")
    scoring_pipe = ScoringPipeline(bundle)

    state_file = tmp_path / "live_nodrop_state.json"
    state_mgr = DurableStateManager(state_file)

    # Jalankan instance service pertama.
    service1 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )
    poller1 = MagicMock(spec=WazuhIndexerLivePoller)

    a1 = make_raw_alert(1, base_t)
    a2 = make_raw_alert(2, base_t + timedelta(minutes=5))
    poller1.poll_recent.return_value = [a1, a2]
    poller1.poll_reconciliation.return_value = [a1, a2]
    poller1.poll_full_reconciliation.return_value = []

    coord1 = LiveIngestionCoordinator(service=service1, poller=poller1)
    res1 = coord1.run_cycle(current_time=base_t + timedelta(minutes=6), force_recent_reconciliation=True)

    assert res1.processed_new_ids == 2
    assert service1.is_seen("alert_1")
    assert service1.is_seen("alert_2")

    # Simulasikan crash/restart proses dengan membuat service baru dari file state yang sama.
    state_mgr2 = DurableStateManager(state_file)
    service2 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr2,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )
    poller2 = MagicMock(spec=WazuhIndexerLivePoller)

    # Rekonsiliasi seluruh retensi di service2 menemukan a1, a2, dan a3 yang baru (dari beberapa hari sebelumnya).
    a3 = make_raw_alert(3, base_t - timedelta(days=3))
    poller2.poll_recent.return_value = []
    poller2.poll_reconciliation.return_value = []
    poller2.poll_full_reconciliation.return_value = [a3, a1, a2]

    coord2 = LiveIngestionCoordinator(service=service2, poller=poller2)
    res2 = coord2.run_cycle(current_time=base_t + timedelta(minutes=12), force_full_reconciliation=True)

    # a1, a2 dikenali sebagai duplikat no-op; a3 diproses dengan bersih.
    assert res2.processed_new_ids == 1
    assert res2.duplicate_noops == 2
    assert service2.is_seen("alert_3")


def test_pending_scoring_survives_scoring_failure_and_reconciliation(tmp_path: Path):
    """Bila scoring gagal saat ingestion, MetaAlert tetap di pending_scoring dan dikuras saat restart; rescan tetap aman."""
    base_t = datetime(2026, 8, 28, 8, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [
        make_raw_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1)
        for i in range(30)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="live-nodrop-v1")
    scoring_pipe = ScoringPipeline(bundle)

    state_file = tmp_path / "pending_scoring_state.json"
    state_mgr = DurableStateManager(state_file)

    service1 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    # Ingest alert 1.
    a1 = make_raw_alert(1, base_t)
    service1.ingest_alert(a1)

    # Flush idle untuk menghasilkan MetaAlert, tetapi score_single di-mock agar error.
    with patch.object(scoring_pipe, "score_single", side_effect=RuntimeError("Model server down")):
        with pytest.raises(RuntimeError, match="Model server down"):
            service1.check_idle_flush(base_t + timedelta(minutes=20))

    # MetaAlert tetap di antrean pending_scoring dan tersimpan di disk.
    assert len(service1.pending_scoring) == 1
    meta_id = service1.pending_scoring[0].meta_id

    # Restart service dengan scoring pipeline yang sehat.
    state_mgr2 = DurableStateManager(state_file)
    service2 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr2,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    # Startup service2 otomatis menguras pending_scoring.
    assert len(service2.pending_scoring) == 0
    assert len(service2.finalized_history) == 1
    assert service2.finalized_history[0].meta_id == meta_id

    # Rekonsiliasi membaca ulang a1.
    poller2 = MagicMock(spec=WazuhIndexerLivePoller)
    poller2.poll_recent.return_value = []
    poller2.poll_reconciliation.return_value = [a1]
    poller2.poll_full_reconciliation.return_value = []

    coord2 = LiveIngestionCoordinator(service=service2, poller=poller2)
    res2 = coord2.run_cycle(current_time=base_t + timedelta(minutes=25), force_recent_reconciliation=True)

    # a1 duplikat no-op, tidak ada MetaAlert duplikat yang terbentuk.
    assert res2.duplicate_noops == 1
    assert res2.processed_new_ids == 0
    assert len(service2.finalized_history) == 1
