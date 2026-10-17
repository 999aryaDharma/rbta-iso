"""Unit test: observability sesuai kenyataan, derivasi system_status dinamis, status integrasi jujur, dan timeseries raw."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

from src.contracts.raw_alert import CanonicalRawAlert
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.registry import ModelRegistry
from src.model.scoring_pipeline import train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.durable_state import DurableStateManager
from src.runtime.observability import (
    get_dashboard_agents,
    get_dashboard_integrations,
    get_dashboard_summary,
    get_dashboard_system,
    get_dashboard_timeseries,
)
from src.runtime.raw_evidence import RawAlertEvidenceStore
from src.runtime.replay_controller import ReplayController
from src.runtime.service import LiveRBTAService
from src.api.server import create_production_app


def _make_test_alert(i: int, ts: datetime) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"art_{i}",
        timestamp=ts,
        agent_id=f"00{1 + (i % 3)}",
        agent_name=f"agent-{1 + (i % 3)}",
        rule_group_primary="pam" if i % 2 == 0 else "syslog",
        rule_level=(i % 12) + 1,
        rule_id=f"550{i % 6}",
        mitre_tactics=("credential-access",) if i % 3 == 0 else (),
        srcip=f"192.168.1.{50 + i % 10}",
        agent_criticality=(i % 3) + 1,
    )


@pytest.fixture
def test_scoring_pipeline(tmp_path: Path):
    base_t = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [_make_test_alert(i, base_t + timedelta(minutes=i * 5)) for i in range(40)]
    runner = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False)
    batch_res = runner.run(alerts)
    bundle = train_reference_pipeline(
        batch_res.meta_alerts,
        random_state=123,
        model_version="rbta-truth-v42",
    )
    from src.model.scoring_pipeline import ScoringPipeline
    return ScoringPipeline(bundle)


def test_dashboard_system_observability_metadata_truth(tmp_path: Path, test_scoring_pipeline):
    """Metadata sistem observability harus sama persis dengan field artefak tanpa fallback karangan."""
    state_mgr = DurableStateManager(tmp_path / "state.json")
    evidence_store = RawAlertEvidenceStore(tmp_path / "evidence.sqlite3")

    service = LiveRBTAService(
        scoring_pipeline=test_scoring_pipeline,
        state_manager=state_mgr,
        raw_evidence_store=evidence_store,
        source_mode="DEFERRED",
    )

    sys_meta = get_dashboard_system(service)

    assert sys_meta["model_version"] == "rbta-truth-v42"
    assert sys_meta["random_state"] == 123
    assert sys_meta["tukey_threshold"] == test_scoring_pipeline.threshold.threshold
    assert len(sys_meta["feature_names"]) == 7
    assert sys_meta["feature_names"] == list(test_scoring_pipeline.schema["features"])
    assert sys_meta["source_mode"] == "DEFERRED"
    assert sys_meta["system_status"] == "READY"


def test_system_status_derived_ready_and_degraded(tmp_path: Path, test_scoring_pipeline):
    """system_status diturunkan dinamis: READY bila semua komponen utuh, DEGRADED bila ada yang rusak."""
    state_mgr = DurableStateManager(tmp_path / "state.json")
    evidence_store = RawAlertEvidenceStore(tmp_path / "evidence.sqlite3")

    service = LiveRBTAService(
        scoring_pipeline=test_scoring_pipeline,
        state_manager=state_mgr,
        raw_evidence_store=evidence_store,
    )
    assert get_dashboard_system(service)["system_status"] == "READY"
    assert get_dashboard_summary(service, evidence_store)["system_status"] == "READY"

    # Rusak metadata pipeline.
    test_scoring_pipeline.metadata.pop("model_version", None)
    assert get_dashboard_system(service)["system_status"] == "DEGRADED"
    assert get_dashboard_summary(service, evidence_store)["system_status"] == "DEGRADED"


def test_production_source_mode_deferred_by_default(tmp_path: Path):
    """create_production_app memakai default RBTA_SOURCE_MODE = DEFERRED dan memvalidasi nilai yang diizinkan."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "state.json"
    evidence_file = tmp_path / "evidence.sqlite3"

    base_t = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
    alerts = [_make_test_alert(i, base_t + timedelta(minutes=i * 5)) for i in range(40)]
    runner = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False)
    bundle = train_reference_pipeline(runner.run(alerts).meta_alerts, random_state=42, model_version="prod-m1")
    registry = ModelRegistry(base_dir=reg_dir)
    registry.publish_bundle(bundle, model_version="prod-m1")

    # Mode default -> DEFERRED.
    env_default = {
        "RBTA_API_KEY": "test-key",
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "prod-m1",
        "RBTA_STATE_FILE": str(state_file),
        "RBTA_RAW_EVIDENCE_DB": str(evidence_file),
    }
    app1 = create_production_app(env=env_default)
    srv1 = app1.state.runtime_resolver.live_service
    assert srv1.source_mode == "DEFERRED"

    # Restart simulasi: OS melepas lock state saat proses berhenti.
    from src.runtime.live_worker import release_state_lock

    release_state_lock(str(state_file))

    # Mode LIVE eksplisit.
    env_live = dict(env_default, RBTA_SOURCE_MODE="LIVE")
    app2 = create_production_app(env=env_live)
    srv2 = app2.state.runtime_resolver.live_service
    assert srv2.source_mode == "LIVE"

    release_state_lock(str(state_file))

    # Mode tidak valid melempar ValueError.
    env_invalid = dict(env_default, RBTA_SOURCE_MODE="UNKNOWN_MODE")
    with pytest.raises(ValueError, match="RBTA_SOURCE_MODE"):
        create_production_app(env=env_invalid)


def test_dashboard_integrations_truthful_status(tmp_path: Path, test_scoring_pipeline):
    """get_dashboard_integrations melaporkan status eksternal sesuai konteks runtime."""
    state_mgr = DurableStateManager(tmp_path / "state.json")
    evidence_store = RawAlertEvidenceStore(tmp_path / "evidence.sqlite3")

    # Saat source_mode DEFERRED.
    service_def = LiveRBTAService(
        scoring_pipeline=test_scoring_pipeline,
        state_manager=state_mgr,
        raw_evidence_store=evidence_store,
        source_mode="DEFERRED",
    )
    integ_def = get_dashboard_integrations(service_def)
    assert integ_def["wazuh"]["status"] == "DEFERRED"
    assert integ_def["rbta"]["status"] == "READY"
    assert integ_def["model"]["status"] == "READY"
    assert integ_def["outbox"]["status"] == "READY"
    assert integ_def["shuffle"]["status"] == "DEFERRED_EXTERNAL"
    assert integ_def["telegram"]["status"] == "DEFERRED_EXTERNAL"

    # Saat source_mode LIVE (tanpa coordinator).
    service_live = LiveRBTAService(
        scoring_pipeline=test_scoring_pipeline,
        state_manager=state_mgr,
        raw_evidence_store=evidence_store,
        source_mode="LIVE",
    )
    integ_live = get_dashboard_integrations(service_live)
    assert integ_live["wazuh"]["status"] == "UNKNOWN"


def test_timeseries_counts_active_buckets_as_raw_evidence(tmp_path: Path, test_scoring_pipeline):
    """Jumlah timeseries raw diambil murni dari raw evidence store, meski masih di bucket aktif."""
    state_mgr = DurableStateManager(tmp_path / "state.json")
    evidence_store = RawAlertEvidenceStore(tmp_path / "evidence.sqlite3")

    service = LiveRBTAService(
        scoring_pipeline=test_scoring_pipeline,
        state_manager=state_mgr,
        raw_evidence_store=evidence_store,
    )

    base_t = datetime.now(timezone.utc).replace(minute=5, second=0, microsecond=0) - timedelta(hours=2)
    a1 = CanonicalRawAlert(
        wazuh_alert_id="raw-1",
        timestamp=base_t,
        agent_id="001",
        agent_name="agent-1",
        rule_group_primary="pam",
        rule_level=7,
        rule_id="5501",
        mitre_tactics=("credential-access",),
        srcip="192.168.1.50",
        agent_criticality=2,
    )
    a2 = CanonicalRawAlert(
        wazuh_alert_id="raw-2",
        timestamp=base_t + timedelta(minutes=5),
        agent_id="001",
        agent_name="agent-1",
        rule_group_primary="pam",
        rule_level=8,
        rule_id="5502",
        mitre_tactics=("credential-access",),
        srcip="192.168.1.51",
        agent_criticality=2,
    )

    # Ingest 2 alert ke service -> tersimpan di raw evidence store, bucket aktif terbentuk, BELUM ada MetaAlert final.
    service.ingest_alert(a1)
    service.ingest_alert(a2)
    assert len(service.finalized_history) == 0

    # Query timeseries untuk window yang mencakup jam UTC saat ini.
    ts_bins = get_dashboard_timeseries(service, evidence_store, window_hours=24)
    hour_key = base_t.strftime("%Y-%m-%d %H:00")
    target_bin = next((b for b in ts_bins if b["timestamp"] == hour_key), None)
    assert target_bin is not None, f"Hour bin {hour_key} not found in {ts_bins}"
    assert target_bin["raw_alerts"] == 2
    assert target_bin["meta_alerts"] == 0

    # Kuras service untuk memfinalkan MetaAlert.
    scored = service.drain_and_score()
    assert len(scored) == 1
    assert len(service.finalized_history) == 1

    # Query timeseries lagi -> raw_alerts tetap 2, meta_alerts sekarang 1.
    ts_bins_after = get_dashboard_timeseries(service, evidence_store, window_hours=24)
    target_bin_after = next((b for b in ts_bins_after if b["timestamp"] == hour_key), None)
    assert target_bin_after is not None
    assert target_bin_after["raw_alerts"] == 2
    assert target_bin_after["meta_alerts"] == 1


def test_dashboard_agents_resolves_legacy_unknown_name_from_canonical_evidence(tmp_path: Path):
    """Run lama yang sudah selesai tetap menyimpan nama host meski bucket-nya sudah dikuras."""
    from types import SimpleNamespace
    from src.rbta.engine import RBTAEngine

    store = RawAlertEvidenceStore(tmp_path / "evidence.sqlite3")
    alert = _make_test_alert(99, datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc))
    engine = RBTAEngine()
    store.store(alert)
    engine.process(alert)
    engine.drain()
    # Simulasikan file state yang ditulis sebelum agent_name ikut disimpan.
    engine._temporal_states[alert.agent_id].agent_name = "unknown"

    agents = get_dashboard_agents(SimpleNamespace(engine=engine), store)
    assert agents[0]["agent_name"] == alert.agent_name


def test_replay_run_provenance_uses_exact_model_version(tmp_path: Path, test_scoring_pipeline):
    """ReplayController menulis versi model persis ke run.json tanpa fallback."""
    replay_data_dir = tmp_path / "replay_data"
    replay_data_dir.mkdir(parents=True)
    sample_jsonl = replay_data_dir / "test_sample.jsonl"
    sample_jsonl.write_text('{"id":"sample-1"}\n', encoding="utf-8")

    replay_runs_dir = tmp_path / "replay_runs"

    controller = ReplayController(
        scoring_pipeline=test_scoring_pipeline,
        replay_data_dir=replay_data_dir,
        replay_runs_dir=replay_runs_dir,
    )

    run_id = controller._init_run_workspace("test_sample.jsonl", "MAX")
    run_meta_file = replay_runs_dir / run_id / "run.json"
    assert run_meta_file.exists()

    import json
    with open(run_meta_file, "r", encoding="utf-8") as f:
        meta_data = json.load(f)

    assert meta_data["model_version"] == "rbta-truth-v42"
    assert meta_data["model_version"] != "v1"
