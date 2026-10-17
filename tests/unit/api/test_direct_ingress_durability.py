"""Unit test durabilitas ingress API langsung, persistensi bucket aktif, dan shutdown yang rapi."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from fastapi.testclient import TestClient
import pytest

from src.api.server import create_production_app
from src.contracts.raw_alert import CanonicalRawAlert
from src.model.registry import ModelRegistry
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.durable_state import DurableStateManager
from src.runtime.service import LiveRBTAService
from src.runtime.raw_evidence import RawAlertEvidenceStore


def make_raw_alert(idx: int, ts: datetime) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"durability_alert_{idx}",
        timestamp=ts,
        agent_id="001",
        agent_name="soc-1",
        rule_group_primary="pam",
        rule_level=(idx % 12) + 1,
        rule_id=f"550{idx % 5}",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1,
    )


def setup_test_model(reg_dir: Path, version: str = "dur-v1") -> None:
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [make_raw_alert(i, base_t + timedelta(minutes=i * 20)) for i in range(30)]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version=version)

    registry = ModelRegistry(base_dir=reg_dir)
    registry.publish_bundle(bundle, model_version=version)


def test_direct_ingress_persists_active_bucket_and_seen_id_before_http_return(tmp_path: Path):
    """Saat alert diterima lewat ingress HTTP, bucket aktif dan ID seen langsung durable di disk."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"
    setup_test_model(reg_dir, "dur-v1")

    env = {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "dur-v1",
        "RBTA_STATE_FILE": str(state_file),
        "RBTA_RAW_EVIDENCE_DB": str(tmp_path / "evidence.sqlite3"),
    }

    # Ingest alert A lewat HTTP API.
    app1 = create_production_app(env=env)
    client1 = TestClient(app1)

    payload = {
        "id": "alert_active_100",
        "timestamp": "2026-08-28T12:00:00.000+0000",
        "agent": {"id": "001", "name": "soc-1"},
        "rule": {"id": "5501", "level": 3, "groups": ["pam"]},
        "rule_group_primary": "pam",
        "agent_criticality": 1,
    }

    resp1 = client1.post("/api/v1/alerts/ingest", json=payload)
    assert resp1.status_code == 200
    assert resp1.json() == {
        "status": "accepted",
        "alert_id": "alert_active_100",
        "is_duplicate": False,
    }

    # Simulasikan crash proses dengan membuat app2 / service2 dari file state yang sama persis.
    # Restart simulasi: OS melepas lock state saat proses berhenti.
    from src.runtime.live_worker import release_state_lock

    release_state_lock(str(state_file))
    app2 = create_production_app(env=env)
    client2 = TestClient(app2)

    # Cek statistik instance baru: seen_alerts_count harus 1, active_buckets_count harus 1.
    stats_resp = client2.get("/runtime/stats")
    assert stats_resp.status_code == 200
    stats_data = stats_resp.json()
    assert stats_data["seen_alerts_count"] == 1
    assert stats_data["active_buckets_count"] == 1

    # Ingest ulang alert A harus dikenali sebagai duplikat no-op.
    resp2 = client2.post("/api/v1/alerts/ingest", json=payload)
    assert resp2.status_code == 200
    assert resp2.json() == {
        "status": "accepted",
        "alert_id": "alert_active_100",
        "is_duplicate": True,
    }


def test_graceful_shutdown_drain_false_preserves_active_bucket_without_forced_finalization(tmp_path: Path):
    """Shutdown rapi (drain=False) menyimpan bucket aktif tanpa membuat MetaAlert buatan."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"
    setup_test_model(reg_dir, "dur-v1")

    reg = ModelRegistry(base_dir=reg_dir)
    bundle = reg.load_bundle("dur-v1")
    scoring_pipe = ScoringPipeline(bundle)
    state_mgr = DurableStateManager(state_file)

    service1 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    t0 = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
    a1 = make_raw_alert(1, t0)
    service1.ingest_alert(a1)

    # Bucket aktif ada.
    assert len(service1.engine._active_buckets) == 1
    assert len(service1.get_history()) == 0

    # Shutdown dengan drain=False.
    service1.shutdown(drain=False)

    # Instance service baru memulihkan bucket aktif.
    service2 = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=DurableStateManager(state_file),
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    assert len(service2.engine._active_buckets) == 1
    assert len(service2.get_history()) == 0
    assert service2.is_seen("durability_alert_1")


@pytest.mark.parametrize("auto_persist", [True, False])
def test_committed_state_has_raw_evidence_visible_to_another_process(tmp_path, auto_persist):
    evidence_path = tmp_path / "evidence.sqlite3"
    service = LiveRBTAService(
        scoring_pipeline=None,
        state_manager=DurableStateManager(tmp_path / "state.json"),
        raw_evidence_store=RawAlertEvidenceStore(evidence_path),
        auto_persist=auto_persist,
    )
    alert = make_raw_alert(1, datetime(2026, 9, 28, tzinfo=timezone.utc))
    service.ingest_alert(alert)
    if not auto_persist:
        service.shutdown(drain=False)
    with sqlite3.connect(evidence_path) as conn:
        row = conn.execute("SELECT wazuh_alert_id FROM raw_alert_evidence").fetchone()
    assert row == (alert.wazuh_alert_id,)
    assert service.state_manager.has_seen_alert_id(alert.wazuh_alert_id)
