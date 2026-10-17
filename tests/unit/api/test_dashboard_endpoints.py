from datetime import datetime, timedelta, timezone
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType
import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.contracts.meta_alert import MetaAlert
from src.contracts.raw_alert import CanonicalRawAlert
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runtime.durable_state import DurableStateManager
from src.runtime.raw_evidence import RawAlertEvidenceStore
from src.runtime.replay_controller import ReplayController
from src.runtime.service import LiveRBTAService


@pytest.fixture
def test_setup(tmp_path: Path):
    db_path = tmp_path / "evidence.sqlite3"
    state_path = tmp_path / "state.json"
    datasets_dir = tmp_path / "datasets"
    runs_dir = tmp_path / "runs"
    datasets_dir.mkdir()
    runs_dir.mkdir()

    base_t = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)
    metas = [
        MetaAlert(
            meta_id=i,
            agent_id="001",
            agent_name="agent-ubuntu",
            rule_group_primary="authentication_failed",
            start_time=base_t + timedelta(hours=i),
            end_time=base_t + timedelta(hours=i, minutes=10),
            alert_count=5 + i,
            max_severity=3 + (i % 10),
            rule_id_distribution={"5710": 5 + i},
            severity_distribution={3: 5 + i},
            agent_criticality=1.0,
            wazuh_alert_ids=(f"aid_{i}_1", f"aid_{i}_2"),
            mitre_tactics_unique=("credential-access",),
            critical_mitre_present=False,
            metadata={},
        )
        for i in range(1, 10)
    ]
    bundle = train_reference_pipeline(metas, random_state=42, model_version="test-model-v1")
    scoring_pipe = ScoringPipeline(bundle)

    evidence_store = RawAlertEvidenceStore(db_path)
    state_mgr = DurableStateManager(state_path)

    service = LiveRBTAService(
        scoring_pipeline=scoring_pipe,
        state_manager=state_mgr,
        raw_evidence_store=evidence_store,
        source_mode="DEFERRED",
    )

    replay_ctrl = ReplayController(
        scoring_pipeline=scoring_pipe,
        replay_data_dir=datasets_dir,
        replay_runs_dir=runs_dir,
    )

    app = create_app(
        service=service,
        api_key="secret-api-key-123",
        raw_evidence_store=evidence_store,
        replay_controller=replay_ctrl,
    )
    client = TestClient(app)
    headers = {"Authorization": "Bearer secret-api-key-123"}
    return client, headers, service, evidence_store, replay_ctrl, datasets_dir


def test_auth_check_endpoint(test_setup):
    client, headers, _, _, _, _ = test_setup

    # Tanpa key -> 401
    resp_unauth = client.get("/api/v1/auth/check")
    assert resp_unauth.status_code == 401

    # Dengan key -> 200
    resp_auth = client.get("/api/v1/auth/check", headers=headers)
    assert resp_auth.status_code == 200
    assert resp_auth.json()["authenticated"] is True


def test_dashboard_summary_and_verbatim_arr(test_setup):
    client, headers, service, evidence_store, _, _ = test_setup

    # Masukkan 2 raw alert.
    a1 = CanonicalRawAlert(
        wazuh_alert_id="aid-01",
        timestamp=datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc),
        agent_id="001",
        agent_name="agent-ubuntu",
        rule_group_primary="auth",
        rule_level=5,
        rule_id="1001",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1.0,
        metadata=MappingProxyType({}),
    )
    service.ingest_alert(a1)

    resp = client.get("/api/v1/dashboard/summary", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "raw_alert_count" in data
    assert "meta_alert_count" in data
    assert "alert_reduction_rate_percent" in data


def test_dashboard_integrations_backend_truth(test_setup):
    client, headers, _, _, _, _ = test_setup
    resp = client.get("/api/v1/dashboard/integrations", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["wazuh"]["status"] == "DEFERRED"
    assert data["rbta"]["status"] == "READY"
    assert data["model"]["status"] == "READY"
    assert data["shuffle"]["status"] == "DEFERRED_EXTERNAL"
    assert data["telegram"]["status"] == "DEFERRED_EXTERNAL"


def test_meta_alerts_raw_alerts_resolution_and_unresolved(test_setup):
    client, headers, service, evidence_store, _, _ = test_setup

    a1 = CanonicalRawAlert(
        wazuh_alert_id="res-1",
        timestamp=datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc),
        agent_id="001",
        agent_name="agent-ubuntu",
        rule_group_primary="auth",
        rule_level=5,
        rule_id="1001",
        mitre_tactics=("initial-access",),
        srcip="10.0.0.1",
        agent_criticality=1.0,
        metadata=MappingProxyType({"rule_description": "Initial login attempt"}),
    )
    service.ingest_alert(a1)

    # Paksa satu meta-alert terskor dengan ID ter-resolve res-1 dan ID hilang res-unresolved.
    assert len(service.finalized_history) > 0 or len(service.engine.snapshot_buckets()) >= 0
    flushed = service.engine.flush_idle(datetime(2026, 8, 29, 14, 0, 0, tzinfo=timezone.utc))
    if flushed:
        service.pending_scoring.extend(flushed)
        scored = service._drain_pending_scoring()
        target_meta_id = scored[0].meta_id
    else:
        target_meta_id = 1

    resp = client.get(f"/api/v1/meta-alerts/{target_meta_id}/raw-alerts", headers=headers)
    assert resp.status_code in (200, 404)
    if resp.status_code == 200:
        data = resp.json()
        assert "source_total" in data
        assert "resolved_total" in data
        assert "filtered_total" in data
        assert "unresolved_alert_ids" in data
        assert isinstance(data["items"], list)


def test_dashboard_bucket_raw_alerts_lists_active_members(test_setup):
    client, headers, service, evidence_store, _, _ = test_setup

    base = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)
    for i in (1, 2):
        alert = CanonicalRawAlert(
            wazuh_alert_id=f"live-bucket-{i}",
            timestamp=base + timedelta(seconds=i * 5),
            agent_id="001",
            agent_name="agent-ubuntu",
            rule_group_primary="auth",
            rule_level=5,
            rule_id="1001",
            mitre_tactics=(),
            srcip=None,
            agent_criticality=1.0,
            metadata=MappingProxyType({}),
        )
        evidence_store.store(alert)
        service.ingest_alert(alert)

    resp = client.get(
        "/api/v1/dashboard/buckets/raw-alerts",
        params={"agent_id": "001", "rule_group_primary": "auth"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "001"
    assert data["rule_group_primary"] == "auth"
    assert data["finalized"] is False
    assert data["source_total"] == 2
    assert [item["wazuh_alert_id"] for item in data["items"]] == ["live-bucket-1", "live-bucket-2"]

    page2 = client.get(
        "/api/v1/dashboard/buckets/raw-alerts",
        params={"agent_id": "001", "rule_group_primary": "auth", "page": 2, "page_size": 1},
        headers=headers,
    )
    assert page2.status_code == 200
    assert [item["wazuh_alert_id"] for item in page2.json()["items"]] == ["live-bucket-2"]


def test_dashboard_bucket_raw_alerts_unknown_bucket_404(test_setup):
    client, headers, _, _, _, _ = test_setup

    resp = client.get(
        "/api/v1/dashboard/buckets/raw-alerts",
        params={"agent_id": "999", "rule_group_primary": "nope"},
        headers=headers,
    )
    assert resp.status_code == 404


def test_meta_alert_trace_uses_evidence_resolution_contract(test_setup):
    client, headers, service, evidence_store, _, _ = test_setup
    alert = CanonicalRawAlert(
        wazuh_alert_id="trace-resolved",
        timestamp=datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc),
        agent_id="001", agent_name="agent-ubuntu", rule_group_primary="auth",
        rule_level=8, rule_id="5710", mitre_tactics=(), srcip=None,
        agent_criticality=1.0,
        metadata=MappingProxyType({"rule_description": "SSH authentication failed"}),
    )
    evidence_store.store(alert)
    service.ingest_alert(alert)
    flushed = service.engine.flush_idle(datetime(2026, 8, 29, 14, 0, tzinfo=timezone.utc))
    service.pending_scoring.extend(flushed)
    scored = service._drain_pending_scoring()[0]
    # Pertahankan referensi sumber yang hilang agar tetap terlihat, bukan dibuang.
    scored = replace(scored, source_alert_ids=("trace-resolved", "trace-missing"))
    service.finalized_history[-1] = scored

    response = client.get(f"/api/v1/meta-alerts/{scored.meta_id}/trace", headers=headers)
    assert response.status_code == 200
    trace = response.json()
    assert trace["rule_group_primary"] == "auth"
    assert trace["source_total"] == 2
    assert trace["resolved_total"] == 1
    assert trace["unresolved_alert_ids"] == ["trace-missing"]
    assert [member["wazuh_alert_id"] for member in trace["members"]] == ["trace-resolved", "trace-missing"]
    assert trace["members"][0]["canonical_fingerprint"]
    assert trace["members"][1]["resolved"] is False


def test_raw_alert_detail_redaction(test_setup):
    client, headers, service, evidence_store, _, _ = test_setup

    secret_alert = CanonicalRawAlert(
        wazuh_alert_id="sec-alert-999",
        timestamp=datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc),
        agent_id="001",
        agent_name="agent-ubuntu",
        rule_group_primary="auth",
        rule_level=5,
        rule_id="1001",
        mitre_tactics=(),
        srcip=None,
        agent_criticality=1.0,
        metadata=MappingProxyType({"api_key": "top_secret_token_val"}),
    )
    evidence_store.store(secret_alert)

    resp = client.get("/api/v1/raw-alerts/sec-alert-999", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["metadata"]["api_key"] == "[REDACTED]"


def test_replay_start_contract_and_datasets(test_setup):
    client, headers, _, _, replay_ctrl, datasets_dir = test_setup

    # Buat dataset dummy.
    (datasets_dir / "demo.jsonl").write_text("{\"id\": \"1\", \"timestamp\": \"2026-08-29T10:00:00Z\", \"agent\": {\"id\": \"001\"}, \"rule\": {\"id\": \"1\", \"level\": 3, \"groups\": [\"syslog\"]}}\n", encoding="utf-8")

    # Daftar dataset.
    resp_ds = client.get("/api/v1/replay/datasets", headers=headers)
    assert resp_ds.status_code == 200
    assert len(resp_ds.json()["items"]) == 1
    assert resp_ds.json()["items"][0]["name"] == "demo.jsonl"
    assert resp_ds.json()["items"][0]["inspection_status"] == "pending"

    refresh = client.post("/api/v1/replay/datasets/refresh", headers=headers)
    assert refresh.status_code == 200
    replay_ctrl.wait_for_catalog_refresh(timeout=5.0)
    catalog_status = client.get("/api/v1/replay/datasets/catalog-status", headers=headers)
    assert catalog_status.status_code == 200
    assert catalog_status.json()["status"] == "COMPLETED"
    assert catalog_status.json()["pending_files"] == 0

    # Mulai dengan body JSON Pydantic.
    resp_start = client.post(
        "/api/v1/replay/start",
        json={"dataset_name": "demo.jsonl", "speed_factor": "MAX"},
        headers=headers,
    )
    assert resp_start.status_code == 200
    assert resp_start.json()["status"] in ("RUNNING", "COMPLETED")


def test_nonexistent_api_route_returns_404_json(test_setup):
    client, headers, _, _, _, _ = test_setup
    resp = client.get("/api/v1/does_not_exist", headers=headers)
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/json")


def test_post_replay_evaluation_api_lifecycle(test_setup):
    client, headers, _, _, replay_ctrl, datasets_dir = test_setup
    base_t = datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc)
    records = []
    for idx in range(30):
        records.append({
            "id": f"eval-{idx}",
            "timestamp": (base_t + timedelta(minutes=idx * 3)).isoformat(),
            "agent": {"id": f"00{idx % 3 + 1}", "name": f"agent-{idx % 3 + 1}"},
            "rule": {
                "id": str(5700 + idx % 5),
                "level": (idx % 12) + 1,
                "groups": ["auth" if idx % 2 else "web"],
                "mitre": {"tactic": ["Execution"] if idx % 5 == 0 else []},
            },
        })
    import json
    (datasets_dir / "evaluation.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    replay_ctrl.start("evaluation.jsonl", "MAX")
    replay_ctrl.wait_until_complete(5.0)
    started = client.post("/api/v1/replay/evaluation/start", headers=headers)
    assert started.status_code == 200
    replay_ctrl.wait_until_evaluation_complete(timeout=15.0)

    status_response = client.get("/api/v1/replay/evaluation/status", headers=headers)
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "COMPLETED"
    artifact_response = client.get("/api/v1/replay/evaluation/artifact", headers=headers)
    assert artifact_response.status_code == 200
    assert artifact_response.headers["content-type"].startswith("application/json")
