"""Integration test end-to-end: alert Wazuh sampai ke Shuffle SOAR."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from starlette.testclient import TestClient

from src.api.app import create_app
from src.api.shuffle_adapter import ShuffleWebhookForwarder
from src.contracts.raw_alert import CanonicalRawAlert
from src.model.registry import ModelRegistry
from src.model.scoring_pipeline import ScoringPipeline, train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner
from src.runtime.durable_state import DurableStateManager
from src.runtime.service import LiveRBTAService


def make_clean_alert(idx: int, ts: datetime, group: str = "pam", level: int = 3, crit: int = 1) -> CanonicalRawAlert:
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


def test_e2e_wazuh_alert_to_shuffle_exactly_once(tmp_path: Path):
    """Alert Wazuh melewati seluruh pipeline penelitian dan sampai ke Shuffle tepat satu kali."""
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)

    # Latih dan publikasikan bundle model reference.
    training_alerts = [
        make_clean_alert(i, base_t + timedelta(minutes=i * 20), level=(i % 12) + 1)
        for i in range(30)
    ]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(training_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version="e2e-v1")

    registry = ModelRegistry(base_dir=tmp_path / "models")
    registry.publish_bundle(bundle, "e2e-v1")

    # Siapkan live service dan aplikasi API.
    state_mgr = DurableStateManager(tmp_path / "state.json")
    service = LiveRBTAService(
        scoring_pipeline=ScoringPipeline(bundle),
        state_manager=state_mgr,
        base_delta_t=timedelta(minutes=15),
        adaptive=False,
    )

    app = create_app(service=service, model_registry=registry, api_key="test-secret")
    api_client = TestClient(app)
    headers = {"Authorization": "Bearer test-secret"}

    # Simulasikan endpoint webhook Shuffle beserta pencatat penerimaan.
    shuffle_forwarder = ShuffleWebhookForwarder(
        webhook_url="https://shuffle.campus.local/api/v1/hooks/rbta_scored",
        api_key="shuffle-token-xyz",
    )
    received_webhooks: list[dict] = []

    def mock_post(url, headers, json, timeout, verify):
        resp = MagicMock()
        resp.status_code = 200
        received_webhooks.append({"headers": dict(headers), "payload": dict(json)})
        return resp

    # Ingest raw alert Wazuh lewat boundary REST.
    # Event 1 pukul 10:00 (terakumulasi).
    raw_1 = {
        "id": "e2e_wazuh_001",
        "timestamp": "2026-08-28T10:00:00.000+0000",
        "agent": {"id": "001", "name": "soc-1"},
        "rule": {"id": "5501", "level": 12, "groups": ["pam"], "mitre": {"tactic": ["Initial Access"]}},
    }
    r1 = api_client.post("/api/v1/alerts/ingest", json=raw_1, headers=headers)
    assert r1.status_code == 200
    assert r1.json()["is_duplicate"] is False

    # Ulangi event 1 -> diterima sebagai duplikat tanpa mengubah core.
    r1_dup = api_client.post("/api/v1/alerts/ingest", json=raw_1, headers=headers)
    assert r1_dup.status_code == 200
    assert r1_dup.json()["is_duplicate"] is True

    # Event 2 pukul 10:20 (jeda 20 menit > delta_t 15 menit -> bucket 1 difinalkan).
    raw_2 = {
        "id": "e2e_wazuh_002",
        "timestamp": "2026-08-28T10:20:00.000+0000",
        "agent": {"id": "001", "name": "soc-1"},
        "rule": {"id": "5501", "level": 3, "groups": ["pam"]},
    }
    r2 = api_client.post("/api/v1/alerts/ingest", json=raw_2, headers=headers)
    assert r2.status_code == 200

    # Outbox berisi tepat 1 meta-alert terskor yang sudah final dari event 1.
    outbox_resp = api_client.get("/api/v1/outbox", headers=headers)
    assert outbox_resp.status_code == 200
    outbox_items = outbox_resp.json()
    assert len(outbox_items) == 1
    scored_meta_dict = outbox_items[0]

    # Teruskan dari outbox ke Shuffle lewat ShuffleWebhookForwarder.
    with patch("requests.Session.post", side_effect=mock_post):
        # Kirim meta-alert ke Shuffle.
        scored_obj = service.get_outbox()[0]
        success = shuffle_forwarder.forward(scored_obj)
        assert success.success is True

        # Konfirmasi dan keluarkan item dari outbox.
        ack_res = api_client.post(f"/api/v1/outbox/{scored_obj.meta_id}/ack", headers=headers)
        assert ack_res.status_code == 200

    # Shuffle menerima tepat 1 webhook dengan event ID dan payload yang benar.
    assert len(received_webhooks) == 1
    webhook = received_webhooks[0]
    assert webhook["headers"]["X-Event-ID"] == f"rbta-meta-{scored_obj.meta_id}"
    assert webhook["payload"]["meta_id"] == scored_obj.meta_id
    assert webhook["payload"]["max_severity"] == 12
    assert "Initial Access" in webhook["payload"]["mitre_tactics"]
    assert webhook["payload"]["decision"] in ("CRITICAL", "SUSPICIOUS", "NOISE_HIGH", "NOISE", "CONTEXTUAL_ANOMALY")

    # Outbox kini kosong dan state durable mencerminkan konfirmasi.
    final_outbox = api_client.get("/api/v1/outbox", headers=headers).json()
    assert len(final_outbox) == 0
