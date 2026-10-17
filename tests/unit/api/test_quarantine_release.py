"""Endpoint quarantine_release untuk operator + peringatan startup Telegram HOLDING.

Mencakup pelepasan quarantine oleh operator dan peringatan startup saat dispatcher
Telegram berada di mode HOLDING karena kredensial tidak ada.
"""
import logging
from types import SimpleNamespace

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.runtime.durable_state import DurableStateManager


def _quarantine_app(tmp_path, api_key="op-key"):
    mgr = DurableStateManager(tmp_path / "state.json")
    service = SimpleNamespace(scoring_pipeline=None, state_manager=mgr)
    app = create_app(service=service, api_key=api_key)
    return app, mgr


def test_release_existing_id_returns_1_and_removes_row(tmp_path):
    app, mgr = _quarantine_app(tmp_path)
    mgr.quarantine_add("q-alert-1", error_type="corrupt-test")
    assert mgr.quarantine_count() == 1
    client = TestClient(app)
    resp = client.post(
        "/api/v1/live/quarantine/q-alert-1/release",
        headers={"Authorization": "Bearer op-key"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"released": 1}
    assert mgr.quarantine_count() == 0
    assert all(
        row["wazuh_alert_id"] != "q-alert-1" for row in mgr.quarantine_list()
    )


def test_release_absent_id_returns_0(tmp_path):
    app, _mgr = _quarantine_app(tmp_path)
    client = TestClient(app)
    resp = client.post(
        "/api/v1/live/quarantine/never-seen-id/release",
        headers={"Authorization": "Bearer op-key"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"released": 0}


def test_release_without_auth_returns_401(tmp_path):
    app, mgr = _quarantine_app(tmp_path)
    mgr.quarantine_add("q-alert-2", error_type="corrupt-test")
    client = TestClient(app)
    resp = client.post("/api/v1/live/quarantine/q-alert-2/release")
    assert resp.status_code == 401
    assert mgr.quarantine_count() == 1


def test_release_without_service_returns_503(tmp_path):
    app = create_app(service=None, api_key="op-key")
    client = TestClient(app)
    resp = client.post(
        "/api/v1/live/quarantine/anything/release",
        headers={"Authorization": "Bearer op-key"},
    )
    assert resp.status_code == 503


def _bootstrap_env(tmp_path, extra):
    from tests.unit.api.test_server_bootstrap import publish_test_model

    reg_dir = tmp_path / "models"
    publish_test_model(reg_dir, "boot-v1")
    return {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "boot-v1",
        "RBTA_STATE_FILE": str(tmp_path / "runtime" / "state.json"),
        "RBTA_API_KEY": "test-secret-key-123",
        **extra,
    }


def test_startup_warns_when_dispatcher_holding_without_creds(tmp_path, caplog, monkeypatch):
    """Worker aktif + tanpa kredensial Telegram + tanpa dry-run -> satu peringatan HOLDING."""
    from src.api.server import create_production_app

    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    with caplog.at_level(logging.WARNING, logger="rbta.server"):
        app = create_production_app(
            env=_bootstrap_env(tmp_path, {"RBTA_LIVE_WORKER_ENABLED": "true"})
        )
    assert app.state.telegram_dispatcher is not None
    assert app.state.telegram_dispatcher.enabled is False
    holding = [r for r in caplog.records if "HOLDING" in r.message]
    assert len(holding) == 1


def test_startup_no_holding_warning_in_explicit_dry_run(tmp_path, caplog):
    """RBTA_TELEGRAM_DRY_RUN=true adalah pilihan operator yang eksplisit -> tanpa peringatan."""
    from src.api.server import create_production_app

    with caplog.at_level(logging.WARNING, logger="rbta.server"):
        app = create_production_app(
            env=_bootstrap_env(
                tmp_path,
                {
                    "RBTA_LIVE_WORKER_ENABLED": "true",
                    "RBTA_TELEGRAM_DRY_RUN": "true",
                },
            )
        )
    assert app.state.telegram_dispatcher is not None
    assert app.state.telegram_dispatcher.enabled is False
    assert not [r for r in caplog.records if "HOLDING" in r.message]
