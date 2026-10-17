"""Unit test bootstrap server produksi dan validasi konfigurasi."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
import pytest

from src.api.server import create_production_app
from src.contracts.raw_alert import CanonicalRawAlert
from src.model.registry import ModelRegistry
from src.model.scoring_pipeline import train_reference_pipeline
from src.runners.batch_runner import BatchResearchRunner


def make_raw_alert(idx: int, ts: datetime) -> CanonicalRawAlert:
    return CanonicalRawAlert(
        wazuh_alert_id=f"bootstrap_alert_{idx}",
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


def publish_test_model(registry_dir: Path, version: str = "boot-v1") -> None:
    base_t = datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc)
    sample_alerts = [make_raw_alert(i, base_t + timedelta(minutes=i * 20)) for i in range(30)]
    batch_res = BatchResearchRunner(base_delta_t=timedelta(minutes=15), adaptive=False).run(sample_alerts)
    bundle = train_reference_pipeline(batch_res.meta_alerts, random_state=42, model_version=version)

    registry = ModelRegistry(base_dir=registry_dir)
    registry.publish_bundle(bundle, model_version=version)


def test_bootstrap_with_valid_config_and_model(tmp_path: Path):
    """Bootstrap produksi berhasil memuat model yang dikonfigurasi dan /health serta /ready mengembalikan 200."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"
    publish_test_model(reg_dir, "boot-v1")

    env = {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "boot-v1",
        "RBTA_STATE_FILE": str(state_file),
        "RBTA_API_KEY": "test-secret-key-123",
    }

    app = create_production_app(env=env)
    client = TestClient(app)

    # Health check.
    h_resp = client.get("/health")
    assert h_resp.status_code == 200
    assert h_resp.json() == {"status": "ok", "service": "rbta-security-analytics"}

    # Readiness check.
    r_resp = client.get("/ready")
    assert r_resp.status_code == 200
    r_data = r_resp.json()
    assert r_data["ready"] is True
    assert r_data["active_model_version"] == "boot-v1"

    # Endpoint statistik terautentikasi.
    s_resp = client.get("/runtime/stats", headers={"Authorization": "Bearer test-secret-key-123"})
    assert s_resp.status_code == 200
    s_data = s_resp.json()
    assert s_data["seen_alerts_count"] == 0
    assert s_data["active_buckets_count"] == 0


def test_bootstrap_missing_model_version_reports_ready_503(tmp_path: Path):
    """Tanpa versi model aktif, /health 200 tetapi /ready 503."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"
    reg_dir.mkdir(parents=True)

    env = {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "",
        "RBTA_STATE_FILE": str(state_file),
    }

    app = create_production_app(env=env)
    client = TestClient(app)

    assert client.get("/health").status_code == 200
    r_resp = client.get("/ready")
    assert r_resp.status_code == 503
    assert r_resp.json()["ready"] is False


def test_bootstrap_invalid_model_version_reports_ready_503(tmp_path: Path):
    """Bila versi model yang dikonfigurasi tidak ada, /ready mengembalikan 503."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"
    reg_dir.mkdir(parents=True)

    env = {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "nonexistent-version",
        "RBTA_STATE_FILE": str(state_file),
    }

    app = create_production_app(env=env)
    client = TestClient(app)

    r_resp = client.get("/ready")
    assert r_resp.status_code == 503
    assert r_resp.json()["ready"] is False


def test_bootstrap_inference_only_no_model_fitting(tmp_path: Path):
    """Bootstrap dan eksekusi server sama sekali tidak melakukan training atau fitting model."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"
    publish_test_model(reg_dir, "boot-v1")

    env = {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "boot-v1",
        "RBTA_STATE_FILE": str(state_file),
    }

    with patch("src.model.scoring_pipeline.train_reference_pipeline") as mock_train:
        app = create_production_app(env=env)
        client = TestClient(app)
        assert client.get("/health").status_code == 200
        assert mock_train.call_count == 0


def test_strict_bootstrap_missing_api_key_raises_runtime_error(tmp_path: Path):
    """Bootstrap strict gagal tertutup bila RBTA_API_KEY tidak ada atau kosong."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"
    publish_test_model(reg_dir, "boot-v1")

    env = {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "boot-v1",
        "RBTA_STATE_FILE": str(state_file),
        "RBTA_API_KEY": "",
    }

    with pytest.raises(RuntimeError, match="RBTA_API_KEY"):
        create_production_app(env=env, strict=True)


def test_strict_bootstrap_missing_model_version_raises_runtime_error(tmp_path: Path):
    """Bootstrap strict gagal tertutup bila RBTA_MODEL_VERSION tidak ada atau kosong."""
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"

    env = {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "   ",
        "RBTA_STATE_FILE": str(state_file),
        "RBTA_API_KEY": "test-key",
    }

    with pytest.raises(RuntimeError, match="RBTA_MODEL_VERSION"):
        create_production_app(env=env, strict=True)


def _bootstrap_env(tmp_path: Path, extra: dict) -> dict:
    reg_dir = tmp_path / "models"
    state_file = tmp_path / "runtime" / "state.json"
    publish_test_model(reg_dir, "boot-v1")
    return {
        "RBTA_MODEL_REGISTRY_DIR": str(reg_dir),
        "RBTA_MODEL_VERSION": "boot-v1",
        "RBTA_STATE_FILE": str(state_file),
        "RBTA_API_KEY": "test-secret-key-123",
        **extra,
    }


def test_worker_and_dispatcher_absent_by_default(tmp_path: Path):
    """Tanpa opt-in, tidak ada thread worker maupun dispatcher yang terpasang."""
    app = create_production_app(env=_bootstrap_env(tmp_path, {}))
    assert app.state.live_worker is None
    assert app.state.telegram_dispatcher is None


def test_worker_enabled_attaches_disabled_dispatcher_without_creds(tmp_path: Path, monkeypatch):
    """Opt-in worker memasang dispatcher yang thread-nya tetap berhenti tanpa kredensial."""
    monkeypatch.delenv("RBTA_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("RBTA_TELEGRAM_CHAT_ID", raising=False)
    app = create_production_app(
        env=_bootstrap_env(tmp_path, {"RBTA_LIVE_WORKER_ENABLED": "true"})
    )
    assert app.state.live_worker is not None
    dispatcher = app.state.telegram_dispatcher
    assert dispatcher is not None
    assert dispatcher.enabled is False


def test_worker_enabled_with_creds_attaches_enabled_dispatcher(tmp_path: Path):
    """Kredensial Telegram eksplisit mengaktifkan dispatcher (thread mulai di lifespan)."""
    app = create_production_app(
        env=_bootstrap_env(
            tmp_path,
            {
                "RBTA_LIVE_WORKER_ENABLED": "true",
                "RBTA_TELEGRAM_BOT_TOKEN": "tok-test",
                "RBTA_TELEGRAM_CHAT_ID": "chat-test",
            },
        )
    )
    dispatcher = app.state.telegram_dispatcher
    assert dispatcher is not None
    assert dispatcher.enabled is True


# Mode dry-run Telegram.

def test_telegram_dry_run_env_forces_disabled_dispatcher(tmp_path: Path):
    """RBTA_TELEGRAM_DRY_RUN=true memaksa dry-run meski kredensial ada."""
    app = create_production_app(
        env=_bootstrap_env(
            tmp_path,
            {
                "RBTA_LIVE_WORKER_ENABLED": "true",
                "RBTA_TELEGRAM_BOT_TOKEN": "tok-test",
                "RBTA_TELEGRAM_CHAT_ID": "chat-test",
                "RBTA_TELEGRAM_DRY_RUN": "true",
            },
        )
    )
    dispatcher = app.state.telegram_dispatcher
    assert dispatcher is not None
    assert dispatcher.enabled is False


def test_worker_enabled_defaults_source_mode_live(tmp_path: Path):
    """Tanpa RBTA_SOURCE_MODE eksplisit, live service memakai LIVE bila worker aktif
    (replay controller tetap memakai mode REPLAY sendiri).
    """
    app = create_production_app(env=_bootstrap_env(tmp_path, {"RBTA_LIVE_WORKER_ENABLED": "true"}))
    assert app.state.live_worker is not None
    assert app.state.live_worker.service.source_mode == "LIVE"


def test_worker_enabled_respects_explicit_source_mode(tmp_path: Path):
    app = create_production_app(
        env=_bootstrap_env(
            tmp_path,
            {"RBTA_LIVE_WORKER_ENABLED": "true", "RBTA_SOURCE_MODE": "DEFERRED"},
        )
    )
    assert app.state.live_worker is not None
    assert app.state.live_worker.service.source_mode == "DEFERRED"


def test_tls_verify_false_warns_and_persists(tmp_path: Path, caplog):
    """WAZUH_INDEXER_VERIFY_TLS=false memberi peringatan saat startup dan mencatat tls_verify=false."""
    import logging

    with caplog.at_level(logging.WARNING, logger="rbta.server"):
        app = create_production_app(
            env=_bootstrap_env(
                tmp_path,
                {
                    "RBTA_LIVE_WORKER_ENABLED": "true",
                    "WAZUH_INDEXER_VERIFY_TLS": "false",
                },
            )
        )
    assert any("TLS" in rec.message or "verify" in rec.message.lower() for rec in caplog.records), (
        [rec.message for rec in caplog.records]
    )
    state = app.state.live_worker.service.get_live_source_state()
    assert state.get("tls_verify") is False


def test_worker_drain_defaults_to_false_in_bootstrap(tmp_path: Path):
    """Bootstrap memasang drain_on_stop=False kecuali diaktifkan eksplisit."""
    base_env = _bootstrap_env(tmp_path, {"RBTA_LIVE_WORKER_ENABLED": "true"})
    app = create_production_app(env=base_env)
    assert app.state.live_worker is not None
    assert app.state.live_worker.drain_on_stop is False

    # CATATAN: direktori terpisah — lock state OS ditahan untuk seluruh proses, jadi bootstrap
    # kedua pada file state yang sama harus langsung gagal (lihat test di bawah).
    opt_dir = tmp_path / "opt-in"
    opt_dir.mkdir()
    env_opt_in = _bootstrap_env(
        opt_dir,
        {"RBTA_LIVE_WORKER_ENABLED": "true", "RBTA_LIVE_WORKER_DRAIN_ON_STOP": "true"},
    )
    app_opt_in = create_production_app(env=env_opt_in)
    assert app_opt_in.state.live_worker.drain_on_stop is True


def test_second_bootstrap_on_same_state_file_fails_fast(tmp_path: Path):
    """Writer live kedua pada file state yang sama ditolak."""
    import pytest as _pytest

    from src.runtime.live_worker import acquire_state_lock

    base_env = _bootstrap_env(tmp_path, {"RBTA_LIVE_WORKER_ENABLED": "true"})
    create_production_app(env=base_env)
    state_file = base_env["RBTA_STATE_FILE"]
    with _pytest.raises(RuntimeError, match="another live writer holds"):
        acquire_state_lock(state_file)


def test_order_buffer_off_by_default(tmp_path: Path):
    """Buffer tetap mati kecuali diaktifkan eksplisit (null yang jujur di status)."""
    app = create_production_app(env=_bootstrap_env(tmp_path, {"RBTA_LIVE_WORKER_ENABLED": "true"}))
    assert app.state.live_worker.coordinator.order_buffer is None


def test_order_buffer_enabled_via_env(tmp_path: Path):
    """RBTA_ORDER_BUFFER_ENABLED=true memasang order buffer."""
    app = create_production_app(
        env=_bootstrap_env(
            tmp_path,
            {"RBTA_LIVE_WORKER_ENABLED": "true", "RBTA_ORDER_BUFFER_ENABLED": "true"},
        )
    )
    assert app.state.live_worker.coordinator.order_buffer is not None


# Lock state berlaku untuk setiap bootstrap, bukan hanya saat worker aktif.

def test_state_lock_applies_without_worker_enabled(tmp_path: Path):
    """Bootstrap tanpa worker tetap mengambil lock state (langsung gagal bila dipegang)."""
    from src.runtime.live_worker import acquire_state_lock, release_state_lock

    base_env = _bootstrap_env(tmp_path, {})
    create_production_app(env=base_env)
    state_file = base_env["RBTA_STATE_FILE"]
    try:
        with pytest.raises(RuntimeError, match="another live writer holds"):
            acquire_state_lock(state_file)
    finally:
        release_state_lock(state_file)
    # Setelah dilepas, file state yang sama bisa diambil lagi.
    try:
        acquire_state_lock(state_file)
    finally:
        release_state_lock(state_file)


# Server meneruskan nilai override mentah dari env_map.

def test_server_forwards_raw_model_override(tmp_path: Path):
    """RBTA_LIVE_MODEL_OVERRIDE diteruskan apa adanya ke worker."""
    app = create_production_app(
        env=_bootstrap_env(
            tmp_path,
            {
                "RBTA_LIVE_WORKER_ENABLED": "true",
                "RBTA_LIVE_MODEL_OVERRIDE": "boot-v1",
            },
        )
    )
    assert app.state.live_worker is not None
    assert app.state.live_worker.model_override == "boot-v1"


def test_tls_verify_choice_always_recorded_in_source_state(tmp_path: Path):
    """tls_verify dicatat untuk pilihan aman maupun tidak aman (selalu terlihat)."""
    app_secure = create_production_app(env=_bootstrap_env(tmp_path / "s", {}))
    app_insecure = create_production_app(
        env=_bootstrap_env(tmp_path / "i", {"WAZUH_INDEXER_VERIFY_TLS": "false"})
    )
    assert app_secure.state.runtime_resolver.live_service.get_live_source_state()["tls_verify"] is True
    assert app_insecure.state.runtime_resolver.live_service.get_live_source_state()["tls_verify"] is False


# Lifespan selalu menjalankan thread dispatcher bila worker ada.

def test_lifespan_starts_disabled_dispatcher_thread(tmp_path: Path):
    """Tanpa kredensial dispatcher tetap nonaktif, tetapi lifespan tetap harus menjalankan
    thread-nya (mode nonaktif/dry-run menguras outbox + mencatat log).
    """
    app = create_production_app(env=_bootstrap_env(tmp_path, {"RBTA_LIVE_WORKER_ENABLED": "true"}))
    dispatcher = app.state.telegram_dispatcher
    assert dispatcher is not None
    assert dispatcher.enabled is False
    # Hanya start worker yang di-stub (kalau tidak, akan menjalankan thread polling jaringan);
    # thread dispatcher yang diuji tetap asli.
    with patch.object(app.state.live_worker, "start", return_value=False):
        with TestClient(app):
            assert dispatcher._thread is not None and dispatcher._thread.is_alive()
    assert dispatcher._thread is None
    assert not app.state.live_worker.is_alive()
    dispatcher.stop()  # idempoten: aman dihentikan dua kali


def test_production_bootstrap_suppresses_and_dryrun_drains_old_escalate(tmp_path: Path):
    """Pin waktu mulai pertama menahan backlog bootstrap; dry-run menguras dan mencatat."""
    import time as _time

    from tests.unit.runtime.test_telegram_dispatcher import _scored
    from src.runtime.live_coordinator import LiveCycleResult, LiveIngestionCoordinator

    def _noop_cycle(self, current_time=None):
        return LiveCycleResult(
            fast_candidates=0, recent_reconciliation_candidates=0,
            full_reconciliation_candidates=0, submitted_candidates=0,
            duplicate_noops=0, processed_new_ids=0, failures=0,
            new_scored_meta_alerts=0,
        )

    env = _bootstrap_env(
        tmp_path,
        {"RBTA_LIVE_WORKER_ENABLED": "true", "RBTA_TELEGRAM_DRY_RUN": "true"},
    )
    app = create_production_app(env=env)
    service = app.state.runtime_resolver.live_service
    old = _scored(900, end_time=datetime.now(timezone.utc) - timedelta(hours=5))
    service.outbox.append(old)

    with patch.object(LiveIngestionCoordinator, "run_cycle", _noop_cycle):
        with TestClient(app):
            deadline = _time.monotonic() + 10.0
            while service.get_outbox() and _time.monotonic() < deadline:
                _time.sleep(0.05)

    assert service.get_outbox() == []
    state = service.get_live_source_state()
    assert state.get("live_first_started_at")
    assert service.state_manager.notification_count() >= 1
    assert "SUPPRESSED_HISTORICAL" in service.state_manager.notification_verdicts()


def test_breaker_ack_env_reaches_coordinator(tmp_path: Path):
    """RBTA_QUARANTINE_BREAKER_ACK diteruskan ke coordinator."""
    app = create_production_app(
        env=_bootstrap_env(
            tmp_path,
            {"RBTA_LIVE_WORKER_ENABLED": "true", "RBTA_QUARANTINE_BREAKER_ACK": "qb-test-1"},
        )
    )
    assert app.state.live_worker.coordinator.breaker_ack == "qb-test-1"
