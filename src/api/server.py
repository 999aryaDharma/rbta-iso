"""Bootstrap server FastAPI produksi: validasi konfigurasi dan pengelolaan lifecycle."""

from contextlib import asynccontextmanager
from datetime import timedelta
import logging
import os
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import FastAPI
import uvicorn

from src.api.app import create_app
from src.deploy.runtime_validation import (
    EXPECTED_MODEL_SHA256_ENV,
    check_expected_model_sha256,
    model_sha256,
)
from src.model.registry import ModelRegistry, ModelRegistryError
from src.model.scoring_pipeline import ScoringPipeline
from src.runtime.durable_state import DurableStateManager
from src.runtime.service import LiveRBTAService

logger = logging.getLogger("rbta.server")


def create_production_app(
    env: Optional[Dict[str, str]] = None,
    strict: bool = False,
) -> FastAPI:
    """Buat dan konfigurasi aplikasi FastAPI produksi lengkap dengan dependency injection.

    Parameters
    ----------
    env : Dict[str, str] | None
        Override environment opsional, untuk test atau bootstrap terprogram.
    strict : bool
        Bila True, RBTA_API_KEY dan RBTA_MODEL_VERSION wajib terisi.

    Returns
    -------
    FastAPI
        Instance aplikasi produksi yang sudah dikonfigurasi.

    Raises
    ------
    RuntimeError
        Bila strict=True dan variabel environment keamanan/model wajib tidak ada.
    ValueError
        Bila path wajib tidak bisa divalidasi atau ditulis.
    ModelRegistryError
        Bila artefak model rusak atau tidak valid.
    """
    env_map = os.environ if env is None else env

    api_key = env_map.get("RBTA_API_KEY")
    registry_dir = Path(env_map.get("RBTA_MODEL_REGISTRY_DIR", "artifacts/models")).resolve()
    model_version = env_map.get("RBTA_MODEL_VERSION")
    state_file_path = Path(env_map.get("RBTA_STATE_FILE", "data/runtime/state.json")).resolve()

    if strict:
        if not api_key or not api_key.strip():
            raise RuntimeError("RBTA_API_KEY environment variable is mandatory and must not be empty in production.")
        if not model_version or not model_version.strip():
            raise RuntimeError("RBTA_MODEL_VERSION environment variable is mandatory and must not be empty in production.")

    # Satu writer live per file state untuk SETIAP bootstrap (bukan hanya saat worker aktif):
    # ambil lock level OS sebelum DurableStateManager atau service sempat menulis,
    # supaya proses kedua langsung gagal di sini.
    from src.runtime.live_worker import acquire_state_lock as _acquire_state_lock

    _acquire_state_lock(state_file_path)

    # Pastikan direktori state bisa diakses.
    state_dir = state_file_path.parent
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        raise ValueError(f"Cannot create or access state directory '{state_dir}': {exc}") from exc

    state_mgr = DurableStateManager(state_file_path)

    registry = ModelRegistry(base_dir=registry_dir, explicit_version=model_version)

    active_version = registry.get_active_version()
    scoring_pipe: Optional[ScoringPipeline] = None
    model_identity: Optional[Dict[str, Any]] = None

    if active_version:
        logger.info("Loading active model artifact version: '%s'", active_version)
        bundle = registry.load_bundle(active_version)
        scoring_pipe = ScoringPipeline(bundle)
        model_identity = {
            "version": active_version,
            "sha256": model_sha256(registry.base_dir / active_version),
            "threshold": bundle.threshold.threshold,
            "q3": bundle.threshold.q3,
        }
        logger.info("Active model sha256(isolation_forest.joblib)=%s", model_identity["sha256"])
    else:
        logger.warning(
            "No active model bundle found in '%s' for version '%s'. /ready will return 503.",
            registry_dir,
            model_version,
        )
    # Guard identitas: model yang dimuat harus persis model yang diharapkan operator.
    check_expected_model_sha256(
        model_identity["sha256"] if model_identity else None,
        env_map.get(EXPECTED_MODEL_SHA256_ENV),
    )

    from src.config.domain import AGENT_CRITICALITY_OVERRIDE

    if AGENT_CRITICALITY_OVERRIDE is not None:
        logger.info(
            "Agent criticality override file loaded: %d entries, sha256=%s",
            AGENT_CRITICALITY_OVERRIDE["entries"],
            AGENT_CRITICALITY_OVERRIDE["sha256"],
        )

    from src.runtime.raw_evidence import RawAlertEvidenceStore
    from src.runtime.replay_controller import ReplayController

    raw_evidence_db = env_map.get("RBTA_RAW_EVIDENCE_DB", "data/runtime/raw_alert_evidence.sqlite3")
    raw_evidence_store = RawAlertEvidenceStore(raw_evidence_db)

    # Service live stateful.
    # Bila live worker diaktifkan dan RBTA_SOURCE_MODE tidak diset eksplisit, service
    # live default ke LIVE. Replay controller demo selalu membangun service REPLAY
    # sendiri, jadi perilaku replay tidak terpengaruh default ini.
    from src.runtime.live_worker import worker_enabled_from_env as _worker_on

    _worker_enabled = _worker_on(env_map)
    raw_source_mode = env_map.get("RBTA_SOURCE_MODE")
    if raw_source_mode is None or not str(raw_source_mode).strip():
        source_mode = "LIVE" if _worker_enabled else "DEFERRED"
    else:
        source_mode = str(raw_source_mode).strip().upper()
    if source_mode not in ("DEFERRED", "LIVE"):
        raise ValueError(f"RBTA_SOURCE_MODE must be either 'DEFERRED' or 'LIVE', got '{source_mode}'")

    # Δt dasar live. Kosong = DEFAULT_BASE_DELTA_T (15 menit, perilaku lama). Run skripsi
    # (rbta-if-thesis-v1) memakai 10 menit; set RBTA_BASE_DELTA_T_MIN=10 untuk paritas.
    service_kwargs: Dict[str, Any] = {}
    raw_delta_t = str(env_map.get("RBTA_BASE_DELTA_T_MIN") or "").strip()
    if raw_delta_t:
        try:
            delta_t_min = float(raw_delta_t)
        except ValueError as exc:
            raise ValueError(f"RBTA_BASE_DELTA_T_MIN must be a number of minutes, got '{raw_delta_t}'") from exc
        if delta_t_min <= 0:
            raise ValueError(f"RBTA_BASE_DELTA_T_MIN must be > 0, got '{raw_delta_t}'")
        service_kwargs["base_delta_t"] = timedelta(minutes=delta_t_min)

    service: Optional[LiveRBTAService] = None
    if scoring_pipe is not None:
        service = LiveRBTAService(
            scoring_pipeline=scoring_pipe,
            state_manager=state_mgr,
            adaptive=True,
            **service_kwargs,
            raw_evidence_store=raw_evidence_store,
            source_mode=source_mode,
        )

    # TLS insecure harus terlihat: beri peringatan saat startup dan selalu catat pilihan
    # operator di state live source untuk jejak bukti penelitian.
    tls_verify_raw = str(env_map.get("WAZUH_INDEXER_VERIFY_TLS", "true")).strip().lower()
    tls_verify = tls_verify_raw != "false"
    if not tls_verify:
        logger.warning(
            "WAZUH_INDEXER_VERIFY_TLS=false: Wazuh indexer TLS certificate "
            "verification is DISABLED. Transport is vulnerable to MITM; "
            "enable verification for production use."
        )
    if service is not None:
        service.update_live_source_state({"tls_verify": tls_verify})
        logger.info("Live RBTA base delta_t = %.0f s", service.base_delta_t.total_seconds())

    # Replay controller untuk demo.
    replay_controller: Optional[ReplayController] = None
    if scoring_pipe is not None:
        default_replay_dir = "/app/data/replay" if Path("/app/data/replay").exists() else "data/test_datasets"
        replay_data_dir = Path(env_map.get("RBTA_REPLAY_DATA_DIR", default_replay_dir)).resolve()
        replay_controller = ReplayController(
            scoring_pipeline=scoring_pipe,
            replay_data_dir=replay_data_dir,
            replay_runs_dir=env_map.get("RBTA_REPLAY_RUNS_DIR"),
        )

    # Lifespan untuk shutdown yang rapi (+ thread live worker opsional).
    from src.runtime.live_worker import (
        LiveWorker,
        drain_on_stop_from_env,
        poll_interval_from_env,
        worker_enabled_from_env,
    )

    from src.runtime.retention import archive_dir_for, make_retention_job, retention_days_from_env

    retention_days = retention_days_from_env(env_map)
    live_worker: Optional[LiveWorker] = None
    if service is not None and worker_enabled_from_env(env_map):
        # Lock state sudah diambil di atas untuk setiap bootstrap; tidak perlu acquire lagi.
        from src.runtime.live_coordinator import LiveIngestionCoordinator

        buffer_enabled = str(env_map.get("RBTA_ORDER_BUFFER_ENABLED", "false")).strip().lower() == "true"
        if buffer_enabled:
            logger.info("Order buffer enabled for live ingestion (waiting-room sorter).")
        live_source = str(env_map.get("RBTA_LIVE_SOURCE", "indexer")).strip().lower()
        poller = None
        if live_source == "api":
            from src.ingestion.wazuh_api_client import WazuhAPIClient
            from src.runtime.api_live_source import WazuhAPILivePoller

            poller = WazuhAPILivePoller(client=WazuhAPIClient())
            logger.info("Live ingestion source: custom flat API (FLAT-API-FREEZE).")
        elif live_source != "indexer":
            raise ValueError(f"RBTA_LIVE_SOURCE must be either 'indexer' or 'api', got '{live_source}'")
        live_worker = LiveWorker(
            service,
            LiveIngestionCoordinator(
                service=service,
                poller=poller,
                order_buffer_enabled=buffer_enabled,
                breaker_ack=(env_map.get("RBTA_QUARANTINE_BREAKER_ACK") or None),
                excluded_agents=env_map.get("RBTA_EXCLUDED_AGENTS", ""),
                retention_days=retention_days,
            ),
            poll_interval=poll_interval_from_env(env_map),
            drain_on_stop=drain_on_stop_from_env(env_map),
            model_override=env_map.get("RBTA_LIVE_MODEL_OVERRIDE"),
            derivation_override=env_map.get("RBTA_LIVE_DERIVATION_OVERRIDE"),
        )

    # Dispatcher Telegram dipasang di samping worker, tidak pernah menyentuhnya.
    # Tanpa kredensial bot ia tetap nonaktif (hanya dry-run: thread tetap jalan agar outbox
    # dikuras dan setiap putaran dicatat, tapi tidak ada yang dikirim). Jalur kirim hanya
    # aktif bila kredensial tersedia lewat make_telegram_sender.
    # RBTA_TELEGRAM_DRY_RUN=true memaksa dry-run: kredensial TIDAK diteruskan ke
    # constructor, sehingga dispatcher memang sengaja nonaktif.
    telegram_dispatcher: Optional[Any] = None
    if live_worker is not None:
        from src.runtime.telegram_dispatcher import TelegramDispatcher, make_telegram_sender

        telegram_dry_run = str(env_map.get("RBTA_TELEGRAM_DRY_RUN", "false")).strip().lower() == "true"
        if telegram_dry_run:
            bot_token = ""
            chat_id = ""
            sender = None
        else:
            bot_token = (env_map.get("RBTA_TELEGRAM_BOT_TOKEN") or "").strip()
            chat_id = (env_map.get("RBTA_TELEGRAM_CHAT_ID") or "").strip()
            sender = make_telegram_sender(bot_token) if bot_token and chat_id else None
        telegram_dispatcher = TelegramDispatcher(
            service, sender=sender, bot_token=bot_token or None, chat_id=chat_id or None
        )
        # Petunjuk startup yang terlihat: worker ada tetapi dispatcher MENAHAN outbox karena
        # kredensial tidak ada, dan operator tidak memilih dry-run secara eksplisit. Peringatan
        # cukup sekali di sini (bukan di loop lifespan) agar deployment tanpa notifikasi langsung ketahuan.
        if not telegram_dry_run and not telegram_dispatcher.enabled:
            logger.warning(
                "Telegram credentials missing; dispatcher HOLDING outbox — "
                "set creds or RBTA_TELEGRAM_DRY_RUN=true"
            )

    # Ekspor bukti harian (T6): <state dir>/evidence, default 00:05 WITA, hanya untuk live.
    from src.runtime.evidence_export import make_evidence_export_job, parse_hhmm

    evidence_dir = Path(env_map.get("RBTA_EVIDENCE_DIR") or (state_dir / "evidence")).resolve()
    evidence_job = None
    export_enabled = str(env_map.get("RBTA_EVIDENCE_EXPORT_ENABLED", "true")).strip().lower() != "false"
    if live_worker is not None and export_enabled:
        evidence_job = make_evidence_export_job(
            service, evidence_dir, model_identity, parse_hhmm(env_map.get("RBTA_EVIDENCE_EXPORT_AT") or "00:05")
        )

    # Retensi harian (T12), default 03:30 WITA; VACUUM hari Minggu. Hanya untuk live.
    retention_job = None
    if live_worker is not None and retention_days > 0:
        retention_job = make_retention_job(
            service, archive_dir_for(env_map), retention_days, at=env_map.get("RBTA_RETENTION_AT") or "03:30"
        )

    # Daily digest NOISE_HIGH (T9), default 07:30 WITA; lewat dispatcher yang sama (dry-run/hold/throttle).
    digest_job = None
    digest_enabled = str(env_map.get("RBTA_DIGEST_ENABLED", "true")).strip().lower() != "false"
    if telegram_dispatcher is not None and digest_enabled:
        from src.runtime.digest_job import make_digest_job

        digest_job = make_digest_job(
            service,
            telegram_dispatcher,
            at=env_map.get("RBTA_DIGEST_AT") or "07:30",
            dashboard_url=(env_map.get("RBTA_DASHBOARD_URL") or "").strip() or None,
        )

    @asynccontextmanager
    async def lifespan(app_instance: FastAPI) -> AsyncGenerator[None, None]:
        logger.info("Starting RBTA production service...")
        if live_worker is not None:
            if live_worker.start():
                logger.info("Live worker thread started.")
            else:
                logger.warning("Live worker already running; keeping single thread.")
        if telegram_dispatcher is not None:
            telegram_dispatcher.start()
            logger.info(
                "Telegram dispatcher thread started (enabled=%s).",
                telegram_dispatcher.enabled,
            )
        if evidence_job is not None:
            evidence_job.start()
            logger.info("Evidence export job started (dir=%s).", evidence_dir)
        if digest_job is not None:
            digest_job.start()
            logger.info("Daily digest job started.")
        if retention_job is not None:
            retention_job.start()
            logger.info("Retention job started (%d days).", retention_days)
        yield
        if retention_job is not None:
            retention_job.stop()
        if digest_job is not None:
            digest_job.stop()
        if evidence_job is not None:
            evidence_job.stop()
        if live_worker is not None and live_worker.drain_on_stop:
            logger.info(
                "Shutting down RBTA production service "
                "(draining active buckets — explicit decommission)..."
            )
        else:
            logger.info("Shutting down RBTA production service (preserving active buckets)...")
        if telegram_dispatcher is not None:
            telegram_dispatcher.stop()
        if live_worker is not None:
            live_worker.stop()
        if replay_controller is not None:
            replay_controller.stop()
        if service is not None:
            service.shutdown(drain=False)

    app = create_app(
        service=service,
        model_registry=registry,
        api_key=api_key,
        raw_evidence_store=raw_evidence_store,
        replay_controller=replay_controller,
    )
    app.router.lifespan_context = lifespan
    app.state.model_identity = model_identity
    app.state.evidence_dir = evidence_dir
    app.state.evidence_job = evidence_job
    app.state.digest_job = digest_job
    app.state.retention_job = retention_job
    app.state.retention_days = retention_days
    app.state.disk_paths = {"state": state_dir, "archive": archive_dir_for(env_map)}
    app.state.live_worker = live_worker
    app.state.telegram_dispatcher = telegram_dispatcher

    return app


def run() -> None:
    """Entrypoint server produksi."""
    log_level = os.getenv("RBTA_LOG_LEVEL", "info").lower()
    logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO))

    host = os.getenv("RBTA_HOST", "0.0.0.0")
    port = int(os.getenv("RBTA_PORT", "8000"))

    app = create_production_app(strict=True)
    uvicorn.run(app, host=host, port=port, log_level=log_level)


if __name__ == "__main__":
    run()
