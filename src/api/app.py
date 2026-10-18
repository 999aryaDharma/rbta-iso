from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from src.api.routes import auth, dashboard, meta_alerts, raw_alerts, replay
from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.model.registry import ModelRegistry
from src.runtime.context_resolver import DashboardRuntimeResolver
from src.runtime.ingress import CollectorIngressBoundary, IngressPayloadError
from src.runtime.raw_evidence import RawAlertEvidenceStore
from src.runtime.replay_controller import ReplayController
from src.runtime.service import LiveRBTAService, _serialize_scored_alert


def _criticality_file_info() -> Optional[Dict[str, Any]]:
    """sha256 + jumlah entri file RBTA_AGENT_CRITICALITY_FILE yang aktif (path tidak diekspos)."""
    from src.config.domain import AGENT_CRITICALITY_OVERRIDE

    if AGENT_CRITICALITY_OVERRIDE is None:
        return None
    return {"sha256": AGENT_CRITICALITY_OVERRIDE["sha256"], "entries": AGENT_CRITICALITY_OVERRIDE["entries"]}


def _disk_status(paths: Dict[str, Any]) -> Dict[str, Any]:
    """Pemakaian disk per volume (state live, arsip); warning bila > 80%."""
    from src.runtime.retention import disk_usage

    return {name: disk_usage(Path(path)) for name, path in paths.items() if path is not None}


def create_app(
    service: Optional[LiveRBTAService] = None,
    model_registry: Optional[ModelRegistry] = None,
    api_key: Optional[str] = None,
    raw_evidence_store: Optional[RawAlertEvidenceStore] = None,
    replay_controller: Optional[ReplayController] = None,
) -> FastAPI:
    """Factory FastAPI: menyiapkan dependency injection dan memasang router modular."""
    app = FastAPI(
        title="RBTA Security Analytics REST Service",
        version="1.0.0",
        description="Dual-mode operational runtime for Rule-Based Temporal Aggregation and Isolation Forest scoring.",
    )

    auth_key = api_key or os.getenv("RBTA_API_KEY")
    ingress_boundary = CollectorIngressBoundary(api_key=auth_key)

    # Resolver runtime memisahkan data live dari data replay run.
    scoring_pipe = service.scoring_pipeline if service else None
    if scoring_pipe is None and replay_controller:
        scoring_pipe = replay_controller.scoring_pipeline

    runtime_resolver = DashboardRuntimeResolver(
        live_service=service,
        live_evidence_store=raw_evidence_store or RawAlertEvidenceStore(),
        replay_controller=replay_controller or ReplayController(scoring_pipeline=scoring_pipe),
        scoring_pipeline=scoring_pipe,
    )

    app.state.runtime_resolver = runtime_resolver
    app.state.raw_evidence_store = raw_evidence_store or runtime_resolver.live_evidence_store
    app.state.replay_controller = replay_controller or runtime_resolver.replay_controller
    app.state.auth_key = auth_key
    # Diisi oleh bootstrap produksi: {version, sha256, threshold, q3} model aktif.
    app.state.model_identity = None
    # Direktori CSV bukti harian (T6); None = endpoint evidence selalu 404.
    app.state.evidence_dir = None
    # Diisi bootstrap produksi (T12): {"state": Path, "archive": Path|None}.
    app.state.disk_paths = {}

    rate_limit = max(1, int(os.getenv("RBTA_CONTROL_RATE_LIMIT", "120")))
    max_request_bytes = max(128, int(os.getenv("RBTA_MAX_REQUEST_BYTES", str(1024 * 1024))))
    rate_windows: Dict[str, deque[float]] = defaultdict(deque)
    rate_lock = threading.Lock()

    @app.middleware("http")
    async def security_and_control_limits(request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > max_request_bytes:
            response = JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={"detail": f"Request body exceeds {max_request_bytes} bytes"},
            )
        else:
            is_control = request.method == "POST" and (
                request.url.path.startswith("/api/v1/replay/")
                or request.url.path == "/api/v1/alerts/ingest"
            )
            limited = False
            if is_control:
                identity = request.headers.get("authorization") or (
                    request.client.host if request.client else "unknown"
                )
                now = time.monotonic()
                with rate_lock:
                    window = rate_windows[identity]
                    while window and now - window[0] >= 60.0:
                        window.popleft()
                    if len(window) >= rate_limit:
                        limited = True
                    else:
                        window.append(now)
            if limited:
                response = JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Control request rate limit exceeded"},
                    headers={"Retry-After": "60"},
                )
            else:
                response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def verify_auth(authorization: Optional[str] = Header(None)) -> None:
        if auth_key:
            supplied = authorization or ""
            supplied_key = supplied[7:] if supplied.startswith("Bearer ") else supplied
            if not compare_digest(str(supplied_key), str(auth_key)):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing Authorization header",
                )

    @app.get("/health", tags=["Monitoring"])
    def health() -> Dict[str, str]:
        """Liveness probe."""
        return {"status": "ok", "service": "rbta-security-analytics"}

    def _build_info() -> Dict[str, str]:
        # Diisi saat docker build oleh CD; cek versi terpasang tanpa SSH.
        return {
            "build_sha": os.environ.get("RBTA_BUILD_SHA", "unknown"),
            "release_tag": os.environ.get("RBTA_RELEASE_TAG", "unknown"),
        }

    @app.get("/ready", tags=["Monitoring"])
    def ready() -> JSONResponse:
        """Readiness probe: memeriksa artefak model dan state runtime."""
        if model_registry is not None and service is None:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"ready": False, "reason": "Service not initialized"},
            )

        if model_registry is None:
            if service is None or service.scoring_pipeline is None:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"ready": False, "reason": "No active model bundle or scoring pipeline configured"},
                )

            # Ambil versi dari metadata, kalau tidak ada dari bundle.
            version = "unknown"
            pipe = service.scoring_pipeline
            if hasattr(pipe, "metadata") and isinstance(pipe.metadata, dict):
                version = pipe.metadata.get("model_version", "unknown")
            elif hasattr(pipe, "bundle") and pipe.bundle is not None:
                version = getattr(pipe.bundle, "model_version", "unknown")

            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"ready": True, "active_model_version": version, **_build_info()},
            )

        active_version = model_registry.get_active_version()
        if not active_version:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"ready": False, "reason": "No active model version published in registry"},
            )

        # Endpoint tanpa auth: hanya status + versi. θ, q3, dan hash model ada di /api/v1/live/status.
        try:
            model_registry.load_bundle(active_version)
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"ready": False, "reason": "Failed loading active bundle"},
            )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"ready": True, "active_model_version": active_version, **_build_info()},
        )

    @app.get("/runtime/stats", tags=["Monitoring"])
    def runtime_stats(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Statistik agregasi runtime live."""
        verify_auth(authorization)
        if service is None:
            return {"status": "uninitialized"}

        seen_cnt = service.state_manager.count_seen_alert_ids()
        buckets_cnt = len(service.engine.snapshot_buckets())

        return {
            "status": "ready",
            "active_buckets": buckets_cnt,
            "active_buckets_count": buckets_cnt,
            "temporal_agents": len(service.engine.snapshot_agents()),
            "seen_alerts_count": seen_cnt,
            "outbox_count": len(service.outbox),
            "finalized_history_count": len(service.finalized_history),
            "pending_scoring_count": len(service.pending_scoring),
            "raw_evidence_count": app.state.raw_evidence_store.count() if app.state.raw_evidence_store else 0,
        }
    @app.get("/api/v1/live/status", tags=["Monitoring"])
    def live_status(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
        """Status ingestion live (read-only, tidak pernah mengubah state service/coordinator).

        Catatan makna field:
        * ``lag_sec`` adalah *umur siklus* (now - cursor transport terakhir), dipertahankan
          demi kompatibilitas; ini BUKAN latensi event end-to-end.
        * ``buffer_size`` bernilai None bila order buffer nonaktif/tidak ada (tidak diukur),
          bukan 0 palsu. Nilai int berarti buffer aktif dan sedang menahan sejumlah alert itu.
        * ``dispatcher`` / ``quarantine_total`` bernilai null sampai subsistemnya terpasang;
          null berarti "tidak tersedia", bukan nol.
        * ``event_lag_sec`` = now - ``end_time`` terbaru yang sudah diskor di history/outbox
          (hanya API publik); null bila belum ada event yang diskor.
        * ``model`` = identitas model aktif {version, sha256 isolation_forest.joblib, threshold, q3};
          null bila bootstrap tidak memuat model. /ready sengaja tidak memuat nilai ini.
        """
        import re as _re

        def _redact_host(value: Optional[str]) -> Optional[str]:
            """Buang scheme://host (beserta kredensial yang mungkin ikut) dari teks error."""
            if value is None:
                return None
            return _re.sub(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s]+", "[host]", value)

        verify_auth(authorization)
        worker = getattr(app.state, "live_worker", None)
        worker_snapshot: Dict[str, Any] = {}
        if worker is not None:
            try:
                worker_snapshot = dict(worker.status())
            except Exception:
                worker_snapshot = {}
        alive = bool(worker_snapshot.get("alive", False)) if worker is not None else False
        last_error = worker_snapshot.get("last_error")
        # Disamarkan: error hanya berupa string, host/kredensial dibuang, response body tidak pernah ikut.
        last_error_str = _redact_host(str(last_error)) if last_error is not None else None

        source_state: Dict[str, Any] = {}
        if service is not None:
            source_state = service.get_live_source_state()
        recent_poll_cursor = source_state.get("recent_poll_cursor")
        lag_sec: Optional[float] = None
        if recent_poll_cursor:
            try:
                cursor_dt = datetime.fromisoformat(str(recent_poll_cursor))
                if cursor_dt.tzinfo is None:
                    cursor_dt = cursor_dt.replace(tzinfo=timezone.utc)
                lag_sec = (datetime.now(timezone.utc) - cursor_dt).total_seconds()
            except (ValueError, TypeError):
                lag_sec = None

        # None = buffer nonaktif/tidak ada (tidak diukur), BUKAN kosong.
        buffer_size: Optional[int] = None
        buffer_stats: Optional[Dict[str, Any]] = None
        if worker is not None:
            try:
                coordinator = getattr(worker, "coordinator", None)
                order_buffer = getattr(coordinator, "order_buffer", None) if coordinator is not None else None
                if order_buffer is not None:
                    full_stats = dict(order_buffer.status())
                    buffer_size = full_stats.get("size")
                    buffer_stats = {
                        key: full_stats.get(key)
                        for key in ("size", "late_total", "future_anomalies", "backpressure_count")
                    }
            except Exception:
                buffer_size = None
                buffer_stats = None

        # Blok dispatcher bernilai null sampai dispatcher terpasang.
        dispatcher_status: Optional[Any] = None
        try:
            dispatcher = getattr(app.state, "telegram_dispatcher", None)
            status_fn = getattr(dispatcher, "status", None) if dispatcher is not None else None
            if callable(status_fn):
                dispatcher_status = status_fn()
        except Exception:
            dispatcher_status = None

        # Utamakan COUNT(*) quarantine (tanpa memuat baris); fallback ke list.
        quarantine_total: Optional[int] = None
        if service is not None:
            try:
                state_manager = getattr(service, "state_manager", None)
                count_fn = getattr(state_manager, "quarantine_count", None)
                if callable(count_fn):
                    quarantine_total = int(count_fn())
                else:
                    quarantine_fn = getattr(state_manager, "quarantine_list", None)
                    if callable(quarantine_fn):
                        items = quarantine_fn()
                        quarantine_total = len(items) if hasattr(items, "__len__") else None
            except Exception:
                quarantine_total = None

        # Lag event diukur dari event-time RAW terbaru yang di-ingest (state coordinator),
        # bukan dari flush hasil skor — kalau tidak, jeda idle-flush dan periode sepi akan
        # memicu alarm palsu. Fallback ke end_time hasil skor bila belum ada ingest.
        newest_ingested_event_time: Optional[str] = source_state.get("newest_ingested_event_time")
        newest_scored_event_time: Optional[str] = None
        event_lag_sec: Optional[float] = None
        lag_basis = newest_ingested_event_time
        if lag_basis:
            try:
                basis_dt = datetime.fromisoformat(str(lag_basis))
                if basis_dt.tzinfo is None:
                    basis_dt = basis_dt.replace(tzinfo=timezone.utc)
                event_lag_sec = (datetime.now(timezone.utc) - basis_dt).total_seconds()
            except (ValueError, TypeError):
                lag_basis = None
                event_lag_sec = None
        if service is not None:
            try:
                newest: Optional[datetime] = None
                for collection_fn in (service.get_history, service.get_outbox):
                    try:
                        items = collection_fn()
                    except Exception:
                        continue
                    for item in items or []:
                        end_time = getattr(item, "end_time", None)
                        if isinstance(end_time, str):
                            try:
                                end_time = datetime.fromisoformat(end_time)
                            except (ValueError, TypeError):
                                continue
                        if not isinstance(end_time, datetime):
                            continue
                        if end_time.tzinfo is None:
                            end_time = end_time.replace(tzinfo=timezone.utc)
                        if newest is None or end_time > newest:
                            newest = end_time
                if newest is not None:
                    newest_scored_event_time = newest.isoformat()
                    if lag_basis is None:
                        event_lag_sec = (datetime.now(timezone.utc) - newest).total_seconds()
            except Exception:
                newest_scored_event_time = None
                if lag_basis is None:
                    event_lag_sec = None

        outbox_pending = 0
        if service is not None:
            outbox_pending = len(service.get_outbox())

        # ingested_total: jumlah alert unik yang durable (ukuran registry dedup).
        # None bila counter tidak tersedia (tidak diukur), bukan 0 palsu.
        ingested_total: Optional[int] = None
        if service is not None:
            try:
                state_manager = getattr(service, "state_manager", None)
                count_fn = getattr(state_manager, "count_seen_alert_ids", None)
                if callable(count_fn):
                    ingested_total = int(count_fn())
            except Exception:
                ingested_total = None

        # Latensi ujung-ke-ujung 24 jam terakhir (event->finalize, finalize->Telegram sent).
        latency_24h: Optional[Dict[str, Any]] = None
        if service is not None:
            try:
                now_utc = datetime.now(timezone.utc)
                summary_fn = getattr(service.state_manager, "latency_summary", None)
                if callable(summary_fn):
                    latency_24h = summary_fn((now_utc - timedelta(hours=24)).isoformat(), now_utc.isoformat())
            except Exception:
                latency_24h = None

        excluded_agents: List[str] = []
        excluded_alerts_total: Dict[str, int] = {}
        coordinator = getattr(worker, "coordinator", None) if worker is not None else None
        if coordinator is not None:
            excluded_agents = sorted(getattr(coordinator, "excluded_agents", ()) or ())
        if service is not None:
            try:
                count_fn = getattr(service.state_manager, "excluded_counts", None)
                if callable(count_fn):
                    excluded_alerts_total = dict(count_fn())
            except Exception:
                excluded_alerts_total = {}

        return {
            "worker_alive": alive,
            "cycles_completed": int(worker_snapshot.get("cycles_completed", 0) or 0),
            "consecutive_failures": int(worker_snapshot.get("consecutive_failures", 0) or 0),
            "last_error": last_error_str,
            "last_cycle_at": worker_snapshot.get("last_cycle_at"),
            "live_model_version": source_state.get("live_model_version"),
            "recent_poll_cursor": recent_poll_cursor,
            "lag_sec": lag_sec,
            "buffer_size": buffer_size,
            "buffer_stats": buffer_stats,
            "outbox_pending": outbox_pending,
            "ingested_total": ingested_total,
            "dispatcher": dispatcher_status,
            "quarantine_total": quarantine_total,
            "newest_scored_event_time": newest_scored_event_time,
            "newest_ingested_event_time": newest_ingested_event_time,
            "event_lag_sec": event_lag_sec,
            "tls_verify": source_state.get("tls_verify"),
            "model": getattr(app.state, "model_identity", None),
            "base_delta_t_sec": service.base_delta_t.total_seconds() if service is not None else None,
            "excluded_agents": excluded_agents,
            "excluded_alerts_total": excluded_alerts_total,
            "agent_criticality_file": _criticality_file_info(),
            "latency_24h": latency_24h,
            "retention_days": getattr(app.state, "retention_days", None),
            "retention_expired_last_cycle": source_state.get("retention_expired_last_cycle"),
            "disk": _disk_status(getattr(app.state, "disk_paths", {}) or {}),
        }

    @app.get("/api/v1/evidence/{file_name}", tags=["Evidence"])
    def download_evidence(file_name: str, authorization: Optional[str] = Header(None)) -> FileResponse:
        """Unduh CSV bukti harian live (allowlist nama file, tanpa path traversal)."""
        from src.runtime.evidence_export import EVIDENCE_FILES

        verify_auth(authorization)
        evidence_dir = getattr(app.state, "evidence_dir", None)
        if file_name not in EVIDENCE_FILES or evidence_dir is None:
            raise HTTPException(status_code=404, detail="Evidence file not found")
        path = Path(evidence_dir) / file_name
        if not path.is_file():
            raise HTTPException(status_code=404, detail="Evidence file not generated yet")
        return FileResponse(path, media_type="text/csv", filename=file_name)

    @app.post("/ingest/wazuh", tags=["Ingress"])
    def ingest_wazuh(
        payload: Dict[str, Any],
        authorization: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Ingest satu item log Wazuh mentah lewat kanonisasi di boundary."""
        verify_auth(authorization)
        if service is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Runtime service uninitialized",
            )
        try:
            canonical_alert = ingress_boundary.ingest(payload, authorization=authorization)
        except IngressPayloadError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            )
        scored_alerts = service.ingest_alert(canonical_alert)
        return {
            "status": "accepted",
            "wazuh_alert_id": canonical_alert.wazuh_alert_id,
            "generated_meta_alerts": len(scored_alerts),
            "meta_alerts": [_serialize_scored_alert(m) for m in scored_alerts],
        }

    @app.post("/api/v1/alerts/ingest", tags=["Ingress"])
    def ingest_alert_v1(
        payload: Dict[str, Any],
        authorization: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Endpoint kompatibilitas untuk ingest raw alert."""
        verify_auth(authorization)
        if service is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Runtime service uninitialized",
            )
        try:
            canonical_alert = ingress_boundary.ingest(payload, authorization=authorization)
        except IngressPayloadError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            )
        is_dup = service.is_seen(canonical_alert.wazuh_alert_id)
        service.ingest_alert(canonical_alert)
        return {
            "status": "accepted",
            "alert_id": canonical_alert.wazuh_alert_id,
            "is_duplicate": is_dup,
        }

    @app.get("/outbox/pending", tags=["Outbox"])
    def get_pending_outbox(
        authorization: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Ambil meta-alert terskor yang belum di-commit dan menunggu dispatch eksternal."""
        verify_auth(authorization)
        if service is None:
            return {"count": 0, "alerts": []}

        alerts = [_serialize_scored_alert(m) for m in service.outbox]
        return {"count": len(alerts), "alerts": alerts}

    @app.get("/api/v1/outbox", tags=["Outbox"])
    def get_outbox_v1(
        authorization: Optional[str] = Header(None),
    ) -> List[Dict[str, Any]]:
        """Ambil langsung daftar alert outbox yang belum di-commit."""
        verify_auth(authorization)
        if service is None:
            return []
        return [_serialize_scored_alert(m) for m in service.outbox]

    @app.post("/api/v1/outbox/{meta_id}/ack", tags=["Outbox"])
    def ack_outbox_v1(
        meta_id: int,
        authorization: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Konfirmasi dispatch satu meta-alert."""
        verify_auth(authorization)
        if service is None:
            raise HTTPException(status_code=503, detail="Service uninitialized")
        if service.commit_outbox([meta_id]) == 0:
            raise HTTPException(status_code=404, detail=f"Pending outbox item #{meta_id} not found")
        return {"status": "acknowledged", "meta_id": meta_id}

    @app.post("/outbox/commit", tags=["Outbox"])
    def commit_outbox(
        meta_ids: List[int],
        authorization: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Konfirmasi dispatch meta-alert yang berhasil."""
        verify_auth(authorization)
        if service is None:
            return {"committed": 0, "remaining": 0}

        committed_count = service.commit_outbox(meta_ids)
        return {"committed": committed_count, "remaining": len(service.outbox)}

    @app.post("/api/v1/live/quarantine/{alert_id}/release", tags=["Outbox"])
    def release_quarantine_v1(
        alert_id: str,
        authorization: Optional[str] = Header(None),
    ) -> Dict[str, Any]:
        """Lepaskan satu baris alert yang dikarantina agar poll berikutnya bisa mencoba ingest ulang.

        Baris ini belum pernah masuk ``seen`` (gagal sebelum commit), jadi menghapusnya
        hanya membuka blokir ID tersebut — poll berikutnya akan ingest ulang dari awal.
        Mengembalikan ``{"released": 1}`` bila baris terhapus, ``{"released": 0}`` bila ID tidak ada.
        """
        verify_auth(authorization)
        state_manager = getattr(service, "state_manager", None) if service is not None else None
        release_fn = getattr(state_manager, "quarantine_release", None)
        if not callable(release_fn):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Quarantine store uninitialized",
            )
        return {"released": int(release_fn(alert_id))}

    # Router API dashboard.
    app.include_router(auth.router)
    app.include_router(dashboard.router)
    app.include_router(meta_alerts.router)
    app.include_router(raw_alerts.router)
    app.include_router(replay.router)

    # Sajikan file statis dashboard untuk mode produksi.
    dashboard_dist_env = os.getenv("RBTA_DASHBOARD_DIST", "dashboard/dist")
    dashboard_dist_path = Path(dashboard_dist_env).resolve()
    if not dashboard_dist_path.exists():
        dashboard_dist_path = Path("/app/dashboard/dist").resolve()

    if dashboard_dist_path.exists() and (dashboard_dist_path / "index.html").exists():
        index_file = dashboard_dist_path / "index.html"
        assets_dir = dashboard_dist_path / "assets"
        if assets_dir.exists():
            app.mount(
                "/dashboard/assets",
                StaticFiles(directory=str(assets_dir)),
                name="dashboard-assets",
            )

        @app.get("/", include_in_schema=False)
        def root_redirect() -> RedirectResponse:
            return RedirectResponse(url="/dashboard/")

        @app.get("/dashboard", include_in_schema=False)
        @app.get("/dashboard/", include_in_schema=False)
        def dashboard_index() -> FileResponse:
            return FileResponse(index_file)

        @app.get("/dashboard/{client_path:path}", include_in_schema=False)
        def dashboard_spa_fallback(client_path: str) -> FileResponse:
            target_path = (dashboard_dist_path / client_path).resolve()
            if target_path.is_relative_to(dashboard_dist_path) and target_path.is_file():
                return FileResponse(target_path)
            return FileResponse(index_file)

    return app
