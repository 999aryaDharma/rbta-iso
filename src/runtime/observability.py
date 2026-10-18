from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.contracts.scored_meta_alert import ScoredMetaAlert
from src.evaluation.metrics import compute_arr
from src.runtime.raw_evidence import RawAlertEvidenceStore
from src.runtime.service import LiveRBTAService


def derive_system_status(service: Optional[LiveRBTAService]) -> Tuple[str, List[str]]:
    """Turunkan status sistem operasional dan diagnostik dari kondisi runtime yang sebenarnya."""
    if service is None:
        return "DEGRADED", ["Live service instance is uninitialized"]

    diagnostics: List[str] = []
    if service.scoring_pipeline is None:
        diagnostics.append("Scoring pipeline is uninitialized")
    else:
        pipe = service.scoring_pipeline
        metadata = pipe.metadata if isinstance(pipe.metadata, dict) else {}
        schema = pipe.schema if isinstance(pipe.schema, dict) else {}

        if not metadata.get("model_version"):
            diagnostics.append("Missing model_version in scoring pipeline metadata")
        features = schema.get("features", [])
        if not features:
            diagnostics.append("Missing feature list in scoring pipeline schema")
        elif len(features) != 7:
            diagnostics.append(f"Expected 7 canonical features, got {len(features)}")
        if pipe.threshold is None or not hasattr(pipe.threshold, "threshold"):
            diagnostics.append("Missing threshold in scoring pipeline")

    if service.state_manager is None:
        diagnostics.append("Durable state manager is uninitialized")
    if service.raw_evidence_store is None:
        diagnostics.append("Raw evidence store is uninitialized")
    if service.engine is None:
        diagnostics.append("RBTA aggregation engine is uninitialized")

    if diagnostics:
        return "DEGRADED", diagnostics
    return "READY", []


def get_dashboard_summary(
    service: LiveRBTAService,
    evidence_store: RawAlertEvidenceStore,
) -> Dict[str, Any]:
    """Susun KPI ringkasan dashboard (murni read-only) memakai metrik penelitian kanonis."""
    raw_count = evidence_store.count()
    history = list(service.finalized_history)
    meta_count = len(history)

    arr_val = compute_arr(raw_count, meta_count) if raw_count > 0 and meta_count <= raw_count else None
    arr_percent = round(arr_val, 2) if arr_val is not None else None

    escalate_count = sum(1 for m in history if m.action == "ESCALATE")
    digest_count = sum(1 for m in history if m.action == "DAILY_DIGEST")
    suppress_count = sum(1 for m in history if m.action == "SUPPRESS")
    critical_count = sum(1 for m in history if m.decision == "CRITICAL")
    anomalies_count = sum(1 for m in history if m.anomaly_score >= m.threshold_used)

    active_buckets = service.engine.snapshot_buckets()
    status, _ = derive_system_status(service)

    return {
        "raw_alert_count": raw_count,
        "meta_alert_count": meta_count,
        "alert_reduction_rate_percent": arr_percent,
        "active_buckets_count": len(active_buckets),
        "escalate_count": escalate_count,
        "digest_count": digest_count,
        "suppress_count": suppress_count,
        "anomalies_detected": anomalies_count,
        "critical_meta_count": critical_count,
        "source_mode": service.source_mode,
        "system_status": status,
    }


def get_dashboard_agents(
    service: LiveRBTAService,
    evidence_store: Optional[RawAlertEvidenceStore] = None,
) -> List[Dict[str, Any]]:
    """Susun snapshot state temporal dengan nama kanonis untuk run lama."""
    agents = service.engine.snapshot_agents()
    if evidence_store is None:
        return agents

    names_by_id = evidence_store.latest_agent_names()
    return [
        {**agent, "agent_name": names_by_id.get(agent["agent_id"], agent["agent_name"])}
        if not agent.get("agent_name") or agent["agent_name"].casefold() == "unknown"
        else agent
        for agent in agents
    ]


def get_dashboard_buckets(service: LiveRBTAService) -> List[Dict[str, Any]]:
    """Susun snapshot bucket RBTA yang saat ini masih terbuka."""
    return service.engine.snapshot_buckets()


class BucketNotActiveError(LookupError):
    """Dilempar bila tidak ada bucket terbuka untuk kunci yang diminta."""

    def __init__(self, agent_id: str, rule_group_primary: str, finalized_meta_id: Optional[int] = None) -> None:
        self.agent_id = agent_id
        self.rule_group_primary = rule_group_primary
        self.finalized_meta_id = finalized_meta_id
        hint = (
            f" sudah final sebagai MetaAlert #{finalized_meta_id}; buka halaman detailnya"
            if finalized_meta_id is not None
            else " (sudah final atau belum pernah ada)"
        )
        super().__init__(
            f"Bucket {agent_id} / {rule_group_primary} tidak aktif{hint}"
        )


def get_dashboard_bucket_raw_alerts(
    service: LiveRBTAService,
    evidence_store: RawAlertEvidenceStore,
    agent_id: str,
    rule_group_primary: str,
    page: int = 1,
    page_size: int = 20,
) -> Dict[str, Any]:
    """Ambil raw alert anggota satu bucket TERBUKA, dengan paginasi dan penyamaran.

    Memakai envelope resolusi yang sama dengan endpoint raw-alerts MetaAlert final, sehingga
    dashboard cukup memakai satu kontrak tabel. ``meta_id`` yang dicadangkan hanya ditampilkan;
    bucket-nya belum final.
    """
    members = service.engine.active_bucket_members(agent_id, rule_group_primary)
    if members is None:
        finalized_meta_id: Optional[int] = None
        for meta in service.finalized_history:
            if meta.agent_id == agent_id and meta.rule_group_primary == rule_group_primary:
                finalized_meta_id = meta.meta_id
        raise BucketNotActiveError(agent_id, rule_group_primary, finalized_meta_id)
    reserved_meta_id, alert_ids = members
    resolved = evidence_store.get_meta_alert_raw_alerts(
        list(alert_ids), meta_id=None, page=page, page_size=page_size
    )
    return {
        "agent_id": agent_id,
        "rule_group_primary": rule_group_primary,
        "meta_id_reserved": reserved_meta_id,
        "finalized": False,
        **resolved,
    }


def get_dashboard_timeseries(
    service: LiveRBTAService,
    evidence_store: RawAlertEvidenceStore,
    window_hours: int = 24,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Susun deret waktu raw alert yang masuk vs MetaAlert yang sudah final.

    Jumlah raw alert diambil murni dari persistensi raw evidence (termasuk bucket aktif).
    Jumlah MetaAlert diambil dari end_time MetaAlert final.
    """
    if start is not None and end is not None:
        # Rentang kustom (inklusif); bin per jam UTC, dibatasi 31 hari oleh endpoint.
        start_time = start.astimezone(timezone.utc) if start.tzinfo else start.replace(tzinfo=timezone.utc)
        now = end.astimezone(timezone.utc) if end.tzinfo else end.replace(tzinfo=timezone.utc)
        start_time = start_time.replace(minute=0, second=0, microsecond=0)
        window_hours = max(1, int((now - start_time).total_seconds() // 3600) + 1)
    else:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(hours=window_hours)

    # Siapkan bin per jam.
    bins: Dict[str, Dict[str, Any]] = {}
    for h in range(window_hours):
        bin_dt = start_time + timedelta(hours=h)
        bin_key = bin_dt.strftime("%Y-%m-%d %H:00")
        bins[bin_key] = {
            "timestamp": bin_key,
            "raw_alerts": 0,
            "meta_alerts": 0,
        }

    # Isi raw alert langsung dari raw evidence store.
    raw_hourly = evidence_store.count_by_hour(start_time, now)
    for k, v in raw_hourly.items():
        if k in bins:
            bins[k]["raw_alerts"] = v

    # Isi MetaAlert final.
    for m in service.finalized_history:
        if m.end_time and start_time <= m.end_time <= now:
            bin_key = m.end_time.strftime("%Y-%m-%d %H:00")
            if bin_key in bins:
                bins[bin_key]["meta_alerts"] += 1

    return list(bins.values())


def get_dashboard_system(service: LiveRBTAService) -> Dict[str, Any]:
    """Susun DTO metadata sistem dan konfigurasi model dari artefak pipeline."""
    pipeline = getattr(service, "scoring_pipeline", None)

    metadata = pipeline.metadata if pipeline and isinstance(pipeline.metadata, dict) else {}
    schema = pipeline.schema if pipeline and isinstance(pipeline.schema, dict) else {}
    threshold_obj = getattr(pipeline, "threshold", None)

    model_version = metadata.get("model_version")
    tukey_threshold = float(threshold_obj.threshold) if threshold_obj and hasattr(threshold_obj, "threshold") else None
    random_state = metadata.get("random_state")
    features = list(schema.get("features", [])) if isinstance(schema, dict) else []
    feature_schema_version = metadata.get("feature_schema_version") or (schema.get("schema_version") if isinstance(schema, dict) else None)
    score_calibration_version = metadata.get("score_calibration_version")
    training_run_id = metadata.get("training_run_id")
    git_commit = metadata.get("git_commit")
    research_config_hash = metadata.get("research_config_hash")
    created_at_utc = metadata.get("created_at_utc")

    status, diagnostics = derive_system_status(service)

    return {
        "model_version": model_version,
        "tukey_threshold": tukey_threshold,
        "random_state": random_state,
        "feature_names": features,
        "feature_schema_version": feature_schema_version,
        "score_calibration_version": score_calibration_version,
        "training_run_id": training_run_id,
        "git_commit": git_commit,
        "research_config_hash": research_config_hash,
        "created_at_utc": created_at_utc,
        "base_delta_t_seconds": service.base_delta_t.total_seconds(),
        "adaptive": service.adaptive,
        "source_mode": service.source_mode,
        "durable_state_path": str(service.state_manager.state_path) if service.state_manager else None,
        "raw_evidence_db_path": str(service.raw_evidence_store.db_path) if service.raw_evidence_store else None,
        "system_status": status,
        "diagnostics": diagnostics,
    }


def get_dashboard_integrations(service: Optional[LiveRBTAService] = None) -> Dict[str, Any]:
    """Kembalikan status integrasi sesuai kondisi runtime backend."""
    source_mode = getattr(service, "source_mode", "DEFERRED") if service else "DEFERRED"

    if source_mode == "DEFERRED":
        wazuh_status = "DEFERRED"
        wazuh_detail = "Production source connectivity deferred before live deployment"
    elif source_mode == "LIVE":
        wazuh_status = "UNKNOWN"
        wazuh_detail = "Live source mode requested; live coordinator unverified"
    else:
        wazuh_status = "DEFERRED"
        wazuh_detail = f"Source mode '{source_mode}' deferred"

    rbta_ready = bool(service and service.engine)
    model_ready = bool(service and service.scoring_pipeline)
    outbox_ready = bool(service and service.state_manager)

    return {
        "wazuh": {
            "name": "Wazuh SIEM Ingestion",
            "status": wazuh_status,
            "detail": wazuh_detail,
        },
        "rbta": {
            "name": "RBTA Temporal Engine",
            "status": "READY" if rbta_ready else "DEGRADED",
            "detail": "Per-agent EMA baseline adaptive clustering active" if rbta_ready else "Engine uninitialized",
        },
        "model": {
            "name": "Isolation Forest Scoring",
            "status": "READY" if model_ready else "DEGRADED",
            "detail": "Trained reference bundle loaded with Tukey IQR threshold" if model_ready else "Scoring pipeline uninitialized",
        },
        "outbox": {
            "name": "Durable Outbox Queue",
            "status": "READY" if outbox_ready else "DEGRADED",
            "detail": "SQLite transactional staging and crash recovery active" if outbox_ready else "Outbox state uninitialized",
        },
        "shuffle": {
            "name": "Shuffle SOAR Webhook",
            "status": "DEFERRED_EXTERNAL",
            "detail": "External SOAR webhook deferred until live deployment",
        },
        "telegram": {
            "name": "Telegram Incident Bot",
            "status": "DEFERRED_EXTERNAL",
            "detail": "External incident bot deferred until live deployment",
        },
    }
