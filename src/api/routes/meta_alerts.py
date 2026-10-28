from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Literal, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from src.api.auth import get_api_key
from src.runtime.context_resolver import DashboardRuntimeResolver

router = APIRouter(prefix="/api/v1/meta-alerts", tags=["meta-alerts"])

SortByField = Literal["meta_id", "start_time", "end_time", "alert_count", "max_severity", "anomaly_score"]


def _get_resolver(request: Request) -> DashboardRuntimeResolver:
    return request.app.state.runtime_resolver


def _scored_alert_to_dict(scored: Any) -> Dict[str, Any]:
    return {
        "meta_id": scored.meta_id,
        "agent_id": scored.agent_id,
        "agent_name": scored.agent_name,
        "rule_group_primary": scored.rule_group_primary,
        "start_time": scored.start_time.isoformat() if hasattr(scored.start_time, "isoformat") else str(scored.start_time),
        "end_time": scored.end_time.isoformat() if hasattr(scored.end_time, "isoformat") else str(scored.end_time),
        "alert_count": scored.alert_count,
        "max_severity": scored.max_severity,
        "mitre_tactics": list(scored.mitre_tactics),
        "seven_features": dict(scored.seven_features),
        "raw_model_score": scored.raw_model_score,
        "anomaly_score": scored.anomaly_score,
        "threshold_used": scored.threshold_used,
        "decision": scored.decision,
        "action": scored.action,
        "escalate": scored.escalate,
        "model_version": scored.model_version,
        "feature_schema_version": scored.feature_schema_version,
        "score_calibration_version": scored.score_calibration_version,
        "source_alert_ids": list(scored.source_alert_ids),
        "metadata": dict(scored.metadata),
        "top_deviations": [list(p) for p in scored.top_deviations] if getattr(scored, "top_deviations", None) else None,
    }


@router.get("")
def list_meta_alerts(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=200, description="Items per page (max 200)"),
    decision: Optional[str] = Query(None, description="Filter by decision"),
    action: Optional[str] = Query(None, description="Filter by action (ESCALATE, DAILY_DIGEST, SUPPRESS)"),
    agent_id: Optional[str] = Query(None, description="Filter by agent ID"),
    rule_group_primary: Optional[str] = Query(None, description="Filter by primary rule group"),
    start: Optional[datetime] = Query(None, description="end_time >= start"),
    end: Optional[datetime] = Query(None, description="end_time <= end"),
    search: Optional[str] = Query(None, description="Search across meta_id, rule_group, agent_name"),
    sort_by: SortByField = Query("end_time", description="Sort field allowlist"),
    sort_order: Literal["asc", "desc"] = Query("desc", description="Sort direction"),
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    service, evidence_store, _ = resolver.resolve(run_id)
    history, total = service.query_history(
        page=page,
        page_size=page_size,
        decision=decision,
        action=action,
        agent_id=agent_id,
        rule_group_primary=rule_group_primary,
        start=start,
        end=end,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    items = [_scored_alert_to_dict(m) for m in history]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


class VerdictIn(BaseModel):
    verdict: Literal["incident", "actionable_benign", "noise"]
    note: str = Field("", max_length=2000)
    labeled_by: str = Field("", max_length=100)


@router.get("/review-queue")
def review_queue(
    end_date: Optional[date] = Query(None, description="Hari terakhir (WITA, YYYY-MM-DD); default hari ini"),
    days: int = Query(7, ge=1, le=31, description="Jumlah hari ke belakang"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    """Antrean review live: semua ESCALATE + sampel deterministik 5% SUPPRESS dan 5% DAILY_DIGEST per hari."""
    from src.runtime.evidence_export import WITA
    from src.runtime.review_queue import SAMPLE_RATE, build_review_queue, summarize_queue

    service, _, _ = resolver.resolve(None)
    if service is None:
        raise HTTPException(status_code=503, detail="Live service uninitialized")
    last = end_date or datetime.now(WITA).date()
    day_list = [last - timedelta(days=i) for i in range(days)]
    items = build_review_queue(service.state_manager, day_list)
    return {"items": items, "summary": summarize_queue(items), "sample_rate": SAMPLE_RATE,
            "days": [d.isoformat() for d in day_list]}


@router.post("/{meta_id}/verdict")
def set_meta_alert_verdict(
    meta_id: int,
    body: VerdictIn,
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    """Simpan label analyst untuk MetaAlert live (tidak mengubah decision/action model)."""
    service, _, _ = resolver.resolve(None)
    if service is None or service.get_meta_detail(meta_id) is None:
        raise HTTPException(status_code=404, detail=f"MetaAlert #{meta_id} not found")
    return service.state_manager.verdict_set(meta_id, body.verdict, body.note.strip(), body.labeled_by.strip())


@router.get("/{meta_id}")
def get_meta_alert_detail(
    meta_id: int,
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    service, evidence_store, _ = resolver.resolve(run_id)
    m = service.get_meta_detail(meta_id)
    if m is not None:
        payload = _scored_alert_to_dict(m)
        if not run_id:
            # Label analyst hanya untuk MetaAlert live.
            payload["analyst_verdict"] = service.state_manager.verdict_map().get(meta_id)
        return payload
    raise HTTPException(status_code=404, detail=f"MetaAlert #{meta_id} not found")


@router.get("/{meta_id}/trace")
def get_meta_alert_trace(
    meta_id: int,
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    service, evidence_store, _ = resolver.resolve(run_id)
    m = service.get_meta_detail(meta_id)
    if m is not None:
        resolution = evidence_store.resolve_provenance_members(list(m.source_alert_ids))
        return {
            "meta_id": m.meta_id,
            "agent_id": m.agent_id,
            "rule_group_primary": m.rule_group_primary,
            "model_version": m.model_version,
            "feature_schema_version": m.feature_schema_version,
            "score_calibration_version": m.score_calibration_version,
            "decision": m.decision,
            "action": m.action,
            **resolution,
        }
    raise HTTPException(status_code=404, detail=f"MetaAlert #{meta_id} trace not found")


@router.get("/{meta_id}/raw-alerts")
def get_meta_alert_raw_alerts(
    meta_id: int,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page (max 200)"),
    search: Optional[str] = Query(None, description="Search query across alert ID, rule, description, IP, log"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    level_min: Optional[int] = Query(None, ge=0, le=15, description="Filter by minimum severity level"),
    level_max: Optional[int] = Query(None, ge=0, le=15, description="Filter by maximum severity level"),
    srcip: Optional[str] = Query(None, description="Filter by source IP"),
    mitre_tactic: Optional[str] = Query(None, description="Filter by MITRE tactic"),
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    service, evidence_store, _ = resolver.resolve(run_id)
    meta = service.get_meta_detail(meta_id)

    if meta is None:
        raise HTTPException(status_code=404, detail=f"MetaAlert #{meta_id} not found")

    source_ids = list(meta.source_alert_ids)
    return evidence_store.get_meta_alert_raw_alerts(
        source_alert_ids=source_ids,
        meta_id=meta_id,
        page=page,
        page_size=page_size,
        search=search,
        rule_id=rule_id,
        level_min=level_min,
        level_max=level_max,
        srcip=srcip,
        mitre_tactic=mitre_tactic,
        redact=True,
    )
