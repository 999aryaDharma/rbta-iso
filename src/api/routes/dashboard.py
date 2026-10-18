from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.api.auth import get_api_key
from src.runtime.context_resolver import DashboardRuntimeResolver
from src.runtime.observability import (
    BucketNotActiveError,
    get_dashboard_agents,
    get_dashboard_bucket_raw_alerts,
    get_dashboard_buckets,
    get_dashboard_integrations,
    get_dashboard_summary,
    get_dashboard_system,
    get_dashboard_timeseries,
)

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


def _get_resolver(request: Request) -> DashboardRuntimeResolver:
    return request.app.state.runtime_resolver


@router.get("/summary")
def dashboard_summary(
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    service, evidence_store, _ = resolver.resolve(run_id)
    return get_dashboard_summary(service, evidence_store)


@router.get("/agents")
def dashboard_agents(
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> List[Dict[str, Any]]:
    service, evidence_store, _ = resolver.resolve(run_id)
    return get_dashboard_agents(service, evidence_store)


@router.get("/buckets")
def dashboard_buckets(
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> List[Dict[str, Any]]:
    service, _, _ = resolver.resolve(run_id)
    return get_dashboard_buckets(service)


@router.get("/buckets/raw-alerts")
def dashboard_bucket_raw_alerts(
    agent_id: str = Query(..., description="Agent ID of the open bucket"),
    rule_group_primary: str = Query(..., description="Primary rule group of the open bucket"),
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, le=200, description="Items per page (max 200)"),
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    service, evidence_store, _ = resolver.resolve(run_id)
    try:
        return get_dashboard_bucket_raw_alerts(
            service, evidence_store, agent_id, rule_group_primary, page, page_size
        )
    except BucketNotActiveError as exc:
        detail: Dict[str, Any] = {"detail": str(exc)}
        if exc.finalized_meta_id is not None:
            detail["finalized_meta_id"] = exc.finalized_meta_id
        raise HTTPException(status_code=404, detail=detail)


@router.get("/timeseries")
def dashboard_timeseries(
    window_hours: int = Query(24, ge=1, le=168, description="Time series lookback window in hours"),
    start: Optional[datetime] = Query(None, description="Custom range start (overrides window_hours)"),
    end: Optional[datetime] = Query(None, description="Custom range end (inclusive)"),
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> List[Dict[str, Any]]:
    if (start is None) != (end is None):
        raise HTTPException(status_code=422, detail="start and end must be given together")
    if start is not None and end is not None:
        a = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
        b = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
        if b < a or (b - a).days > 31:
            raise HTTPException(status_code=422, detail="range must be 0-31 days with end >= start")
    service, evidence_store, _ = resolver.resolve(run_id)
    return get_dashboard_timeseries(service, evidence_store, window_hours=window_hours, start=start, end=end)


@router.get("/system")
def dashboard_system(
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    service, _, _ = resolver.resolve(run_id)
    return get_dashboard_system(service)


@router.get("/integrations")
def dashboard_integrations(
    run_id: Optional[str] = Query(None, description="Optional replay run context ID"),
    resolver: DashboardRuntimeResolver = Depends(_get_resolver),
    api_key: str = Depends(get_api_key),
) -> Dict[str, Any]:
    service, _, _ = resolver.resolve(run_id)
    return get_dashboard_integrations(service)
