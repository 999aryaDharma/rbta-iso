from fastapi import APIRouter, Depends
from src.api.auth import get_api_key

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.get("/check")
def check_auth(api_key: str = Depends(get_api_key)):
    """Endpoint ringan untuk frontend memvalidasi API key sebelum disimpan di sessionStorage."""
    return {"status": "authenticated", "authenticated": True}
