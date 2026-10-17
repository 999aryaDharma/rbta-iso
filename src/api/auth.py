from typing import Optional
from fastapi import Header, HTTPException, Request, status
from hmac import compare_digest
import os


def get_api_key(request: Request, authorization: Optional[str] = Header(None)) -> str:
    """Dependency yang mencocokkan header Authorization dengan API key yang dikonfigurasi."""
    expected_key = getattr(request.app.state, "auth_key", None)
    if expected_key is None:
        expected_key = os.getenv("RBTA_API_KEY", "")

    if not expected_key:
        return ""

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )

    supplied_key = authorization[7:] if authorization.startswith("Bearer ") else authorization
    if not compare_digest(str(supplied_key), str(expected_key)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header",
        )

    return expected_key
