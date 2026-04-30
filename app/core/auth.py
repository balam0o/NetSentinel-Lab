import os
import secrets

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

from app.core.config import settings


API_KEY_HEADER_NAME = "X-API-Key"

api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)


def get_configured_api_key() -> str:
    env_value = os.getenv("NETSENTINEL_API_KEY")
    if env_value is not None:
        return env_value.strip()

    return settings.netsentinel_api_key.strip()


def is_auth_enabled() -> bool:
    return bool(get_configured_api_key())


def require_api_key(api_key: str | None = Depends(api_key_header)) -> None:
    configured_api_key = get_configured_api_key()

    if not configured_api_key:
        return

    if not api_key or not secrets.compare_digest(api_key, configured_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )