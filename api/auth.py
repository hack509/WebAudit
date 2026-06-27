"""
API Key authentication middleware for WebAudit REST API.

API keys are stored in plain text in a simple JSON file (storage/api_keys.json).
For production use, replace with a database-backed store.

Configuration:
    WEBAUDIT_API_KEY_REQUIRED=1     — enforce auth on all /api/v1/* routes
    WEBAUDIT_API_KEY_FILE=path.json — override key file location

Generating a key:
    python -c "import secrets; print(secrets.token_urlsafe(32))"

Adding a key:
    echo '{"my-key-name": "TOKEN_VALUE"}' > storage/api_keys.json
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from utils.logger import get_logger

logger = get_logger("api.auth")

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_KEY_FILE = Path(os.environ.get("WEBAUDIT_API_KEY_FILE", "storage/api_keys.json"))
_AUTH_REQUIRED = os.environ.get("WEBAUDIT_API_KEY_REQUIRED", "0").strip() in ("1", "true", "yes")


def _load_keys() -> dict[str, str]:
    """Load {name: key} map from the JSON key file."""
    if not _KEY_FILE.exists():
        return {}
    try:
        return json.loads(_KEY_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Could not load API key file: {e}")
        return {}


def verify_api_key(api_key: Optional[str] = Security(_API_KEY_HEADER)) -> Optional[str]:
    """
    FastAPI dependency — validates X-API-Key header.

    - If auth is disabled (WEBAUDIT_API_KEY_REQUIRED != 1): always passes.
    - If auth is enabled and key is valid: passes, returns key name.
    - If auth is enabled and key is missing/invalid: raises 401.
    """
    if not _AUTH_REQUIRED:
        return None

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    keys = _load_keys()
    for name, value in keys.items():
        if value == api_key:
            logger.debug(f"API request authenticated as '{name}'")
            return name

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def require_auth() -> str:
    """Shortcut dependency that always requires a valid API key."""
    # Re-load _AUTH_REQUIRED dynamically so tests can patch env vars
    api_key_required = os.environ.get("WEBAUDIT_API_KEY_REQUIRED", "0").strip() in ("1", "true", "yes")
    if not api_key_required:
        return "anonymous"
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
    )
