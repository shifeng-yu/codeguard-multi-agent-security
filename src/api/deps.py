"""Dependency injection for FastAPI routes.

Provides reusable dependencies for:
- Configuration
- Redis connection
- API Key authentication (MVP: static key)
- Task state lookup
"""

from __future__ import annotations

import hmac
import os
from typing import TYPE_CHECKING

from fastapi import Header, HTTPException, Request

if TYPE_CHECKING:  # pragma: no cover - typing only
    from src.storage.audit_log import AuditLogger
    from src.storage.console_store import ConsoleStore

# ------------------------------------------------------------------
# API Key auth
# ------------------------------------------------------------------

async def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """Verify the X-API-Key header against the configured key.

    MVP: Single static key from environment.
    v1.0+: OAuth2 / JWT token validation.
    """
    configured_key = os.getenv("CODEGUARD_API_KEY", "")

    # No key configured => reject all requests (explicit secure-by-default)
    if not configured_key:
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "SEC-003",
                    "message": "API key not configured. Set CODEGUARD_API_KEY.",
                }
            }
        )

    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "SEC-003", "message": "Missing X-API-Key header"}},
        )

    if not hmac.compare_digest(x_api_key, configured_key):
        raise HTTPException(
            status_code=401,
            detail={"error": {"code": "SEC-003", "message": "Invalid API key"}},
        )

    return "authenticated"


# ------------------------------------------------------------------
# Task state
# ------------------------------------------------------------------

async def get_task_state(task_id: str, request: Request) -> dict:
    """Fetch task state from Redis. Returns 404 if task not found.

    The Redis client is stored in app.state.redis (set in create_app).
    """
    redis = getattr(request.app.state, "redis", None)
    if not redis:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    import json
    key = f"codeguard:task:{task_id}:result"
    try:
        raw = await redis.get(key)
        if not raw:
            raise HTTPException(
                status_code=404,
                detail={"error": {"code": "TASK-001", "message": "Task not found"}},
            )
        return json.loads(raw)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "TASK-001", "message": "Task not found"}},
        ) from None


# ------------------------------------------------------------------
# Console (Web dashboard) dependencies
# ------------------------------------------------------------------

_console_store: object | None = None


def get_console_store() -> ConsoleStore:
    """Return a process-wide ConsoleStore (schema init happens once)."""
    global _console_store
    if _console_store is None:
        from src.storage.console_store import ConsoleStore

        _console_store = ConsoleStore()
    return _console_store  # type: ignore[return-value]


def reset_console_store(store: object | None = None) -> None:
    """Test hook: swap or clear the cached console store."""
    global _console_store
    _console_store = store


_audit_logger: object | None = None


def get_audit_logger() -> AuditLogger:
    """Return a process-wide AuditLogger."""
    global _audit_logger
    if _audit_logger is None:
        from src.storage.audit_log import AuditLogger

        _audit_logger = AuditLogger()
    return _audit_logger  # type: ignore[return-value]


async def verify_console_access(
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """Auth for read-only console endpoints.

    Unlike :func:`verify_api_key` (secure-by-default: no key configured means
    reject), the console allows keyless access when ``CODEGUARD_API_KEY`` is
    unset. That keeps the local demo one double-click away, while any deployment
    that sets a key enforces it on the console too.
    """
    configured_key = os.getenv("CODEGUARD_API_KEY", "")

    if not configured_key:
        return "local-demo"

    if not x_api_key or not hmac.compare_digest(x_api_key, configured_key):
        raise HTTPException(
            status_code=401,
            detail={
                "error": {
                    "code": "SEC-003",
                    "message": "Invalid or missing X-API-Key header",
                }
            },
        )
    return "authenticated"
