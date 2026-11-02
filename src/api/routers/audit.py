"""Console: audit log search and chain-integrity verification."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from src.api.deps import get_audit_logger, verify_console_access
from src.api.schemas.console import AuditListResponse, IntegrityResponse
from src.storage.audit_log import AuditLogger

router = APIRouter(dependencies=[Depends(verify_console_access)])


@router.get("", response_model=AuditListResponse)
async def list_audit_entries(
    action: str | None = None,
    scan_id: str | None = None,
    task_id: str | None = None,
    operator: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    logger: AuditLogger = Depends(get_audit_logger),
) -> dict:
    """Filtered, paginated audit log. Newest entries first."""
    items = logger.query(
        action=action,
        scan_id=scan_id,
        task_id=task_id,
        operator=operator,
        limit=limit,
        offset=offset,
    )
    total = logger.count(
        action=action, scan_id=scan_id, task_id=task_id, operator=operator
    )
    return {"items": items, "count": total, "limit": limit, "offset": offset}


@router.get("/verify", response_model=IntegrityResponse)
async def verify_audit_chain(
    logger: AuditLogger = Depends(get_audit_logger),
) -> dict:
    """Recompute the SHA-256 row chain and report any broken link.

    This is the endpoint behind the console's "verify chain" button: it proves
    the append-only guarantees claimed in the README rather than asserting them.
    """
    result = logger.verify_integrity()
    return {
        "valid": bool(result.get("valid", False)),
        "total_rows": int(result.get("total_rows", 0)),
        "bad_rows": list(result.get("bad_rows", [])),
    }
