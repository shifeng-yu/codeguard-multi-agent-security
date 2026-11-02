"""Console: scan history, detail, findings and the live event stream."""

from __future__ import annotations

from contextlib import suppress

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request

from src.api.deps import get_console_store, verify_console_access
from src.api.schemas.console import (
    FindingItem,
    ScanDetailResponse,
    ScanListResponse,
)
from src.api.sse import sse_response
from src.storage.console_store import ConsoleStore
from src.utils.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(dependencies=[Depends(verify_console_access)])


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    repo: str | None = None,
    status: str | None = None,
    verdict: str | None = None,
    since: str | None = None,
    store: ConsoleStore = Depends(get_console_store),
) -> dict:
    """Paginated scan history, newest first."""
    return store.list_scans(
        page=page,
        page_size=page_size,
        repo=repo,
        status=status,
        verdict=verdict,
        since=since,
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan_detail(
    scan_id: str,
    store: ConsoleStore = Depends(get_console_store),
) -> dict:
    """One scan with its severity breakdown, agent timeline and findings."""
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "SCAN-001", "message": "Scan not found"}},
        )
    return {
        **scan,
        "severity_breakdown": store.finding_breakdown(scan_id),
        "timeline": store.list_events(scan_id),
        "findings": store.list_findings(scan_id),
    }


@router.get("/{scan_id}/findings", response_model=list[FindingItem])
async def get_scan_findings(
    scan_id: str,
    severity: str | None = None,
    verdict: str | None = None,
    finding_type: str | None = None,
    store: ConsoleStore = Depends(get_console_store),
) -> list[dict]:
    """Findings for one scan, filterable by severity / verdict / type."""
    if not store.get_scan(scan_id):
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "SCAN-001", "message": "Scan not found"}},
        )
    return store.list_findings(
        scan_id, severity=severity, verdict=verdict, finding_type=finding_type
    )


@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    request: Request,
    store: ConsoleStore = Depends(get_console_store),
) -> dict:
    """Full report: file storage first, Redis task result as fallback."""
    if not store.get_scan(scan_id):
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "SCAN-001", "message": "Scan not found"}},
        )

    from src.storage.report_store import LocalFileReportStorage

    try:
        report = LocalFileReportStorage().load_json(scan_id)
        if report:
            return {"scan_id": scan_id, "source": "file", "report": report}
    except Exception as exc:  # noqa: BLE001
        logger.warning("report_file_read_failed", scan_id=scan_id, error=str(exc)[:150])

    redis = getattr(request.app.state, "redis", None)
    if redis is not None:
        try:
            raw = await redis.get(f"codeguard:task:{scan_id}:result")
            if raw:
                import json

                data = raw.decode("utf-8") if isinstance(raw, bytes) else raw
                return {"scan_id": scan_id, "source": "redis", "report": json.loads(data)}
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_redis_read_failed", scan_id=scan_id, error=str(exc)[:150])

    raise HTTPException(
        status_code=404,
        detail={"error": {"code": "SCAN-002", "message": "Report not available yet"}},
    )


@router.get("/{scan_id}/stream")
async def stream_scan_events(
    scan_id: str,
    request: Request,
    store: ConsoleStore = Depends(get_console_store),
    last_event_id: int = Query(0, ge=0),
    header_last_event_id: str | None = Header(None, alias="Last-Event-ID"),
):
    """SSE stream of the agent chain: replay from SQLite, then live from Redis."""
    if not store.get_scan(scan_id):
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "SCAN-001", "message": "Scan not found"}},
        )

    resume_from = last_event_id
    if header_last_event_id:
        with suppress(ValueError):
            resume_from = max(resume_from, int(header_last_event_id))

    return sse_response(
        request=request, scan_id=scan_id, store=store, last_event_id=resume_from
    )
