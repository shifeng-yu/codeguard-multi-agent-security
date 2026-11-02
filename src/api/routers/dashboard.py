"""Console: dashboard aggregations (cards, severity split, trend, risk packages)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from src.api.deps import get_console_store, verify_console_access
from src.api.schemas.console import (
    DashboardSummary,
    SeverityDistributionResponse,
    TopPackageResponse,
    TrendResponse,
)
from src.storage.console_store import ConsoleStore

router = APIRouter(dependencies=[Depends(verify_console_access)])


@router.get("/summary", response_model=DashboardSummary)
async def get_summary(
    days: int = Query(1, ge=1, le=365),
    store: ConsoleStore = Depends(get_console_store),
) -> dict:
    """Headline numbers for the overview cards."""
    return store.summary(days=days)


@router.get("/severity", response_model=SeverityDistributionResponse)
async def get_severity_distribution(
    days: int = Query(30, ge=1, le=365),
    store: ConsoleStore = Depends(get_console_store),
) -> dict:
    """Finding counts per severity bucket (all four buckets always present)."""
    return {"items": store.severity_distribution(days=days)}


@router.get("/trend", response_model=TrendResponse)
async def get_trend(
    days: int = Query(30, ge=1, le=365),
    store: ConsoleStore = Depends(get_console_store),
) -> dict:
    """Daily scan / block / CVE counts, gap-filled so the chart has no holes."""
    return {"items": store.trend(days=days)}


@router.get("/top-packages", response_model=TopPackageResponse)
async def get_top_packages(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(10, ge=1, le=50),
    store: ConsoleStore = Depends(get_console_store),
) -> dict:
    """Most frequently blocked third-party packages."""
    return {"items": store.top_packages(days=days, limit=limit)}
