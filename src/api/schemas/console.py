"""Response schemas for the Web console API.

Deliberately flat: the console renders tables and charts, so nested objects
add parsing work on the client without adding value.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanItem(BaseModel):
    """One row in the task list."""

    scan_id: str
    repo: str = ""
    pr_number: int | None = None
    head_sha: str = ""
    trigger_type: str = "manual"
    scan_scope: str = "full"
    status: str = "running"
    verdict: str | None = None
    overall_blocking: bool = False
    blocker_count: int = 0
    warning_count: int = 0
    cve_count: int = 0
    code_issue_count: int = 0
    llm_degraded: bool = False
    degraded_reasons: list[str] = Field(default_factory=list)
    started_at: str = ""
    finished_at: str | None = None
    duration_ms: int | None = None


class ScanListResponse(BaseModel):
    items: list[ScanItem]
    total: int
    page: int
    page_size: int


class FindingItem(BaseModel):
    id: int
    scan_id: str
    finding_type: str
    finding_id: str = ""
    cve_id: str | None = None
    rule_id: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    severity: str = "low"
    cvss_score: float | None = None
    dependency_type: str | None = None
    file_path: str | None = None
    line_number: int | None = None
    message: str = ""
    evidence_source: str | None = None
    evidence_url: str | None = None
    verdict: str | None = None
    blocking: bool = False
    appealable: bool = False


class TimelineEvent(BaseModel):
    seq: int
    agent: str
    stage: str = ""
    status: str
    duration_ms: int | None = None
    payload: dict = Field(default_factory=dict)
    created_at: str = ""


class ScanDetailResponse(ScanItem):
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    findings: list[FindingItem] = Field(default_factory=list)


class DashboardSummary(BaseModel):
    window_days: int = 1
    scans: int = 0
    blocked: int = 0
    passed: int = 0
    human_review: int = 0
    cves: int = 0
    blockers: int = 0
    avg_duration_ms: float = 0.0
    repos: int = 0


class SeverityBucket(BaseModel):
    severity: str
    count: int


class SeverityDistributionResponse(BaseModel):
    items: list[SeverityBucket]


class TrendPoint(BaseModel):
    date: str
    scans: int = 0
    blocked: int = 0
    cves: int = 0


class TrendResponse(BaseModel):
    items: list[TrendPoint]


class PackageRisk(BaseModel):
    package_name: str
    findings: int = 0
    blocked: int = 0
    severity: str = "low"


class TopPackageResponse(BaseModel):
    items: list[PackageRisk]


class RepoItem(BaseModel):
    repo_full_name: str
    installation_id: int = 0
    github_repo_id: int | None = None
    default_branch: str = "main"
    enabled: bool = True
    authorized_at: str = ""
    last_scan_at: str | None = None


class RepoListResponse(BaseModel):
    items: list[RepoItem]
    count: int


class RepoToggleRequest(BaseModel):
    repo_full_name: str
    enabled: bool


class InstalledRepoRef(BaseModel):
    full_name: str
    id: int | None = None


class InstallCallbackRequest(BaseModel):
    """Body of the GitHub App setup callback.

    GitHub itself posts ``installation_id`` and ``setup_action`` as query
    parameters; a small server-side adapter may forward a richer body.
    """

    installation_id: int
    setup_action: str = "install"
    repos: list[InstalledRepoRef] = Field(default_factory=list)
    account: str = ""


class InstallUrlResponse(BaseModel):
    url: str
    app_slug: str = ""
    configured: bool = False


class AuditItem(BaseModel):
    id: int
    timestamp: str
    action: str
    operator: str
    detail: dict = Field(default_factory=dict)
    evidence_link: str = ""
    scan_id: str = ""
    task_id: str = ""
    row_hash: str = ""


class AuditListResponse(BaseModel):
    items: list[AuditItem]
    count: int
    limit: int
    offset: int


class IntegrityResponse(BaseModel):
    valid: bool
    total_rows: int
    bad_rows: list[dict] = Field(default_factory=list)
