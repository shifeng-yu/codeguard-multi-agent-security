"""Console: repository authorization, GitHub App install callback and sync."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse

from src.api.deps import get_audit_logger, get_console_store, verify_console_access
from src.api.schemas.console import (
    InstallCallbackRequest,
    InstallUrlResponse,
    RepoItem,
    RepoListResponse,
    RepoToggleRequest,
)
from src.integrations.github_app import GitHubAppAuth
from src.storage.audit_log import AuditLogger
from src.storage.console_store import ConsoleStore
from src.utils.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(dependencies=[Depends(verify_console_access)])


def get_github_app() -> GitHubAppAuth:
    """Dependency provider so FastAPI does not map GitHubAppAuth args to query params."""
    return GitHubAppAuth()


@router.get("", response_model=RepoListResponse)
async def list_repositories(store: ConsoleStore = Depends(get_console_store)) -> dict:
    """Repositories the GitHub App has been authorized for."""
    items = store.list_repos()
    return {"items": items, "count": len(items)}


@router.post("", response_model=RepoItem, status_code=201)
async def authorize_repository(
    body: RepoItem,
    store: ConsoleStore = Depends(get_console_store),
    audit: AuditLogger = Depends(get_audit_logger),
) -> dict:
    """Manually register a repository (offline demo path, no GitHub call)."""
    if not body.repo_full_name.strip():
        raise HTTPException(
            status_code=422,
            detail={"error": {"code": "REPO-001", "message": "repo_full_name is required"}},
        )
    row = store.upsert_repo(
        repo_full_name=body.repo_full_name.strip(),
        installation_id=body.installation_id,
        github_repo_id=body.github_repo_id,
        default_branch=body.default_branch or "main",
        enabled=body.enabled,
    )
    _audit(audit, "repo_authorized", row.get("repo_full_name", ""), {"source": "manual"})
    return row


@router.patch("", response_model=RepoItem)
async def toggle_repository(
    body: RepoToggleRequest,
    store: ConsoleStore = Depends(get_console_store),
    audit: AuditLogger = Depends(get_audit_logger),
) -> dict:
    """Enable or disable scanning for one repository."""
    if not store.set_repo_enabled(body.repo_full_name, body.enabled):
        raise HTTPException(
            status_code=404,
            detail={"error": {"code": "REPO-002", "message": "Repository not found"}},
        )
    _audit(
        audit,
        "repo_toggled",
        body.repo_full_name,
        {"enabled": body.enabled},
    )
    return store.get_repo(body.repo_full_name) or {}


@router.get("/install/url", response_model=InstallUrlResponse)
async def get_install_url(
    app: GitHubAppAuth = Depends(get_github_app),
) -> dict:
    """URL the console's "install" button opens, plus whether the app is set up."""
    return {
        "url": app.install_url(),
        "app_slug": app.slug,
        "configured": app.configured,
    }


@router.post("/install/callback", response_model=RepoListResponse)
async def install_callback(
    body: InstallCallbackRequest,
    store: ConsoleStore = Depends(get_console_store),
    audit: AuditLogger = Depends(get_audit_logger),
    app: GitHubAppAuth = Depends(get_github_app),
) -> dict:
    """Handle the GitHub App setup callback (JSON form).

    Used by the offline fixture and by any adapter that forwards the redirect
    with the repository list attached.
    """
    repos = [
        {"full_name": ref.full_name, "id": ref.id, "default_branch": "main"}
        for ref in body.repos
        if ref.full_name
    ]

    if not repos:
        repos = await app.list_installation_repositories(body.installation_id)

    if not repos:
        logger.warning(
            "install_callback_no_repositories",
            installation_id=body.installation_id,
            configured=app.configured,
        )
        return {"items": [], "count": 0}

    saved = []
    for repo in repos:
        full_name = repo.get("full_name") or repo.get("name", "")
        if not full_name:
            continue
        saved.append(
            store.upsert_repo(
                repo_full_name=full_name,
                installation_id=body.installation_id,
                github_repo_id=repo.get("id"),
                default_branch=repo.get("default_branch") or "main",
            )
        )
        _audit(
            audit,
            "repo_authorized",
            full_name,
            {
                "source": "github_app",
                "installation_id": body.installation_id,
                "setup_action": body.setup_action,
            },
        )
    return {"items": saved, "count": len(saved)}


@router.get("/install/callback", response_class=HTMLResponse, include_in_schema=False)
async def install_callback_browser(
    installation_id: int = Query(...),
    setup_action: str = Query("install"),
    store: ConsoleStore = Depends(get_console_store),
    audit: AuditLogger = Depends(get_audit_logger),
    app: GitHubAppAuth = Depends(get_github_app),
) -> HTMLResponse:
    """Browser landing page GitHub redirects to after installation."""
    repos = await app.list_installation_repositories(installation_id) if app.configured else []
    for repo in repos:
        full_name = repo.get("full_name")
        if not full_name:
            continue
        store.upsert_repo(
            repo_full_name=full_name,
            installation_id=installation_id,
            github_repo_id=repo.get("id"),
            default_branch=repo.get("default_branch") or "main",
        )
        _audit(
            audit,
            "repo_authorized",
            full_name,
            {"source": "github_app", "installation_id": installation_id},
        )

    if repos:
        body = f"已授权 {len(repos)} 个仓库，可以关闭此页面回到控制台。"
    elif app.configured:
        body = "安装已完成，但该 installation 未授权任何仓库。"
    else:
        body = "GitHub App 未配置（GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY），无法自动同步仓库。"

    return HTMLResponse(
        f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
        <title>CodeGuard 安装完成</title></head>
        <body style="font-family:system-ui;padding:48px;color:#1f2937">
        <h2>CodeGuard GitHub App</h2>
        <p>installation_id = {installation_id} · setup_action = {setup_action}</p>
        <p>{body}</p>
        </body></html>"""
    )


@router.post("/install/sync/{installation_id}", response_model=RepoListResponse)
async def sync_installation(
    installation_id: int,
    store: ConsoleStore = Depends(get_console_store),
    app: GitHubAppAuth = Depends(get_github_app),
) -> dict:
    """Pull the repository list for an installation again (idempotent)."""
    repos = await app.list_installation_repositories(installation_id)
    saved = []
    for repo in repos:
        full_name = repo.get("full_name")
        if not full_name:
            continue
        saved.append(
            store.upsert_repo(
                repo_full_name=full_name,
                installation_id=installation_id,
                github_repo_id=repo.get("id"),
                default_branch=repo.get("default_branch") or "main",
            )
        )
    if not saved:
        raise HTTPException(
            status_code=502,
            detail={
                "error": {
                    "code": "REPO-003",
                    "message": "GitHub returned no repositories (check app credentials)",
                }
            },
        )
    return {"items": saved, "count": len(saved)}


def _audit(audit: AuditLogger, action: str, repo: str, detail: dict[str, Any]) -> None:
    """Write an audit entry; never let logging break the request."""
    try:
        audit.log(action=action, operator="console", detail={"repo": repo, **detail})
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit_write_failed", action=action, error=str(exc)[:150])
