"""Run a real offline scan and persist it for the Web console.

Why this exists: the console must show data that came from an actual scan, not
from a fixture table. This script drives the same four Agents the Celery
pipeline drives — only without Redis and without Celery — and writes the same
rows the workers would write (via ``scan_recorder``).

Usage::

    python scripts/demo_scan.py --repo C:/Users/86186/fastapi_src --name encode/fastapi
    python scripts/demo_scan.py --repo ./ --name acme/api --pr 42 --trigger webhook

The repository path may be any local git checkout; it is cloned into a temp
directory first, exactly like a remote scan.
"""

from __future__ import annotations

import argparse
import asyncio
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.core.models import ScanScope  # noqa: E402
from src.monitoring import scan_recorder  # noqa: E402
from src.preprocess.metadata import run_preprocessing  # noqa: E402

# Set while a scan is in flight so a crash can still close the row as failed.
_ACTIVE_SCAN: str | None = None


def _git_head(repo_path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.stdout.strip() or uuid4().hex * 2
    except Exception:
        return uuid4().hex * 2


def _git_branch(repo_path: Path) -> str:
    """Current branch of a local checkout, so cloning does not guess 'main'."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "branch", "--show-current"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.stdout.strip() or "main"
    except Exception:
        return "main"


def _is_remote(value: str) -> bool:
    """True when the argument looks like a git remote rather than a local path."""
    return value.startswith(("http://", "https://", "git@", "ssh://")) or value.endswith(".git")


def _remote_default_branch(url: str) -> str:
    """Ask the remote for its default branch instead of assuming ``main``."""
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--symref", url, "HEAD"],
            capture_output=True,
            text=True,
            timeout=25,
        )
        for line in result.stdout.splitlines():
            if line.startswith("ref:") and "refs/heads/" in line:
                return line.split("refs/heads/", 1)[1].split()[0]
    except Exception:  # noqa: BLE001 - fall back below
        pass
    return "main"


async def run_scan(args: argparse.Namespace) -> int:
    global _ACTIVE_SCAN
    remote = _is_remote(args.repo)
    repo_path = None if remote else Path(args.repo).resolve()
    if repo_path is not None and not repo_path.exists():
        print(f"ERROR: repository path not found: {repo_path}")
        return 2

    scan_id = f"demo-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid4().hex[:6]}"
    head_sha = _git_head(repo_path) if repo_path is not None else ""

    work_dir = Path(tempfile.mkdtemp(prefix="codeguard_demo_")) / "repo"
    report_dir = Path(args.report_dir).resolve()

    pr_info = (
        {
            "pr_number": args.pr,
            "base_branch": args.base_branch,
            "head_branch": args.head_branch or "demo",
            "base_sha": "",
            "head_sha": head_sha,
        }
        if args.pr
        else None
    )

    scan_recorder.scan_started(
        scan_id,
        repo_url=args.name,
        pr_info=pr_info,
        trigger_type=args.trigger,
        scan_scope="full",
    )
    _ACTIVE_SCAN = scan_id

    started = time.monotonic()
    print(f"[1/5] 预处理 {args.repo if remote else repo_path}")
    metadata = run_preprocessing(
        repo_url=args.repo if remote else str(repo_path),
        work_dir=work_dir,
        task_id=scan_id,
        scan_id=scan_id,
        scan_scope=ScanScope.FULL,
        branch=args.branch
        or (_git_branch(repo_path) if repo_path is not None else _remote_default_branch(args.repo)),
    )
    deps = metadata.get("dependencies", [])
    scan_recorder.add_event(
        scan_id,
        "preprocess",
        "finished",
        stage="preprocess",
        duration_ms=int((time.monotonic() - started) * 1000),
        payload={
            "language": metadata.get("language", "unknown"),
            "dependencies": len(deps),
            "files": len(metadata.get("files") or metadata.get("changed_files") or []),
        },
    )
    print(f"      依赖 {len(deps)} 个 · 语言 {metadata.get('language', 'unknown')}")

    print("[2/5] 安全审计 Agent（Semgrep + OSV，零 LLM）")
    from src.agents.security.agent import SecurityAuditAgent

    security_agent = SecurityAuditAgent()
    scan_recorder.agent_started(scan_id, "security", stage="security")
    security_result = await security_agent.execute(
        code_metadata=metadata,
        scan_scope="full",
        scan_id=scan_id,
        task_id=scan_id,
    )
    security_data = security_result.get("data", {}) or {}
    vulnerabilities = security_data.get("vulnerabilities") or []
    code_issues = security_data.get("code_issues") or []
    scan_recorder.agent_finished(
        scan_id,
        "security",
        duration_ms=security_result.get("duration_ms"),
        degraded=bool(security_result.get("degraded", False)),
        stage="security",
        payload={
            "vulnerabilities": len(vulnerabilities),
            "code_issues": len(code_issues),
        },
    )
    print(f"      CVE {len(vulnerabilities)} 个 · 代码问题 {len(code_issues)} 个")

    print("[3/5] 冲突消解 Agent（5 条裁决规则 + 人在回路）")
    from src.agents.conflict.agent import ConflictResolutionAgent

    conflict_agent = ConflictResolutionAgent()
    scan_recorder.agent_started(scan_id, "conflict", stage="conflict")
    conflict_result = await conflict_agent.execute(
        security_report=security_data,
        code_metadata=metadata,
        task_id=scan_id,
        scan_id=scan_id,
    )
    conflict_data = conflict_result.get("data", {}) or {}
    decisions = conflict_data.get("decisions") or []
    scan_recorder.agent_finished(
        scan_id,
        "conflict",
        duration_ms=conflict_result.get("duration_ms"),
        degraded=bool(conflict_result.get("degraded", False)),
        stage="conflict",
        payload={"decisions": len(decisions)},
    )
    blocking = sum(1 for item in decisions if item.get("verdict") == "block")
    print(f"      裁决 {len(decisions)} 项 · 阻断 {blocking} 项")

    print("[4/5] 报告聚合 Agent")
    # Migration runs on the Redis event sidecar and needs an explicit target
    # version; record the skip so the console still shows all four Agents.
    scan_recorder.agent_skipped(scan_id, "migration", reason="未指定迁移目标版本")
    from src.agents.reporter.agent import ReportAggregationAgent
    from src.storage.report_store import LocalFileReportStorage

    reporter = ReportAggregationAgent(report_store=LocalFileReportStorage(str(report_dir)))
    scan_recorder.agent_started(scan_id, "reporter", stage="report")
    report_result = await reporter.execute(
        security_data={"security": security_data, "conflict": conflict_data},
        migration_data={},
        repo_url=args.name,
        code_metadata=metadata,
        scan_id=scan_id,
        task_id=scan_id,
    )
    report = report_result.get("data", {}) or {}
    scan_recorder.agent_finished(
        scan_id,
        "reporter",
        duration_ms=report_result.get("duration_ms"),
        degraded=bool(report_result.get("degraded", False)),
        stage="report",
        payload={"degraded": bool(report.get("degraded", False))},
    )

    print("[5/5] 落库 + 关闭扫描")
    scan_recorder.scan_finished(scan_id, report)
    _ACTIVE_SCAN = None

    total_ms = int((time.monotonic() - started) * 1000)
    summary = report.get("summary", {}) or {}
    print("")
    print("=" * 58)
    print(f"scan_id      : {scan_id}")
    print(f"仓库          : {args.name}")
    print(f"CVE / 阻断项  : {len(vulnerabilities)} / {summary.get('blocking_count', 0)}")
    print(f"总耗时        : {total_ms} ms")
    print(f"报告          : {report_dir / scan_id / 'report.json'}")
    print("控制台        : http://127.0.0.1:5173/scans/" + scan_id)
    print("=" * 58)

    shutil.rmtree(work_dir.parent, ignore_errors=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline demo scan -> console tables")
    parser.add_argument("--repo", required=True, help="Local checkout path or git URL to scan")
    parser.add_argument("--name", default="", help="owner/name shown in the console")
    parser.add_argument("--pr", type=int, default=0, help="PR number (0 = manual scan)")
    parser.add_argument("--trigger", default="manual", choices=["manual", "webhook"])
    parser.add_argument("--branch", default="", help="Branch to clone (default: current branch)")
    parser.add_argument("--base-branch", default="master")
    parser.add_argument("--head-branch", default="")
    parser.add_argument("--report-dir", default="data/reports")
    args = parser.parse_args()
    args.name = args.name or Path(args.repo).resolve().name

    try:
        return asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        if _ACTIVE_SCAN:
            scan_recorder.scan_failed(_ACTIVE_SCAN, error="interrupted by user")
        return 130
    except Exception:
        traceback.print_exc()
        if _ACTIVE_SCAN:
            scan_recorder.scan_failed(_ACTIVE_SCAN, error="demo_scan crashed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
