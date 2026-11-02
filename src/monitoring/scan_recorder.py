"""Best-effort scan telemetry recorder.

The Celery tasks call these functions at stage boundaries. There are two sinks:

1. SQLite via :class:`~src.storage.console_store.ConsoleStore` — the history the
   console queries (task list, trend, severity distribution, audit drill-down).
2. Redis Pub/Sub channel ``scan:{scan_id}:events`` — the live feed behind the
   SSE endpoint.

Hard invariant: **nothing in this module may raise**. A missing table, a locked
database, or an unreachable Redis must degrade to "no telemetry", never to a
broken security chain. Every public function swallows and logs.
"""

from __future__ import annotations

import json
import os
from typing import Any

from src.utils.logging import get_logger

logger = get_logger(__name__)

CHANNEL_TEMPLATE = "scan:{scan_id}:events"

_store_singleton: Any = None


def _store() -> Any:
    """Lazily build the store so importing this module stays cheap."""
    global _store_singleton
    if _store_singleton is None:
        from src.storage.console_store import ConsoleStore

        _store_singleton = ConsoleStore()
    return _store_singleton


def reset_store(store: Any = None) -> None:
    """Test hook: swap or clear the cached store instance."""
    global _store_singleton
    _store_singleton = store


def _publish(scan_id: str, event: dict[str, Any]) -> None:
    """Push one event to the SSE channel. Silently drops when Redis is down."""
    try:
        import redis

        client = redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        client.publish(
            CHANNEL_TEMPLATE.format(scan_id=scan_id),
            json.dumps(event, ensure_ascii=False, default=str),
        )
        client.close()
    except Exception as exc:  # noqa: BLE001 - telemetry must never break the chain
        logger.debug("scan_event_publish_failed", scan_id=scan_id, error=str(exc)[:120])


# ----------------------------------------------------------------------
# Scan lifecycle
# ----------------------------------------------------------------------


def scan_started(
    scan_id: str,
    *,
    repo_url: str = "",
    pr_info: dict[str, Any] | None = None,
    trigger_type: str | None = None,
    scan_scope: str = "full",
) -> None:
    """Create the scan row and open the SSE stream."""
    try:
        pr = pr_info or {}
        inferred_trigger = trigger_type or ("webhook" if pr else "manual")
        _store().create_scan(
            scan_id,
            repo=_normalize_repo(repo_url),
            pr_number=pr.get("pr_number"),
            head_sha=pr.get("head_sha", ""),
            trigger_type=inferred_trigger,
            scan_scope=scan_scope,
        )
        _publish(
            scan_id,
            {
                "event": "scan.started",
                "scan_id": scan_id,
                "trigger_type": inferred_trigger,
                "repo": _normalize_repo(repo_url),
            },
        )
        _audit(
            "scan_started",
            {
                "scan_id": scan_id,
                "repo": _normalize_repo(repo_url),
                "trigger_type": inferred_trigger,
                "pr_number": pr.get("pr_number"),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan_started_record_failed", scan_id=scan_id, error=str(exc)[:150])


def scan_status(scan_id: str, status: str) -> None:
    """Update the coarse status (running / paused / failed)."""
    try:
        _store().update_scan_status(scan_id, status)
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan_status_record_failed", scan_id=scan_id, error=str(exc)[:150])


def scan_finished(
    scan_id: str,
    report: dict[str, Any] | None = None,
    *,
    status: str = "completed",
) -> None:
    """Persist findings, final counts and the closing SSE event.

    Args:
        scan_id: Scan identifier (equal to the task id in the current pipeline).
        report: AggregatedReport dict produced by the reporter agent.
        status: Terminal status to record.
    """
    try:
        report = report or {}
        summary = report.get("summary") or {}
        security = report.get("security") or {}
        security_report = security.get("security_report") or {}
        conflict = security.get("conflict_decision") or {}

        findings = _extract_findings(security_report, conflict)
        store = _store()
        store.replace_findings(scan_id, findings)

        blocker_count = int(summary.get("blocking_count", 0) or 0)
        human_required = bool(conflict.get("human_intervention_required"))
        verdict = "human_review" if human_required else ("block" if blocker_count else "pass")

        store.finish_scan(
            scan_id,
            status=status,
            verdict=verdict,
            overall_blocking=bool(conflict.get("overall_blocking", blocker_count > 0)),
            blocker_count=blocker_count,
            warning_count=int(summary.get("warning_count", 0) or 0),
            cve_count=sum(1 for f in findings if f["finding_type"] == "vulnerability"),
            code_issue_count=sum(1 for f in findings if f["finding_type"] == "code_issue"),
            llm_degraded=bool(report.get("degraded", False)),
            degraded_reasons=list(report.get("degraded_reasons") or []),
        )

        repo = _repo_of(scan_id)
        if repo:
            store.touch_repo_scan(repo)

        duration_ms = _duration_of(scan_id)
        cve_count = sum(1 for f in findings if f["finding_type"] == "vulnerability")
        # Persist the terminal event too, so a late SSE client can replay the
        # whole stream from SQLite without Redis.
        seq = store.add_event(
            scan_id,
            "scan",
            "finished",
            stage="scan",
            duration_ms=duration_ms,
            payload={
                "verdict": verdict,
                "blocker_count": blocker_count,
                "cve_count": cve_count,
                "status": status,
            },
        )
        _publish(
            scan_id,
            {
                "event": "scan.finished",
                "seq": seq,
                "scan_id": scan_id,
                "status": status,
                "verdict": verdict,
                "blocker_count": blocker_count,
                "cve_count": cve_count,
                "duration_ms": duration_ms,
            },
        )
        _audit(
            "verdict_made",
            {
                "scan_id": scan_id,
                "verdict": verdict,
                "blocker_count": blocker_count,
                "cve_count": cve_count,
                "repo": repo,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan_finished_record_failed", scan_id=scan_id, error=str(exc)[:150])


def scan_failed(scan_id: str, *, error: str = "") -> None:
    """Mark a scan failed without losing the partial timeline."""
    try:
        _store().finish_scan(scan_id, status="failed", verdict="error")
        add_event(scan_id, "pipeline", "failed", stage="report", payload={"error": error[:300]})
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan_failed_record_failed", scan_id=scan_id, error=str(exc)[:150])


# ----------------------------------------------------------------------
# Agent lifecycle
# ----------------------------------------------------------------------


def agent_started(scan_id: str, agent: str, *, stage: str = "") -> None:
    try:
        seq = _store().add_event(
            scan_id, agent, "started", stage=stage or agent
        )
        _publish(
            scan_id,
            {
                "event": "agent.started",
                "seq": seq,
                "scan_id": scan_id,
                "agent": agent,
                "stage": stage or agent,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "agent_started_record_failed", scan_id=scan_id, agent=agent, error=str(exc)[:150]
        )


def agent_finished(
    scan_id: str,
    agent: str,
    *,
    duration_ms: float | int | None = None,
    degraded: bool = False,
    stage: str = "",
    payload: dict[str, Any] | None = None,
) -> None:
    try:
        rounded = int(duration_ms) if duration_ms is not None else None
        status = "degraded" if degraded else "finished"
        seq = _store().add_event(
            scan_id,
            agent,
            status,
            stage=stage or agent,
            duration_ms=rounded,
            payload=payload,
        )
        _publish(
            scan_id,
            {
                "event": "agent.finished",
                "seq": seq,
                "scan_id": scan_id,
                "agent": agent,
                "stage": stage or agent,
                "status": status,
                "duration_ms": rounded,
                "payload": payload or {},
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "agent_finished_record_failed", scan_id=scan_id, agent=agent, error=str(exc)[:150]
        )


def agent_skipped(scan_id: str, agent: str, *, reason: str = "") -> None:
    try:
        seq = _store().add_event(
            scan_id, agent, "skipped", stage=agent, payload={"reason": reason}
        )
        _publish(
            scan_id,
            {
                "event": "agent.finished",
                "seq": seq,
                "scan_id": scan_id,
                "agent": agent,
                "stage": agent,
                "status": "skipped",
                "duration_ms": None,
                "payload": {"reason": reason},
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "agent_skipped_record_failed", scan_id=scan_id, agent=agent, error=str(exc)[:150]
        )


def add_event(
    scan_id: str,
    agent: str,
    status: str,
    *,
    stage: str = "",
    duration_ms: int | None = None,
    payload: dict[str, Any] | None = None,
) -> None:
    """Low-level escape hatch for stages that are not full Agents (preprocess)."""
    try:
        seq = _store().add_event(
            scan_id, agent, status, stage=stage, duration_ms=duration_ms, payload=payload
        )
        _publish(
            scan_id,
            {
                "event": "agent.finished" if status != "started" else "agent.started",
                "seq": seq,
                "scan_id": scan_id,
                "agent": agent,
                "stage": stage or agent,
                "status": status,
                "duration_ms": duration_ms,
                "payload": payload or {},
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan_event_record_failed", scan_id=scan_id, error=str(exc)[:150])


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------


def _audit(action: str, detail: dict[str, Any], operator: str = "system") -> None:
    """Append one audit-log entry. Best-effort: never breaks a scan."""
    try:
        from src.storage.audit_log import AuditLogger

        AuditLogger().log(
            action=action,
            operator=operator,
            detail=detail,
            scan_id=str(detail.get("scan_id") or "") or None,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit_append_failed", action=action, error=str(exc)[:150])


def _normalize_repo(repo_url: str) -> str:
    """Reduce a clone URL to ``owner/name`` when possible."""
    if not repo_url:
        return ""
    value = repo_url.strip().rstrip("/")
    if value.endswith(".git"):
        value = value[:-4]
    if value.startswith("git@"):
        # git@github.com:owner/name
        _, _, tail = value.partition(":")
        return tail
    if "://" in value:
        parts = value.split("/")
        return "/".join(parts[-2:]) if len(parts) >= 2 else value
    return value


def _repo_of(scan_id: str) -> str:
    try:
        scan = _store().get_scan(scan_id)
        return (scan or {}).get("repo", "") or ""
    except Exception:  # noqa: BLE001
        return ""


def _duration_of(scan_id: str) -> int | None:
    try:
        scan = _store().get_scan(scan_id)
        return (scan or {}).get("duration_ms")
    except Exception:  # noqa: BLE001
        return None


def _extract_findings(
    security_report: dict[str, Any], conflict: dict[str, Any]
) -> list[dict[str, Any]]:
    """Flatten vulnerabilities + code issues, merging the conflict verdicts."""
    decisions = {
        str(d.get("finding_id", "")): d
        for d in (conflict.get("decisions") or [])
    }
    findings: list[dict[str, Any]] = []

    for vuln in security_report.get("vulnerabilities") or []:
        finding_id = str(vuln.get("cve_id") or "")
        decision = decisions.get(finding_id, {})
        # The conflict verdict is authoritative: a degraded scan escalates
        # medium findings to "block", and the console must show that decision
        # rather than the scanner's original flag.
        blocked = decision.get("verdict") == "block" or bool(vuln.get("blocking", False))
        findings.append(
            {
                "finding_type": "vulnerability",
                "finding_id": finding_id,
                "cve_id": finding_id or None,
                "rule_id": None,
                "package_name": vuln.get("package_name"),
                "installed_version": vuln.get("affected_version"),
                "fixed_version": vuln.get("fixed_version"),
                "severity": str(vuln.get("severity", "low")).lower(),
                "cvss_score": vuln.get("cvss_score"),
                "dependency_type": vuln.get("dependency_type"),
                "file_path": vuln.get("file_location"),
                "line_number": None,
                "message": vuln.get("description", ""),
                "evidence_source": vuln.get("evidence_source"),
                "evidence_url": vuln.get("evidence_url"),
                "verdict": decision.get("verdict"),
                "blocking": blocked,
                "appealable": bool(decision.get("appealable", False)),
            }
        )

    for issue in security_report.get("code_issues") or []:
        rule_id = str(issue.get("rule_id") or "")
        decision = decisions.get(rule_id, {})
        blocked = decision.get("verdict") == "block" or bool(issue.get("blocking", False))
        findings.append(
            {
                "finding_type": "code_issue",
                "finding_id": rule_id,
                "cve_id": None,
                "rule_id": rule_id,
                "package_name": None,
                "installed_version": None,
                "fixed_version": None,
                "severity": str(issue.get("severity", "low")).lower(),
                "cvss_score": None,
                "dependency_type": None,
                "file_path": issue.get("file_path"),
                "line_number": issue.get("line_number"),
                "message": issue.get("message", ""),
                "evidence_source": "Semgrep",
                "evidence_url": None,
                "verdict": decision.get("verdict"),
                "blocking": blocked,
                "appealable": bool(decision.get("appealable", False)),
            }
        )

    return findings
