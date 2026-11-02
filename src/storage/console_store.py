"""Query and write layer for the console metadata tables.

Kept separate from :mod:`src.storage.console_db` (schema/connections) so that
the recorder, the API routers, and the tests all share one definition of "how a
scan row is shaped".

Every method opens its own connection; there is no long-lived cursor, because
Celery workers call into this module from several threads and processes.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from src.storage.console_db import ConsoleDatabase

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
_RANK_SEVERITY = {4: "critical", 3: "high", 2: "medium", 1: "low"}
_SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def _decode_json(value: Any, default: Any) -> Any:
    if not value:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class ConsoleStore:
    """Read/write facade over repos, scans, findings and agent_events."""

    def __init__(self, db: ConsoleDatabase | None = None) -> None:
        self._db = db or ConsoleDatabase()

    @property
    def db_path(self) -> str:
        return self._db.db_path

    # ------------------------------------------------------------------
    # Repos
    # ------------------------------------------------------------------

    def upsert_repo(
        self,
        *,
        repo_full_name: str,
        installation_id: int = 0,
        github_repo_id: int | None = None,
        default_branch: str = "main",
        enabled: bool = True,
        authorized_at: str | None = None,
    ) -> dict[str, Any]:
        """Insert or update a GitHub App installation for one repository."""
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT INTO repos (github_repo_id, repo_full_name, installation_id,
                                   default_branch, enabled, authorized_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(repo_full_name) DO UPDATE SET
                    github_repo_id = COALESCE(excluded.github_repo_id, repos.github_repo_id),
                    installation_id = excluded.installation_id,
                    default_branch = excluded.default_branch,
                    enabled = excluded.enabled,
                    authorized_at = repos.authorized_at
                """,
                (
                    github_repo_id,
                    repo_full_name,
                    installation_id,
                    default_branch,
                    int(enabled),
                    authorized_at or _now_iso(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM repos WHERE repo_full_name = ?", (repo_full_name,)
            ).fetchone()
        return _row(row) or {}

    def list_repos(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM repos"
        params: list[Any] = []
        if enabled_only:
            sql += " WHERE enabled = ?"
            params.append(1)
        sql += " ORDER BY authorized_at DESC"
        with self._db.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_repo(self, repo_full_name: str) -> dict[str, Any] | None:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM repos WHERE repo_full_name = ?", (repo_full_name,)
            ).fetchone()
        return _row(row)

    def set_repo_enabled(self, repo_full_name: str, enabled: bool) -> bool:
        with self._db.connect() as conn:
            cursor = conn.execute(
                "UPDATE repos SET enabled = ? WHERE repo_full_name = ?",
                (int(enabled), repo_full_name),
            )
        return cursor.rowcount > 0

    def touch_repo_scan(self, repo_full_name: str, when: str | None = None) -> None:
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE repos SET last_scan_at = ? WHERE repo_full_name = ?",
                (when or _now_iso(), repo_full_name),
            )

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def create_scan(
        self,
        scan_id: str,
        *,
        task_id: str = "",
        repo: str = "",
        pr_number: int | None = None,
        head_sha: str = "",
        trigger_type: str = "manual",
        scan_scope: str = "full",
        started_at: str | None = None,
    ) -> dict[str, Any]:
        """Create a scan row; repeated calls for the same id are no-ops."""
        with self._db.connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (scan_id, task_id, repo, pr_number, head_sha,
                                   trigger_type, scan_scope, status, started_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?)
                ON CONFLICT(scan_id) DO NOTHING
                """,
                (
                    scan_id,
                    task_id or scan_id,
                    repo,
                    pr_number,
                    head_sha,
                    trigger_type,
                    scan_scope,
                    started_at or _now_iso(),
                ),
            )
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return _row(row) or {}

    def update_scan_status(self, scan_id: str, status: str) -> None:
        with self._db.connect() as conn:
            conn.execute(
                "UPDATE scans SET status = ? WHERE scan_id = ?", (status, scan_id)
            )

    def finish_scan(
        self,
        scan_id: str,
        *,
        status: str = "completed",
        verdict: str | None = None,
        overall_blocking: bool = False,
        blocker_count: int = 0,
        warning_count: int = 0,
        cve_count: int = 0,
        code_issue_count: int = 0,
        llm_degraded: bool = False,
        degraded_reasons: list[str] | None = None,
        finished_at: str | None = None,
        duration_ms: int | None = None,
    ) -> None:
        finished = finished_at or _now_iso()
        if duration_ms is None:
            duration_ms = self._elapsed_ms(scan_id, finished)
        with self._db.connect() as conn:
            conn.execute(
                """
                UPDATE scans SET
                    status = ?, verdict = ?, overall_blocking = ?,
                    blocker_count = ?, warning_count = ?, cve_count = ?,
                    code_issue_count = ?, llm_degraded = ?, degraded_reasons = ?,
                    finished_at = ?, duration_ms = ?
                WHERE scan_id = ?
                """,
                (
                    status,
                    verdict,
                    int(overall_blocking),
                    blocker_count,
                    warning_count,
                    cve_count,
                    code_issue_count,
                    int(llm_degraded),
                    json.dumps(degraded_reasons or [], ensure_ascii=False),
                    finished,
                    duration_ms,
                    scan_id,
                ),
            )

    def _elapsed_ms(self, scan_id: str, finished_at: str) -> int | None:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT started_at FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if not row or not row["started_at"]:
            return None
        try:
            started = datetime.fromisoformat(row["started_at"])
            finished = datetime.fromisoformat(finished_at)
            return max(0, int((finished - started).total_seconds() * 1000))
        except (TypeError, ValueError):
            return None

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        data = _row(row)
        if data:
            data["degraded_reasons"] = _decode_json(data.get("degraded_reasons"), [])
        return data

    def list_scans(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        repo: str | None = None,
        status: str | None = None,
        verdict: str | None = None,
        since: str | None = None,
    ) -> dict[str, Any]:
        """Paginated scan list, newest first."""
        page = max(1, page)
        page_size = min(max(1, page_size), 200)

        where: list[str] = []
        params: list[Any] = []
        if repo:
            where.append("repo = ?")
            params.append(repo)
        if status:
            where.append("status = ?")
            params.append(status)
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)
        if since:
            where.append("started_at >= ?")
            params.append(since)
        clause = f"WHERE {' AND '.join(where)}" if where else ""

        with self._db.connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) AS n FROM scans {clause}", params
            ).fetchone()["n"]
            rows = conn.execute(
                f"""SELECT * FROM scans {clause}
                    ORDER BY started_at DESC, scan_id DESC
                    LIMIT ? OFFSET ?""",
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()

        items = []
        for row in rows:
            data = dict(row)
            data["degraded_reasons"] = _decode_json(data.get("degraded_reasons"), [])
            items.append(data)
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def replace_findings(self, scan_id: str, findings: list[dict[str, Any]]) -> int:
        """Replace all findings for a scan (idempotent on task retries)."""
        now = _now_iso()
        with self._db.connect() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.executemany(
                """
                INSERT INTO findings (
                    scan_id, finding_type, finding_id, cve_id, rule_id,
                    package_name, installed_version, fixed_version, severity,
                    cvss_score, dependency_type, file_path, line_number, message,
                    evidence_source, evidence_url, verdict, blocking, appealable,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        f.get("finding_type", ""),
                        f.get("finding_id", ""),
                        f.get("cve_id"),
                        f.get("rule_id"),
                        f.get("package_name"),
                        f.get("installed_version"),
                        f.get("fixed_version"),
                        f.get("severity", "low"),
                        f.get("cvss_score"),
                        f.get("dependency_type"),
                        f.get("file_path"),
                        f.get("line_number"),
                        f.get("message", ""),
                        f.get("evidence_source"),
                        f.get("evidence_url"),
                        f.get("verdict"),
                        int(bool(f.get("blocking"))),
                        int(bool(f.get("appealable"))),
                        now,
                    )
                    for f in findings
                ],
            )
        return len(findings)

    def list_findings(
        self,
        scan_id: str,
        *,
        severity: str | None = None,
        verdict: str | None = None,
        finding_type: str | None = None,
    ) -> list[dict[str, Any]]:
        where = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if verdict:
            where.append("verdict = ?")
            params.append(verdict)
        if finding_type:
            where.append("finding_type = ?")
            params.append(finding_type)
        with self._db.connect() as conn:
            rows = conn.execute(
                f"""SELECT * FROM findings WHERE {' AND '.join(where)}
                    ORDER BY blocking DESC, id ASC""",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    def finding_breakdown(self, scan_id: str) -> dict[str, int]:
        """Counts by severity for one scan, all four buckets always present."""
        with self._db.connect() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity",
                (scan_id,),
            ).fetchall()
        counts = dict.fromkeys(_SEVERITY_ORDER, 0)
        for row in rows:
            counts[row["severity"]] = row["n"]
        return counts

    # ------------------------------------------------------------------
    # Agent events
    # ------------------------------------------------------------------

    def add_event(
        self,
        scan_id: str,
        agent: str,
        status: str,
        *,
        stage: str = "",
        duration_ms: int | None = None,
        payload: dict[str, Any] | None = None,
    ) -> int:
        """Append one agent lifecycle event. Returns its auto-increment id (seq)."""
        with self._db.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO agent_events (scan_id, agent, stage, status,
                                          duration_ms, payload, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    agent,
                    stage,
                    status,
                    duration_ms,
                    json.dumps(payload or {}, ensure_ascii=False, default=str),
                    _now_iso(),
                ),
            )
            return int(cursor.lastrowid or 0)

    def list_events(
        self, scan_id: str, *, after_id: int = 0
    ) -> list[dict[str, Any]]:
        with self._db.connect() as conn:
            rows = conn.execute(
                """SELECT * FROM agent_events
                   WHERE scan_id = ? AND id > ?
                   ORDER BY id ASC""",
                (scan_id, after_id),
            ).fetchall()
        events = []
        for row in rows:
            data = dict(row)
            data["seq"] = data["id"]
            data["payload"] = _decode_json(data.get("payload"), {})
            events.append(data)
        return events

    # ------------------------------------------------------------------
    # Dashboard aggregations
    # ------------------------------------------------------------------

    def _cutoff(self, days: int) -> str:
        return (datetime.now(UTC) - timedelta(days=days)).isoformat()

    def summary(self, *, days: int = 1) -> dict[str, Any]:
        """Headline numbers for the console overview cards."""
        cutoff = self._cutoff(days)
        with self._db.connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS scans,
                       COALESCE(SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END), 0) AS blocked,
                       COALESCE(SUM(CASE WHEN verdict = 'pass' THEN 1 ELSE 0 END), 0) AS passed,
                       COALESCE(SUM(CASE WHEN verdict = 'human_review'
                                    THEN 1 ELSE 0 END), 0) AS human_review,
                       COALESCE(SUM(cve_count), 0) AS cves,
                       COALESCE(SUM(blocker_count), 0) AS blockers,
                       COALESCE(AVG(duration_ms), 0) AS avg_duration_ms
                FROM scans WHERE started_at >= ?
                """,
                (cutoff,),
            ).fetchone()
            repos = conn.execute("SELECT COUNT(*) AS n FROM repos").fetchone()["n"]
        return {
            "window_days": days,
            "scans": row["scans"],
            "blocked": row["blocked"],
            "passed": row["passed"],
            "human_review": row["human_review"],
            "cves": row["cves"],
            "blockers": row["blockers"],
            "avg_duration_ms": round(row["avg_duration_ms"] or 0, 1),
            "repos": repos,
        }

    def severity_distribution(self, *, days: int = 30) -> list[dict[str, Any]]:
        cutoff = self._cutoff(days)
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT f.severity AS severity, COUNT(*) AS n
                FROM findings f JOIN scans s ON s.scan_id = f.scan_id
                WHERE s.started_at >= ?
                GROUP BY f.severity
                """,
                (cutoff,),
            ).fetchall()
        counts = dict.fromkeys(_SEVERITY_ORDER, 0)
        for row in rows:
            if row["severity"] in counts:
                counts[row["severity"]] = row["n"]
        return [
            {"severity": sev, "count": counts[sev]} for sev in _SEVERITY_ORDER
        ]

    def trend(self, *, days: int = 30) -> list[dict[str, Any]]:
        """Daily scan counts with gap filling, oldest day first."""
        cutoff = self._cutoff(days)
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT substr(started_at, 1, 10) AS day,
                       COUNT(*) AS scans,
                       COALESCE(SUM(CASE WHEN verdict = 'block' THEN 1 ELSE 0 END), 0) AS blocked,
                       COALESCE(SUM(cve_count), 0) AS cves
                FROM scans
                WHERE started_at >= ?
                GROUP BY day ORDER BY day ASC
                """,
                (cutoff,),
            ).fetchall()

        by_day = {
            row["day"]: {
                "scans": row["scans"],
                "blocked": row["blocked"],
                "cves": row["cves"],
            }
            for row in rows
        }
        today = datetime.now(UTC).date()
        series = []
        for offset in range(days - 1, -1, -1):
            day = (today - timedelta(days=offset)).isoformat()
            point = by_day.get(day, {"scans": 0, "blocked": 0, "cves": 0})
            series.append({"date": day, **point})
        return series

    def top_packages(self, *, days: int = 30, limit: int = 10) -> list[dict[str, Any]]:
        cutoff = self._cutoff(days)
        with self._db.connect() as conn:
            rows = conn.execute(
                """
                SELECT f.package_name AS package_name,
                       COUNT(*) AS findings,
                       COALESCE(SUM(CASE WHEN f.verdict = 'block' THEN 1 ELSE 0 END), 0) AS blocked,
                       MAX(CASE f.severity
                             WHEN 'critical' THEN 4
                             WHEN 'high' THEN 3
                             WHEN 'medium' THEN 2
                             ELSE 1 END) AS rank
                FROM findings f JOIN scans s ON s.scan_id = f.scan_id
                WHERE s.started_at >= ?
                  AND f.package_name IS NOT NULL AND f.package_name != ''
                GROUP BY f.package_name
                ORDER BY blocked DESC, rank DESC, findings DESC
                LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        return [
            {
                "package_name": row["package_name"],
                "findings": row["findings"],
                "blocked": row["blocked"],
                "severity": _RANK_SEVERITY.get(row["rank"], "low"),
            }
            for row in rows
        ]


def severity_rank(severity: str) -> int:
    """Numeric rank for sorting severities (critical highest)."""
    return _SEVERITY_RANK.get(severity, 0)
