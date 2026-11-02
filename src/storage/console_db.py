"""Console metadata database: repos / scans / findings / agent_events.

The Web console needs queryable metadata that the report layer cannot provide.
Reports are written as one JSON file per scan (``LocalFileReportStorage``), which
cannot answer "list the last 30 scans" or "draw a 30-day severity trend" without
walking the whole directory. These four tables close that gap.

Design:
- Same SQLite file as the audit log (``data/codeguard.db``), separate tables.
- Schema is created idempotently on first use; no migration framework.
- One connection per operation, so Celery worker threads and processes do not
  share handles. ``:memory:`` is supported via a cached connection.
- All timestamps are UTC ISO-8601 strings, sortable as text.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress

_SCHEMA: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS repos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_repo_id INTEGER,
        repo_full_name TEXT NOT NULL UNIQUE,
        installation_id INTEGER NOT NULL DEFAULT 0,
        default_branch TEXT NOT NULL DEFAULT 'main',
        enabled INTEGER NOT NULL DEFAULT 1,
        authorized_at TEXT NOT NULL,
        last_scan_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL DEFAULT '',
        repo TEXT NOT NULL DEFAULT '',
        pr_number INTEGER,
        head_sha TEXT NOT NULL DEFAULT '',
        trigger_type TEXT NOT NULL DEFAULT 'manual',
        scan_scope TEXT NOT NULL DEFAULT 'full',
        status TEXT NOT NULL DEFAULT 'running',
        verdict TEXT,
        overall_blocking INTEGER NOT NULL DEFAULT 0,
        blocker_count INTEGER NOT NULL DEFAULT 0,
        warning_count INTEGER NOT NULL DEFAULT 0,
        cve_count INTEGER NOT NULL DEFAULT 0,
        code_issue_count INTEGER NOT NULL DEFAULT 0,
        llm_degraded INTEGER NOT NULL DEFAULT 0,
        degraded_reasons TEXT NOT NULL DEFAULT '[]',
        started_at TEXT NOT NULL,
        finished_at TEXT,
        duration_ms INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        finding_id TEXT NOT NULL DEFAULT '',
        cve_id TEXT,
        rule_id TEXT,
        package_name TEXT,
        installed_version TEXT,
        fixed_version TEXT,
        severity TEXT NOT NULL DEFAULT 'low',
        cvss_score REAL,
        dependency_type TEXT,
        file_path TEXT,
        line_number INTEGER,
        message TEXT NOT NULL DEFAULT '',
        evidence_source TEXT,
        evidence_url TEXT,
        verdict TEXT,
        blocking INTEGER NOT NULL DEFAULT 0,
        appealable INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS agent_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        agent TEXT NOT NULL,
        stage TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL,
        duration_ms INTEGER,
        payload TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_scans_repo_time ON scans(repo, started_at)",
    "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
    "CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at)",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
    "CREATE INDEX IF NOT EXISTS idx_findings_package ON findings(package_name)",
    "CREATE INDEX IF NOT EXISTS idx_events_scan ON agent_events(scan_id, id)",
)


def resolve_db_path(db_path: str | None = None) -> str:
    """Resolve the SQLite path, honouring CONSOLE_DB_PATH then DATABASE_URL."""
    if db_path:
        return db_path
    explicit = os.getenv("CONSOLE_DB_PATH", "").strip()
    if explicit:
        return explicit
    return os.getenv("DATABASE_URL", "data/codeguard.db").replace("sqlite:///", "")


class ConsoleDatabase:
    """Thin SQLite wrapper for the console metadata tables.

    Usage::

        db = ConsoleDatabase()
        with db.connect() as conn:
            conn.execute("SELECT COUNT(*) FROM scans").fetchone()
    """

    _schema_lock = threading.Lock()

    def __init__(self, db_path: str | None = None) -> None:
        self._db_path = resolve_db_path(db_path)
        self._schema_ready = False
        self._memory_conn: sqlite3.Connection | None = None

    @property
    def db_path(self) -> str:
        return self._db_path

    # ------------------------------------------------------------------
    # Connections
    # ------------------------------------------------------------------

    def _raw_connect(self) -> sqlite3.Connection:
        if self._db_path == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = self._new_connection(":memory:")
            return self._memory_conn

        parent = os.path.dirname(self._db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return self._new_connection(self._db_path)

    @staticmethod
    def _new_connection(target: str) -> sqlite3.Connection:
        conn = sqlite3.connect(target, timeout=10)
        conn.row_factory = sqlite3.Row
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA foreign_keys=ON",
            "PRAGMA busy_timeout=10000",
        ):
            # WAL is unavailable on some network filesystems; the default
            # rollback journal still works, so this is not fatal.
            with suppress(sqlite3.Error):
                conn.execute(pragma)
        return conn

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a connection, committing on success and rolling back on error."""
        self._ensure_schema()
        conn = self._raw_connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if self._db_path != ":memory:":
                conn.close()

    def _ensure_schema(self) -> None:
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            conn = self._raw_connect()
            try:
                for statement in _SCHEMA:
                    conn.execute(statement)
                conn.commit()
            finally:
                if self._db_path != ":memory:":
                    conn.close()
            self._schema_ready = True

    def close(self) -> None:
        """Close the cached in-memory connection, if any."""
        if self._memory_conn is not None:
            self._memory_conn.close()
            self._memory_conn = None

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def table_names(self) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        return [row["name"] for row in rows]
