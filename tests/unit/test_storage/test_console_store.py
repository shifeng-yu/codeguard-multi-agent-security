"""Tests for the console metadata store (scans / findings / events / dashboard)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.storage.console_db import ConsoleDatabase
from src.storage.console_store import ConsoleStore, severity_rank


@pytest.fixture()
def store(tmp_path) -> ConsoleStore:
    return ConsoleStore(ConsoleDatabase(str(tmp_path / "console.db")))


class TestSchema:
    def test_tables_created(self, store: ConsoleStore) -> None:
        assert set(store._db.table_names()) >= {
            "repos",
            "scans",
            "findings",
            "agent_events",
        }

    def test_schema_is_idempotent(self, tmp_path) -> None:
        path = str(tmp_path / "console.db")
        ConsoleStore(ConsoleDatabase(path))
        second = ConsoleStore(ConsoleDatabase(path))
        assert "scans" in second._db.table_names()


class TestScanLifecycle:
    def test_create_and_finish(self, store: ConsoleStore) -> None:
        store.create_scan(
            "scan-1",
            repo="encode/fastapi",
            pr_number=42,
            head_sha="abc123",
            trigger_type="webhook",
        )
        created = store.get_scan("scan-1")
        assert created is not None
        assert created["status"] == "running"
        assert created["pr_number"] == 42

        store.finish_scan(
            "scan-1",
            verdict="block",
            blocker_count=3,
            cve_count=19,
            overall_blocking=True,
        )
        finished = store.get_scan("scan-1")
        assert finished is not None
        assert finished["status"] == "completed"
        assert finished["verdict"] == "block"
        assert finished["cve_count"] == 19
        assert finished["duration_ms"] is not None

    def test_create_is_idempotent(self, store: ConsoleStore) -> None:
        store.create_scan("scan-1", repo="a/b")
        store.create_scan("scan-1", repo="a/c")
        assert store.get_scan("scan-1")["repo"] == "a/b"

    def test_list_scans_filters_and_paginates(self, store: ConsoleStore) -> None:
        now = datetime.now(UTC)
        for i in range(5):
            scan_id = f"scan-{i}"
            store.create_scan(
                scan_id,
                repo="a/b" if i % 2 == 0 else "c/d",
                started_at=(now - timedelta(hours=i)).isoformat(),
            )
            store.finish_scan(scan_id, verdict="block" if i < 2 else "pass")

        page = store.list_scans(page=1, page_size=2)
        assert page["total"] == 5
        assert len(page["items"]) == 2
        assert page["items"][0]["scan_id"] == "scan-0"

        blocked = store.list_scans(verdict="block")
        assert blocked["total"] == 2

        by_repo = store.list_scans(repo="c/d")
        assert by_repo["total"] == 2


class TestFindings:
    def test_replace_and_filter(self, store: ConsoleStore) -> None:
        store.create_scan("scan-1")
        rows = [
            {
                "finding_type": "vulnerability",
                "finding_id": "CVE-2024-0001",
                "cve_id": "CVE-2024-0001",
                "package_name": "fastapi",
                "severity": "critical",
                "verdict": "block",
                "blocking": True,
            },
            {
                "finding_type": "code_issue",
                "finding_id": "py-eval",
                "rule_id": "py-eval",
                "severity": "low",
                "verdict": "defer",
                "blocking": False,
            },
        ]
        assert store.replace_findings("scan-1", rows) == 2
        assert len(store.list_findings("scan-1")) == 2
        assert len(store.list_findings("scan-1", severity="critical")) == 1
        assert len(store.list_findings("scan-1", verdict="defer")) == 1

        breakdown = store.finding_breakdown("scan-1")
        assert breakdown == {"critical": 1, "high": 0, "medium": 0, "low": 1}

    def test_replace_is_idempotent(self, store: ConsoleStore) -> None:
        store.create_scan("scan-1")
        rows = [{"finding_type": "vulnerability", "finding_id": "CVE-1", "severity": "high"}]
        store.replace_findings("scan-1", rows)
        store.replace_findings("scan-1", rows)
        assert len(store.list_findings("scan-1")) == 1


class TestAgentEvents:
    def test_append_and_replay(self, store: ConsoleStore) -> None:
        store.create_scan("scan-1")
        first = store.add_event("scan-1", "security", "started", stage="security")
        second = store.add_event(
            "scan-1", "security", "finished", stage="security", duration_ms=1200,
            payload={"vulnerabilities": 19},
        )
        assert second > first

        events = store.list_events("scan-1")
        assert [e["status"] for e in events] == ["started", "finished"]
        assert events[1]["duration_ms"] == 1200
        assert events[1]["payload"] == {"vulnerabilities": 19}

        replay = store.list_events("scan-1", after_id=first)
        assert len(replay) == 1


class TestDashboard:
    def test_summary(self, store: ConsoleStore) -> None:
        store.create_scan("scan-1", repo="a/b")
        store.finish_scan("scan-1", verdict="block", blocker_count=2, cve_count=5)
        store.create_scan("scan-2", repo="a/b")
        store.finish_scan("scan-2", verdict="pass")

        summary = store.summary(days=1)
        assert summary["scans"] == 2
        assert summary["blocked"] == 1
        assert summary["passed"] == 1
        assert summary["cves"] == 5

    def test_severity_distribution_pads_empty_buckets(self, store: ConsoleStore) -> None:
        store.create_scan("scan-1")
        store.replace_findings(
            "scan-1",
            [
                {"finding_type": "vulnerability", "finding_id": "CVE-1", "severity": "critical"},
                {"finding_type": "vulnerability", "finding_id": "CVE-2", "severity": "critical"},
                {"finding_type": "code_issue", "finding_id": "r1", "severity": "low"},
            ],
        )
        dist = {d["severity"]: d["count"] for d in store.severity_distribution(days=30)}
        assert dist == {"critical": 2, "high": 0, "medium": 0, "low": 1}

    def test_trend_fills_missing_days(self, store: ConsoleStore) -> None:
        store.create_scan("scan-1")
        store.finish_scan("scan-1", verdict="block", cve_count=3)

        series = store.trend(days=7)
        assert len(series) == 7
        assert series[-1]["date"] == datetime.now(UTC).date().isoformat()
        assert series[-1]["scans"] == 1
        assert series[0]["scans"] == 0

    def test_top_packages_sorted_by_blockers(self, store: ConsoleStore) -> None:
        store.create_scan("scan-1")
        store.replace_findings(
            "scan-1",
            [
                {"finding_type": "vulnerability", "finding_id": "C1",
                 "package_name": "jinja2", "severity": "high", "verdict": "block"},
                {"finding_type": "vulnerability", "finding_id": "C2",
                 "package_name": "starlette", "severity": "low", "verdict": "defer"},
            ],
        )
        top = store.top_packages(days=30)
        assert top[0]["package_name"] == "jinja2"
        assert top[0]["blocked"] == 1


class TestRepos:
    def test_upsert_is_idempotent_and_updates(self, store: ConsoleStore) -> None:
        store.upsert_repo(repo_full_name="a/b", installation_id=1)
        store.upsert_repo(repo_full_name="a/b", installation_id=2, enabled=False)
        repos = store.list_repos()
        assert len(repos) == 1
        assert repos[0]["installation_id"] == 2
        assert repos[0]["enabled"] == 0
        assert store.list_repos(enabled_only=True) == []

    def test_set_enabled_unknown_repo(self, store: ConsoleStore) -> None:
        assert store.set_repo_enabled("nope/nope", False) is False


def test_severity_rank_order() -> None:
    assert severity_rank("critical") > severity_rank("high") > severity_rank("low")
