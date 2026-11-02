"""Tests for the best-effort scan telemetry recorder."""

from __future__ import annotations

import pytest

from src.monitoring import scan_recorder
from src.storage.console_db import ConsoleDatabase
from src.storage.console_store import ConsoleStore

REPORT = {
    "summary": {"blocking_count": 1, "warning_count": 1, "pass_count": 0},
    "security": {
        "security_report": {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-0001",
                    "package_name": "fastapi",
                    "affected_version": "0.100.0",
                    "fixed_version": "0.110.0",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "dependency_type": "direct",
                    "file_location": "requirements.txt",
                    "description": "prototype pollution",
                    "evidence_source": "OSV",
                    "evidence_url": "https://osv.dev/CVE-2024-0001",
                    "blocking": True,
                }
            ],
            "code_issues": [
                {
                    "rule_id": "py-eval",
                    "severity": "medium",
                    "file_path": "app/main.py",
                    "line_number": 12,
                    "message": "use of eval",
                    "blocking": False,
                }
            ],
        },
        "conflict_decision": {
            "overall_blocking": True,
            "human_intervention_required": False,
            "decisions": [
                {"finding_id": "CVE-2024-0001", "verdict": "block", "appealable": True},
                {"finding_id": "py-eval", "verdict": "defer", "appealable": False},
            ],
        },
    },
    "degraded": False,
    "degraded_reasons": [],
}


@pytest.fixture()
def rec(tmp_path, monkeypatch):
    store = ConsoleStore(ConsoleDatabase(str(tmp_path / "console.db")))
    scan_recorder.reset_store(store)
    published: list[dict] = []
    monkeypatch.setattr(
        scan_recorder,
        "_publish",
        lambda scan_id, event: published.append({"scan_id": scan_id, **event}),
    )
    # Audit writes go to the real DB path; keep the suite side-effect free.
    monkeypatch.setattr(scan_recorder, "_audit", lambda *args, **kwargs: None)
    yield scan_recorder, store, published
    scan_recorder.reset_store(None)


class TestScanLifecycle:
    def test_scan_started_creates_row_and_event(self, rec) -> None:
        module, store, published = rec
        module.scan_started(
            "scan-1",
            repo_url="https://github.com/encode/fastapi.git",
            pr_info={"pr_number": 7, "head_sha": "deadbeef"},
        )
        row = store.get_scan("scan-1")
        assert row["repo"] == "encode/fastapi"
        assert row["pr_number"] == 7
        assert row["trigger_type"] == "webhook"
        assert published[0]["event"] == "scan.started"

    def test_manual_trigger_when_no_pr_info(self, rec) -> None:
        module, store, _ = rec
        module.scan_started("scan-1", repo_url="git@github.com:a/b.git")
        assert store.get_scan("scan-1")["trigger_type"] == "manual"
        assert store.get_scan("scan-1")["repo"] == "a/b"

    def test_scan_finished_persists_findings_and_verdict(self, rec) -> None:
        module, store, published = rec
        module.scan_started("scan-1", repo_url="https://github.com/encode/fastapi")
        module.scan_finished("scan-1", REPORT)

        scan = store.get_scan("scan-1")
        assert scan["status"] == "completed"
        assert scan["verdict"] == "block"
        assert scan["cve_count"] == 1
        assert scan["code_issue_count"] == 1
        assert scan["blocker_count"] == 1
        assert scan["overall_blocking"] == 1

        findings = store.list_findings("scan-1")
        assert len(findings) == 2
        verdicts = {f["finding_id"]: f["verdict"] for f in findings}
        assert verdicts == {"CVE-2024-0001": "block", "py-eval": "defer"}
        assert findings[0]["blocking"] == 1

        assert published[-1]["event"] == "scan.finished"
        assert published[-1]["verdict"] == "block"

    def test_human_review_verdict_wins_over_block(self, rec) -> None:
        module, store, _ = rec
        module.scan_started("scan-1")
        report = {
            **REPORT,
            "security": {
                **REPORT["security"],
                "conflict_decision": {
                    **REPORT["security"]["conflict_decision"],
                    "human_intervention_required": True,
                },
            },
        }
        module.scan_finished("scan-1", report)
        assert store.get_scan("scan-1")["verdict"] == "human_review"

    def test_scan_finished_without_report_still_closes_row(self, rec) -> None:
        module, store, _ = rec
        module.scan_started("scan-1")
        module.scan_finished("scan-1", None)
        assert store.get_scan("scan-1")["verdict"] == "pass"

    def test_scan_failed_marks_status(self, rec) -> None:
        module, store, _ = rec
        module.scan_started("scan-1")
        module.scan_failed("scan-1", error="boom")
        scan = store.get_scan("scan-1")
        assert scan["status"] == "failed"
        assert any(e["status"] == "failed" for e in store.list_events("scan-1"))


class TestAgentEvents:
    def test_agent_lifecycle_is_ordered(self, rec) -> None:
        module, store, published = rec
        module.scan_started("scan-1")
        module.agent_started("scan-1", "security", stage="security")
        module.agent_finished("scan-1", "security", duration_ms=1234.6, stage="security")

        events = store.list_events("scan-1")
        assert [e["status"] for e in events] == ["started", "finished"]
        assert events[1]["duration_ms"] == 1234
        assert [p["event"] for p in published] == [
            "scan.started",
            "agent.started",
            "agent.finished",
        ]

    def test_degraded_agent_marks_status(self, rec) -> None:
        module, store, _ = rec
        module.scan_started("scan-1")
        module.agent_finished("scan-1", "migration", degraded=True)
        assert store.list_events("scan-1")[-1]["status"] == "degraded"

    def test_skipped_agent(self, rec) -> None:
        module, store, _ = rec
        module.scan_started("scan-1")
        module.agent_skipped("scan-1", "migration", reason="no target")
        event = store.list_events("scan-1")[-1]
        assert event["status"] == "skipped"
        assert event["payload"]["reason"] == "no target"


class TestResilience:
    def test_recorder_swallows_store_failures(self, monkeypatch) -> None:
        class Broken:
            def __getattr__(self, name):
                def boom(*args, **kwargs):
                    raise RuntimeError("db is gone")
                return boom

        scan_recorder.reset_store(Broken())
        monkeypatch.setattr(scan_recorder, "_publish", lambda *a, **k: None)
        monkeypatch.setattr(scan_recorder, "_audit", lambda *a, **k: None)
        # None of these may raise.
        scan_recorder.scan_started("scan-1")
        scan_recorder.agent_started("scan-1", "security")
        scan_recorder.agent_finished("scan-1", "security", duration_ms=1)
        scan_recorder.agent_skipped("scan-1", "migration")
        scan_recorder.scan_finished("scan-1", REPORT)
        scan_recorder.scan_failed("scan-1", error="x")
        scan_recorder.reset_store(None)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://github.com/encode/fastapi.git", "encode/fastapi"),
        ("https://github.com/encode/fastapi/", "encode/fastapi"),
        ("git@github.com:encode/fastapi.git", "encode/fastapi"),
        ("encode/fastapi", "encode/fastapi"),
        ("", ""),
    ],
)
def test_normalize_repo(raw: str, expected: str) -> None:
    assert scan_recorder._normalize_repo(raw) == expected
