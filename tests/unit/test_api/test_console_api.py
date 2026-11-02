"""API tests for the console routers (scans / dashboard / audit / repos)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.api.deps import get_audit_logger, get_console_store
from src.api.app import create_app
from src.storage.audit_log import AuditLogger
from src.storage.console_db import ConsoleDatabase
from src.storage.console_store import ConsoleStore


@pytest.fixture()
def api(tmp_path):
    store = ConsoleStore(ConsoleDatabase(str(tmp_path / "console.db")))
    audit = AuditLogger(str(tmp_path / "audit.db"))

    app = create_app()
    app.dependency_overrides[get_console_store] = lambda: store
    app.dependency_overrides[get_audit_logger] = lambda: audit

    # No context manager: skip lifespan so the tests never touch Redis.
    return TestClient(app), store, audit


def _seed_scan(store: ConsoleStore, scan_id: str = "scan-1") -> str:
    store.create_scan(
        scan_id,
        repo="encode/fastapi",
        pr_number=42,
        head_sha="deadbeef",
        trigger_type="webhook",
    )
    store.add_event(scan_id, "security", "started", stage="security")
    store.add_event(scan_id, "security", "finished", stage="security", duration_ms=1200)
    store.replace_findings(
        scan_id,
        [
            {
                "finding_type": "vulnerability",
                "finding_id": "CVE-2024-0001",
                "cve_id": "CVE-2024-0001",
                "package_name": "jinja2",
                "severity": "high",
                "verdict": "block",
                "blocking": True,
            },
            {
                "finding_type": "code_issue",
                "finding_id": "py-eval",
                "rule_id": "py-eval",
                "severity": "medium",
                "verdict": "defer",
            },
        ],
    )
    store.finish_scan(scan_id, verdict="block", blocker_count=1, cve_count=1)
    store.add_event(
        scan_id, "scan", "finished", stage="scan", payload={"verdict": "block"}
    )
    return scan_id


class TestScanEndpoints:
    def test_empty_list(self, api) -> None:
        client, _, _ = api
        response = client.get("/api/v1/scans")
        assert response.status_code == 200
        assert response.json() == {"items": [], "total": 0, "page": 1, "page_size": 20}

    def test_list_and_filter(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        body = client.get("/api/v1/scans").json()
        assert body["total"] == 1
        assert body["items"][0]["repo"] == "encode/fastapi"
        assert body["items"][0]["verdict"] == "block"

        assert client.get("/api/v1/scans", params={"repo": "other/repo"}).json()["total"] == 0
        assert client.get("/api/v1/scans", params={"verdict": "block"}).json()["total"] == 1

    def test_detail_includes_timeline_and_findings(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        body = client.get("/api/v1/scans/scan-1").json()
        assert body["scan_id"] == "scan-1"
        assert body["severity_breakdown"]["high"] == 1
        assert len(body["findings"]) == 2
        assert [e["agent"] for e in body["timeline"]][0] == "security"

    def test_detail_404(self, api) -> None:
        client, _, _ = api
        assert client.get("/api/v1/scans/nope").status_code == 404

    def test_findings_filters(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        body = client.get("/api/v1/scans/scan-1/findings", params={"severity": "high"}).json()
        assert len(body) == 1
        assert body[0]["cve_id"] == "CVE-2024-0001"

    def test_report_missing(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        assert client.get("/api/v1/scans/scan-1/report").status_code == 404


class TestStream:
    def test_finished_scan_closes_stream(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        with client.stream("GET", "/api/v1/scans/scan-1/stream") as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            body = "".join(response.iter_text())
        assert "agent.finished" in body
        assert "scan.finished" in body

    def test_stream_404_for_unknown_scan(self, api) -> None:
        client, _, _ = api
        assert client.get("/api/v1/scans/nope/stream").status_code == 404

    def test_resume_from_last_event_id(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        with client.stream(
            "GET", "/api/v1/scans/scan-1/stream", params={"last_event_id": 3}
        ) as response:
            body = "".join(response.iter_text())
        # Only the persisted terminal event survives the resume point.
        assert "agent.finished" not in body
        assert "scan.finished" in body


class TestDashboard:
    def test_summary(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        body = client.get("/api/v1/dashboard/summary").json()
        assert body["scans"] == 1
        assert body["blocked"] == 1
        assert body["cves"] == 1

    def test_severity_and_trend(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        severity = client.get("/api/v1/dashboard/severity").json()["items"]
        assert {b["severity"]: b["count"] for b in severity}["high"] == 1

        trend = client.get("/api/v1/dashboard/trend", params={"days": 3}).json()["items"]
        assert len(trend) == 3
        assert trend[-1]["scans"] == 1

    def test_top_packages(self, api) -> None:
        client, store, _ = api
        _seed_scan(store)
        items = client.get("/api/v1/dashboard/top-packages").json()["items"]
        assert items[0]["package_name"] == "jinja2"
        assert items[0]["blocked"] == 1


class TestAudit:
    def test_list_and_verify(self, api) -> None:
        client, _, audit = api
        audit.log(action="scan_started", operator="system", detail={"scan_id": "s1"})
        audit.log(action="verdict_made", operator="system", detail={"verdict": "block"})

        body = client.get("/api/v1/audit").json()
        assert body["count"] == 2
        assert body["items"][0]["action"] == "verdict_made"

        filtered = client.get("/api/v1/audit", params={"action": "scan_started"}).json()
        assert filtered["count"] == 1

        integrity = client.get("/api/v1/audit/verify").json()
        assert integrity["valid"] is True
        assert integrity["total_rows"] == 2

    def test_tampering_is_detected(self, api) -> None:
        client, _, audit = api
        audit.log(action="scan_started", operator="system", detail={"scan_id": "s1"})

        import sqlite3

        conn = sqlite3.connect(audit._db_path)
        conn.execute("UPDATE audit_log SET detail = '{\"scan_id\": \"tampered\"}' WHERE id = 1")
        conn.commit()
        conn.close()

        integrity = client.get("/api/v1/audit/verify").json()
        assert integrity["valid"] is False
        assert integrity["bad_rows"]


class TestRepos:
    def test_authorize_list_and_toggle(self, api) -> None:
        client, _, _ = api
        created = client.post(
            "/api/v1/repos",
            json={"repo_full_name": "encode/fastapi", "installation_id": 7},
        )
        assert created.status_code == 201
        assert created.json()["enabled"] in (True, 1)

        listed = client.get("/api/v1/repos").json()
        assert listed["count"] == 1

        toggled = client.patch(
            "/api/v1/repos",
            json={"repo_full_name": "encode/fastapi", "enabled": False},
        )
        assert toggled.status_code == 200
        assert bool(toggled.json()["enabled"]) is False

        assert (
            client.patch(
                "/api/v1/repos", json={"repo_full_name": "nope/nope", "enabled": False}
            ).status_code
            == 404
        )

    def test_install_url_without_credentials(self, api, monkeypatch) -> None:
        monkeypatch.delenv("GITHUB_APP_ID", raising=False)
        monkeypatch.delenv("GITHUB_APP_SLUG", raising=False)
        client, _, _ = api
        body = client.get("/api/v1/repos/install/url").json()
        assert body["configured"] is False
        assert body["url"] == ""

    def test_install_callback_accepts_explicit_repos(self, api) -> None:
        client, store, audit = api
        body = client.post(
            "/api/v1/repos/install/callback",
            json={
                "installation_id": 99,
                "repos": [{"full_name": "acme/api", "id": 123}],
            },
        ).json()
        assert body["count"] == 1
        assert store.get_repo("acme/api")["installation_id"] == 99
        assert audit.count(action="repo_authorized") == 1
