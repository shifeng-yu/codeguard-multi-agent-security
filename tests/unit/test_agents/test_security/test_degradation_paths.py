"""Regression tests for two degradation defects found during the console work.

1. A missing Semgrep binary raised ``FileNotFoundError`` out of the scanner,
   which turned a degraded code scan into a failed security Agent.
2. The degraded CVE path fed raw ``cve_cache`` rows into ``Vulnerability``,
   which failed Pydantic validation and again produced an empty result.
"""

from __future__ import annotations

import pytest

from src.agents.security.agent import _cache_row_to_vuln
from src.agents.security.code_scanner import CodeScanner
from src.agents.security.cve_scanner import _normalize_cvss, _normalize_severity
from src.agents.security.models import Vulnerability
from src.core.models import Severity


class TestSeverityNormalization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("critical", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("Moderate", Severity.MEDIUM),
            ("MODERATE", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("important", Severity.HIGH),
            ("negligible", Severity.LOW),
            (None, Severity.MEDIUM),
            ("garbage", Severity.MEDIUM),
        ],
    )
    def test_aliases(self, raw, expected) -> None:
        assert _normalize_severity(raw) is expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [(7.5, 7.5), ("9.1", 9.1), (None, None), ("", None), ("n/a", None), (12.0, None)],
    )
    def test_cvss(self, raw, expected) -> None:
        assert _normalize_cvss(raw) == expected


class TestDegradedCacheRowMapping:
    def test_raw_cache_row_becomes_valid_vulnerability(self) -> None:
        row = {
            "id": 12,
            "package_name": "transformers",
            "version": "==4.40.0",
            "ecosystem": "pypi",
            "cve_id": "CVE-2024-1234",
            "severity": "MODERATE",
            "cvss_score": None,
            "fixed_version": "4.41.0",
            "summary": "deserialization issue",
            "evidence_source": "OSV",
            "evidence_url": "https://osv.dev/CVE-2024-1234",
            "raw_json": "{}",
        }

        mapped = _cache_row_to_vuln(row, "transformers", "==4.40.0")
        model = Vulnerability(**mapped)  # must not raise

        assert model.cve_id == "CVE-2024-1234"
        assert model.affected_version == "==4.40.0"
        assert model.severity == "medium"
        assert model.fix_available is True
        assert model.blocking is False  # medium on a direct dep

    def test_high_severity_is_blocking(self) -> None:
        row = {"cve_id": "CVE-1", "severity": "HIGH", "fixed_version": None}
        model = Vulnerability(**_cache_row_to_vuln(row, "jinja2", "==2.11.0"))
        assert model.severity == "high"
        assert model.blocking is True
        assert model.fix_available is False

    def test_missing_severity_defaults_instead_of_failing(self) -> None:
        model = Vulnerability(**_cache_row_to_vuln({"cve_id": "CVE-2"}, "x", "1.0"))
        assert model.severity == "medium"


class TestSemgrepLocator:
    """A correct install must be found even when PATH does not include it."""

    def test_explicit_override_wins(self, monkeypatch, tmp_path) -> None:
        from src.agents.security import code_scanner

        fake = tmp_path / "semgrep-custom"
        fake.write_text("", encoding="utf-8")
        monkeypatch.setenv("CODEGUARD_SEMGREP_BIN", str(fake))
        monkeypatch.setattr(code_scanner.shutil, "which", lambda name: "/usr/bin/semgrep")

        assert code_scanner._locate_semgrep() == str(fake)

    def test_finds_console_script_in_scripts_subdir(self, monkeypatch, tmp_path) -> None:
        from src.agents.security import code_scanner

        fake_python = tmp_path / "python.exe"
        fake_python.write_text("", encoding="utf-8")
        scripts = tmp_path / "Scripts"
        scripts.mkdir()
        exe = scripts / ("semgrep.exe" if __import__("os").name == "nt" else "semgrep")
        exe.write_text("", encoding="utf-8")

        monkeypatch.setattr(code_scanner.sys, "executable", str(fake_python))
        monkeypatch.setattr(code_scanner.shutil, "which", lambda name: None)

        assert code_scanner._locate_semgrep() == str(exe)

    def test_falls_back_to_bare_name_when_absent(self, monkeypatch, tmp_path) -> None:
        from src.agents.security import code_scanner

        fake_python = tmp_path / "python.exe"
        fake_python.write_text("", encoding="utf-8")
        monkeypatch.setattr(code_scanner.sys, "executable", str(fake_python))
        monkeypatch.setattr(code_scanner.shutil, "which", lambda name: None)

        assert code_scanner._locate_semgrep() == "semgrep"


class TestMissingSemgrepDegrades:
    @pytest.mark.asyncio
    async def test_scan_returns_degraded_when_binary_missing(self, monkeypatch, tmp_path) -> None:
        from src.agents.security import code_scanner

        monkeypatch.setattr(code_scanner, "_locate_semgrep", lambda: "")
        monkeypatch.setattr(code_scanner, "HAS_SEMGREP_SDK", False)

        target = tmp_path / "app.py"
        target.write_text("print('x')\n", encoding="utf-8")

        scanner = CodeScanner()
        issues, degraded, reason = await scanner.scan(
            str(tmp_path),
            [{"path": "app.py"}],
            language="python",
        )

        assert issues == []
        assert degraded is True
        assert "not installed" in reason

    @pytest.mark.asyncio
    async def test_unexpected_subprocess_error_degrades(self, monkeypatch, tmp_path) -> None:
        from src.agents.security import code_scanner

        monkeypatch.setattr(code_scanner, "_locate_semgrep", lambda: "semgrep")

        async def boom(*args, **kwargs):
            raise FileNotFoundError("spawn failed")

        scanner = CodeScanner()
        monkeypatch.setattr(scanner, "_scan_with_cli", boom)

        issues, degraded, reason = await scanner.scan(
            str(tmp_path), [{"path": "app.py"}], language="python"
        )
        assert issues == []
        assert degraded is True
        assert "spawn failed" in reason
