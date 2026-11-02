"""Semgrep-based static code analyzer.

Runs Semgrep rules against source code. Zero LLM.
Supports: Python (MVP), extensible to JS/TS/Java.

Deployment modes:
- Python SDK (preferred): import semgrep directly.
- Subprocess fallback: semgrep CLI via sandbox.

Confidence levels:
- high: Well-tested rules (e.g., hardcoded secrets).
- medium: Community rules with reasonable accuracy.
- low: Experimental rules; findings are informational only, not blocking.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from src.utils.sandbox import run_tool_safely

# Check Semgrep availability
try:
    import semgrep  # noqa: F401
    HAS_SEMGREP_SDK = True
except ImportError:
    HAS_SEMGREP_SDK = False


def _semgrep_env(binary: str) -> dict[str, str] | None:
    """Give a ``pip install --target`` Semgrep its own package root.

    Such an install has no entry in site-packages: the launcher is a stub that
    imports ``semgrep`` from ``PYTHONPATH``. Only inject when the sibling package
    directory really exists, so normal installs are unaffected.
    """
    try:
        binary_path = Path(binary).resolve()
        root = binary_path.parent.parent
    except OSError:
        return None
    if not (root / "semgrep").is_dir():
        return None

    # The launcher re-executes `pysemgrep` from its own bin directory, and the
    # sandbox builds a minimal PATH, so both PYTHONPATH and PATH must be given.
    existing_pythonpath = os.environ.get("PYTHONPATH", "")
    existing_path = os.environ.get("PATH", "")
    return {
        "PYTHONPATH": str(root) + (os.pathsep + existing_pythonpath if existing_pythonpath else ""),
        "PATH": str(binary_path.parent) + (os.pathsep + existing_path if existing_path else ""),
    }


def _locate_semgrep() -> str:
    """Locate the semgrep executable without relying on the ambient PATH.

    Fallback order:
    1. ``CODEGUARD_SEMGREP_BIN`` (explicit override for custom installs).
    2. `semgrep` found on PATH (normal installs).
    3. The interpreter's own directory (virtualenv/conda env root on POSIX).
    4. The interpreter's ``Scripts`` (Windows venv) or ``bin`` subdirectory —
       conda base installs put console scripts in ``<prefix>/Scripts``, while
       ``sys.executable`` lives in ``<prefix>``. Missing this made a correct
       install look absent and silently degraded every code scan.
    """
    override = os.getenv("CODEGUARD_SEMGREP_BIN", "").strip()
    if override and Path(override).exists():
        return override

    found = shutil.which("semgrep")
    if found:
        return found

    exe = "semgrep.exe" if os.name == "nt" else "semgrep"
    base = Path(sys.executable).resolve().parent
    subdir = "Scripts" if os.name == "nt" else "bin"

    for candidate in (base / exe, base / subdir / exe):
        if candidate.exists():
            return str(candidate)

    return "semgrep"


# ------------------------------------------------------------------
# Confidence-based rule classification
# ------------------------------------------------------------------

HIGH_CONFIDENCE_RULES = {
    "generic.secrets.security.detected-private-key",
    "generic.secrets.security.detected-aws-access-key",
    "python.lang.security.audit.detect-sql-string",
    "python.lang.security.audit.hardcoded-tmp-file",
    # Custom rules under config/semgrep/ (deterministic patterns)
    "config.semgrep.python-hardcoded-secret",
    "config.semgrep.python-sql-string-concat",
    "config.semgrep.python-insecure-hmac-comparison",
}

LOW_CONFIDENCE_RULES: set[str] = set()  # Populated from experimental rulesets

# Rules that are always blocking regardless of severity
ALWAYS_BLOCKING_RULES = {
    "generic.secrets.security.detected-private-key",
    "generic.secrets.security.detected-aws-access-key",
    "config.semgrep.python-hardcoded-secret",
    "config.semgrep.python-sql-string-concat",
}


class CodeScanner:
    """Static code analysis via Semgrep rule engine.

    Usage:
        scanner = CodeScanner()
        issues, degraded, reason = await scanner.scan(
            repo_path="/tmp/repo",
            changed_files=[{"path": "main.py"}],
            language="python",
        )
    """

    def __init__(self, config_dir: str | None = None) -> None:
        self._config_dir = Path(config_dir or "config/semgrep")
        self._use_sdk = HAS_SEMGREP_SDK

    async def scan(
        self,
        repo_path: str | Path,
        changed_files: list[dict[str, Any]],
        *,
        language: str = "python",
        file_blacklist: list[str] | None = None,
    ) -> tuple[list[dict[str, Any]], bool, str]:
        """Run Semgrep scan on changed files.

        Args:
            repo_path: Repository root directory.
            changed_files: List of file metadata dicts.
            language: Programming language (only Python in MVP).
            file_blacklist: Path patterns to skip.

        Returns:
            (code_issues, degraded, degraded_reason) tuple.
        """
        blacklist = file_blacklist or ["test/", "tests/", "docs/"]

        # Filter to scan-eligible files
        scan_files = [
            f for f in changed_files
            if self._should_scan(f.get("path", ""), language, blacklist)
        ]

        if not scan_files:
            return [], False, ""

        # Run Semgrep
        try:
            if self._use_sdk:
                issues, degraded, reason = await self._scan_with_sdk(
                    repo_path, scan_files
                )
            else:
                issues, degraded, reason = await self._scan_with_cli(
                    repo_path, scan_files
                )
        except Exception as exc:  # noqa: BLE001 - a scan failure must degrade, not raise
            return [], True, f"Semgrep invocation failed: {str(exc)[:200]}"

        # Classify confidence and blocking
        for issue in issues:
            rule_id = issue.get("rule_id", "")
            if rule_id in HIGH_CONFIDENCE_RULES:
                issue["confidence"] = "high"
            elif rule_id in LOW_CONFIDENCE_RULES:
                issue["confidence"] = "low"
            else:
                issue["confidence"] = "medium"

            # Blocking logic
            severity = issue.get("severity", "medium")
            confidence = issue.get("confidence", "medium")
            rule_id = issue.get("rule_id", "")

            if (
                rule_id in ALWAYS_BLOCKING_RULES
                or severity in ("critical", "high") and confidence != "low"
            ):
                issue["blocking"] = True
            else:
                issue["blocking"] = False

        return issues, degraded, reason

    # ------------------------------------------------------------------
    # SDK mode (preferred)
    # ------------------------------------------------------------------

    async def _scan_with_sdk(
        self, repo_path: str | Path, files: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], bool, str]:
        """Scan using the Semgrep Python SDK."""
        try:
            # The SDK can be called programmatically.
            # For MVP, we use the CLI fallback which is more widely tested.
            # When semgrep SDK is stable, replace this block.
            return await self._scan_with_cli(repo_path, files)
        except Exception:
            degraded = True
            reason = "Semgrep SDK failed; results may be incomplete"
            return [], degraded, reason

    # ------------------------------------------------------------------
    # CLI fallback
    # ------------------------------------------------------------------

    async def _scan_with_cli(
        self, repo_path: str | Path, files: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], bool, str]:
        """Scan using `semgrep` CLI via sandboxed subprocess."""
        repo = Path(repo_path)
        targets = [str(repo / f["path"]) for f in files if (repo / f["path"]).exists()]

        if not targets:
            return [], False, ""

        binary = _locate_semgrep()
        tool_env = _semgrep_env(binary)

        # Use local custom rules (offline, deterministic output).
        # NOTE: `--config auto` is intentionally avoided: it downloads registry
        # rules at scan time (network-dependent) and conflicts with `--metrics off`
        # on semgrep >= 1.174 ("Cannot create auto config when metrics are off").
        args = [
            "scan",
            "--config", str(self._config_dir),
            "--json",                   # Machine-readable output
            "--no-git-ignore",          # Don't skip .gitignored files
            "--metrics", "off",         # No telemetry
            "--quiet",
        ] + targets

        # A missing binary is a deployment condition, not a crash: degrade and
        # let the rest of the security chain (CVE scan) still produce a verdict.
        try:
            rc, stdout, stderr = run_tool_safely(binary, args, timeout=60, env=tool_env)
        except OSError as exc:
            # Covers FileNotFoundError / PermissionError / WinError 87 (a bare
            # name that resolves to nothing on Windows).
            return [], True, f"Semgrep CLI not installed or not executable: {exc}"

        if rc != 0 and not stdout:
            # rc == -1 means the sandbox could not even start the process
            # (missing binary / bad executable); report it as a deployment
            # problem rather than a scan failure.
            if rc == -1:
                return [], True, f"Semgrep CLI not installed or failed to start: {stderr[:200]}"
            # Semgrep returned non-zero with no output -> real failure
            degraded = True
            reason = f"Semgrep execution failed (rc={rc}): {stderr[:200]}"
            return [], degraded, reason

        try:
            raw = json.loads(stdout) if stdout else {"results": []}
        except json.JSONDecodeError:
            degraded = True
            reason = "Semgrep output was not valid JSON"
            return [], degraded, reason

        issues = self._parse_semgrep_output(raw)
        self._fix_snippets_from_source(issues)
        return issues, False, ""

    @staticmethod
    def _fix_snippets_from_source(issues: list[dict[str, Any]]) -> None:
        """Overwrite code_snippet with the actual source line.

        Semgrep's `extra.lines` can be unreliable (multi-line patterns /
        registry metadata). Reading the real line from disk keeps the report
        truthful: the snippet always shows the exact code that triggered.
        """
        for issue in issues:
            fp = issue.get("file_path", "")
            line = issue.get("line_number")
            if not fp or not line:
                continue
            try:
                with open(fp, encoding="utf-8", errors="replace") as f:
                    src_lines = f.readlines()
                if 1 <= int(line) <= len(src_lines):
                    snippet = src_lines[int(line) - 1].strip()
                    if snippet:
                        issue["code_snippet"] = snippet[:200]
            except OSError:
                continue

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_semgrep_output(self, raw: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse Semgrep JSON output into CodeIssue-like dicts."""
        issues = []
        for result in raw.get("results", []):
            path = result.get("path", "")
            check_id = result.get("check_id", "")
            extra = result.get("extra", {})
            severity = extra.get("severity", "medium").lower()
            # Semgrep severity scale is ERROR/WARNING/INFO; map to CodeGuard's
            # critical/high/medium so ERROR findings actually block.
            severity = {"error": "high", "warning": "medium", "info": "low"}.get(
                severity, severity
            )
            message = extra.get("message", "")
            fix_lines = extra.get("fix", "")
            start = result.get("start", {})
            line_number = start.get("line", 0)

            # Extract code snippet from lines if available
            lines = extra.get("lines", "")
            snippet = lines.strip()[:200] if lines else ""

            issues.append({
                "rule_id": check_id,
                "severity": severity,
                "confidence": "medium",  # Overridden by classifier later
                "file_path": path,
                "line_number": line_number,
                "code_snippet": snippet,
                "message": message.strip()[:500] if message else "",
                "fix_suggestion": fix_lines.strip()[:500] if fix_lines else "",
                "blocking": False,  # Overridden by classifier later
            })

        return issues

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    # Language -> file extension mapping (extensible via config)
    LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
        "python": [".py"],
        "javascript": [".js", ".jsx", ".mjs"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "go": [".go"],
        "rust": [".rs"],
        "ruby": [".rb"],
        "php": [".php"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".hpp", ".cc", ".cxx"],
    }

    @classmethod
    def _should_scan(
        cls, file_path: str, language: str, blacklist: list[str]
    ) -> bool:
        """Determine if a file should be scanned by Semgrep.

        Language filtering is driven by LANGUAGE_EXTENSIONS config,
        not hardcoded per-language checks. Add new languages by
        extending the dict — no code changes needed.
        """
        # Language -> extension lookup
        valid_extensions = cls.LANGUAGE_EXTENSIONS.get(language, [])
        if valid_extensions:
            import os
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in valid_extensions:
                return False

        # Blacklist filter: return False if any blacklisted path matches
        return all(pattern.rstrip("/") not in file_path for pattern in blacklist)
