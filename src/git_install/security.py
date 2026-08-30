"""Non-executing security analysis for discovered Python packages."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from git_install.command import CommandError, run

SECURITY_SCAN_EXCLUDES = ".git,.venv,venv,node_modules,tests,test,docs,examples,benchmarks,benchmark"


def _bandit(root: Path) -> str:
    """Return a compact Bandit summary; findings are signals, never a safety verdict."""
    scan_root = root / "src" if (root / "src").is_dir() else root
    try:
        result = run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                str(scan_root),
                "-x",
                SECURITY_SCAN_EXCLUDES,
                "-f",
                "json",
                "--exit-zero",
                "-q",
            ],
            check=False,
            timeout=30,
        )
    except CommandError as error:
        return f"Live security scan: unavailable ({error})"
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "Bandit failed"
        return f"Live security scan: unavailable ({detail.splitlines()[0]})"
    try:
        findings = json.loads(result.stdout).get("results", [])
    except (json.JSONDecodeError, AttributeError):
        return "Live security scan: unavailable (Bandit returned invalid JSON)"
    counts = {
        severity: sum(item.get("issue_severity") == severity for item in findings) for severity in ("HIGH", "MEDIUM")
    }
    return f"Live security scan: {counts['HIGH']} high · {counts['MEDIUM']} medium"


def scan_python(root: Path) -> str:
    """Run the built-in non-executing Python security scanner."""
    return _bandit(root)


def findings(root: Path) -> list[tuple[str, str, str, int, str]]:
    scan_root = root / "src" if (root / "src").is_dir() else root
    try:
        result = run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-r",
                str(scan_root),
                "-x",
                SECURITY_SCAN_EXCLUDES,
                "-f",
                "json",
                "--exit-zero",
                "-q",
            ],
            check=False,
            timeout=30,
        )
        data = json.loads(result.stdout)
    except (CommandError, json.JSONDecodeError, OSError):
        return []
    return [
        (
            item.get("issue_severity", "UNKNOWN"),
            item.get("test_id", "—"),
            item.get("filename", "—"),
            item.get("line_number", 0),
            item.get("issue_text", ""),
        )
        for item in data.get("results", [])
        if item.get("issue_severity") in {"HIGH", "MEDIUM"}
    ]
