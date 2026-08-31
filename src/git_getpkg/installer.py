from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from git_getpkg.command import run
from git_getpkg.models import Package


@dataclass(frozen=True)
class DependencyAudit:
    findings: tuple[tuple[str, str, str, tuple[str, ...]], ...]
    error: str | None = None


def environment_path(package: Package, commit: str | None, source_identity: str) -> Path:
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", package.name).strip("-") or "package"
    identity = f"{source_identity}\0{commit or 'working-tree'}\0{package.relative_path}"
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:12]
    return data_home / "git-getpkg" / "environments" / f"{safe_name}-{suffix}"


def pipx_install_command(package: Package) -> list[str]:
    """Build the bundled-pipx command for a project with declared console scripts."""
    return [sys.executable, "-m", "pipx", "install", "--python", sys.executable, str(package.directory)]


def install_python_application(package: Package, *, dry_run: bool) -> list[list[str]]:
    """Install a Python CLI project through the pipx bundled with git-getpkg."""
    command = pipx_install_command(package)
    if not dry_run:
        run(command)
    return [command]


def validate_python_application(package: Package) -> str | None:
    """Run pip's dependency check inside the package's pipx-managed environment."""
    result = run(
        [sys.executable, "-m", "pipx", "runpip", package.name, "check"],
        check=False,
    )
    if result.returncode == 0:
        return None
    return result.stdout.strip() or result.stderr.strip() or "pipx pip check failed"


def ensure_pipx_path() -> None:
    """Let pipx configure the application directory for the current user's shell."""
    run([sys.executable, "-m", "pipx", "ensurepath"])


def expose_python_application(package: Package) -> None:
    run([sys.executable, "-m", "pipx", "expose", package.name])


def remove_python_application(package: Package) -> None:
    run([sys.executable, "-m", "pipx", "uninstall", package.name], check=False)


def remove_environment(environment: Path) -> None:
    shutil.rmtree(environment, ignore_errors=True)


def _site_packages(python: Path) -> Path:
    result = run([str(python), "-c", "import site; print(site.getsitepackages()[0])"])
    return Path(result.stdout.strip())


def audit_python(environment: Path) -> DependencyAudit:
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return _audit_path(_site_packages(python))


def audit_python_application(package: Package) -> DependencyAudit:
    result = run(
        [sys.executable, "-m", "pipx", "runpip", package.name, "show", "pip"],
        check=False,
    )
    location = next(
        (line.partition(":")[2].strip() for line in result.stdout.splitlines() if line.startswith("Location:")),
        None,
    )
    if result.returncode or not location:
        return DependencyAudit((), result.stderr.strip() or "Could not locate pipx environment for dependency audit")
    return _audit_path(Path(location))


def _audit_path(path: Path) -> DependencyAudit:
    result = run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "--path",
            str(path),
            "--vulnerability-service",
            "osv",
            "--format",
            "json",
            "--progress-spinner",
            "off",
        ],
        check=False,
        timeout=60,
    )
    if result.returncode not in {0, 1}:
        return DependencyAudit((), result.stderr.strip() or result.stdout.strip() or "Dependency audit failed")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return DependencyAudit((), "Dependency audit returned unreadable results")
    packages = payload if isinstance(payload, list) else payload.get("dependencies", [])
    if not isinstance(packages, list):
        return DependencyAudit((), "Dependency audit returned an unsupported result format")
    findings = tuple(
        (package["name"], package["version"], vulnerability["id"], tuple(vulnerability.get("fix_versions", [])))
        for package in packages
        if isinstance(package, dict)
        for vulnerability in package.get("vulns", [])
        if isinstance(vulnerability, dict)
    )
    return DependencyAudit(findings)


def install_python(
    package: Package, commit: str | None, source_identity: str, *, dry_run: bool
) -> tuple[Path, list[list[str]]]:
    target = environment_path(package, commit, source_identity)
    python = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    commands = [
        [sys.executable, "-m", "venv", str(target)],
        [str(python), "-m", "pip", "install", str(package.directory)],
    ]
    if not dry_run:
        if not python.exists():
            run(commands[0])
        run(commands[1])
    return target, commands


def validate_python(environment: Path) -> str | None:
    """Return a dependency-consistency error after installation, if any."""
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    result = run([str(python), "-m", "pip", "check"], check=False)
    return None if result.returncode == 0 else (result.stdout.strip() or result.stderr.strip() or "pip check failed")


def high_risk_pip_signals() -> list[str]:
    """Report only dependency-source settings with material supply-chain risk."""
    signals: list[str] = []
    if os.environ.get("PIP_EXTRA_INDEX_URL"):
        signals.append("High risk: PIP_EXTRA_INDEX_URL is active (dependency-confusion exposure)")
    if os.environ.get("PIP_TRUSTED_HOST"):
        signals.append("High risk: PIP_TRUSTED_HOST is active")
    if os.environ.get("PIP_INDEX_URL", "").startswith("http://"):
        signals.append("High risk: PIP_INDEX_URL uses insecure HTTP")
    return signals
