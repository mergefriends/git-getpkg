from __future__ import annotations

import hashlib
import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from git_getpkg.command import run
from git_getpkg.models import Package


@dataclass(frozen=True)
class ShimResult:
    directory: Path
    created: list[str]
    conflicts: list[str]


@dataclass(frozen=True)
class PathResult:
    configured: bool
    profile: Path | None
    message: str


def environment_path(package: Package, commit: str | None, source_identity: str) -> Path:
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", package.name).strip("-") or "package"
    identity = f"{source_identity}\0{commit or 'working-tree'}\0{package.relative_path}"
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:12]
    return data_home / "git-getpkg" / "environments" / f"{safe_name}-{suffix}"


def bin_directory() -> Path:
    return Path(os.environ.get("XDG_BIN_HOME", Path.home() / ".local" / "bin"))


def ensure_bin_on_path(
    *, directory: Path | None = None, shell: str | None = None, home: Path | None = None
) -> PathResult:
    """Persist a narrowly scoped PATH entry for future interactive shells."""
    directory = directory or bin_directory()
    if str(directory) in os.environ.get("PATH", "").split(os.pathsep):
        return PathResult(False, None, f"{directory} is already on PATH")
    home = home or Path.home()
    shell_name = Path(shell or os.environ.get("SHELL", "")).name
    if shell_name == "zsh":
        profile = home / ".zshrc"
        entry = f'export PATH={shlex.quote(str(directory))}:"$PATH"'
    elif shell_name == "bash":
        profile = home / (".bash_profile" if (home / ".bash_profile").exists() else ".bashrc")
        entry = f'export PATH={shlex.quote(str(directory))}:"$PATH"'
    elif shell_name == "fish":
        config_home = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        profile = config_home / "fish" / "config.fish"
        entry = f"set -gx PATH {shlex.quote(str(directory))} $PATH"
    else:
        return PathResult(False, None, f"Could not identify a supported shell; add {directory} to PATH")
    start = "# >>> git-getpkg PATH >>>"
    end = "# <<< git-getpkg PATH <<<"
    existing = profile.read_text() if profile.exists() else ""
    if start not in existing:
        profile.parent.mkdir(parents=True, exist_ok=True)
        suffix = "" if not existing or existing.endswith("\n") else "\n"
        profile.write_text(f"{existing}{suffix}{start}\n{entry}\n{end}\n")
        return PathResult(True, profile, f"Added {directory} to PATH in {profile}")
    return PathResult(False, profile, f"{directory} is already managed in {profile}")


def _console_scripts(package: Package, environment: Path) -> list[str]:
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    query = """
import json
import re
import sys
from importlib.metadata import distributions

def normalized(value):
    return re.sub(r"[-_.]+", "-", value).lower()

target = normalized(sys.argv[1])
for distribution in distributions():
    name = distribution.metadata.get("Name", "")
    if normalized(name) == target:
        print(json.dumps(sorted(entry.name for entry in distribution.entry_points if entry.group == "console_scripts")))
        break
else:
    print("[]")
"""
    result = run([str(python), "-c", query, package.name])
    import json

    return json.loads(result.stdout)


def create_command_shims(
    package: Package,
    environment: Path,
    *,
    directory: Path | None = None,
    scripts: list[str] | None = None,
) -> ShimResult:
    """Expose only this package's console scripts without replacing user-owned commands."""
    directory = directory or bin_directory()
    directory.mkdir(parents=True, exist_ok=True)
    scripts = scripts if scripts is not None else _console_scripts(package, environment)
    source_directory = environment / ("Scripts" if os.name == "nt" else "bin")
    created: list[str] = []
    conflicts: list[str] = []
    for name in scripts:
        source = source_directory / (f"{name}.exe" if os.name == "nt" else name)
        destination = directory / (f"{name}.cmd" if os.name == "nt" else name)
        if not source.exists():
            continue
        if destination.exists() and "Managed by git-getpkg" not in destination.read_text(errors="ignore"):
            conflicts.append(name)
            continue
        if os.name == "nt":
            destination.write_text(f'@rem Managed by git-getpkg\r\n@"{source}" %*\r\n')
        else:
            destination.write_text(f'#!/bin/sh\n# Managed by git-getpkg\nexec {shlex.quote(str(source))} "$@"\n')
            destination.chmod(0o755)
        created.append(name)
    return ShimResult(directory, created, conflicts)


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
