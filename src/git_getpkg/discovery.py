from __future__ import annotations

import json
import os
import re

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.9-3.10
    import tomli as tomllib
from pathlib import Path

from git_getpkg.models import Package

IGNORED_DIRECTORIES = {".git", ".venv", "venv", "node_modules", "vendor", "target", "__pycache__"}


def _package(
    root: Path,
    manifest: Path,
    name: str,
    version: str | None,
    ecosystem: str,
    *,
    installable: bool,
    warning: str | None = None,
    signals: tuple[str, ...] = (),
) -> Package:
    relative = manifest.parent.relative_to(root)
    return Package(
        name,
        version,
        ecosystem,
        manifest.parent,
        manifest,
        str(relative) if str(relative) != "." else ".",
        installable,
        warning,
        signals,
    )


def _python_signals(directory: Path, data: dict) -> tuple[str, ...]:
    signals: list[str] = []
    build_system = data.get("build-system", {})
    backend = build_system.get("build-backend")
    if backend:
        signals.append(f"Build backend: {backend}")
    build_requires = build_system.get("requires", [])
    if build_requires and any("==" not in requirement for requirement in build_requires):
        signals.append("Build requirements are not exact-pinned")
    project = data.get("project", {})
    dependencies = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        dependencies.extend(group)
    pinned = sum("==" in dependency for dependency in dependencies if " @ " not in dependency)
    unpinned = sum("==" not in dependency for dependency in dependencies if " @ " not in dependency)
    if dependencies:
        signals.append(f"Dependencies: {pinned} exact-pinned · {unpinned} unpinned")
    for dependency in dependencies:
        if " @ " not in dependency:
            continue
        source = dependency.split(" @ ", 1)[1].strip().lower()
        if source.startswith("git+"):
            signals.append("VCS dependency declared")
        elif source.startswith(("file:", "./", "../", "/")):
            signals.append("Local-path dependency declared")
        else:
            signals.append("Direct URL dependency declared")
    for lockfile in ("uv.lock", "poetry.lock", "Pipfile.lock"):
        if (directory / lockfile).is_file():
            signals.append(f"Lockfile present: {lockfile}")
    return tuple(dict.fromkeys(signals))


def _python_package(root: Path, manifest: Path) -> Package | None:
    if manifest.name == "pyproject.toml":
        data = tomllib.loads(manifest.read_text())
        project = data.get("project", {})
        name = project.get("name") or manifest.parent.name
        version = project.get("version")
        backend = data.get("build-system", {}).get("build-backend")
        warning = (
            f"Uses custom build backend: {backend}"
            if backend and backend not in {"setuptools.build_meta", "setuptools.build_meta:__legacy__"}
            else None
        )
        return _package(
            root,
            manifest,
            name,
            version,
            "Python",
            installable=True,
            warning=warning,
            signals=_python_signals(manifest.parent, data),
        )
    text = manifest.read_text(errors="replace")
    name = re.search(r"name\s*=\s*[\"']([^\"']+)", text)
    version = re.search(r"version\s*=\s*[\"']([^\"']+)", text)
    return _package(
        root,
        manifest,
        name.group(1) if name else manifest.parent.name,
        version.group(1) if version else None,
        "Python",
        installable=True,
        warning="setup.py may execute arbitrary build code",
    )


def discover(root: Path) -> list[Package]:
    packages: list[Package] = []
    resolved_root = root.resolve()

    def is_safe_file(path: Path) -> bool:
        if path.is_symlink() or not path.is_file():
            return False
        try:
            path.resolve().relative_to(resolved_root)
        except ValueError:
            return False
        return True

    manifest_names = {"pyproject.toml", "setup.py", "package.json", "Cargo.toml", "go.mod", "Gemfile", "composer.json"}
    manifests: list[Path] = []
    for directory, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        directories[:] = [name for name in directories if name not in IGNORED_DIRECTORIES]
        for filename in filenames:
            if filename in manifest_names:
                candidate = Path(directory, filename)
                if is_safe_file(candidate):
                    manifests.append(candidate)
    manifests.sort()
    python_by_directory: dict[Path, Path] = {}
    priority = {"pyproject.toml": 0, "setup.py": 1}
    for manifest in manifests:
        if manifest.name in priority and not any(
            part in IGNORED_DIRECTORIES for part in manifest.relative_to(root).parts
        ):
            existing = python_by_directory.get(manifest.parent)
            if existing is None or priority[manifest.name] < priority[existing.name]:
                python_by_directory[manifest.parent] = manifest
    seen_kinds: set[tuple[Path, str]] = set()
    for manifest in manifests:
        if not manifest.is_file() or any(part in IGNORED_DIRECTORIES for part in manifest.relative_to(root).parts):
            continue
        if manifest.name in priority and python_by_directory.get(manifest.parent) != manifest:
            continue
        package: Package | None = None
        try:
            if manifest.name in {"pyproject.toml", "requirements.txt", "setup.py"}:
                package = _python_package(root, manifest)
            elif manifest.name == "package.json":
                data = json.loads(manifest.read_text())
                scripts = data.get("scripts", {})
                warning = (
                    "Defines install lifecycle scripts"
                    if any(key in scripts for key in ("preinstall", "install", "postinstall"))
                    else None
                )
                package = _package(
                    root,
                    manifest,
                    data.get("name", manifest.parent.name),
                    data.get("version"),
                    "Node.js",
                    installable=False,
                    warning=warning,
                )
            elif manifest.name == "Cargo.toml":
                data = tomllib.loads(manifest.read_text())
                item = data.get("package", {})
                package = _package(
                    root,
                    manifest,
                    item.get("name", manifest.parent.name),
                    item.get("version"),
                    "Rust",
                    installable=False,
                )
            elif manifest.name == "go.mod":
                first = manifest.read_text().splitlines()[0]
                package = _package(root, manifest, first.removeprefix("module ").strip(), None, "Go", installable=False)
            elif manifest.name == "Gemfile":
                package = _package(root, manifest, manifest.parent.name, None, "Ruby", installable=False)
            elif manifest.name == "composer.json":
                data = json.loads(manifest.read_text())
                package = _package(
                    root,
                    manifest,
                    data.get("name", manifest.parent.name),
                    data.get("version"),
                    "PHP",
                    installable=False,
                )
        except (OSError, ValueError, tomllib.TOMLDecodeError, json.JSONDecodeError) as error:
            package = _package(
                root,
                manifest,
                manifest.parent.name,
                None,
                "Unknown",
                installable=False,
                warning=f"Could not parse manifest: {error}",
            )
        if package:
            key = (manifest.parent, package.ecosystem)
            if key in seen_kinds:
                continue
            packages.append(package)
            seen_kinds.add(key)
    return sorted(packages, key=lambda item: (item.name.lower(), item.relative_path))
