from __future__ import annotations

from datetime import datetime, timedelta, timezone

from git_getpkg.command import run
from git_getpkg.models import Package, PackageReport, SourceInfo


def _last_touched(source: SourceInfo, package: Package) -> tuple[str | None, str | None, str | None]:
    if not source.commit:
        return None, None, None
    result = run(
        ["git", "-C", str(source.root), "log", "-1", "--format=%cn%x00%cI%x00%an", "--", package.relative_path],
        check=False,
    )
    if result.returncode or not result.stdout.strip():
        return None, None, None
    committer, date, author = result.stdout.rstrip("\n").split("\x00", 2)
    return committer, date, author


def source_signals(source: SourceInfo) -> list[str]:
    findings: list[str] = []
    if source.commit:
        findings.append(f"Pinned to commit {source.commit[:12]}")
        signature = run(["git", "-C", str(source.root), "verify-commit", source.commit], check=False)
        findings.append(
            "Commit signature verified locally"
            if signature.returncode == 0
            else "Commit signature not verified locally"
        )
    else:
        findings.append("No Git commit could be resolved")
    return findings


def assess(
    source: SourceInfo,
    package: Package,
    repository_signals: list[str] | None = None,
    base_signals: list[str] | None = None,
) -> PackageReport:
    findings: list[str] = []
    committer, date, author = _last_touched(source, package)
    findings.extend(base_signals if base_signals is not None else source_signals(source))
    if package.install_warning:
        findings.append(package.install_warning)
    findings.extend(package.metadata_signals)
    display_committer = committer
    if committer and committer.casefold() == "github" and author and author != committer:
        display_committer = f"{author} via GitHub"
        findings.append("Committed by GitHub")
    elif author and author != committer:
        findings.append(f"Authored by {author}")
    if date:
        try:
            touched = datetime.fromisoformat(date.replace("Z", "+00:00"))
            if touched < datetime.now(timezone.utc) - timedelta(days=730):
                findings.append("Package has not changed in over two years")
        except ValueError:
            pass
    if not package.installable:
        findings.append("Installation is not supported in v1")
    if (source.root / "SECURITY.md").is_file():
        findings.append("Security policy present")
    if (source.root / ".gitmodules").is_file():
        findings.append("Submodules detected (not initialized)")
    findings.extend(repository_signals or [])
    return PackageReport(package=package, last_touched_by=display_committer, last_touched_at=date, signals=findings)
