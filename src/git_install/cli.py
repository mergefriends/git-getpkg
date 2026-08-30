from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack, nullcontext
from urllib.parse import urlparse

from rich.console import Console

from git_install.discovery import discover
from git_install.github import Repository
from git_install.github import repositories as github_repositories
from git_install.github import signals as github_signals
from git_install.installer import (
    bin_directory,
    create_command_shims,
    ensure_bin_on_path,
    high_risk_pip_signals,
    install_python,
    validate_python,
)
from git_install.models import PackageReport, SourceInfo
from git_install.security import findings as security_findings
from git_install.security import scan_python
from git_install.source import open_source
from git_install.trust import assess, source_signals

MAX_PARALLEL_REPOSITORY_SCANS = 8
OWNER_DISCOVERY_CLONE_TIMEOUT_SECONDS = 90


def _link(label: str, url: str | None, enabled: bool) -> str:
    if not url or not enabled:
        return label
    return f"\033]8;;{url}\033\\{label}\033]8;;\033\\"


def _display_date(value: str | None) -> str:
    return value[:10] if value else "—"


def _display_bytes(value: int | None) -> str:
    if value is None:
        return "—"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.0f} {unit}" if unit in {"B", "KiB"} else f"{amount:.1f} {unit}"
        amount /= 1024
    return "—"


def _compact_signals(signals: list[str], *, limit: int = 2) -> str:
    value = " · ".join(signals[:limit])
    if len(signals) > limit:
        value += f" +{len(signals) - limit}"
    return value


def render_reports(reports: list[PackageReport], source: SourceInfo, *, links: bool) -> str:
    headers = ["Package", "Type", "Repository", "Namespace", "Path", "Last touched", "Signals"]
    raw_rows: list[list[str]] = []
    for report in reports:
        touched = (
            "—" if not report.last_touched_by else f"{report.last_touched_by}, {_display_date(report.last_touched_at)}"
        )
        raw_rows.append(
            [
                report.package.name + (f" {report.package.version}" if report.package.version else ""),
                report.package.ecosystem,
                source.repository_name,
                source.namespace or "—",
                report.package.relative_path,
                touched,
                _compact_signals(report.signals),
            ]
        )
    widths = [len(header) for header in headers]
    for row in raw_rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    output = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    output.append("  ".join("-" * width for width in widths))
    for row in raw_rows:
        rendered = list(row)
        rendered[2] = _link(row[2], source.repository_url, links)
        rendered[3] = _link(row[3], source.namespace_url, links) if row[3] != "—" else row[3]
        output.append(
            "  ".join(cell + " " * max(0, widths[index] - len(row[index])) for index, cell in enumerate(rendered))
        )
    return "\n".join(output)


def render_repositories(repositories: list[Repository], *, links: bool) -> str:
    headers = ["Repository", "Language", "Updated", "Visibility", "Status", "Package scan"]
    rows: list[list[str]] = []
    for repository in repositories:
        status = "archived" if repository.archived else "fork" if repository.fork else "active"
        rows.append(
            [
                repository.name,
                repository.language or "—",
                _display_date(repository.updated_at),
                "private" if repository.private else "public",
                status,
                "eligible" if repository.is_package_candidate else "skipped",
            ]
        )
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    output = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    output.append("  ".join("-" * width for width in widths))
    for repository, row in zip(repositories, rows):
        rendered = list(row)
        rendered[0] = _link(row[0], repository.url, links)
        output.append(
            "  ".join(cell + " " * max(0, widths[index] - len(row[index])) for index, cell in enumerate(rendered))
        )
    return "\n".join(output)


def render_discovery_size_footer(repositories: list[Repository], table: str) -> str:
    known_size_kib = sum(repository.reported_size_kib or 0 for repository in repositories)
    unknown_sizes = sum(repository.reported_size_kib is None for repository in repositories)
    summary = f"Estimated checkout data: {_display_bytes(known_size_kib * 1024)}"
    if unknown_sizes:
        summary += f" ({unknown_sizes} unavailable)"
    detail = "Dependencies and build artifacts are not included."
    width = max((len(line) for line in table.splitlines()), default=0)
    return "\n".join((summary.rjust(width), detail.rjust(width)))


def render_owner_reports(reports: list[tuple[SourceInfo, PackageReport]], *, links: bool) -> str:
    headers = ["Repository source", "Package", "Install", "Last touched", "Signals"]
    rows: list[list[str]] = []
    for source, report in reports:
        touched = (
            "—" if not report.last_touched_by else f"{report.last_touched_by}, {_display_date(report.last_touched_at)}"
        )
        rows.append(
            [
                source.repository_url or source.original,
                report.package.name + (f" {report.package.version}" if report.package.version else ""),
                "Python ready" if report.package.ecosystem == "Python" and report.package.installable else "list only",
                touched,
                _compact_signals(report.signals),
            ]
        )
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    output = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    output.append("  ".join("-" * width for width in widths))
    for (source, _), row in zip(reports, rows):
        rendered = list(row)
        rendered[0] = _link(row[0], source.repository_url, links)
        output.append(
            "  ".join(cell + " " * max(0, widths[index] - len(row[index])) for index, cell in enumerate(rendered))
        )
    return "\n".join(output)


def _reports(source: SourceInfo, *, enrich: bool) -> list[PackageReport]:
    packages = discover(source.root)
    context = github_signals(source) if enrich else []
    base = source_signals(source)
    reports = [assess(source, package, context, base) for package in packages]
    for report in reports:
        if report.package.ecosystem == "Python":
            report.signals.append(scan_python(report.package.directory))
    return reports


def _confirm(prompt: str, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        raise RuntimeError("Refusing non-interactive installation without --yes. Use --dry-run to inspect the plan.")
    return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}


def _select(reports: list[PackageReport], name: str | None) -> list[PackageReport]:
    if not name:
        return reports
    matches = [report for report in reports if report.package.name == name]
    if not matches:
        raise ValueError(f"No package named {name!r} was discovered.")
    if len(matches) > 1:
        locations = ", ".join(report.package.relative_path for report in matches)
        raise ValueError(f"Package name {name!r} is ambiguous: {locations}")
    return matches


def _scan_github_repository(repository: Repository) -> list[tuple[SourceInfo, PackageReport]]:
    """Clone, scan, and clean up one approved repository in a worker thread."""
    with open_source(repository.clone_url, clone_timeout=OWNER_DISCOVERY_CLONE_TIMEOUT_SECONDS) as source:
        return [(source, report) for report in _reports(source, enrich=False)]


def github_owner_from_source(value: str) -> str | None:
    """Recognize an owner URL without confusing it with a repository URL."""
    if value.startswith("github:"):
        owner = value.removeprefix("github:")
        return owner or None
    parsed = urlparse(value)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.scheme == "https" and parsed.hostname == "github.com" and len(parts) == 1:
        return parts[0]
    return None


def _list_github_owner(owner: str, args: argparse.Namespace, *, console: Console, show_progress: bool) -> int:
    repositories = [repository for repository in github_repositories(owner) if not repository.archived]
    language_candidates = [repository for repository in repositories if repository.is_package_candidate]
    candidates = language_candidates
    if args.as_json:
        print(
            json.dumps(
                [
                    {
                        "name": repository.name,
                        "url": repository.url,
                        "clone_url": repository.clone_url,
                        "language": repository.language,
                        "updated_at": repository.updated_at,
                        "private": repository.private,
                        "archived": repository.archived,
                        "fork": repository.fork,
                        "reported_size_kib": repository.reported_size_kib,
                        "package_scan_eligible": repository in candidates,
                    }
                    for repository in repositories
                ],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    links = not args.no_links and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
    print(
        f"Discovered {len(repositories)} active repositories; "
        f"{len(language_candidates)} have a supported primary language; "
        f"{len(candidates)} are eligible for package scanning."
    )
    if not candidates:
        print("No active repositories are eligible for package scanning.")
        return 0
    table = render_repositories(candidates, links=links)
    print(table)
    print(render_discovery_size_footer(candidates, table))
    if not args.discover_packages:
        if not sys.stdin.isatty():
            print("Re-run with --discover-packages to clone eligible repositories and inspect package manifests.")
            return 0
        if not _confirm(f"Discover packages in {len(candidates)} eligible repositories?", False):
            return 0
    reports: list[tuple[SourceInfo, PackageReport]] = []
    failures: list[tuple[Repository, Exception]] = []
    workers = min(MAX_PARALLEL_REPOSITORY_SCANS, len(candidates))
    activity = (
        console.status(f"Scanning repositories (0/{len(candidates)})…", spinner="dots")
        if show_progress
        else nullcontext()
    )
    with activity as status, ThreadPoolExecutor(max_workers=workers, thread_name_prefix="git-install") as executor:
        futures = {executor.submit(_scan_github_repository, repository): repository for repository in candidates}
        for completed, future in enumerate(as_completed(futures), start=1):
            repository = futures[future]
            try:
                reports.extend(future.result())
            except (ValueError, RuntimeError, OSError) as error:
                failures.append((repository, error))
            if status:
                status.update(f"Scanning repositories ({completed}/{len(candidates)})…")
    for repository, error in failures:
        print(f"Could not scan {repository.name}: {error}", file=sys.stderr)
    reports.sort(
        key=lambda item: (
            (item[0].repository_url or item[0].original).lower(),
            item[1].package.name.lower(),
            item[1].package.relative_path,
        )
    )
    if reports:
        num_pkgs = len(reports)
        num_repos = len(candidates) - len(failures)
        print(
            f"\nDiscovered {num_pkgs} package{'s' if len(reports) != 1 else ''} across {num_repos} repositories."
        )
        if sys.stdin.isatty() and _confirm("Show discovered packages?", False):
            print(render_owner_reports(reports, links=links))
            print("\nInstall one: git install <repository source> <package>")
            print("Install all from a repository: git install <repository source>")
    elif not failures:
        print("No supported package manifests found in eligible repositories.")
    return 1 if failures else 0


def _install(
    source: SourceInfo,
    reports: list[PackageReport],
    args: argparse.Namespace,
    *,
    console: Console,
    show_progress: bool,
) -> int:
    selected = _select(reports, args.package)
    if not selected:
        print("No packages discovered.")
        return 0

    print(f"Discovered {len(selected)} package{'s' if len(selected) != 1 else ''}.")
    show_review = args.dry_run or (not args.yes and sys.stdin.isatty() and _confirm("Show package details?", False))
    if show_review:
        _print_install_review(source, selected)
        for signal in high_risk_pip_signals():
            print(f"  • {signal}")

    unsupported = [
        item.package.name for item in selected if item.package.ecosystem != "Python" or not item.package.installable
    ]
    if unsupported:
        raise RuntimeError(f"v1 can install only installable Python projects: {', '.join(unsupported)}")
    source_identity = source.repository_url or str(source.root)
    plans = [install_python(item.package, source.commit, source_identity, dry_run=True) for item in selected]
    if show_review:
        for target, commands in plans:
            print(f"\nTarget environment: {target}")
            for command in commands:
                print("  $ " + shlex.join(command))
    managed_bin = bin_directory()
    if str(managed_bin) not in os.environ.get("PATH", "").split(os.pathsep) and show_review:
        print(f"\nAfter installation, git install will add {managed_bin} to your shell PATH for future terminals.")
    if args.dry_run:
        return 0
    if not args.yes and sys.stdin.isatty() and _confirm("Show Live security scan findings?", False):
        print("\nSeverity  Rule  File  Line  Finding")
        for report in selected:
            for severity, rule, filename, line, message in security_findings(report.package.directory):
                print(f"{severity:<8}  {rule:<4}  {filename}  {line:<4}  {message}")
    if not _confirm(
        f"Install {len(selected)} package(s)? These commands may execute package build/install code. Continue?",
        args.yes,
    ):
        print("Cancelled.")
        return 0
    failures = 0
    for report in selected:
        try:
            activity = (
                console.status(f"Installing {report.package.name}…", spinner="dots") if show_progress else nullcontext()
            )
            with activity:
                target, _ = install_python(report.package, source.commit, source_identity, dry_run=False)
            print(f"Installed {report.package.name} into {target}")
            validation_error = validate_python(target)
            if validation_error:
                failures += 1
                print(f"Dependency validation failed for {report.package.name}: {validation_error}", file=sys.stderr)
            shims = create_command_shims(report.package, target)
            if shims.created:
                print(f"Added command(s) to {shims.directory}: {', '.join(shims.created)}")
                path_result = ensure_bin_on_path(directory=shims.directory)
                print(path_result.message)
                if path_result.configured:
                    print("Open a new terminal to use these commands by name.")
            if shims.conflicts:
                print(f"Did not replace existing command(s): {', '.join(shims.conflicts)}", file=sys.stderr)
        except Exception as error:  # Continue to report every requested package.
            failures += 1
            print(f"Failed to install {report.package.name}: {error}", file=sys.stderr)
    return 1 if failures else 0


def _print_install_review(source: SourceInfo, selected: list[PackageReport]) -> None:
    """Show the opt-in pre-install review in a compact table."""
    headers = ["Package", "Commit", "Live security scan", "Signals"]
    rows: list[list[str]] = []
    for report in selected:
        security = next(
            (item for item in report.signals if item.startswith("Live security scan:")),
            "Live security scan: unavailable",
        )
        other = [item for item in report.signals if item != security]
        rows.append(
            [
                report.package.name,
                (source.commit or "unresolved")[:12],
                security.removeprefix("Live security scan: "),
                _compact_signals(other, limit=4),
            ]
        )
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    print()
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print("  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        prog="git install", description="Safely discover and install packages from Git sources."
    )
    command.add_argument("--version", action="version", version="git-install 0.1.0")
    subcommands = command.add_subparsers(dest="command", required=False)
    list_command = subcommands.add_parser("list", help="Discover packages without executing repository code")
    list_command.add_argument("source")
    list_command.add_argument("--json", action="store_true", dest="as_json")
    list_command.add_argument("--no-links", action="store_true")
    list_command.add_argument(
        "--discover-packages",
        action="store_true",
        help="After listing github:OWNER repositories, clone eligible repositories and scan manifests.",
    )
    install = subcommands.add_parser("install", help="Install packages from source")
    install.add_argument("source")
    install.add_argument("package", nargs="?")
    install.add_argument("--dry-run", action="store_true")
    install.add_argument("--yes", action="store_true")
    return command


def main(argv: list[str] | None = None) -> int:
    values = list(argv if argv is not None else sys.argv[1:])
    # `git install <source>` is the friendly default form.
    if values and values[0] not in {"list", "install", "--help", "-h", "--version"}:
        values.insert(0, "install")
    args = parser().parse_args(values)
    if args.command is None:
        parser().print_help()
        return 0
    try:
        console = Console(stderr=True)
        show_progress = sys.stderr.isatty() and not (args.command == "list" and args.as_json)
        github_owner = github_owner_from_source(args.source) if args.command == "list" else None
        if github_owner:
            if args.as_json and args.discover_packages:
                raise ValueError("--json and --discover-packages cannot be used together.")
            return _list_github_owner(github_owner, args, console=console, show_progress=show_progress)
        with ExitStack() as stack:
            activity = console.status("Preparing source…", spinner="dots") if show_progress else nullcontext()
            with activity as status:
                source = stack.enter_context(open_source(args.source))
                if status:
                    status.update("Scanning package manifests and running Security scan…")
                reports = _reports(source, enrich=args.command == "install")
                if status and args.command == "install":
                    status.update("Preparing installation review…")
            if args.command == "list":
                if args.as_json:
                    print(json.dumps([report.as_dict(source) for report in reports], indent=2, sort_keys=True))
                elif reports:
                    links = not args.no_links and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
                    print(render_reports(reports, source, links=links))
                else:
                    print("No supported package manifests found.")
                return 0
            return _install(source, reports, args, console=console, show_progress=show_progress)
    except (ValueError, RuntimeError, OSError) as error:
        print(f"git install: {error}", file=sys.stderr)
        return 2
