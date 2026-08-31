from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack, nullcontext
from io import StringIO
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from git_getpkg.discovery import discover
from git_getpkg.github import Repository
from git_getpkg.github import repositories as github_repositories
from git_getpkg.github import signals as github_signals
from git_getpkg.installer import (
    audit_python,
    audit_python_application,
    ensure_pipx_path,
    expose_python_application,
    high_risk_pip_signals,
    install_python,
    install_python_application,
    remove_environment,
    remove_python_application,
    validate_python,
    validate_python_application,
)
from git_getpkg.models import PackageReport, SourceInfo
from git_getpkg.security import findings as security_findings
from git_getpkg.security import scan_python
from git_getpkg.source import cleanup_stale_remote_checkouts, open_source
from git_getpkg.trust import assess, source_signals

MAX_PARALLEL_REPOSITORY_SCANS = 8
OWNER_DISCOVERY_CLONE_TIMEOUT_SECONDS = 90


def _link(label: str, url: str | None, enabled: bool) -> Text:
    return Text(label, style=f"link {url}") if url and enabled else Text(label)


def _terminal_width() -> int:
    return shutil.get_terminal_size(fallback=(100, 24)).columns


def _render_table(headers: list[str], rows: list[list[str | Text]], *, links: bool = False) -> str:
    """Render a compact table that adapts to the active terminal width."""
    width = _terminal_width()
    stream = StringIO()
    console = Console(
        file=stream,
        width=width,
        force_terminal=links,
        color_system="standard" if links else None,
        highlight=False,
    )
    table = Table(box=None, pad_edge=False, collapse_padding=True, show_edge=False, header_style="bold")
    for header in headers:
        table.add_column(
            header,
            overflow="ellipsis",
            max_width=max(24, width // 2) if header in {"Signals", "Finding"} else None,
            no_wrap=header not in {"Signals", "Finding"},
            ratio=1 if header in {"Signals", "Finding"} else None,
        )
    for row in rows:
        table.add_row(*row)
    console.print(table)
    return stream.getvalue().rstrip()


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
    width = _terminal_width()
    if width < 80:
        headers = ["Package", "Last touched", "Signals"]
    elif width < 110:
        headers = ["Package", "Type", "Last touched", "Signals"]
    else:
        headers = ["Package", "Type", "Repository", "Namespace", "Path", "Last touched", "Signals"]
    rows: list[list[str | Text]] = []
    for report in reports:
        touched = (
            "—" if not report.last_touched_by else f"{report.last_touched_by}, {_display_date(report.last_touched_at)}"
        )
        values: dict[str, str | Text] = {
            "Package": report.package.name + (f" {report.package.version}" if report.package.version else ""),
            "Type": report.package.ecosystem,
            "Repository": _link(source.repository_name, source.repository_url, links),
            "Namespace": _link(source.namespace, source.namespace_url, links) if source.namespace else "—",
            "Path": report.package.relative_path,
            "Last touched": touched,
            "Signals": _compact_signals(report.signals),
        }
        rows.append([values[header] for header in headers])
    return _render_table(headers, rows, links=links)


def render_repositories(repositories: list[Repository], *, links: bool) -> str:
    headers = ["Repository", "Language", "Updated", "Visibility", "Status", "Package scan"]
    rows: list[list[str | Text]] = []
    for repository in repositories:
        status = "archived" if repository.archived else "fork" if repository.fork else "active"
        rows.append(
            [
                _link(repository.name, repository.url, links),
                repository.language or "—",
                _display_date(repository.updated_at),
                "private" if repository.private else "public",
                status,
                "eligible" if repository.is_package_candidate else "skipped",
            ]
        )
    return _render_table(headers, rows, links=links)


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
    width = _terminal_width()
    headers = (
        ["Repository source", "Package", "Signals"]
        if width < 100
        else ["Repository source", "Package", "Install", "Last touched", "Signals"]
    )
    rows: list[list[str | Text]] = []
    for source, report in reports:
        touched = (
            "—" if not report.last_touched_by else f"{report.last_touched_by}, {_display_date(report.last_touched_at)}"
        )
        values: dict[str, str | Text] = {
            "Repository source": _link(source.repository_url or source.original, source.repository_url, links),
            "Package": report.package.name + (f" {report.package.version}" if report.package.version else ""),
            "Install": (
                "Python ready" if report.package.ecosystem == "Python" and report.package.installable else "list only"
            ),
            "Last touched": touched,
            "Signals": _compact_signals(report.signals),
        }
        rows.append([values[header] for header in headers])
    return _render_table(headers, rows, links=links)


def _reports(source: SourceInfo, *, enrich: bool, security_package: str | None = None) -> list[PackageReport]:
    packages = discover(source.root)
    context = github_signals(source) if enrich else []
    base = source_signals(source)
    reports = [assess(source, package, context, base) for package in packages]
    for report in reports:
        if report.package.ecosystem == "Python" and (
            security_package is None or report.package.name == security_package
        ):
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


def _print_source_risk_findings(reports: list[PackageReport]) -> None:
    """Print detailed non-executing Bandit findings for selected Python packages."""
    rows: list[list[str]] = []
    for report in reports:
        for severity, rule, filename, line, message in security_findings(report.package.directory):
            rows.append([severity, rule, filename, str(line), message])
    if rows:
        print(_render_table(["Severity", "Rule", "File", "Line", "Finding"], rows))
    else:
        print("No high or medium source-risk findings.")


def _source_risk_command(source: str, package: str | None) -> str:
    """Return a copy-pasteable command for detailed source-risk findings."""
    values = ["git", "getpkg", "scan", source]
    if package:
        values.append(package)
    return shlex.join(values)


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
    with activity as status, ThreadPoolExecutor(max_workers=workers, thread_name_prefix="git-getpkg") as executor:
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
            print("\nInstall one: git getpkg <repository source> <package>")
            print("Install all from a repository: git getpkg <repository source>")
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
    if args.dry_run:
        return 0
    console.print(
        f"[yellow]Source-risk details:[/] [dim]{_source_risk_command(args.source, args.package)}[/]"
    )
    if not _confirm(
        f"Install {len(selected)} package(s)? These commands may execute package build/install code. Continue?",
        args.yes,
    ):
        print("Cancelled.")
        return 0
    failures = 0
    progress = (
        Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console,
            transient=True,
        )
        if show_progress
        else None
    )
    with progress or nullcontext():
        for report in selected:
            task = progress.add_task(f"Installing {report.package.name}", total=4) if progress else None
            try:
                if report.package.has_console_scripts:
                    install_python_application(report.package, dry_run=False)
                    target = None
                else:
                    target, _ = install_python(report.package, source.commit, source_identity, dry_run=False)
                if progress:
                    progress.update(task, description=f"Validating {report.package.name}", completed=1)
                validation_error = (
                    validate_python_application(report.package) if target is None else validate_python(target)
                )
                if progress:
                    progress.update(task, description=f"Auditing dependencies for {report.package.name}", completed=2)
                audit = audit_python_application(report.package) if target is None else audit_python(target)
                if validation_error or audit.error or audit.findings:
                    failures += 1
                    if report.package.has_console_scripts:
                        remove_python_application(report.package)
                    elif target:
                        remove_environment(target)
                    console.print(
                        f"[bold red]✗ Installation failed for {report.package.name}; staged environment removed.[/]"
                    )
                    if validation_error:
                        print(f"Dependency validation failed: {validation_error}", file=sys.stderr)
                    if audit.error:
                        print(f"Dependency audit unavailable: {audit.error}", file=sys.stderr)
                    for package, version, advisory, fixes in audit.findings:
                        fixed = ", ".join(fixes) or "no fix published"
                        print(f"Dependency audit: {package} {version} · {advisory} · fixed in {fixed}", file=sys.stderr)
                    continue
                if target:
                    print(f"Installed {report.package.name} into {target}")
                else:
                    if progress:
                        progress.update(task, description=f"Exposing commands for {report.package.name}", completed=3)
                    expose_python_application(report.package)
                    ensure_pipx_path()
                    print("Pipx manages this package's commands. Open a new terminal if they are not yet on PATH.")
                if progress:
                    progress.update(task, description=f"Installed {report.package.name}", completed=4)
                console.print(f"[bold green]✓ Installed {report.package.name} · dependency audit clean (OSV).[/]")
            except Exception as error:  # Continue to report every requested package.
                failures += 1
                console.print(f"[bold red]✗ Failed to install {report.package.name}: {error}[/]")
    return 1 if failures else 0


def _print_install_review(source: SourceInfo, selected: list[PackageReport]) -> None:
    """Show the opt-in pre-install review in a compact table."""
    headers = ["Package", "Source risk scan", "Signals"] if _terminal_width() < 90 else [
        "Package",
        "Commit",
        "Source risk scan",
        "Signals",
    ]
    rows: list[list[str]] = []
    for report in selected:
        security = next(
            (item for item in report.signals if item.startswith("Source risk scan (Bandit):")),
            "Source risk scan (Bandit): unavailable",
        )
        other = [item for item in report.signals if item != security]
        values = {
            "Package": report.package.name,
            "Commit": (source.commit or "unresolved")[:12],
            "Source risk scan": security.removeprefix("Source risk scan (Bandit): "),
            "Signals": _compact_signals(other, limit=4),
        }
        rows.append([values[header] for header in headers])
    print()
    print(_render_table(headers, rows))


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        prog="git getpkg", description="Safely discover and install packages from Git sources."
    )
    command.add_argument("--version", action="version", version="git-getpkg 0.1.0")
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
    scan = subcommands.add_parser("scan", help="Show detailed non-executing source-risk findings")
    scan.add_argument("source")
    scan.add_argument("package", nargs="?")
    return command


def main(argv: list[str] | None = None) -> int:
    values = list(argv if argv is not None else sys.argv[1:])
    # `git getpkg <source>` is the friendly default form.
    if values and values[0] not in {"list", "install", "scan", "--help", "-h", "--version"}:
        values.insert(0, "install")
    args = parser().parse_args(values)
    if args.command is None:
        parser().print_help()
        return 0
    try:
        console = Console(stderr=True)
        cleanup_stale_remote_checkouts()
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
                    status.update("Scanning package manifests and running source risk scan…")
                reports = _reports(
                    source,
                    enrich=args.command == "install",
                    security_package=args.package if args.command in {"install", "scan"} else None,
                )
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
            if args.command == "scan":
                selected = _select(reports, args.package)
                if not selected:
                    print("No packages discovered.")
                    return 0
                _print_source_risk_findings(selected)
                return 0
            return _install(source, reports, args, console=console, show_progress=show_progress)
    except (ValueError, RuntimeError, OSError) as error:
        print(f"git getpkg: {error}", file=sys.stderr)
        return 2
