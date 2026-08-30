from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

from git_getpkg.cli import (
    _list_github_owner,
    _reports,
    github_owner_from_source,
    render_discovery_size_footer,
    render_owner_reports,
    render_reports,
    render_repositories,
)
from git_getpkg.github import Repository
from git_getpkg.models import Package, PackageReport, SourceInfo


class CliTests(unittest.TestCase):
    def test_list_reports_do_not_request_github_enrichment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
            source = SourceInfo(
                "https://github.com/acme/demo.git",
                root,
                True,
                None,
                "main",
                "https://github.com/acme/demo",
                "demo",
                "acme",
                "https://github.com/acme",
            )
            with patch("git_getpkg.cli.github_signals") as github_signals:
                _reports(source, enrich=False)
            github_signals.assert_not_called()

    def test_install_reports_request_github_enrichment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
            source = SourceInfo(
                "https://github.com/acme/demo.git",
                root,
                True,
                None,
                "main",
                "https://github.com/acme/demo",
                "demo",
                "acme",
                "https://github.com/acme",
            )
            with patch(
                "git_getpkg.cli.github_signals", return_value=["GitHub: verified organization"]
            ) as github_signals:
                reports = _reports(source, enrich=True)
            github_signals.assert_called_once_with(source)
            self.assertIn("GitHub: verified organization", reports[0].signals)

    def test_list_renderer_outputs_only_the_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
            source = SourceInfo(".", root, False, None, None, None, "demo", None, None)
            report = _reports(source, enrich=False)[0]
            output = render_reports([report], source, links=False)
            self.assertNotIn("\n  •", output)

    def test_repository_renderer_marks_scan_eligibility(self) -> None:
        repositories = [
            Repository(
                "acme",
                "python-tool",
                "https://github.com/acme/python-tool",
                "https://github.com/acme/python-tool.git",
                "Python",
                None,
                False,
                False,
                False,
            ),
            Repository(
                "acme",
                "docs",
                "https://github.com/acme/docs",
                "https://github.com/acme/docs.git",
                "Markdown",
                None,
                False,
                False,
                False,
            ),
        ]
        output = render_repositories(repositories, links=False)
        self.assertIn("python-tool", output)
        self.assertIn("eligible", output)
        self.assertIn("skipped", output)

    def test_github_owner_url_is_distinct_from_repository_url(self) -> None:
        self.assertEqual(github_owner_from_source("https://github.com/psf"), "psf")
        self.assertEqual(github_owner_from_source("https://github.com/psf/"), "psf")
        self.assertEqual(github_owner_from_source("github:psf"), "psf")
        self.assertIsNone(github_owner_from_source("https://github.com/psf/requests.git"))

    def test_owner_listing_excludes_archived_repositories(self) -> None:
        active = Repository(
            "acme",
            "active",
            "https://github.com/acme/active",
            "https://github.com/acme/active.git",
            "Python",
            None,
            False,
            False,
            False,
        )
        archived = Repository(
            "acme",
            "archived",
            "https://github.com/acme/archived",
            "https://github.com/acme/archived.git",
            "Python",
            None,
            False,
            True,
            False,
        )
        args = SimpleNamespace(as_json=True, no_links=True, discover_packages=False)
        output = StringIO()
        with patch("git_getpkg.cli.github_repositories", return_value=[active, archived]), redirect_stdout(output):
            result = _list_github_owner("acme", args, console=Console(), show_progress=False)
        self.assertEqual(result, 0)
        self.assertIn('"active"', output.getvalue())
        self.assertNotIn('"name": "archived"', output.getvalue())

    def test_owner_table_only_shows_repositories_eligible_for_scanning(self) -> None:
        candidate = Repository(
            "acme",
            "tool",
            "https://github.com/acme/tool",
            "https://github.com/acme/tool.git",
            "Python",
            None,
            False,
            False,
            False,
            1024,
        )
        skipped = Repository(
            "acme",
            "docs",
            "https://github.com/acme/docs",
            "https://github.com/acme/docs.git",
            "Markdown",
            None,
            False,
            False,
            False,
        )
        args = SimpleNamespace(as_json=False, no_links=True, discover_packages=False)
        output = StringIO()
        with (
            patch("git_getpkg.cli.github_repositories", return_value=[candidate, skipped]),
            patch("git_getpkg.cli.sys.stdin.isatty", return_value=False),
            redirect_stdout(output),
        ):
            result = _list_github_owner("acme", args, console=Console(), show_progress=False)
        self.assertEqual(result, 0)
        self.assertIn("tool", output.getvalue())
        self.assertNotIn("docs", output.getvalue())
        self.assertIn("Estimated checkout data: 1.0 MiB", output.getvalue())

    def test_discovery_size_footer_is_right_aligned_and_caveated(self) -> None:
        repository = Repository(
            "acme",
            "tool",
            "https://github.com/acme/tool",
            "https://github.com/acme/tool.git",
            "Python",
            None,
            False,
            False,
            False,
            1536,
        )
        footer = render_discovery_size_footer([repository], "Repository  Package scan\n----------  ------------")
        self.assertIn("Estimated checkout data: 1.5 MiB", footer)
        self.assertIn("Dependencies and build artifacts are not included.", footer)

    def test_owner_scan_reports_count_before_showing_package_table(self) -> None:
        root = Path("/tmp/acme-tool")
        source = SourceInfo(
            "https://github.com/acme/tool.git",
            root,
            True,
            "abc",
            "main",
            "https://github.com/acme/tool",
            "tool",
            "acme",
            "https://github.com/acme",
        )
        package = Package("acme-tool", None, "Python", root, root / "pyproject.toml", ".", True)
        report = PackageReport(package, None, None)
        candidate = Repository(
            "acme",
            "tool",
            "https://github.com/acme/tool",
            "https://github.com/acme/tool.git",
            "Python",
            None,
            False,
            False,
            False,
            1,
        )

        @contextmanager
        def fake_open_source(_value: str, **_kwargs: object):
            yield source

        args = SimpleNamespace(as_json=False, no_links=True, discover_packages=True)
        output = StringIO()
        with (
            patch("git_getpkg.cli.github_repositories", return_value=[candidate]),
            patch("git_getpkg.cli.open_source", fake_open_source),
            patch("git_getpkg.cli._reports", return_value=[report]),
            patch("git_getpkg.cli.sys.stdin.isatty", return_value=True),
            patch("git_getpkg.cli._confirm", return_value=False) as confirm,
            redirect_stdout(output),
        ):
            result = _list_github_owner("acme", args, console=Console(), show_progress=False)
        self.assertEqual(result, 0)
        self.assertIn("Discovered 1 package across 1 repositories.", output.getvalue())
        self.assertNotIn("acme-tool", output.getvalue())
        confirm.assert_called_once_with("Show discovered packages?", False)

    def test_owner_package_table_includes_copyable_repository_source(self) -> None:
        root = Path("/tmp/acme-tool")
        source = SourceInfo(
            "https://github.com/acme/tool.git",
            root,
            True,
            "abc",
            "main",
            "https://github.com/acme/tool",
            "tool",
            "acme",
            "https://github.com/acme",
        )
        package = Package("acme-tool", None, "Python", root, root / "pyproject.toml", ".", True)
        output = render_owner_reports(
            [(source, PackageReport(package, None, None, ["one", "two", "three"]))], links=False
        )
        self.assertIn("https://github.com/acme/tool", output)
        self.assertNotIn("Type", output)
        self.assertIn("Python ready", output)
        self.assertIn("one · two +1", output)
