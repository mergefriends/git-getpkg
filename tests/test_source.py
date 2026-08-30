from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from git_getpkg.command import CommandError, run
from git_getpkg.github import repositories
from git_getpkg.models import Package
from git_getpkg.source import open_source
from git_getpkg.trust import assess


class SourceTests(unittest.TestCase):
    def test_github_owner_repositories_flatten_pages_and_filter_languages(self) -> None:
        payload = [
            [
                {
                    "name": "python-tool",
                    "html_url": "https://github.com/acme/python-tool",
                    "clone_url": "https://github.com/acme/python-tool.git",
                    "language": "Python",
                    "size": 1536,
                },
            ],
            [
                {
                    "name": "docs",
                    "html_url": "https://github.com/acme/docs",
                    "clone_url": "https://github.com/acme/docs.git",
                    "language": "Markdown",
                },
            ],
        ]
        with patch("git_getpkg.github._paged_api", return_value=payload) as paged_api:
            found = repositories("acme")
        paged_api.assert_called_once_with("orgs/acme/repos?type=all&per_page=100")
        self.assertEqual([repository.name for repository in found], ["python-tool", "docs"])
        self.assertTrue(found[0].is_package_candidate)
        self.assertEqual(found[0].reported_size_kib, 1536)
        self.assertFalse(found[1].is_package_candidate)

    def test_missing_gh_is_explained_after_github_access_failure(self) -> None:
        failure = CommandError("git ls-remote: Repository not found")
        with (
            patch("git_getpkg.source._default_branch", side_effect=failure),
            patch("git_getpkg.source.shutil.which", return_value=None),
        ):
            with self.assertRaisesRegex(CommandError, r"GitHub CLI \(`gh`\) was not found"):
                with open_source("https://github.com/acme/private.git"):
                    pass

    def test_existing_gh_has_auth_recovery_guidance(self) -> None:
        failure = CommandError("git ls-remote: Repository not found")
        with (
            patch("git_getpkg.source._default_branch", side_effect=failure),
            patch("git_getpkg.source.shutil.which", return_value="/usr/bin/gh"),
        ):
            with self.assertRaisesRegex(CommandError, r"gh auth login.*gh auth setup-git"):
                with open_source("git@github.com:acme/private.git"):
                    pass

    def test_network_failure_does_not_claim_an_authentication_problem(self) -> None:
        failure = CommandError("git ls-remote: Could not resolve host: github.com")
        with patch("git_getpkg.source._default_branch", side_effect=failure):
            with self.assertRaisesRegex(CommandError, r"Could not resolve host") as raised:
                with open_source("https://github.com/acme/private.git"):
                    pass
        self.assertNotIn("GitHub authentication may be required", str(raised.exception))

    def test_local_source_is_not_modified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run(["git", "init", "-q", str(root)])
            run(["git", "-C", str(root), "config", "user.email", "test@example.com"])
            run(["git", "-C", str(root), "config", "user.name", "Test"])
            (root / "pyproject.toml").write_text("[project]\nname='demo'\n")
            run(["git", "-C", str(root), "add", "."])
            run(["git", "-C", str(root), "commit", "-qm", "fixture"])
            with open_source(str(root)) as source:
                self.assertFalse(source.is_remote)
                self.assertEqual(source.root, root.resolve())
                self.assertIsNotNone(source.commit)

    def test_remote_checkout_is_removed_after_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "working"
            remote = Path(directory) / "remote.git"
            run(["git", "init", "-q", str(root)])
            run(["git", "-C", str(root), "config", "user.email", "test@example.com"])
            run(["git", "-C", str(root), "config", "user.name", "Test"])
            (root / "pyproject.toml").write_text("[project]\nname='demo'\n")
            run(["git", "-C", str(root), "add", "."])
            run(["git", "-C", str(root), "commit", "-qm", "fixture"])
            run(["git", "clone", "--bare", "-q", str(root), str(remote)])
            with open_source(remote.as_uri()) as source:
                checkout = source.root
                self.assertTrue(source.is_remote)
                self.assertTrue((checkout / "pyproject.toml").exists())
                self.assertIsNotNone(source.commit)
            self.assertFalse(checkout.exists())

    def test_last_touched_prefers_commit_user_over_author(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run(["git", "init", "-q", str(root)])
            run(["git", "-C", str(root), "config", "user.email", "committer@example.com"])
            run(["git", "-C", str(root), "config", "user.name", "Release Manager"])
            (root / "pyproject.toml").write_text("[project]\nname='demo'\n")
            run(["git", "-C", str(root), "add", "."])
            run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "author.name=dependabot[bot]",
                    "-c",
                    "author.email=49699333+dependabot[bot]@users.noreply.github.com",
                    "commit",
                    "-qm",
                    "dependency update",
                ]
            )
            with open_source(str(root)) as source:
                package = Package("demo", None, "Python", root, root / "pyproject.toml", ".", True)
                report = assess(source, package)
            self.assertEqual(report.last_touched_by, "Release Manager")
            self.assertIn("Authored by dependabot[bot]", report.signals)

    def test_last_touched_explains_generic_github_committer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run(["git", "init", "-q", str(root)])
            run(["git", "-C", str(root), "config", "user.email", "github@noreply.github.com"])
            run(["git", "-C", str(root), "config", "user.name", "GitHub"])
            (root / "pyproject.toml").write_text("[project]\nname='demo'\n")
            run(["git", "-C", str(root), "add", "."])
            run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "author.name=Garrett Haley",
                    "-c",
                    "author.email=garrett@example.com",
                    "commit",
                    "-qm",
                    "web commit",
                ]
            )
            with open_source(str(root)) as source:
                package = Package("demo", None, "Python", root, root / "pyproject.toml", ".", True)
                report = assess(source, package)
            self.assertEqual(report.last_touched_by, "Garrett Haley via GitHub")
            self.assertIn("Committed by GitHub", report.signals)
