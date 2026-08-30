from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from git_getpkg.discovery import discover
from git_getpkg.installer import create_command_shims, ensure_bin_on_path
from git_getpkg.models import Package


class DiscoveryTests(unittest.TestCase):
    def test_discovers_python_project_and_ignores_venv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname = 'demo'\nversion = '1.2.3'\n")
            (root / ".venv").mkdir()
            (root / ".venv" / "pyproject.toml").write_text("[project]\nname = 'ignored'\n")
            packages = discover(root)
        self.assertEqual(
            [(item.name, item.version, item.ecosystem) for item in packages], [("demo", "1.2.3", "Python")]
        )

    def test_python_signals_describe_build_and_dependency_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                "[build-system]\nrequires = ['hatchling>=1.0']\nbuild-backend = 'hatchling.build'\n"
                "[project]\nname = 'demo'\ndependencies = ['requests==2.0', 'tool @ git+https://github.com/acme/tool.git']\n"
            )
            (root / "uv.lock").write_text("version = 1\n")
            (root / "requirements-dev.txt").write_text(
                "--extra-index-url https://packages.example.test\npackage==1 --hash=sha256:abc\n"
            )
            package = discover(root)[0]
        self.assertIn("Build backend: hatchling.build", package.metadata_signals)
        self.assertIn("Build requirements are not exact-pinned", package.metadata_signals)
        self.assertIn("Dependencies: 1 exact-pinned · 0 unpinned", package.metadata_signals)
        self.assertIn("VCS dependency declared", package.metadata_signals)
        self.assertIn("Lockfile present: uv.lock", package.metadata_signals)

    def test_ignores_requirements_without_package_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("requests\n")
            packages = discover(root)
        self.assertEqual(packages, [])

    def test_ignores_symlinked_manifest_outside_scan_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "pyproject.toml"
            external.write_text("[project]\nname = 'outside'\n")
            (root / "pyproject.toml").symlink_to(external)
            self.assertEqual(discover(root), [])

    def test_command_shim_does_not_replace_user_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = root / "environment"
            executable = environment / "bin" / "demo"
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\n")
            executable.chmod(0o755)
            package = Package("demo", None, "Python", root, root / "pyproject.toml", ".", True)
            result = create_command_shims(package, environment, directory=root / "bin", scripts=["demo"])
            self.assertEqual(result.created, ["demo"])
            user_command = root / "bin" / "demo"
            user_command.write_text("user command")
            result = create_command_shims(package, environment, directory=root / "bin", scripts=["demo"])
            self.assertEqual(result.conflicts, ["demo"])

    def test_path_configuration_is_marked_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            target = home / ".local" / "bin"
            first = ensure_bin_on_path(directory=target, shell="/bin/zsh", home=home)
            second = ensure_bin_on_path(directory=target, shell="/bin/zsh", home=home)
            self.assertTrue(first.configured)
            self.assertFalse(second.configured)
            self.assertEqual((home / ".zshrc").read_text().count("# >>> git-getpkg PATH >>>"), 1)
