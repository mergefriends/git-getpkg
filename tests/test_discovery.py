from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from git_getpkg.discovery import discover


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

    def test_marks_declared_python_console_scripts_for_pipx_installation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text(
                "[project]\nname = 'demo'\n[project.scripts]\ndemo = 'demo:main'\n"
            )
            package = discover(root)[0]
        self.assertTrue(package.has_console_scripts)
        self.assertIn("Console commands declared: demo", package.metadata_signals)

    def test_python_library_without_console_scripts_uses_venv_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
            package = discover(root)[0]
        self.assertFalse(package.has_console_scripts)

    def test_ignores_requirements_without_package_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("requests\n")
            packages = discover(root)
        self.assertEqual(packages, [])

    def test_ignores_packaging_fixtures_and_documentation_examples(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text("[project]\nname = 'real-package'\n")
            for parent in (root / "tests" / "fixture", root / "docs" / "example"):
                parent.mkdir(parents=True)
                (parent / "pyproject.toml").write_text("[project]\nname = 'not-a-package'\n")
            packages = discover(root)
        self.assertEqual([package.name for package in packages], ["real-package"])

    def test_ignores_symlinked_manifest_outside_scan_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "pyproject.toml"
            external.write_text("[project]\nname = 'outside'\n")
            (root / "pyproject.toml").symlink_to(external)
            self.assertEqual(discover(root), [])
