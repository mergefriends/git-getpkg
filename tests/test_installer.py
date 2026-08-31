from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from git_getpkg.installer import (
    ensure_pipx_path,
    install_python_application,
    pipx_install_command,
    validate_python_application,
)
from git_getpkg.models import Package


class PipxInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        self.package = Package("demo", None, "Python", self.root, self.root / "pyproject.toml", ".", True)

    def tearDown(self) -> None:
        self.root.rmdir()

    def test_pipx_install_uses_the_bundled_module_and_current_python(self) -> None:
        self.assertEqual(
            pipx_install_command(self.package),
            [sys.executable, "-m", "pipx", "install", "--python", sys.executable, str(self.root)],
        )

    def test_pipx_install_is_skipped_for_dry_run(self) -> None:
        with patch("git_getpkg.installer.run") as run:
            commands = install_python_application(self.package, dry_run=True)
        self.assertEqual(commands, [pipx_install_command(self.package)])
        run.assert_not_called()

    def test_pipx_validation_reports_a_failure(self) -> None:
        with patch("git_getpkg.installer.run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = ""
            run.return_value.stderr = "broken requirement"
            self.assertEqual(validate_python_application(self.package), "broken requirement")

    def test_pipx_path_setup_uses_the_bundled_module(self) -> None:
        with patch("git_getpkg.installer.run") as run:
            ensure_pipx_path()
        run.assert_called_once_with([sys.executable, "-m", "pipx", "ensurepath"])
