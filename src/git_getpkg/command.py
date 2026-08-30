from __future__ import annotations

import subprocess
from pathlib import Path


class CommandError(RuntimeError):
    pass


def run(
    args: list[str], *, cwd: Path | None = None, check: bool = True, timeout: float | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise CommandError(f"{' '.join(args[:3])}: timed out after {error.timeout:g} seconds") from error
    if check and result.returncode:
        message = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise CommandError(f"{' '.join(args[:3])}: {message}")
    return result
