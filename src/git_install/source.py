from __future__ import annotations

import contextlib
import os
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from git_install.command import CommandError, run
from git_install.models import SourceInfo

MAX_REMOTE_CHECKOUT_BYTES = 512 * 1024 * 1024


def _remote_parts(value: str) -> tuple[str | None, str | None, str | None, str | None]:
    """Return repository name, namespace, repository URL, and namespace URL when derivable."""
    normalized = value
    if re.match(r"^[^/@:]+@[^:]+:.+", value):
        user_host, path = value.split(":", 1)
        host = user_host.split("@", 1)[1]
        normalized = f"https://{host}/{path}"
    parsed = urlparse(normalized)
    path = parsed.path.strip("/")
    parts = path.removesuffix(".git").split("/") if path else []
    if not parts:
        return None, None, value, None
    repo = parts[-1]
    namespace = "/".join(parts[:-1]) or None
    base = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else None
    repo_url = f"{base}/{'/'.join(parts)}" if base else value
    namespace_url = f"{base}/{namespace}" if base and namespace else None
    return repo, namespace, repo_url, namespace_url


def _git_metadata(root: Path) -> tuple[str | None, str | None]:
    commit = run(["git", "-C", str(root), "rev-parse", "HEAD"], check=False)
    branch = run(["git", "-C", str(root), "branch", "--show-current"], check=False)
    return (
        commit.stdout.strip() if commit.returncode == 0 else None,
        branch.stdout.strip() if branch.returncode == 0 else None,
    )


def _default_branch(url: str) -> str:
    result = run(["git", "-c", "protocol.ext.allow=never", "ls-remote", "--symref", url, "HEAD"], timeout=45)
    for line in result.stdout.splitlines():
        if line.startswith("ref:") and line.endswith("\tHEAD"):
            ref = line.split()[1]
            return ref.removeprefix("refs/heads/")
    raise CommandError("Could not determine the remote repository's default branch.")


def _validate_remote_url(value: str) -> None:
    if re.match(r"^[^/@:\\s]+@[^:\\s]+:.+", value):
        return  # Standard Git SSH shorthand: git@example.com:team/repository.git
    parsed = urlparse(value)
    if parsed.scheme not in {"https", "ssh", "file"}:
        raise ValueError("Remote source must use https://, ssh://, file://, or standard SSH Git syntax.")


def _is_github_remote(value: str) -> bool:
    if re.match(r"^[^/@:\s]+@github\.com:[^\s]+", value):
        return True
    return urlparse(value).hostname == "github.com"


def _github_access_guidance(value: str, error: CommandError) -> CommandError:
    """Add an actionable, opt-in recovery path for private GitHub repositories."""
    authentication_markers = (
        "authentication",
        "authorization",
        "permission denied",
        "repository not found",
        "could not read username",
        "http 401",
        "http 403",
        "sso",
    )
    if not _is_github_remote(value) or not any(marker in str(error).lower() for marker in authentication_markers):
        return error
    if not shutil.which("gh"):
        message = (
            f"{error}\n\n"
            "GitHub authentication may be required to access this repository. "
            "GitHub CLI (`gh`) was not found. Install it, run `gh auth login`, then try again."
        )
    else:
        message = (
            f"{error}\n\n"
            "GitHub authentication may be required to access this repository. "
            "Run `gh auth login` and then `gh auth setup-git`, then try again."
        )
    return CommandError(message)


def _directory_size(root: Path) -> int:
    size = 0
    for directory, _, filenames in os.walk(root, followlinks=False):
        for filename in filenames:
            path = Path(directory, filename)
            try:
                size += path.lstat().st_size
            except OSError:
                continue
    return size


@contextlib.contextmanager
def open_source(value: str, *, clone_timeout: float = 300):
    path = Path(value).expanduser()
    if path.exists():
        root = path.resolve()
        if not root.is_dir():
            raise ValueError(f"Local source is not a directory: {root}")
        commit, branch = _git_metadata(root)
        yield SourceInfo(value, root, False, commit, branch, None, root.name, None, None)
        return

    temp_root = Path(tempfile.mkdtemp(prefix="git-install-"))
    try:
        _validate_remote_url(value)
        try:
            branch = _default_branch(value)
        except CommandError as error:
            raise _github_access_guidance(value, error) from error
        checkout = temp_root / "source"
        try:
            run(
                [
                    "git",
                    "-c",
                    "protocol.ext.allow=never",
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    "--branch",
                    branch,
                    value,
                    str(checkout),
                ],
                timeout=clone_timeout,
            )
        except CommandError as error:
            raise _github_access_guidance(value, error) from error
        size = _directory_size(checkout)
        if size > MAX_REMOTE_CHECKOUT_BYTES:
            remote_mib = size / 1024 / 1024
            max_mib = MAX_REMOTE_CHECKOUT_BYTES / 1024 / 1024
            raise ValueError(
                f"Remote checkout is {remote_mib:.0f} MiB, above the {max_mib:.0f} MiB safety limit."
            )
        commit, _ = _git_metadata(checkout)
        repo, namespace, repo_url, namespace_url = _remote_parts(value)
        yield SourceInfo(
            value, checkout, True, commit, branch, repo_url, repo or checkout.name, namespace, namespace_url
        )
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
