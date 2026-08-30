"""Optional GitHub context, obtained through the user's existing gh CLI."""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from urllib.parse import urlparse

from git_getpkg.command import run
from git_getpkg.models import SourceInfo

SUPPORTED_PRIMARY_LANGUAGES = frozenset({"Python", "JavaScript", "TypeScript", "Rust", "Go", "Ruby", "PHP"})


class GitHubApiError(RuntimeError):
    """A failed GitHub CLI API request with enough context for safe recovery."""

    @property
    def is_not_found(self) -> bool:
        return "404" in str(self) or "not found" in str(self).lower()


@dataclass(frozen=True)
class Repository:
    owner: str
    name: str
    url: str
    clone_url: str
    language: str | None
    updated_at: str | None
    private: bool
    archived: bool
    fork: bool
    reported_size_kib: int | None = None

    @property
    def is_package_candidate(self) -> bool:
        return self.language in SUPPORTED_PRIMARY_LANGUAGES


def _owner_repo(source: SourceInfo) -> tuple[str, str] | None:
    url = source.repository_url
    if not url or urlparse(url).hostname != "github.com" or not source.namespace or "/" in source.namespace:
        return None
    return source.namespace, source.repository_name


def _api(endpoint: str) -> object | None:
    if not shutil.which("gh"):
        return None
    result = run(["gh", "api", endpoint], check=False, timeout=20)
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _paged_api(endpoint: str) -> object:
    if not shutil.which("gh"):
        raise GitHubApiError(
            "GitHub owner discovery requires GitHub CLI (`gh`). Install it, run `gh auth login`, then try again."
        )
    result = run(["gh", "api", "--paginate", "--slurp", endpoint], check=False, timeout=60)
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip() or "GitHub API request failed"
        raise GitHubApiError(f"Could not list GitHub repositories: {message}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise GitHubApiError("GitHub returned an invalid repository listing.") from error


def repositories(owner: str) -> list[Repository]:
    """List an org's repositories, falling back to a user account when needed."""
    if not owner or "/" in owner:
        raise ValueError("GitHub owner must be a single organization or user name.")
    try:
        payload = _paged_api(f"orgs/{owner}/repos?type=all&per_page=100")
    except GitHubApiError as organization_error:
        if not organization_error.is_not_found:
            raise
        try:
            payload = _paged_api(f"users/{owner}/repos?type=owner&per_page=100")
        except GitHubApiError:
            raise organization_error
    pages = payload if isinstance(payload, list) else []
    rows = [row for page in pages if isinstance(page, list) for row in page if isinstance(row, dict)]
    return [
        Repository(
            owner=owner,
            name=str(row.get("name", "unknown")),
            url=str(row.get("html_url", f"https://github.com/{owner}/{row.get('name', '')}")),
            clone_url=str(row.get("clone_url", f"https://github.com/{owner}/{row.get('name', '')}.git")),
            language=row.get("language") if isinstance(row.get("language"), str) else None,
            updated_at=row.get("pushed_at") if isinstance(row.get("pushed_at"), str) else None,
            private=bool(row.get("private")),
            archived=bool(row.get("archived")),
            fork=bool(row.get("fork")),
            reported_size_kib=row.get("size") if isinstance(row.get("size"), int) and row["size"] >= 0 else None,
        )
        for row in rows
    ]


def signals(source: SourceInfo) -> list[str]:
    target = _owner_repo(source)
    if not target:
        return []
    owner, repository = target
    repo = _api(f"repos/{owner}/{repository}")
    if not isinstance(repo, dict):
        return ["GitHub context unavailable"]
    values = [f"GitHub: {repo.get('stargazers_count', 0)} stars · {repo.get('forks_count', 0)} forks"]
    if repo.get("archived"):
        values.append("GitHub: repository archived")
    if repo.get("fork"):
        values.append("GitHub: repository is a fork")
    contributors = _api(f"repos/{owner}/{repository}/contributors?per_page=100")
    if isinstance(contributors, list):
        values.append(f"GitHub: {len(contributors)} visible contributors")
    organization = _api(f"orgs/{owner}")
    if isinstance(organization, dict) and organization.get("is_verified"):
        values.append("GitHub: verified organization")
    return values
