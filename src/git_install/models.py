from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SourceInfo:
    original: str
    root: Path
    is_remote: bool
    commit: str | None
    default_branch: str | None
    repository_url: str | None
    repository_name: str
    namespace: str | None
    namespace_url: str | None


@dataclass(frozen=True)
class Package:
    name: str
    version: str | None
    ecosystem: str
    directory: Path
    manifest: Path
    relative_path: str
    installable: bool
    install_warning: str | None = None
    metadata_signals: tuple[str, ...] = ()


@dataclass
class PackageReport:
    package: Package
    last_touched_by: str | None
    last_touched_at: str | None
    signals: list[str] = field(default_factory=list)

    def as_dict(self, source: SourceInfo) -> dict:
        value = asdict(self.package)
        value["directory"] = str(self.package.directory)
        value["manifest"] = str(self.package.manifest)
        value["signals"] = self.signals
        value["last_touched_by"] = self.last_touched_by
        value["last_touched_at"] = self.last_touched_at
        value["source"] = {
            "url": source.repository_url,
            "commit": source.commit,
            "branch": source.default_branch,
            "repository": source.repository_name,
            "namespace": source.namespace,
            "namespace_url": source.namespace_url,
        }
        return value
