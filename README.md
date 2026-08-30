# git-install

`git install` safely discovers packages in a local directory or Git repository,
then installs selected Python packages into isolated managed environments.

## Install

```bash
python3 -m pip install .
```

The installed `git-install` executable is exposed by Git as `git install` when
it is on your `PATH`.

## Usage

```bash
git install list ./my-monorepo
git install list https://example.com/team/project.git
git install list https://github.com/octo-org
git install list https://github.com/octo-org --discover-packages
git install ./my-monorepo
git install ./my-monorepo api-client --dry-run
git install ./my-monorepo api-client --yes
```

`list` is read-only. It recursively detects Python, Node.js, Rust, Go, Ruby,
and PHP manifests and always displays package maintenance and installation-risk
signals. Python projects are the only installable package type in v1.

Python packages receive a non-executing Bandit-based Security scan during
discovery. Its findings are risk signals, not a guarantee that code is safe.

Git is required. If the GitHub CLI (`gh`) is installed and authenticated,
GitHub repositories are enriched with public repository/organization signals
(stars, forks, visible contributors, archive/fork status, and verified-org
status). This is optional and never prevents generic Git usage.

If access to a GitHub remote fails, `git install` explains how to install `gh`
when it is missing. If it is already available, it directs you to run
`gh auth login` followed by `gh auth setup-git`; it never installs software or
changes your Git credential configuration automatically.

To inventory a GitHub organization or user, use `git install list https://github.com/OWNER`.
This lists repositories from the authenticated GitHub API and marks only
active (non-archived) repositories whose primary language is supported by discovery. It then asks
before shallow-cloning those eligible repositories. Use `--discover-packages`
to provide that second approval in a non-interactive workflow. This mode
requires `gh`; it can include private repositories available to the authenticated
GitHub account.

After scanning, it reports the number of discovered packages and, in an
interactive terminal, asks before displaying the package table.
Eligible repositories are cloned and scanned in parallel, with at most eight
temporary checkouts active at once. Owner discovery times out an individual
clone after 90 seconds.

The inventory footer shows the total GitHub-reported source size for eligible
repositories before package discovery begins. It is a
download/storage planning signal, not an installed-size estimate: dependencies
and build artifacts are not included.

`github:OWNER` remains available as a compact equivalent, but standard GitHub
owner URLs are the recommended form. A two-segment GitHub URL remains a normal
repository source and is cloned through Git as usual.

Remote repositories are shallow-cloned from their default branch to a temporary
directory, pinned to the resulting commit SHA, and deleted after the command
finishes. Only HTTPS and SSH remotes are accepted (with `file://` retained for
local testing); external Git transport helpers are blocked. Remote checkouts
are limited to 512 MiB after clone. Local directories are scanned in place and
never modified.

Installations use a durable isolated Python environment under
`$XDG_DATA_HOME/git-install/environments` (or `~/.local/share` by default), so
the temporary source checkout can safely be removed afterward.


Console scripts declared by an installed Python package are exposed through
`$XDG_BIN_HOME` (or `~/.local/bin` by default). Existing user-owned commands
are never replaced. When needed, `git install` adds a small, marked PATH entry
to the active shell's configuration (`.zshrc`, `.bashrc`/`.bash_profile`, or
Fish `config.fish`). New terminals can then run the installed commands by name.

## Safety

- Discovery never executes repository code.
- Install plans show the resolved commit, trust findings, target environment,
  and exact commands before confirmation.
- Use `--dry-run` to inspect an install without changing anything.
- Non-interactive installs require `--yes`.
- Build hooks and unsupported package types are clearly flagged.
- Trust is deliberately conservative: `Unknown` means no online vulnerability
  or provenance verification has occurred, not that a package is safe.
- Symlinked manifests and manifests resolving outside the scan root are ignored.

## Development

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m git_install list .
```
