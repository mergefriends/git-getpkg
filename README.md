# git-install

`git install` discovers packages in a local directory or Git repository,
then installs selected Python packages into isolated managed environments.

## Install

```bash
brew install pipx && pipx ensurepath && pipx install git+https://github.com/mergefriends/git-install.git
```

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

## Development

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m git_install list .
```
