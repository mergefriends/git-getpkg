# git-install

`git install` discovers packages in a local directory or Git repository,
then installs selected Python packages into isolated managed environments.

## Install

```bash
brew install pipx && pipx ensurepath && pipx install git+https://github.com/mergefriends/git-install.git
```

## Usage
Find all packages in a repo
```bash
git install list https://github.com/psf/black
```
Find all packages in an organization
```bash
git install list https://github.com/psf
```
Install all packages in a repo
```bash
git install list https://github.com/psf/black
```
Install a single package from a repo
```bash
git install list https://github.com/psf/black black
```

## Development

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m git_install list .
```
