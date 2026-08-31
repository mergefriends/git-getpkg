# git-getpkg

Install every Python tool in a repository with one Git command — no hunting through folders, no manual virtualenv setup.

## Install
Linux:
```bash
apt-get install pipx && pipx ensurepath && pipx install git-getpkg
```
Mac:
```bash
brew install pipx && pipx ensurepath && pipx install git-getpkg
```

## Usage
Find all packages in a repo
```bash
git getpkg list https://github.com/psf/black
```
Find all packages in an organization
```bash
git getpkg list https://github.com/psf
```
Install all packages in a repo
```bash
git getpkg https://github.com/psf/black
```
Install a single package from a repo
```bash
git getpkg https://github.com/psf/black black
```

## Develop, build, and test locally

Requires Python 3.10+ and pipx. From the repository root:

```bash
pipx install --editable . --force
pipx run pytest -q
git getpkg list .
g```
