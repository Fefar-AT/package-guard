# Release notes

## v1.8.1

First release from this repository.

- Every `npm`, `npx`, `pip` and `uv` command that would fetch a package is
  stopped until you approve the exact version at one permission prompt.
- Established packages are approved on the guard's own evidence; unknown ones
  are researched by a read-only subagent first.
- Manifests and lockfiles are gated: `npm install`, `npm ci`, `pip install -r`,
  `uv sync`, `uv add` and `uv run` install only approved versions, and every
  package in a lockfile is checked against OSV before the install.
- Install scripts are followed: a lifecycle script that installs something
  unapproved, or runs a script file the guard cannot read, is refused unless
  scripts are off (`--ignore-scripts`).
- Package sources are pinned to the official npm and PyPI registries; other
  registries, git, URL and path sources are refused.
- Claude cannot edit the guard, its approvals or `.claude/settings.json`, and
  cannot run git commands that would change them.
- Packages that reach disk without approval are reported after the command.
- Optional: `PG_SANDBOX=1` turns on the Claude Code sandbox to protect the
  guard's files from every command, with the network left open.
