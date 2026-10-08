# Release notes

## v1.8.5

- Package Guard reads a vetter's report on current Claude Code builds, which
  deliver it as a queued message. Before this, approvals of packages that
  needed the vetter were refused.

## v1.8.4

- The README lists three ways to clone: SSH key, HTTPS login or `gh`. `gh` is
  no longer presented as required.

## v1.8.3

- The README asks for `gh auth setup-git` once, so the upgrade's `git pull`
  can use your `gh` login, and covers two clone failures in Troubleshooting.

## v1.8.2

- Install and upgrade use the same two commands: `gh repo clone` on the first
  run, `git pull` after that. A private repository now works with your
  existing `gh` login.
- The branch is now `main`.
- The installer and `--check` print the installed version.
- The README lists what you need before installing, what the install adds to
  your project, and where to send feedback.

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
