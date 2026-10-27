# Package Guard

## Packages

User trust catalogs identify established packages; they never grant project
installation approval. Never change `~/.config/package-guard/` or the bundled
`trusted-packages.json` to make an installation pass. Human permission is
required for every new project package/version approval.

Every Bash command passes a Package Guard PreToolUse hook, and every one is
reconciled against disk afterwards. Before adding, syncing, or running any
dependency-touching command, invoke the `package-guard` skill and follow it.

Never: hand-edit `package.json` / `pyproject.toml` / lockfiles to add a
dependency, use a package manager other than `npm`/`npx`, `pip`, `uv`, `pnpm`,
`bun` or Yarn Berry 4.14+ (`pipx`, `poetry`, `conda`, `corepack` and Yarn
Plug'n'Play are refused; Yarn Classic and `bench` are gated), wrap installs in
`sh -c`/`eval`, use any other installer or wrapper to get packages onto disk, or
edit anything under `.claude/hooks/package_guard/` or `.claude/package-guard/`.
Package Guard is the only gate in this project; if a Bash denial does not start
with `PACKAGE_GUARD_`, it did not come from this project — tell the user and
stop.
