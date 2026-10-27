# Release notes

## v1.12.1

Closes holes found after v1.12.0 shipped; upgrade if you use a Frappe bench. **After
upgrading, run `sh .claude/hooks/package_guard/pg bench-config apply` once in the bench
folder**: the guard writes stricter installer files, and bench commands are refused
until you do.

- **A baseline vouches for a Yarn sub-folder only when it lists that folder.**
  A folder under `node_modules`, `.git` or `__pycache__`, or a new one, gets
  the full review and malware check.
- **`bench build` checks an app whose `build` script is any value**, not only
  text, as Frappe's own build runs Yarn there too.
- **`bench build` no longer skips apps Frappe's build finds.** Frappe v16
  treats a folder as an app when its `hooks.py`, `modules.txt` and
  `patches.txt` are anywhere inside it, and v15 builds every line of
  `sites/apps.txt`. Package Guard now checks all of those folders like any
  other app, and refuses an `apps.txt` line that points outside `apps/` or
  is not exactly one folder of it (`./plain`, `plain/` and `PLAIN` count as `plain`).
- **A version range in your own app is installed at the release you approved**, not
  the newest one. After you approve a range's package, run `bench-config apply`
  again; the guard checks the pinned release before every bench install, and
  refuses a range that has none, even while a review is open.
- **Your own app may use only the `flit_core` or `setuptools` build backend**; any
  other can ask for packages nobody reviews. An app with no `[build-system]` gets
  uv's default `setuptools`, which is now reviewed and pinned like any build
  requirement (run `bench-config apply` after approving it); a `[build-system]`
  that lists no requirements is refused, and the approved versions also hold
  while your app is being built. `UV_PRERELEASE`
  and the other release-choosing variables are refused before a bench command.
- **Recreating the bench's `env/` is refused in every spelling** (`python3
  -mvenv --clear env`, `-m virtualenv`, `$PWD/env`).
- **`python setup.py <command>` is refused in any project**, whatever the command: a
  `setup.cfg` alias can make `build` install packages. `setup.py --version` still runs.
  `python -m setup` is refused too.
- **`bench-config apply --new-app NAME`** is refused when NAME is a project on
  PyPI or a requirement of the bench, and the name lasts until the next `apply`.

## v1.12.0

- **Frappe / ERPNext benches now work with the guard** (Frappe v15 and v16
  verified on a real bench; v14 and v11–v13 not confirmed yet). `bench setup
  requirements`, `bench update --requirements`, `bench new-app`, `bench build`
  and `bench pip install name==version` are checked instead of refused, and
  Yarn Classic (v1) is read in full.
- **Approve Frappe once per release.** The packages of frappe, erpnext and hrms
  are approved as one list (a *baseline*) in your own terminal, and the team
  shares it. Known malware always blocks; known bugs in old packages are shown,
  never block.
- **Your own app's packages are still checked one by one**, Python and
  JavaScript. A typo goes to review; the fake `frappe` or `erpnext` on PyPI, a
  missing Frappe app pulled from PyPI, or a package pointed at some other
  download are refused.
- **bench's own installs are locked down.** `bench-config apply` writes the
  settings bench's installers read (`env/pip.conf`, `uv.toml`, a `.yarnrc` per
  app): only what the baselines list, no install scripts, no building from
  source except your own apps. The guard checks them before every bench install.
- Still yours to run: `bench init`, `get-app`, a plain `update`,
  `switch-to-branch`, `setup env`, and the system installers. Open Claude at the
  bench folder. The steps are in [DETAILS](DETAILS.md#frappe--erpnext).

## v1.11.0

- **Modes: enforce, warn, off.** A supported way to turn the guard down for a
  while, instead of uninstalling it. Only you can do it, from your own
  terminal (`sh .claude/hooks/package_guard/pg mode warn --reason "..."`); Claude
  is refused. It goes back to `enforce` after 24 hours by default, and every
  package installed while it was down is checked when it comes back. See
  [DETAILS](DETAILS.md#turning-it-down-modes).
- **More install routes are caught.** Every spelling of `python -m pip`
  (`-mpip`, `-Im pip`, `pip.__main__`, any interpreter name),
  `python setup.py develop` / `install`, `venv --upgrade-deps`, `easy_install`,
  module runners such as `python -m runpy pip`, and `PYTHONPATH`-style
  variables in front of an installer. Each one used to install with the guard
  silent; now each is reviewed or refused.
- **More `bench` verbs are refused** until Frappe support lands in v1.12.0
  (`migrate-env`, `install`, `setup production`, `setup role`, `setup firewall`,
  ...). `bench build`, `start`, `migrate` and site commands still run.
- The README is now a short quick start; everything else is in `DETAILS.md`.
- The Docker Sandboxes kit can be one zip with the guard inside.

## v1.10.0

- pnpm, Bun and Yarn Berry (4.14.0 or newer) now work with the guard. They go
  through the same review as npm: exact versions, the lock read in full
  (`pnpm-lock.yaml` v9, text `bun.lock`, Berry `yarn.lock`), install scripts
  off or on a reviewed allow-list, and no `.pnpmfile`, Bun `preload`, Yarn
  `yarnPath` or plugin, or alternate registry. The project's `packageManager`
  pin (`pnpm@X.Y.Z`, `yarn@4.X.Y`) is reviewed once like a package. `pnpm dlx`, `bunx` and
  `yarn dlx` need an exact version and a review, like `npx`. `pipx`, `poetry`,
  `conda` and `corepack` stay refused.
- When a lock is missing or stale the guard names a command that installs
  nothing: `pnpm install --lockfile-only --ignore-scripts`, `bun install
  --lockfile-only --ignore-scripts` or `yarn install --mode=update-lockfile`.
- Refused flags: `-r`, `--filter`, `-w`, `-g`/`--global`, `-C`/`--dir`, `--cwd`.
  Refused verbs: pnpm `init`, `link`, `rebuild`, `approve-builds`, `import`,
  `self-update`, `env`, `deploy`, `pack`, `publish`, `patch`, `store add`; Bun
  `create`, `init`, `build`, `upgrade`, `pm trust`, `pm cache`, `pm pack`,
  `patch`, `publish`; Yarn `exec`, `set`, `workspace(s)`, `create`, `init`,
  `upgrade`, `global`, `npm publish`, `pack`, `patch`, `plugin`, `constraints`,
  `rebuild`, `unplug`, `node`. Use `yarn run <script>`, not `yarn <script>`.
  `pnpm create <x>@<exact>` is reviewed like `npm init`. `remove` is checked
  like the lock-only forms; for a package found on disk the guard names
  `pnpm remove <pkg>`, `bun remove <pkg> --ignore-scripts` or
  `yarn remove <pkg> --mode=skip-build`.
- `pnpm --version` and `yarn --version` (and `-v`, `--help`, `-h`, `help`) are
  checked like any other run of the manager: pnpm and Yarn switch to the release
  `packageManager` pins and Yarn runs `yarnPath`, so the pin must be reviewed
  and a `yarnPath`, plugin or `.pnpmfile` is refused. Without a pin or one of
  those, a print passes.
- Known gaps: `pnpm update`, `bun update` and `yarn up` can move a package
  within its existing range, like `npm update`. Yarn's checksums cannot be compared with npm's, so a person reads
  the `yarn.lock` diff. Yarn Classic and Plug'n'Play, workspaces and catalogs
  are refused. The approval flow is verified by tests; the maintainer checks a
  live approval. The cache layouts the disk check reads have not been checked
  against real managers, and pnpm store files with unexpected names are
  skipped.
- The guard's runner is unchanged: `uv` with exactly Python 3.11.
- Upgrading: re-run the installer (or `/package-guard:setup` for the plugin) so
  your project's `CLAUDE.md` gets the new package-manager wording.

## v1.9.2

- The repository is public, so the one-line install works again with no
  GitHub login:
  `curl -fsSL https://raw.githubusercontent.com/Fefar-AT/package-guard/release/install.sh | sh -s -- <project>`.
  Outside members install the plugin without asking for access.
- When the installer cannot clone, it shows git's own error and the likely
  cause (usually the network or a sandbox rule) instead of asking you to log
  in.

## v1.9.1

- Windows hosts without WSL2 can run the guard in a Docker sandbox (`sbx`)
  with the kit in `.sbx/package-guard/`. The guard runs on Linux inside it.
- The guard's files now stay LF on a Windows checkout. A CRLF `run.sh`
  (Git for Windows' default) blocked every command and kept Claude from
  ending its turn. Re-run the installer once: it adds `.gitattributes`
  lines and repairs the file, and `--check` reports both until you do.
- `git -c safe.directory=...` and other `-c` options no longer slip a
  checkout that rewrites the guard's files past the hook.

## v1.9.0

- Package Guard is now a Claude Code plugin for teams. The Owner connects the
  repository to claude.ai once (Organization settings, Plugins & skills, Sync
  from GitHub), and it reaches every member. Members sign in with their
  claude.ai account. Outside members install it with `claude plugin install`.
  The README has a quick start for each.
- **Projects set up with `install.sh` need `/package-guard:setup` once** after
  the plugin arrives. Until then both guards run there and approvals cannot
  complete, because each refuses the other's approve command. Setup removes
  the old hooks and keeps your approvals. Do this before the Owner makes the
  plugin Required.
- Everyone needs `uv`, installed once. Python 3.11 is then installed for you at
  the start of a session. If `uv` is missing, you are told to install it and
  nothing else happens; the guard blocks Bash commands and file edits until
  you do.
- The guard runs on Python 3.11 exactly, through `uv`. Before, it used
  whichever Python `uv` found first. A newer Python alone no longer counts.
  `install.sh` installs a uv-managed 3.11 if there is none.
- With the plugin, if the guard cannot start, or times out, the command is now
  blocked instead of let through (Claude Code v2.1.295 or newer).
- Native Windows works with the plugin, with Git for Windows. PowerShell
  commands are refused because the guard cannot inspect them; set
  `CLAUDE_CODE_USE_POWERSHELL_TOOL=0` so Claude uses Git Bash. `install.sh`
  still needs macOS, Linux or WSL2.
- The README has a new "Logging in to GitHub" section. When its clone fails,
  `install.sh` now explains how to log in over HTTPS (`gh auth login`, Git
  Credential Manager or a token), use SSH, or install from a ZIP. The
  `curl | sh` one-liner does not work while the repository is private.
- Fixed: with the plugin, approvals could not be recorded. The approve,
  decline and revoke commands Claude shows now work in a plugin project.
- Fixed: the plugin left the approvals and settings unprotected. File edits are
  now checked too, and changes to the project's approval records and
  `.claude/settings*.json`, your `~/.config/package-guard/` and the guard's own
  files are refused.
- Fixed: `/package-guard:setup` could not run. It now shows one command to
  type with a `!` in front.
- Fixed: with no Python 3.11 on the machine, the guard's error kept Claude from
  finishing its turn, over and over. It now fails the normal way and says
  clearly to run `uv python install 3.11`.
- Fixed: `uv` in `~/.local/bin` was missed when Claude Code started from the
  macOS dock.

## v1.8.7

- A refused package manager (pnpm, yarn, bun) could slip past the guard when
  a flag with a value came before the command word, as in
  `pnpm -C list add evil`. Only the word right after the manager counts now,
  and any other flag in front of it is refused. A bare `--version` or
  `--help` still works.
- `env` for a refused manager is now refused, and so are `config set`,
  `config delete` and `config edit`. These could point the registry somewhere
  else or download Node. Only `config get` and `config list` are still
  allowed.
- `bunx`, `pnpx`, `pnx` and `yarnpkg` are now recognised and refused. They
  download and run packages, so use `npx` instead, which the guard reviews.
- `corepack` is now refused, apart from `corepack --version` and
  `corepack --help`. It downloads package managers, and `corepack use` installs
  a project's dependencies with no review. Fetching corepack itself through
  `npx` or `npm exec` is refused too.
- Command names are matched in any letter case, and with a Windows `.cmd`,
  `.bat` or `.ps1` ending, wherever that makes the guard stricter. `NPM
  install x` is now reviewed like `npm install x`.
- Look-alikes are not given a free pass: `Echo` is not treated as the
  harmless built-in `echo`.

## v1.8.6

- The approval prompt is short: one line per package, with more lines only
  for something you should weigh. Six well-known packages fit in about a
  dozen lines instead of eighty.
- The prompt speaks plain words. It says which kind it is ("approve 6
  recommended packages", "1 package needs your decision", "1 package NOT
  recommended"), gives each reason as a short phrase ("published 2 days ago",
  "few users (800 downloads a week)", "its source repository could not be
  confirmed"), and ends a package that needs your decision with Claude's
  suggestion ("Claude suggests: use pypi:django@6.1.1 instead"). For the
  recommended ones a "Why" line says what held for all of them: from the
  official registry, first published over a year ago, widely used, no known
  vulnerabilities or malware reports (checked today), nothing runs while
  installing. `cli.py show` keeps the technical detail.
- Recommended packages are approved first, on one prompt. Packages the
  vetter leaves to your judgement come after, on a prompt of their own,
  once Claude has told you in one line each what it suggests. An approve
  that mixes the two is refused, and the message names the two commands to
  run instead.
- A package the vetter does not recommend, or whose name is one letter from
  a far more popular one, gets a prompt of its own: an approve that mixes it
  with other packages is refused. One prompt holds at most 12 packages.
- When the guard refuses an approve (no vetter verdict yet, an id it cannot
  use), the message now starts with `PACKAGE_GUARD_CLI_REFUSED`. Before, it
  started with "Package Guard:", and Claude took it for a block from
  somewhere else and stopped instead of waiting for the vetter.
- Installing from a subfolder reviews the project npm or uv actually
  installs: the nearest `package.json` or `pyproject.toml` above the folder,
  or the uv workspace it belongs to. Before, `npm ci` or `uv sync --locked`
  run in a folder without a manifest of its own was let through unreviewed.
  An outside environment named from a subfolder is remembered for its
  project, and a path into `.claude/` is refused in any letter case.
- When the project has no `package.json` or `pyproject.toml` of its own,
  npm and uv go on looking in the folders above it, and install whatever
  project they find there. That install is now refused, naming the folder,
  with `npm init -y` or `uv init --no-workspace` to give the project its
  own manifest. The same holds for a workspace above the project that
  takes it as a member.
- Running the vetter again cannot soften its verdict. Once it says "do not
  recommend", "needs review" or "lookalike" on complete evidence, a later
  report can only keep or tighten that, and the prompt and the one-package
  rule use the stricter answer. A rerun after a network failure still
  replaces a verdict given on partial evidence.
- For a `uv` command in a project that names no Python, the guard asks uv
  which interpreter it would use before judging the wheels. When the guard
  had to assume the interpreter, the prompt says "wheel for CPython 3.X
  (assumed interpreter)" instead of "no install-time code".
- Fewer well-known packages are sent for research. numpy, pandas, duckdb,
  structlog, vite, prettier and similar packages now pass the guard's own
  checks: repository links in any spelling, `setup.py` and monorepo
  projects, license expressions, fresh releases that are signed by the same
  publisher, and npm trusted publishing are all read correctly. The license
  is shown, never a reason to hold a package back.
- `uv` environments outside the project work: `UV_PROJECT_ENVIRONMENT`,
  `UV_LINK_MODE`, `UV_CACHE_DIR` and other location settings are allowed,
  and the guard checks that environment like `.venv`. Settings that change
  where packages come from are still refused, and the message says why.
- Very large npm packages, such as `@prisma/client`, are reviewed instead of
  failing with "response too large". Their release history is unknown, so
  they always go to the vetter and to you.
- A single network timeout or dropped connection no longer fails a review
  or an approval; the guard retries once.
- When a build backend such as `uv_build>=0.9,<0.10` is not pinned, the
  message names the exact version to write and says the edit is allowed.
- A fresh npm release skips the vetter only when it comes from the same
  trusted-publisher setup as the last release at least a week old, is
  signed, keeps the same repository, and adds no install script and no
  new or non-registry dependency. Anything else goes to the vetter.
- Commands that used to slip past the guard are now caught: `X+=1` and
  line-continued prefixes before an install, wrappers such as `nice`,
  `timeout` and `env -S`, and npm flag values that start with `-`
  (`--save=--registry=...`). Setting `HOME`, `PREFIX`, `XDG_CONFIG_HOME`,
  `CONDA_PREFIX` or `UV_PYTHON` on a package command, or `set -a` before
  one, is refused.
- More commands that hid an install are refused, and each message says what
  to run instead:
  - a command that writes `package.json`, a lockfile, `.npmrc`, `uv.toml`, a
    requirements file or another installer setting and then installs: run
    the write and the install as separate commands. `ln -s` beside an
    install is refused the same way;
  - an install behind a tool the guard does not know (`flock`, `script`,
    `mise exec`, `direnv exec`), behind a command name held in a variable
    or substitution (`$C install x`, `$(command -v npm) install x`), inside
    `$(...)`, backticks or `<(...)`, piped or fed to a shell
    (`echo '...' | bash`, `bash <<EOF`), or run by `uv run`;
  - `env -S` text with a `\` or a `$`, which env rewrites before it runs;
  - an install after `source`, `eval`, `read`, `for NAME in`, `printf -v` or
    `export $(...)`, which can set the variables npm, pip and uv read: run
    the package command on its own. For a virtualenv, call `.venv/bin/pip`
    instead of activating it.

  `gtimeout`, `genv` and `builtin` are read like `timeout`, `env` and a
  plain command, so installs behind them are reviewed as usual.
- `uv venv --seed` with an index, find-links or mirror flag (`--index-url`,
  `--default-index`, `--extra-index-url`, `--index`, `--find-links`, `-i`,
  `-f`, `--python-install-mirror`) is refused: `--seed` installs pip from
  that location. `uv venv`, `uv venv .venv --python 3.12` and `uv venv --seed`
  are unchanged. Short options bundled with others (`-qi URL`) are now read
  as uv reads them on `uv build`, `uv sync`, `uv run` and `uv pip sync`,
  `--allow-insecure-host` is refused after the verb on `uv sync`, `uv build`
  and `uv pip sync`, and `uv venv --directory` or `--project` is refused like
  the same flags on `uv sync`.
- `uv sync` and `uv run` count as locked only with `--locked`, `--frozen`
  or `UV_LOCKED=1` written on the same command; an earlier `export` no
  longer counts. `uv version 1.2.3` and `uv version --bump` are reviewed
  like `uv sync`, because they re-lock and sync.
- Commands that install nothing are no longer refused: `uv --version`,
  `npm init -y --init-type=module` and the other `npm init` settings, and
  `npm install --no-bin-links` for folders that cannot hold symlinks.
- `cli.py show` prints everything the prompt leaves out, refreshed.

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
