# Release notes

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
