# Package Guard

Package Guard stops Claude Code from installing an npm or PyPI package you have
not approved.

When Claude runs `npm install express`, a hook stops the command before it
runs, resolves the exact version, and checks it against the registry and the
OSV vulnerability database. An established package goes straight to a
permission prompt with that evidence. An unknown one is researched first by a
read-only subagent. You approve once, and only then does the install run,
pinned to the exact version you saw.

Approval is per `name@version`, recorded in the project, and committed with
it, so teammates do not approve the same package again.

---

## Requirements

| Need | Notes |
|---|---|
| macOS, Linux or WSL2 | Native Windows is not supported. |
| Claude Code | Hooks must be enabled (they are by default). |
| `uv`, or Python 3.11+ | The installer adds `uv` to `~/.local/bin` if it is missing. Every machine that runs Claude Code in the project needs one of them. |
| `git` | For the installer. |
| Network access to `registry.npmjs.org`, `pypi.org` and `api.osv.dev` | Without it, reviews fail and nothing is installed. |

There are no package dependencies: the guard uses the Python standard library
only, and writes nothing outside your project.

---

## Install

**1. Install into your project.**

```bash
git clone --depth 1 --branch release https://github.com/Fefar-AT/package-guard.git ~/.cache/package-guard
sh ~/.cache/package-guard/install.sh /path/to/your-project
```

A path that does not exist yet becomes a new project, with `git init`. Once
the repository is public, this one-liner does the same from inside a project:

```bash
curl -fsSL https://raw.githubusercontent.com/Fefar-AT/package-guard/release/install.sh | sh
```

**2. Commit.** The installer prints the exact `git add` and `git commit` to run.

**3. Start Claude Code** in the project (restart it if it was open) and run
`/hooks`. `PreToolUse` → `Bash` must be listed.

**4. Try it.** Ask Claude to add a package, for example "add date-fns". You
should get one permission prompt showing the package's evidence.

Check an install at any time:

```bash
python3 ~/.cache/package-guard/install.py /path/to/your-project --check
```

**Upgrade:** run step 1 again. **Remove:**
`python3 ~/.cache/package-guard/install.py /path/to/your-project --uninstall`.
Removal keeps `vetted.json` and `declined.json`, your record of decisions.

---

## What you will see

1. Claude runs one install command for everything it needs.
2. The guard stops it and lists each package as `established` (it passed the
   guard's own checks: age, release history, downloads, a matching source
   repository, no lookalike of a far more popular name, no install script, no
   known advisory, an allowed license) or `unresolved`.
3. For unresolved packages Claude starts the `package-vetter` subagent, which
   researches them and returns `RECOMMEND`, `NEEDS_HUMAN_REVIEW` or
   `DO_NOT_RECOMMEND` with its reasons.
4. **You get one permission prompt** listing every package with its evidence
   and, where it ran, the vetter's verdict.
5. Yes records those exact versions in `.claude/package-guard/vetted.json`,
   and Claude installs them. No installs nothing.

Packages you already approved install with no prompt and no network call.

## What changes for you

| You will notice | Why | What to do |
|---|---|---|
| Claude will not run `git pull`, or a checkout that touches the guard's files | Incoming commits could change the guard or its approvals | Run it yourself: `! git pull` in Claude Code, or your terminal |
| Claude will not edit `.claude/settings.json` or the guard's files | So Claude cannot switch the guard off | Edit them yourself |
| An install whose `postinstall` runs a script file is refused | The guard cannot see what that file installs | Let Claude add `--ignore-scripts`, or run it yourself |
| `uv sync` refuses a sub-package with no `[build-system]` | Its default build backend would run unreviewed | Pin the build backend in that `pyproject.toml` |
| A version range in `package.json` or a requirements file is refused | The guard approves exact versions only | Pin with `npm install --package-lock-only`, `uv lock` or `uv pip compile`; the message names the command |

Claude installs packages with `npm`, `npx`, `pip` and `uv` only. `pnpm`, `yarn`,
`bun`, `pipx`, `poetry` and `conda` are refused.

---

## Optional: the sandbox

Without it, the guard gates every install, but a script Claude runs could
still rewrite the guard's own files. The Claude Code sandbox closes that:

```bash
PG_SANDBOX=1 sh ~/.cache/package-guard/install.sh /path/to/your-project
```

It protects the guard's files and approvals from every Bash command, and keeps
the network open, so there is no list of websites to maintain. It needs Claude
Code v2.1.186 or later, and on Linux or WSL2 `bubblewrap` and `socat`
(`sudo apt-get install bubblewrap socat`).

It still confines every command Claude runs in the project:

- writes outside the project fail, unless the path is added to
  `sandbox.filesystem.allowWrite` in `.claude/settings.json`;
- git over SSH fails on macOS, so use HTTPS remotes;
- Docker does not run inside it;
- Claude's WebFetch tool can open any website without asking.

---

## Commands

Claude runs these for you; you see a permission prompt for each one that
changes a decision. Prefix each with
`uv run --no-project --no-config --no-python-downloads`.

```bash
.claude/hooks/package_guard/cli.py show <review-id>...       # show reviews
.claude/hooks/package_guard/cli.py approve <review-id>...    # approve exact versions
.claude/hooks/package_guard/cli.py decline <review-id>...    # never install this version
.claude/hooks/package_guard/cli.py undecline <review-id>...  # reverse a decline
.claude/hooks/package_guard/cli.py revoke <review-id>...     # withdraw an approval
.claude/hooks/package_guard/cli.py audit                     # re-check approvals against OSV
```

`audit` exits 1 on a malware hit, so it can gate CI.

**Shared trust catalog.** The guard ships a list of well-known package
identities. To keep your own copy across projects, run the installer with
`--init-user-trust`; it creates `~/.config/package-guard/trusted-packages.json`
once and never overwrites it. A catalog match only saves research. Every
version still needs your approval in each project.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The clone asks for a password or says "not found" | The repository is private and your GitHub account has no access | Ask the maintainer for access; run `gh auth login` |
| Every command is denied with "no runner found" | Claude Code started from the macOS dock without `~/.local/bin` on PATH | Start `claude` from a terminal |
| A package installs with no prompt | The hooks are not loaded | Restart Claude Code in the project root; run `--check` |
| A refusal that does not start with `PACKAGE_GUARD_` | Something other than the guard blocked it | Read the message; the guard is not involved |
| `PACKAGE_GUARD_ERROR` on every review | The registries or `api.osv.dev` are unreachable | Check your network or proxy |
| With the sandbox on Linux, Claude Code will not start | `bubblewrap` or `socat` is missing | Install them, or re-install without `PG_SANDBOX=1` |

Do not run another package-gating hook alongside this one; two gates on the same
commands confuse Claude and can let packages through the other one's path.

---

## Limits

- **Dependencies of dependencies are checked, not reviewed.** For npm and uv
  projects the guard reviews direct dependencies; the rest of the lockfile is
  checked against OSV, and known malware anywhere blocks the install. A
  requirements file from `uv pip compile` lists everything, so everything in it
  is reviewed.
- **A script file can hide an install.** For `npm run`, `make` or `bash x.sh`,
  the guard sees only the outer command. Claude is told to run any install
  such a script makes as its own command first, and anything that reaches disk
  unapproved is reported afterwards.
- **A source-only PyPI release** is flagged on the prompt, because its build
  backend runs unreviewed.
- **The evidence cannot prove a package is safe.** Approval means you accepted
  what the guard and the vetter found, not that the package is harmless.
