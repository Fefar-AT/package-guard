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

> **Before you install**
>
> - macOS, Linux or WSL2 only. Native Windows is not supported.
> - Claude installs packages with `npm`, `npx`, `pip` and `uv` only. `pnpm`,
>   `yarn`, `bun`, `pipx`, `poetry` and `conda` are refused, so a project that
>   uses one of them cannot use the guard yet.
> - Internal use only. Do not share it outside the organization.

---

## Requirements

| Need | Notes |
|---|---|
| Claude Code | Hooks must be enabled (they are by default). |
| `uv`, or Python 3.11+ | The installer adds `uv` to `~/.local/bin` if it is missing. Every machine that runs Claude Code in the project needs one of them. |
| `git` with a GitHub login that has access to this repository | An SSH key, an HTTPS login (keychain, Git Credential Manager, token), or `gh`. See step 1. |
| Network access to `registry.npmjs.org`, `pypi.org` and `api.osv.dev` | Without it, reviews fail and nothing is installed. |

There are no package dependencies: the guard uses the Python standard library
only.

---

## Install

**1. Fetch the guard and install it into your project.**

First time, clone with the GitHub login you already use (pick one line):

```bash
git clone --depth 1 git@github.com:Fefar-AT/package-guard.git ~/.cache/package-guard          # SSH key
git clone --depth 1 https://github.com/Fefar-AT/package-guard.git ~/.cache/package-guard      # HTTPS login
gh repo clone Fefar-AT/package-guard ~/.cache/package-guard -- --depth 1 && gh auth setup-git # gh, no git login yet
```

Then install:

```bash
sh ~/.cache/package-guard/install.sh /path/to/your-project
```

To upgrade later, pull and install again:

```bash
git -C ~/.cache/package-guard pull --ff-only
sh ~/.cache/package-guard/install.sh /path/to/your-project
```

A path that does not exist yet becomes a new project, with `git init`. Once
the repository is public, this one-liner does both from inside a project:

```bash
curl -fsSL https://raw.githubusercontent.com/Fefar-AT/package-guard/main/install.sh | sh
```

**2. Commit.** The installer prints the exact `git add` and `git commit` to run.

**3. Start Claude Code** in the project (restart it if it was open) and run
`/hooks`. `PreToolUse` → `Bash` must be listed.

**4. Try it.** Ask Claude to add a package, for example "add date-fns". You
should get one permission prompt showing the package's evidence.

Check an install, and the version it runs, at any time:

```bash
python3 ~/.cache/package-guard/install.py /path/to/your-project --check
```

**Remove:**
`python3 ~/.cache/package-guard/install.py /path/to/your-project --uninstall`.
Removal keeps `vetted.json` and `declined.json`, your record of decisions.

## What gets added to your project

Review these before you commit them:

- `.claude/hooks/package_guard/`: the guard, with a `VERSION` file
- `.claude/agents/package-vetter.md` and `.claude/skills/package-guard/`
- `.claude/settings.json`: the guard's hooks and deny rules, merged into what
  is already there
- `.claude/package-guard/`: `vetted.json`, `declined.json` and
  `reports/.gitignore`, your approvals
- `CLAUDE.md`: a `## Packages` section, appended
- `.gitignore`: four lines for the guard's machine-local files

Outside the project, the installer writes only the clone in
`~/.cache/package-guard`, and `uv` in `~/.local/bin` if it was missing.

## Feedback

Open an issue at https://github.com/Fefar-AT/package-guard/issues and include
the `installed vX` line that `--check` prints.

---

## What you will see

1. Claude runs one install command for everything it needs.
2. The guard stops it and lists each package as `established` (it passed the
   guard's own checks: age, release history, downloads, a matching source
   repository, no lookalike of a far more popular name, no install script, no
   known advisory, a known publisher) or `unresolved`. The license is shown,
   never a reason to hold a package back.
3. For unresolved packages Claude starts the `package-vetter` subagent, which
   researches them and returns `RECOMMEND`, `NEEDS_HUMAN_REVIEW` or
   `DO_NOT_RECOMMEND` with its reasons.
4. **You get one permission prompt for the recommended packages**, one
   line per package and a plain "Why" line:

   ```
   Package Guard — approve 2 recommended packages for this project
     pypi:pandas@3.0.6
     pypi:numpy@2.5.3

   Why: from the official PyPI registry, first published over a year ago, widely used (10,000+
   downloads a week), no known vulnerabilities or malware reports for these versions (checked today),
   nothing runs while installing, published from its own source repository.
   Approve these exact versions? To skip one or see details, reject and tell Claude.
   ```

   A package gets more lines only when there is something to weigh, such as
   a fresh release, few users or a license that is not permissive.
5. **Then one prompt for the packages the vetter left to you.** Claude
   first tells you in one line per package what it suggests:

   ```
   Package Guard — 1 package needs your decision
     pypi:django@6.1.2
       published 2 days ago
       Claude suggests: use pypi:django@6.1.1 instead
   Approve this exact version anyway? Rejecting installs nothing and declines nothing.
   ```

   The two kinds are never on one prompt. A package the vetter advises
   against, or whose name is one letter from a far more popular one, stays
   out of both: Claude tells you why and offers the alternative.
6. Yes records those exact versions in `.claude/package-guard/vetted.json`,
   and Claude installs them. No installs nothing. To skip one package, say no
   and tell Claude; it asks again for the rest. `cli.py show <review-id>`
   prints everything the prompt left out.

Packages you already approved install with no prompt and no network call.

## What changes for you

| You will notice | Why | What to do |
|---|---|---|
| Claude will not run `git pull`, or a checkout that touches the guard's files | Incoming commits could change the guard or its approvals | Run it yourself: `! git pull` in Claude Code, or your terminal |
| Claude will not edit `.claude/settings.json` or the guard's files | So Claude cannot switch the guard off | Edit them yourself |
| An install whose `postinstall` runs a script file is refused | The guard cannot see what that file installs | Let Claude add `--ignore-scripts`, or run it yourself |
| `uv add`, `uv sync` or `uv build` refuses a build backend range, such as `uv_build>=0.9,<0.10` | The build backend runs unreviewed unless it is pinned | Let Claude change that line to the exact version the message names. This is allowed and adds no dependency. An app created with `uv init --app --no-package` has no build backend |
| A version range in `package.json` or a requirements file is refused | The guard approves exact versions only | Pin with `npm install --package-lock-only --ignore-scripts`, `uv lock` or `uv pip compile`; the message names the command |
| `uv` cannot create `.venv` on a mount that refuses symlinks | The filesystem, not the guard | Put the environment elsewhere: `UV_PROJECT_ENVIRONMENT=/absolute/path uv sync --locked`. The guard checks that environment like `.venv` |

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
| The clone says "Repository not found" although you have access | Your git config sends GitHub URLs over SSH (`url...insteadOf`) with a key from another account | Run `git config --global --get-regexp insteadof`, and remove the rule or use the account's SSH key |
| The upgrade's `git pull` asks for a username | git cannot use your `gh` login | Run `gh auth setup-git` once |
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
