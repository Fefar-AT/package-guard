# Package Guard: details

The short version is in the [README](README.md). This page holds everything
else: other ways to install, setup for an organization, Windows, Docker
Sandboxes, requirements, the full list of what you will see, commands, every
troubleshooting row and the limits.

- [Install](#install)
- [Logging in to GitHub](#logging-in-to-github)
- [Requirements](#requirements)
- [What gets added to your project](#what-gets-added-to-your-project)
- [What you will see](#what-you-will-see)
- [What changes for you](#what-changes-for-you)
- [Supported package managers](#supported-package-managers)
- [Frappe / ERPNext](#frappe--erpnext)
- [Turning it down: modes](#turning-it-down-modes)
- [Optional: the sandbox](#optional-the-sandbox)
- [Commands](#commands)
- [Troubleshooting](#troubleshooting)
- [Limits](#limits)
- [Feedback](#feedback)

---

## Install

Package Guard is a Claude Code plugin. Find your role:

- [Team members](#team-members): the plugin arrives by itself.
- [The Owner](#the-owner-one-time-setup): connects the repository once.
- [Outside members](#outside-members): install it yourself.
- [Fallback: install from files](#fallback-install-from-files): for a machine
  without the plugin.

**Everyone needs `uv`, once.** Install it from <https://docs.astral.sh/uv/>.
You do not need to install Python: the plugin installs Python 3.11 by itself at
the start of a session if it is missing. Until `uv` is there, the guard blocks
Bash commands and file edits, and tells you what to run.

### Team members

Nothing to install. Your organization's Owner has added Package Guard to the
claude.ai team, and it syncs to you.

- Sign in to Claude Code with your **claude.ai account** (Claude Code v2.1.273
  or newer). A session that uses an API key does not get synced plugins.
- Once it is **Required**, you cannot turn it off. While it is only **Available
  to install**, install it from the plugin list.
- Then, once per project, run `/package-guard:setup`. Claude shows you a
  command; run it yourself by typing it with a `!` in front.

### The Owner: one-time setup

On the Team plan, in claude.ai:

1. Go to **Organization settings → Plugins & skills → Add → Sync from GitHub**
   and connect `Fefar-AT/package-guard`.
2. Set availability to **Available to install** first, and pilot it with a few
   people. Include one project that was set up with `install.sh`, and one
   machine without `uv`.
3. Migrate every project that was set up with `install.sh`: run
   `/package-guard:setup` in it once. Until then both guards run there, and
   approvals cannot complete because each refuses the other's approve command.
   Setup removes the old hooks and keeps the approvals.
4. When the pilot is happy and those projects are migrated, switch it to
   **Required**. Members cannot turn off a Required plugin.

Good to know:

- Org sync reads only the `main` branch and re-syncs on every push, so a new
  release goes live for everyone.
- The repository is public and lives on a personal GitHub account. Whether org
  sync accepts a personal-account repository is not documented. If it refuses,
  move the repository into a GitHub organization.

### Outside members

You are not in the organization, so you install the plugin yourself (Claude
Code v2.1.292 or newer).

1. Install (the repository `Fefar-AT/package-guard` is public; no GitHub
   login is needed):

   ```bash
   claude plugin install package-guard --marketplace Fefar-AT/package-guard
   ```

   The same in two steps:

   ```bash
   claude plugin marketplace add Fefar-AT/package-guard
   claude plugin install package-guard@package-guard
   ```

2. Once per project, run `/package-guard:setup` (type the command Claude shows
   you with a `!` in front).

Claude asks where to install: **user** (all your projects), **project** (shared
with the repository) or **local** (only you, in this project). Auto-update is
off by default, and turning it on needs a git credential helper (the Credential
Manager or `gh auth login` below set one up).

### Windows

- Native Windows needs **Git for Windows** (Git Bash) in this release.
- Claude may try the PowerShell tool. The guard refuses PowerShell commands
  because it cannot inspect them. Set `CLAUDE_CODE_USE_POWERSHELL_TOOL=0` under
  `env` in your user settings so Claude uses Git Bash instead.
- The guard is set to block when its hook cannot start; that needs Claude Code
  v2.1.295 or newer.
- Full PowerShell support is planned.
- WSL2 behaves like Linux.
- Or run Claude Code in a Docker sandbox, with no WSL2 and no Git for
  Windows: see [Docker Sandboxes](#docker-sandboxes-sbx).
- The install.sh fallback does not run on native Windows. Use the plugin.

### Docker Sandboxes (`sbx`)

[Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) run Claude Code in a
small Linux VM, on Windows without WSL2 or Docker Desktop (Windows 11 x64 with
the Windows Hypervisor Platform turned on). The project folder is mounted into
the VM, and the guard runs there as on any Linux machine.

Once per machine:

```powershell
winget install -h Docker.sbx      # macOS: brew install docker/tap/sbx
sbx login
sbx policy init balanced
```

Then, from the project folder: create the sandbox, let it reach the guard's
evidence sources, install the guard in it, and start Claude.

```powershell
sbx create --name myproj claude .
sbx policy allow network --sandbox myproj "api.osv.dev,api.npmjs.org,hugovk.dev,pypistats.org,api.deps.dev,data.jsdelivr.com,inspector.pypi.io,releases.astral.sh,python-downloads.astral.sh,registry.yarnpkg.com,codeload.github.com"
sbx exec myproj -- sh -c "curl -fsSL https://raw.githubusercontent.com/Fefar-AT/package-guard/release/install.sh | sh -s -- ."
sbx run --name myproj
```

The `balanced` preset blocks those hosts, and without `api.osv.dev` every
review is denied; `--sandbox` keeps the rule to this one sandbox. The install
writes into your project folder, so commit it as usual. A new sandbox on a
project that already carries the guard still needs the `policy allow` and
`curl` lines: they set up Python 3.11 inside it and leave the project as is. Git for Windows checks out files with CRLF by
default, and a CRLF `run.sh` blocks every command; the installer adds
`.gitattributes` lines that keep the guard's files LF.

#### A Frappe bench, and Yarn Classic, in a sandbox

Frappe's JavaScript uses Yarn Classic (1.x), and a bench lives in a folder with
`apps/` and `sites/`. The guard runs in the sandbox as above; these are the
differences.

**The hosts.** Yarn Classic downloads every tarball from `registry.yarnpkg.com`,
and some Frappe locks pin a GitHub tarball on `codeload.github.com`. The command
under "Then, from the project folder" already lists both. To add them to a
sandbox you have already made, run this one command (it is the whole list, so it
is safe to run again):

```powershell
sbx policy allow network --sandbox myproj "api.osv.dev,api.npmjs.org,hugovk.dev,pypistats.org,api.deps.dev,data.jsdelivr.com,inspector.pypi.io,releases.astral.sh,python-downloads.astral.sh,registry.yarnpkg.com,codeload.github.com"
```

If a bench step still fails to download, a host is missing: look at your `sbx`
version's log of blocked requests, add the host with the same command, and tell
us which one it was.

**What the guard does with a Yarn Classic project.** It reads `yarn.lock` and
every `.yarnrc` whatever line endings Git for Windows gave them (CRLF is read as
LF; a stray lone CR is refused). An install must carry `--frozen-lockfile` and
`--ignore-scripts`. They may instead be set in `.yarnrc`, but only when the guard
can show that the `yarn` on the command's PATH is Yarn Classic 1.x (it looks at
where `yarn` points, through links and Corepack shims, and never runs it); a Berry
`yarn` is refused, and one the guard cannot identify counts only the two flags on
the command, which Berry rejects. `YARN_IGNORE_SCRIPTS=true` in front of the command
counts as `--ignore-scripts` under the same condition. A `.yarnrc` that the guard
cannot read exactly the way Yarn does (for example a value like `trueish`) is not
counted. A lock that points at a GitHub tarball or a git commit is refused unless a baseline you approved lists it.

**What the kit prints.** When the sandbox's folder is a bench, the kit's start
step prints the next steps and writes nothing: ask Claude to plan a baseline
for each app in `apps/`, approve each plan, then ask for `bench-config apply`.
Open Claude at the bench folder, not inside an app: a session started in
`apps/<app>` may not load the bench folder's guard. These steps, and the line
that tells Claude how a bench is installed, are in kits built from a guard that
supports benches; a kit built from an older one leaves them out.

**What stays yours.** `bench init`, `bench get-app` and `bench update` are run
by you, inside the sandbox, for example
`sbx exec myproj -- bench init --frappe-branch version-15 frappe-bench`. The
guard does not install Python, Node, MariaDB or Redis for you either: put them
in the sandbox's image, or install them yourself.

**Links on a Windows folder.** Bench's Python environment (`env/`) is made of
links. Whether the project folder on your PC accepts them inside the sandbox is
not confirmed yet. To find out, run `ln -s a b` in that folder from the sandbox.
If it fails, keep the bench on the sandbox's own disk and install the guard
there. The kit sets `UV_LINK_MODE=copy` so that uv's own copies are quiet.

### Setup

`/package-guard:setup` tells you what it will write (the approval records, a
`## Packages` section in `CLAUDE.md`, `.gitignore` lines), asks, and writes it.
A project with the older file-based install is migrated: the old hooks are
removed so they never run twice, and your approvals are kept. Without setup the
gate still works; nothing is pre-approved, so every new package needs your
approval.

### Fallback: install from files

For a machine without the plugin, on macOS, Linux or WSL2. The repository is public, so
the one-liner works with no login:

```bash
curl -fsSL https://raw.githubusercontent.com/Fefar-AT/package-guard/release/install.sh | sh -s -- /path/to/your-project
```

Or clone it first, or use a ZIP:

```bash
git clone --depth 1 --branch release https://github.com/Fefar-AT/package-guard.git ~/.cache/package-guard
sh ~/.cache/package-guard/install.sh /path/to/your-project
```

With a ZIP, unzip it and run `sh <folder>/install.sh /path/to/your-project`.

A path that does not exist yet becomes a new project (`git init` included). The
installer adds `uv` to `~/.local/bin` if you do not have it, and a
uv-managed Python 3.11 if uv cannot find one, then prints the next steps. Run
the `git add` and `git commit` it printed, start `claude` (restart it if it
was open) and run `/hooks`: `PreToolUse` → `Bash` must be listed.

**Upgrade:** pull and run the installer again:

```bash
git -C ~/.cache/package-guard pull --ff-only
sh ~/.cache/package-guard/install.sh /path/to/your-project
```

**Check**, and see the version it runs:
`python3 ~/.cache/package-guard/install.py /path/to/your-project --check`.

**Remove:**
`python3 ~/.cache/package-guard/install.py /path/to/your-project --uninstall`.
Removal keeps `vetted.json` and `declined.json`, your record of decisions.

**Optional sandbox:** see [the sandbox](#optional-the-sandbox).

If you later get the plugin, run `/package-guard:setup` once in each such
project. It removes the old hooks and keeps your approvals; until then both
guards run and approvals cannot complete.

**Try it** in either case: ask Claude to add a package, for example "add
date-fns". You should get one permission prompt showing the package's evidence.

## Logging in to GitHub

The repository is public: cloning it, the `curl | sh` install and the plugin
install need **no GitHub login**. You need one only to install from a private
fork, or for plugin auto-update if Claude Code asks for a credential helper.
Then pick one way, do it once in a terminal (not through Claude), and git
remembers it (**GitHub does not accept your account password for git**):

1. **GitHub CLI.** Run `gh auth login`, choose **GitHub.com**, then **HTTPS**,
   then **Login with a web browser**. It also sets up git for you.
2. **Git Credential Manager.** It signs you in through the browser. It comes
   with Git for Windows; on macOS run `brew install --cask git-credential-manager`.
3. **A personal access token.** Create one in your GitHub settings, and paste
   it when git asks for the password.

Check access: `git ls-remote https://github.com/Fefar-AT/package-guard.git`
should print lines. If it hangs or fails, the network to github.com is the
likely cause (a proxy, or a sandbox rule), not a login.

Other ways in:

- **SSH.** Install with `PG_REPO=git@github.com:Fefar-AT/package-guard.git sh install.sh <project>`.
- **A ZIP.** Download it from GitHub in the browser, or ask the maintainer to
  send one, unzip it and run `sh <folder>/install.sh <project>`. For the plugin,
  `claude plugin marketplace add ./<folder>` works, but it never updates itself.

Why a terminal: when Claude runs a command, nobody can type a password or answer
a browser prompt, so a missing login fails instead of asking.

---

## Requirements

| Need | Notes |
|---|---|
| Claude Code | Hooks must be enabled (they are by default). Team members need v2.1.273 or newer, outside members v2.1.292 or newer. |
| `uv` | Install it once from <https://docs.astral.sh/uv/>. The guard runs on Python 3.11 exactly, and nothing else. The plugin installs it through `uv` at the start of a session; the install.sh fallback also adds `uv` to `~/.local/bin` if it is missing. A newer Python alone does not count. |
| `git`, and for outside members a GitHub login with access to this repository | See [Logging in to GitHub](#logging-in-to-github). |
| Network access to `registry.npmjs.org`, `pypi.org` and `api.osv.dev` | Without it, reviews fail and nothing is installed. |

Every machine that runs Claude Code in a guarded project needs `uv`. Without
it, Bash commands and file edits are blocked, with a message that says what to
run. There are no package dependencies: the guard uses the Python standard
library only.

---

## What gets added to your project

With the plugin, `/package-guard:setup` writes only the approval records under
`.claude/package-guard/`, a `## Packages` section in `CLAUDE.md` and a few
`.gitignore` lines. The guard itself lives in the plugin. Review them before
you commit them.

With the install.sh fallback, the installer adds all of this:

- `.claude/hooks/package_guard/`: the guard, with a `VERSION` file
- `.claude/agents/package-vetter.md` and `.claude/skills/package-guard/`
- `.claude/settings.json`: the guard's hooks and deny rules, merged into what
  is already there
- `.claude/package-guard/`: `vetted.json`, `declined.json` and
  `reports/.gitignore`, your approvals
- `CLAUDE.md`: a `## Packages` section, appended
- `.gitignore`: four lines for the guard's machine-local files

Outside the project, the installer writes only the clone in
`~/.cache/package-guard`, and `uv` in `~/.local/bin` and a uv-managed Python
3.11 if they were missing.

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

Claude installs packages with `npm`, `npx`, `pip`, `uv`, `pnpm`, `bun` and Yarn
Berry 4.14+, and in a Frappe bench Yarn Classic and `bench`. `pipx`, `poetry`,
`conda` and `corepack` are refused.

### Supported package managers

| Manager | What the guard needs | Notes |
|---|---|---|
| `npm`, `npx` | `package-lock.json` for a bare install | The baseline the others follow |
| `pnpm`, `pnpx`/`pnx` | `pnpm-lock.yaml` (v9); `packageManager` is optional but must be an exact reviewed version | Scripts off (`--ignore-scripts`) or `onlyBuiltDependencies` listing only reviewed packages, in `pnpm-workspace.yaml` or the `pnpm` key of `package.json` |
| `bun`, `bunx` | A text `bun.lock` (not `bun.lockb`) | Scripts off or `trustedDependencies` (even `[]`); `bun install` before `bun run` when there is no `node_modules` |
| `yarn`, `yarnpkg` | A Berry `yarn.lock`, `packageManager: yarn@4.14.0` or newer, `nodeLinker: node-modules` in `.yarnrc.yml` | `--mode=skip-build` turns scripts off; bare `yarn` is an install |
| `pip`, `uv` | As before | The guard's own runner is uv with exactly Python 3.11; your project's uv and pip are unchanged |
| `pipx`, `poetry`, `conda`, `corepack` and Plug'n'Play | Not supported | Refused by the hook |
| Yarn Classic (v1), `bench` | A baseline for each upstream app and the guard's installer files | Gated, not refused: see [Frappe / ERPNext](#frappe--erpnext) |

The same rules apply to every supported manager: exact versions only, each
reviewed and approved before it installs, one manager per project, no
alternate registry, no code loaded from `.pnpmfile.cjs`, a Bun `preload`, a
Yarn `yarnPath` or a plugin. `pnpm-workspace.yaml`, `.yarnrc.yml`, `bunfig.toml`
and the pnpm `.npmrc` keys are read, not refused outright: only known-safe keys
pass, and an unknown key is refused by name (a `packages:` list or a registry
setting is refused). Workspaces and catalogs are refused. The project's
`packageManager` pin (`pnpm@X.Y.Z`, `yarn@4.X.Y`) is reviewed once like a
package. Use `yarn run <script>`, not `yarn <script>`. Known gaps:
`pnpm update`, `bun update` and `yarn up` can move a package within its existing
range (as `npm update` does), Yarn's lock checksums cannot be compared with
npm's integrity digests, and the
cache layouts the disk check reads have not been verified against real
managers.

---

## Frappe / ERPNext


**What the guard does.**

- The packages of Frappe, ERPNext and HRMS come from their releases, not from
  Claude. You approve them **once per Frappe release**, as one list (a
  *baseline*), instead of package by package. The baseline is kept with the
  project's guard files, so the whole team shares it.
- The packages your own app adds are checked **one by one**, like any project.
  A typo such as `reqeusts-toolbelt` goes to review, never straight in.
- The fake `frappe` or `erpnext` on PyPI is **blocked**, whatever has been
  approved: those names are apps in your bench, never downloads.
- Old packages have known bugs. The guard **shows** them when you approve a
  baseline and does not block on them. Known malware always blocks, on every
  Frappe version.
- Install scripts stay off. A package fetched from GitHub is allowed only as a
  full commit from an owner you allowed (`frappe`, `quilljs`), and only when a
  baseline you approved lists it.
- `bench-config apply` writes the files bench's own installs read
  (`env/pip.conf`, `uv.toml`, a `.yarnrc` in each app), so that
  `bench setup requirements` installs exactly what the baselines list. The guard
  checks them before every bench install and refuses if they were changed.
- The plan text says a baseline "pins and checks this set; it does not prevent
  a package outside it from installing". That is about the baseline alone. What
  stops a package outside it is the review: Claude cannot install a package that
  neither a baseline nor you approved, and a name that does not exist is refused.

**The five commands you run**, in your own terminal, in the bench folder (only
`baseline approve` and `baseline revoke` are yours alone):

```sh
sh .claude/hooks/package_guard/pg baseline plan --app apps/frappe   # write a proposal and show it
sh .claude/hooks/package_guard/pg baseline approve bl-<id>          # approve it: you read the prompt
sh .claude/hooks/package_guard/pg bench-config apply                # write the installer files (Claude may run it too: you get a prompt)
sh .claude/hooks/package_guard/pg bench-config check                # do they still hold?
sh .claude/hooks/package_guard/pg baseline revoke bl-<id>           # take an approval back
```

Do `plan` and `approve` once for each app in `apps/` that is not your own
(`frappe`, `erpnext`, `hrms`), then `apply`. Plan again, approve and `apply`
when you move to a new Frappe release.

A bench has one Python env, and ERPNext runs on Frappe, so the baselines of one
bench must agree on the packages they share. `baseline plan` therefore works out
a new app together with the bench's other approved apps, in either order. If no
set of versions fits all of them, the plan says so and names the packages that
clash. If `bench-config apply` refuses because two baselines you approved earlier
clash, plan the later app again and approve the new plan.

**Run again after you add an app.** `bench new-app` (and `bench get-app`, which
is yours to run) adds a folder the guard has not written files for. The next
bench command says a `.yarnrc` or another file is missing: run `bench-config
apply` again.

**Before `bench new-app`.** `bench new-app` installs the app it has just made,
before the guard could list it, and the guard's `uv.toml` lets uv build only the
apps it lists. So name the new app first, then let bench create it:

```sh
sh .claude/hooks/package_guard/pg bench-config apply --new-app myapp
```

Claude may run this too, with the prompt showing the name; allow it only when
`myapp` is the name of a new app of yours and not the name of a package from an
index. Once the app exists the name is dropped and the app is listed like any
other. If you skip this step, `bench new-app` makes the folder and then fails at
the install ("Building source distributions for `myapp` is disabled"): run the
command above and `bench setup requirements`.

The build tool of a new app (`flit-core` in the app bench makes) comes from your
approved Frappe baseline, so `bench new-app` can build it. Your app's own list
still counts as one of your packages, so the next `bench setup requirements`
asks for one review of it, once.

**Which command form.** The `pg` lines above are for you, in your terminal.
Claude cannot use `pg`; when it needs `bench-config apply` or `baseline plan`
the hook gives it the exact form to run, `uv run --no-project --no-config
--no-python-downloads <project>/.claude/hooks/package_guard/cli.py bench-config
apply`. Either way you answer the prompt for `apply`.

**Yarn must be visible to the guard.** Every bench command that runs Yarn (an
install, and a build in an app that has a `build` script and no `node_modules`)
needs Yarn Classic 1.x on the PATH the guard sees, which is the PATH Claude Code
was started with. nvm and volta often set `yarn` only inside your shell. If the
guard says the `yarn` it finds "is not shown to be Yarn Classic", start Claude
Code from a shell where `yarn --version` prints 1.x, then try again.

**The same checks as a plain `yarn install`.** Whatever a bench command runs
Yarn on in your own apps gets what a direct `yarn install` there gets: the lock
may name only the npm registry, every direct package is reviewed, the whole
tree is checked for known malware, and `.npmrc` files (the app, its parents,
your home folder, the system ones) may not name a proxy, a certificate
authority, switch TLS checking off or point at another registry. A build that
would install in an app added after the last `bench-config apply` is refused
until you apply again.

**Which folders are checked.** Only the folders where Yarn really runs: each
app's own folder, plus a sub-folder that a script in the app's `package.json`
runs Yarn in (`cd banking && yarn install`, `yarn --cwd ui build`). A folder with
a `package.json` that no script names, such as Frappe's `ui/`, is not checked,
because bench never runs Yarn there. If a script is too dynamic to follow (it
uses a variable, backticks or `~`), every folder of that app that has a
`yarn.lock` is checked.

**ERPNext 16 and `banking/`.** ERPNext's build runs `cd banking && yarn build`,
and its `postinstall` (`cd banking && yarn install`) does not run, because the
guard keeps install scripts off. So `banking/` has no `node_modules` and the
build cannot find its tools. When that is the case the guard says so in the
answer to `bench build` and names the command: with `apps/erpnext/banking` as the
working directory, as its own command, run `yarn install --frozen-lockfile
--ignore-scripts`. An approved ERPNext baseline already covers `banking/yarn.lock`,
so that command is allowed without a review per package. If the lock was
changed after the approval, the baseline no longer covers it and every package
is reviewed instead.

**Adding a JavaScript package to your own app.** Your app uses Yarn Classic
(version 1). A package that `package.json` lists and `yarn.lock` does not have
goes to review by name and exact version, like `npm install name@1.2.3`; a typo
that does not exist on npm is refused outright. Nothing that runs `yarn` in that
app is allowed until the lock has it. After you approve, Claude removes the line
from `package.json` and adds the package the Classic way, inside the app's
folder: `yarn add <name>@<exact version> --ignore-scripts`. That writes
`package.json` and `yarn.lock`.

**What Claude may do.** Run `baseline plan`, `show`, `list` and
`bench-config check` and `bench-config apply` (you get a prompt and decide);
run `bench setup requirements`,
`bench update --requirements`, `bench new-app` and `bench build` once the
baselines and the installer files hold; install a package into the bench's env
with an exact version after review (`bench pip install name==1.2.3`).

**What Claude may not do.** Approve a baseline, add a trusted GitHub owner, or
change the installer files by hand; run `bench init`,
`get-app`, `update` with anything but `--requirements`, `switch-to-branch`,
`setup env`, `migrate-env` or the system installers (`bench install`,
`setup production`, `setup role`): those stay yours. Open Claude at the bench
folder, not inside an app.

**Versions.** Run on a real bench in the sandbox lab: frappe-bench 5.31.1 with
Frappe 15.124.0 and ERPNext 15.124.1 (Python 3.11, Node 20, Yarn 1.22.22).
bench 5.31.1 makes the env with `uv venv` and installs with `uv pip install -e`;
it does not use pip. Frappe 16.53.0 and ERPNext 16.52.1 (Python 3.14, Node 24)
ran on the same lab: plan, approve, apply, `bench setup requirements`, `bench
build` with ERPNext's `banking/` route, and the site served its login page; the
typo, fake `frappe` and malware installs were refused on both versions. The
tests run the whole flow offline on v15. Frappe v14 uses the same steps as v15
but has not been run on a real bench. Frappe v11 to v13 use older Python and Node: their baselines are planned
from recorded runs, show many more known bugs, and have not been run on a real
bench.

## Turning it down: modes

Most people who want the guard off want past one block. Try these first:

1. **One package was refused and you trust it.** Approve it at the prompt
   Claude shows you, or ask Claude to open a review for it. Approvals are per
   `name@version` and per project.
2. **A refusal looks wrong.** Ask Claude to show you the review
   (`cli.py show <review-id>`). If the guard is wrong, that is a bug worth
   reporting.

To turn the guard down, use its mode switch from your own terminal, in the
project folder. `pg` is a short launcher for people: it runs the same CLI on
the same Python 3.11 as the hooks.

```bash
sh .claude/hooks/package_guard/pg mode                                  # show every layer and the last log lines
sh .claude/hooks/package_guard/pg mode warn --reason demo               # refusals become warnings, for 24h
sh .claude/hooks/package_guard/pg mode off --reason incident --for 8h   # installs are not checked, for 8h
sh .claude/hooks/package_guard/pg mode off --reason hobby --permanent   # no expiry
sh .claude/hooks/package_guard/pg mode warn --reason socket --project   # mode.json, for everyone; commit it
sh .claude/hooks/package_guard/pg mode enforce                          # back on (add --project for mode.json)
```

Run these in a separate terminal window, not with `!` inside Claude Code:
`!` commands have no terminal to type the confirmation in. With the plugin
there is no `pg`; ask Claude to run `mode warn`, and the guard's message
prints the full command to paste into your terminal.

- **Three modes.** `enforce` (the default) refuses unvetted packages. `warn`
  lets them through with a warning, and your normal permission prompt still
  shows. `off` does not check installs at all.
- **Layers.** A machine policy (`/Library/Application Support/PackageGuard/policy.json`,
  `/etc/package-guard/policy.json` or `%ProgramData%\PackageGuard\policy.json`)
  wins, and with `"locked": true` nothing below it can change the mode. Then
  your personal setting (`.mode.local.json`, gitignored), then the project's
  (`mode.json`, committed), then `enforce`.
- **Expiry.** A setting lasts 24 hours unless you pass `--for 30m|8h|7d` or
  `--permanent`; then the guard is back on by itself.
- **Only you can turn it down.** The hook refuses `mode warn` and `mode off`
  from Claude and gives it the command for you. The CLI needs a terminal and
  asks you to type the mode name.
- **You will see it.** Claude Code shows a banner once per session while the
  guard is down, and each change is logged in `.mode-log.jsonl`.
- **Coming back on reviews the gap.** When `enforce` returns, every new
  package that is not vetted becomes an open finding, and is handled like any
  other.
- **Protection of the guard itself stays in every mode.** Writes to guard
  files, git operations on them and malformed CLI calls are still refused.

---

## Optional: the sandbox

This is for the install.sh fallback. Without it, the guard gates every install, but a script Claude runs could
still rewrite the guard's own files. The Claude Code sandbox closes that:

```bash
PG_SANDBOX=1 sh ~/.cache/package-guard/install.sh /path/to/your-project
```

It protects the guard's files and approvals from every Bash command, and keeps
the network open, so there is no list of websites to maintain. It needs Claude
Code v2.1.186 or later, and on Linux or WSL2 `bubblewrap` and `socat`
(`sudo apt-get install bubblewrap socat`).

**Already opted in?** The list of writable places grew. After you update the guard,
`install.py --check` fails on a sandboxed project and names the entries it lacks.
Run the installer once more with `--sandbox` (`PG_SANDBOX=1 sh
~/.cache/package-guard/install.sh <project>`): it only adds, and your own entries
stay.

It still confines every command Claude runs in the project:

- writes outside the project fail, unless the path is added to
  `sandbox.filesystem.allowWrite` in `.claude/settings.json`. The installer lists
  the package managers' own places: `~/.npm`, `~/.cache/uv`, `~/.cache/pip`,
  `~/Library/Caches/pip`, and for Yarn Classic and bench `~/.cache/yarn`,
  `~/.yarn`, `~/.config/yarn`, `~/.yarnrc` and `~/.cache/bench`. The guard reads
  those Yarn files before every yarn command, so a write to them is checked
  before the next install;
- git over SSH fails on macOS, so use HTTPS remotes;
- Docker does not run inside it;
- Claude's WebFetch tool can open any website without asking.

---

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

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The clone fails, hangs, or says "not found" | Usually no network access to github.com (a proxy, or a sandbox rule); or `PG_REF` names no branch; or `PG_REPO` is a private fork | Check the network first (in sbx: `sbx policy allow network --sandbox <name> github.com`); the installer prints git's own error. Private fork: [Logging in to GitHub](#logging-in-to-github) |
| Every Bash command or file edit is blocked and the message names `uv` | `uv` is not installed | Install it once from <https://docs.astral.sh/uv/>, then start a new session |
| Two guards run, and approvals never complete | The project still has the install.sh hooks next to the plugin | Run `/package-guard:setup` in the project once |
| Claude cannot use PowerShell | The guard refuses PowerShell commands | Set `CLAUDE_CODE_USE_POWERSHELL_TOOL=0` under `env` in your user settings |
| The clone says "Repository not found" although you have access | Your git config sends GitHub URLs over SSH (`url...insteadOf`) with a key from another account | Run `git config --global --get-regexp insteadof`, and remove the rule or use the account's SSH key |
| The upgrade's `git pull` asks for a username | git cannot use your `gh` login | Run `gh auth setup-git` once |
| Every command is denied with "no runner found", and `uv` is installed | Python 3.11 is missing, and the install at session start failed or has not run yet | Run `uv python install 3.11` in a terminal, then start a new session |
| A package installs with no prompt | The hooks are not loaded | Restart Claude Code in the project root; run `--check` |
| A refusal that does not start with `PACKAGE_GUARD_` | Something other than the guard blocked it | Read the message; the guard is not involved |
| `PACKAGE_GUARD_ERROR` on every review | The registries or `api.osv.dev` are unreachable | Check your network or proxy |
| With the sandbox on Linux, Claude Code will not start | `bubblewrap` or `socat` is missing | Install them, or re-install without `PG_SANDBOX=1` |

Do not run another package-gating hook alongside this one; two gates on the same
commands confuse Claude and can let packages through the other one's path.

---

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

---

## Feedback

Open an issue at https://github.com/Fefar-AT/package-guard/issues and include
the `installed vX` line that `--check` prints.
