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

## Install

1. Install `uv` once, from <https://docs.astral.sh/uv/>. You do not need to
   install Python: the plugin installs Python 3.11 by itself at the start of a
   session if it is missing. Until `uv` is there, the guard blocks Bash
   commands and file edits, and tells you what to run.
2. Install the plugin (Claude Code v2.1.292 or newer; the repository is public,
   so no GitHub login is needed):

   ```bash
   claude plugin install package-guard --marketplace Fefar-AT/package-guard
   ```

3. In each project, run `/package-guard:setup`. Claude shows you a command;
   run it yourself by typing it with a `!` in front.

If you are in an organization, your Owner may have synced the plugin to you
already. Then skip step 2. See [Team members](DETAILS.md#team-members).

Other ways to install (Owner setup, Windows, Docker Sandboxes, a machine
without the plugin) are in [DETAILS.md](DETAILS.md#install).

Then try it: ask Claude to add a package, for example "add date-fns". You
should get one permission prompt showing the package's evidence.

---

## What you will see

Claude runs one install command for everything it needs. The guard stops it,
checks each package, and Claude asks you once:

```
Package Guard — approve 2 recommended packages for this project
  pypi:pandas@3.0.6
  pypi:numpy@2.5.3

Why: from the official PyPI registry, first published over a year ago, widely used (10,000+
downloads a week), no known vulnerabilities or malware reports for these versions (checked today),
nothing runs while installing, published from its own source repository.
Approve these exact versions? To skip one or see details, reject and tell Claude.
```

Yes records those exact versions in `.claude/package-guard/vetted.json`, and
Claude installs them. No installs nothing. Packages you already approved
install with no prompt. A package the guard cannot vouch for gets its own
second prompt. More in [What you will see](DETAILS.md#what-you-will-see).

---

## Supported

| | Supported | Refused |
|---|---|---|
| OS | macOS, Linux, WSL2, native Windows (needs Git for Windows) | |
| JavaScript | `npm`, `npx`, `pnpm`, `bun`, Yarn Berry 4.14+ | `corepack`, Yarn Classic, Plug'n'Play |
| Python | `pip`, `uv` | `pipx`, `poetry`, `conda` |
| Frappe / ERPNext bench | Not yet supported, coming in v1.12 | `bench` verbs that install |

A project that uses a refused tool cannot use the guard yet. Details and
lockfile rules: [Supported package managers](DETAILS.md#supported-package-managers).

---

## Turning it down

To get past a block, first approve the package at the prompt. To turn the guard
down for a while, run this yourself, in your own terminal window in the project
folder (not with `!` inside Claude Code, and Claude cannot run it):

```bash
sh .claude/hooks/package_guard/pg mode warn --reason "why"   # refusals become warnings
sh .claude/hooks/package_guard/pg mode enforce               # back on
```

It expires by itself after 24 hours. `warn` lets packages through with a
warning, and your normal permission prompt still shows. `off` stops checking
installs. With the plugin there is no `pg`: ask Claude to run `mode warn`, and
the guard prints the full command to paste into your terminal. More forms and
the rules: [Turning it down: modes](DETAILS.md#turning-it-down-modes).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Every Bash command or file edit is blocked and the message names `uv` | Install `uv` from <https://docs.astral.sh/uv/>, then start a new session |
| Every command is denied with "no runner found", and `uv` is installed | Run `uv python install 3.11` in a terminal, then start a new session |
| Two guards run, and approvals never complete | The project still has the old file-based hooks. Run `/package-guard:setup` in the project once |
| Claude cannot use PowerShell | The guard refuses PowerShell. Set `CLAUDE_CODE_USE_POWERSHELL_TOOL=0` under `env` in your user settings |
| A package installs with no prompt | The hooks are not loaded. Restart Claude Code in the project root |

More rows: [Troubleshooting](DETAILS.md#troubleshooting).

---

## More

All on one page, [DETAILS.md](DETAILS.md):

- [Install: every way](DETAILS.md#install), including [Windows](DETAILS.md#windows)
  and [Docker Sandboxes](DETAILS.md#docker-sandboxes-sbx)
- [Requirements](DETAILS.md#requirements) and
  [what gets added to your project](DETAILS.md#what-gets-added-to-your-project)
- [Commands](DETAILS.md#commands) and [limits](DETAILS.md#limits)
- [Feedback](DETAILS.md#feedback): open an issue at
  https://github.com/Fefar-AT/package-guard/issues
