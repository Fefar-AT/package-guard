---
name: package-guard
description: >-
  Package Guard protocol for this project. Invoke BEFORE any command that
  acquires, adds, or syncs a dependency (npm/npx/pip/uv/pnpm/pnpx/bun/bunx/
  yarn/yarn dlx), before writing or editing package.json / pyproject.toml /
  requirements / a lockfile, and before running anything that executes commands
  from a file (npm run, pnpm run, bun run, yarn run, npm start, make, just,
  bash *.sh, uv run <script>). Also invoke on any PACKAGE_GUARD_ denial.
---

# Package Guard protocol (mandatory)

## Per-user trust and project approval

An identity catalog ships with the guard for established npm and PyPI packages.
A user-owned replacement at `~/.config/package-guard/trusted-packages.json`
is shared across that user's projects; it does not contain approved versions.
The bundled catalog is used only when the user file is absent. Do not create,
edit, delete, or replace either catalog yourself to make an install pass.

`user trust: TRUSTED IDENTITY` means the exact registry/name and canonical
repository matched a current catalog. It is NOT project approval. Live
registry/OSV checks and release checks still run, including at approval time.
A trusted identity with a risky release is still `reputation: unresolved` and
needs the vetter. A catalog match with passing release checks is established
without popularity/near-name web research. Catalog problems or identity
mismatches require research; nothing is silently approved.

Only the real human permission prompt authorizes the project's exact package
version. Never use auto/bypass permission mode or enter the human's response
yourself. Approval in another project does not authorize this project.

## Installation protocol

This project runs a Package Guard hook on every Bash command. Any `npm`, `npx`,
`npm create`, `pip`, `uv add`, `uv pip`, `uvx`, `uv tool`, `pnpm`, `pnpx`,
`bun`, `bunx`, `yarn` or `yarn dlx` command that acquires a package is blocked unless the **exact version** is already vetted in
`.claude/package-guard/vetted.json`. Follow this protocol exactly:

1. **Batch first.** When a task needs packages, put ALL of them in ONE install
   command (for example `npm install react react-dom vite`). Do not install
   packages one at a time. Do not pin versions from memory — leave them
   unpinned so the review resolves the current version from the registry.

2. **On `PACKAGE_GUARD_REVIEW_REQUIRED`: STOP running install commands.**
   The denial lists one `review_id` per package, each with a reputation line.
   - `reputation: established` — either a current user catalog identity and
     the live release checks held, or the hook's full research checks held (age, releases,
     weekly downloads, repository manifest, no near-name giant, no install
     script, no advisory, not fresh unless an attested release continues its
     publisher). The license is shown, never a criterion. The id needs no vetter.
     State in one line per package whether it is the mainstream choice for its
     purpose and name a successor if you know one, then run the approve
     command the denial gives for exactly those ids (rules in step 3).
   - `reputation: unresolved` — spawn the `package-vetter` subagent (Agent
     tool, `subagent_type: package-vetter`) ONCE, passing every `review_id`
     marked unresolved, the intended purpose of each package, and the
     high-level requirement. Pass nothing else. The harness runs it in the
     background and delivers its report as a notification: tell the user it
     is running, run no other package command meanwhile, and you may end the
     turn to wait for it — the Stop hook allows that while a vetter is in
     flight. Retrying the install before the review is closed just returns
     the same review ids.

   Handle both kinds in the same denial in parallel: approve the established
   ids first, then wait for the vetter on the rest. The hook refuses approve
   for an unresolved id until the vetter's report is in, and accepts an
   established id without one.

3. **Act on the subagent's verdicts.** Present them to the user concisely:
   one line per package — its `VERDICT`, confidence, every red-flag code and
   its `Alternative`. Never soften it, never drop a red flag. Paste a
   package's full human block only when the user asks for it. For a
   `NEEDS_HUMAN_REVIEW` package, lead that line with its red flags in plain
   words and the risk they carry (`PUBLISHER_NOT_MAINTAINER`: the account
   that published this version is not one of the package's maintainers), then
   end that line with your suggestion: use the alternative the subagent named,
   or approve only if the user needs this exact package. Never suggest
   approving it outright; say no more for it than the permission prompt does.
   - **Approve the recommended ids first.** Run ONE approve command with every
     `RECOMMEND` id together (the established ids were approved in step 2).
     Copy it **verbatim from the denial message** — it gives an absolute path
     to `cli.py`, so it works from any directory — with the ids filled in:
     `uv run --no-project --no-config --no-python-downloads <ABSOLUTE>/.claude/hooks/package_guard/cli.py approve <id> <id> ...`
     With the Package Guard plugin, the denial names the plugin's own `cli.py`
     instead and puts `--root <project>` right after the subcommand; copy it
     exactly as given.
     Run it as a **simple standalone command**. Never prefix it with `cd`,
     never join it with `&&` or `;`, never wrap it in a subshell — the hook
     refuses any compound form, because a wrapped approve would skip the
     human prompt. Claude Code will show the user a permission prompt that
     lists the packages and says in plain words why they are recommended.
     Never bypass it.
     One approve takes at most 12 ids. With more, run one approve per group
     of 12, one after another, each as its own command.
   - **Then the `NEEDS_HUMAN_REVIEW` ids, in a separate approve.** After the
     one-line-per-package message above, run ONE approve command with every
     `NEEDS_HUMAN_REVIEW` id together, the same way. Do not wait for a reply
     in chat: for a `NEEDS_HUMAN_REVIEW` package the permission prompt IS the
     question. It shows each reason in plain words and your suggestion. The
     hook refuses an approve that names recommended and `NEEDS_HUMAN_REVIEW`
     ids together (`PACKAGE_GUARD_CLI_REFUSED: cannot approve — this approve
     mixes …`), approves nothing, and names the two commands to run instead,
     recommended first.
   - For `DO_NOT_RECOMMEND`, or a `TYPO_SQUAT` red flag (a lookalike), do not
     approve, and keep the id out of the batch. The same goes for an id the
     denial lists under `LOOKALIKE ids`, whose name the hook itself found one
     edit from a far more downloaded package. The hook enforces this: an
     approve naming such an id together with any other id is refused
     (`approve flagged packages alone`), and nothing in it is approved.
     Tell the user in one short message and offer the alternative — the
     established alternative the subagent named, installed unpinned so it
     gets its own review. Run a separate approve for that id, alone, only if
     the user explicitly asks to approve it anyway. Choosing the alternative
     settles the original review once the alternative is approved: it stops
     counting as open and needs no decline, and the same holds for a review
     of another version of a package the user has since approved. If the
     user says never to install it, run `decline` (step 4).
   - Never run the vetter again to get a different verdict. A later report
     cannot soften a `DO_NOT_RECOMMEND`, a `NEEDS_HUMAN_REVIEW` or a
     `TYPO_SQUAT` given on complete evidence: the hook keeps the stricter
     verdict for the prompt and for the one-package rule. A rerun replaces
     only a verdict given on partial evidence, such as one marked
     `PROVIDER_UNREACHABLE`.

4. **If the user rejects the prompt or asks to drop a package**, record it and
   say so in your reply. A rejected prompt ends your turn as "Interrupted" —
   that is expected, not an error; wait for the user. Dropping a package is not
   a decline: run `... cli.py decline <review-id>` only for a package the user
   said never to install — same rules as approve: absolute path, simple
   standalone command, no `cd` / `&&` / `;`. It shows its own permission
   prompt, marked PERMANENT. Then re-run approve with the remaining ids.
   Never retry a declined package or version.

   **An approve the harness refuses is not a package problem.** If the approve
   command comes back refused by a message that does **not** start with
   `PACKAGE_GUARD_`, nobody could answer the prompt — that is an
   approval-surface problem, and no amount of research changes it. Report what
   was blocked and stop; never re-run the vetter for an id that was already
   established, and never retry the approve hoping for a different answer.

   **Every approve the guard refuses starts with a `PACKAGE_GUARD_` code.**
   The refusals for a missing vetter verdict, a lapsed established reputation,
   recommended and `NEEDS_HUMAN_REVIEW` ids in one approve, and an id that
   approve, decline, undecline or revoke cannot use start with
   `PACKAGE_GUARD_CLI_REFUSED`. They are the guard's own messages, and each says
   what to do: *no package-vetter verdict* means wait for the vetter's
   notification, or ask the same vetter to resend its report; *the established
   reputation did not hold* means launch the vetter for those ids; *nothing was
   vetted* names the ids to leave out before you re-run approve with the rest;
   *mixes recommended packages* names the two approves to run instead, the
   recommended one first.
   Act on them; do not treat them as a harness block.

5. **After approval, retry with the exact versions** given in the report's
   `retry` line (for example `npm install react@19.1.0 vite@6.3.5`). The hook
   allows exact vetted versions without further prompts. The pinned retry is
   the **next package command you run** — not something to come back to after
   the next question, and not something a vetter wait excuses. An approval you
   did not spend leaves the package uninstalled: never report a package as
   installed on the strength of its approval, and if you end the turn without
   installing something you approved, say so. The hook will tell you, on the
   next allow, which approvals this session left unspent.

6. **Manifests are gated too.** A command that installs a whole manifest is
   vetted the same way as one that names packages, so an install can be
   blocked over packages you did not name:
   - every `npm install` (bare, `npm ci`, or naming a package) installs the
     `package.json` of its project — the nearest one at or above the working
     directory, because npm walks up; so do `npm update`, `npm dedupe` and
     `npm audit fix`, which re-resolve from the registry;
   - `pip install -r <file>` (also `python -m pip`, `uv pip install`,
     `uv pip sync`) installs everything that file lists;
   - `uv sync` installs the locked project, and so does `uv run` in a project
     (it syncs before running) unless you pass `--no-sync` or `--no-project`;
     `uv add` re-syncs it too. In a uv project, always run `uv sync --locked`
     / `uv run --locked …` — without `--locked` uv re-resolves pyproject.toml
     and installs versions nobody reviewed, so the plain form is refused.
     `--extra` / `--all-extras` put the extras up for review as well. From a
     subdirectory uv acts on the nearest `pyproject.toml` above it, or on its
     workspace root, and that project is what gets reviewed.

   npm and uv do not stop at this project's folder. When the project has no
   `package.json` (npm) or `pyproject.toml` (uv) of its own, they climb into
   the folders above it and install whatever project they find there; a
   workspace above the project that lists it does the same. The hook refuses
   that install and names the outside folder. Do not edit or move anything
   outside the project to get past it. To make this folder the project, run
   `npm init -y` or `uv init --no-workspace` as its own command first, then
   the install; otherwise tell the user which project the install would use.

   **Decoration does not change any of this.** A pipe, a redirect, a `;`, a
   `&&`, a leading `VAR=value`, `sudo`, or `sh -c "..."` are all parsed through
   to the command underneath — `uv sync 2>&1 | tail` is gated exactly like a
   bare `uv sync`. Two things still refuse rather than gate: a `cd` in the same
   command (run it as its own command first), and a package name built from a
   variable or glob (name the exact package and version).

   `pipx`, `poetry`, `conda`, `corepack` and Yarn Plug'n'Play are
   **refused by the hook**, not merely discouraged in this file. Yarn Classic
   (v1) and Frappe's `bench` are gated, not refused. Open Claude at the bench
   folder, not inside an app. In a bench:
   - `bench setup requirements`, `bench update --requirements`,
     `bench new-app`, `bench build` and `bench update --patch --build` run only
     when every upstream app (`frappe`, `erpnext`, `hrms`) has a baseline the
     user approved and the guard's installer files hold. Otherwise the denial
     (`PACKAGE_GUARD_BASELINE_REQUIRED` or `PACKAGE_GUARD_BENCH_CONFIG`) names the
     command: run the `baseline plan` it gives, then ask the user to approve the
     proposal in their own terminal. `bench-config apply` is a command you run
     as the denial words it; the user answers its prompt. You never run
     `baseline approve` or `git-owners add`; do not retry or reword them.
   - Your own app's packages are reviewed one by one, like any project; a
     requirement that names an app of the bench (`frappe`, `erpnext`) is local
     code and is refused whatever the index offers; never edit the file to get
     past it, tell the user.
   - `bench init`, `get-app`, `switch-to-branch`, `setup env`, `migrate-env`, a
     plain `update`, and the system installers (`bench install`,
     `setup production`, `setup role`) stay the user's: tell them, do not look
     for another way. Other bench commands (`start`, `migrate`, site commands)
     run as usual.
   - An install into a bench's own Python env is gated like any pip install of
     an exact version: `<bench>/env/bin/pip install name==version`,
     `<bench>/env/bin/python -m pip install ...`,
     `uv pip install ... --python <bench>/env/bin/python` and
     `bench pip install name==version`, from the bench root or from `apps/<app>`.

   **pnpm, Bun and Yarn Berry are gated like npm**, next.

   **pnpm, Bun and Yarn Berry (v1.10.0).** The same rules as npm: every package
   is named with an exact version, reviewed and approved before it is
   installed; a bare `pnpm install`, `bun install` or `yarn` (bare `yarn` IS an
   install) is gated on what the manifest and lock say; decoration does not
   change any of it. What differs:
   - Locks. The project needs exactly one manager's lock, and the guard reads
     it in full: `pnpm-lock.yaml` (v9), a text `bun.lock` (a binary `bun.lockb`
     is refused), or a Berry `yarn.lock` (a Classic v1 lock is read in full and gated in a bench,
     see above). A fresh
     project with no dependencies may run its first add without a lock. Root
     `peerDependencies` must be in the lock (pnpm, Bun). It works both ways:
     npm is refused in a project whose lock or `packageManager` belongs to
     pnpm, Bun or Yarn. Use that project's manager.
   - Manager pin. The project's `packageManager` (`pnpm@X.Y.Z`, or `yarn@4.X.Y`
     with X at least 14) is reviewed once like a package (the npm packages
     `pnpm` and `@yarnpkg/cli-dist`) and checked on every pnpm and Yarn command.
     Yarn needs `nodeLinker: node-modules`. `COREPACK_*` variables are refused.
   - Scripts off or an allow-list. Dependency install scripts must be off:
     `--ignore-scripts` for pnpm and Bun, `--mode=skip-build` for Yarn (Berry
     has no `--ignore-scripts`), or an explicit reviewed allow-list: pnpm
     `onlyBuiltDependencies` (in `pnpm-workspace.yaml` or the `pnpm` key of
     `package.json`), Bun `trustedDependencies` (`package.json`), Yarn
     `dependenciesMeta.<pkg>.built`. Without one, Bun and pnpm 9 would run the
     default trusted list. The human edits the allow-list, not you.
   - No code loading, no redirects, allow-listed config. `.pnpmfile.cjs`, a Bun
     `preload`, a Yarn `yarnPath`, plugins, another registry in `.npmrc`,
     `bunfig.toml`, `pnpm-workspace.yaml` or `.yarnrc.yml`, workspaces and
     catalogs are refused. The config files are read, not refused outright:
     only known-safe keys pass, and an unknown key is refused by name. Never
     edit those files, a lock, or a manager's config to make a gate pass; tell
     the user which file and setting the denial names.
   - Runners. `pnpm dlx`, `bunx` / `bun x`, `pnpx` / `pnx` and `yarn dlx` take
     an exact `<pkg>@<version>` and are reviewed like `npx` (`--no-install`
     counts only before the package name). `pnpm run|exec|test|start`,
     `bun run|test|<file>` and `yarn run` run project code: read what they run
     first (as for `npm run`). Use `yarn run <script>`, never `yarn <script>`.
     A Bun run cannot share a command with anything that could change
     `node_modules`. With no `node_modules`, Bun installs what a file imports
     at run time, and Yarn needs an install state, so run `bun install` /
     `yarn install` first, as its own reviewed command.
   - Refused. Flags `-r`/`--recursive`, `--filter`, `-w`, `-g`/`--global`,
     `-C`/`--dir` and `--cwd` (to use a subdirectory, `cd` there in its own
     command first), and every alternate-registry or config flag. Verbs that
     run, publish or fetch code outside the gate: pnpm `init`, `link`,
     `rebuild`, `approve-builds`, `import`, `self-update`, `env`, `deploy`,
     `pack`, `publish`, `patch`, `store add`; Bun `create`, `init`, `build`,
     `upgrade`, `pm trust|cache|pack`, `patch`; Yarn `exec`, `set`,
     `workspace(s)`, `create`, `init`, `upgrade`, `global`, `npm publish`,
     `pack`, `patch`, `plugin`, `constraints`, `rebuild`, `unplug`, `node`.
     `pnpm create <x>@<exact>` is reviewed like `npm init`.
   - Missing or stale lock. The remedies install nothing and are always
     allowed: `pnpm install --lockfile-only --ignore-scripts`,
     `bun install --lockfile-only --ignore-scripts`, or
     `yarn install --mode=update-lockfile` (refused if the root `package.json`
     has an install-time script). pnpm `--dry-run` is not a remedy.
   - Removal. `remove` / `rm` / `uninstall` is checked like the lock-only forms
     (config, mixed locks, pinned manager, root install scripts). When a finding
     is on disk, run `pnpm remove <pkg>`, `bun remove <pkg> --ignore-scripts` or
     `yarn remove <pkg> --mode=skip-build`.

   Package Guard never guesses what a version range means. If a dependency is
   not pinned to an exact version you get `PACKAGE_GUARD_MANIFEST_UNPINNED`.
   Fix it by letting the real resolver pin the versions — each of these
   installs nothing and is always allowed — then re-run the install:
   - npm: `npm install --package-lock-only --ignore-scripts` (writes
     `package-lock.json`; without `--ignore-scripts` npm still runs the
     project's own lifecycle scripts, so that form is refused)
   - requirements: `uv pip compile <input>.in -o <file>`
   - uv project: `uv lock` (writes `uv.lock`)

   Pinning the specs by hand to exact versions works too. Run the pinning
   command in the manifest's own directory; the denial names it.

   A build backend (`[build-system] requires` in `pyproject.toml`, fetched by
   `uv build`, `pip install --no-deps .`, and `uv sync` / `uv add` in a
   packaged project) has no resolver to pin it. The denial names the exact
   line to write, e.g. change `uv_build>=0.9.7,<0.10.0` to
   `uv_build==0.9.29`. **Pinning an existing `[build-system]` requirement as
   the denial instructs is allowed and is not adding a dependency.** Edit only
   that requirement, then re-run the same command; the pinned version is
   reviewed like any package. An application needs no build backend: create
   it with `uv init --app --no-package`.

   One run reviews at most 20 new packages — named on the command line or
   declared by the manifest — within a time budget, and says how many it
   deferred. Approve what was reviewed, then re-run the same install: reviews
   already opened are reused, so every run makes progress.
   `PACKAGE_GUARD_REVIEW_BUDGET` means nothing finished in time — re-run;
   never work around it.

   To install into a subdirectory, `cd` there in its own command first;
   `npm install --prefix <dir>` is refused.

7. **You cannot end your turn with an open review — unless a vetter is
   running.** A Stop hook blocks stopping while any of this session's reviews
   is neither approved nor declined (`PACKAGE_GUARD_PENDING_REVIEWS`), except
   while a `package-vetter` you launched has not reported yet (it reads the
   session transcript to know). Close every review via step 3 or 4, or ask
   the user a direct question about the package — never go silent.

When presenting vetter verdicts, include each package's recommendation and
its confidence score (0-100) so the user can judge before the prompt. The hook
refuses `approve` for an unresolved id until the vetter's notification is in
this session, so the order is fixed: report arrives, you present it, then you
approve. An established id has no vetter step; its prompt carries the hook's
own reputation facts instead.

**Never**, at any point in this protocol:
- run `approve` for an unresolved id before the vetter's notification has
  arrived, or for an unresolved id the vetter did not return a verdict for;
- state a verdict the vetter did not return, or a confidence it did not give —
  if the report has no verdict for an id, say so, then load the SendMessage
  tool (it is deferred: ToolSearch with query `select:SendMessage`) and ask
  the same vetter (SendMessage to its agent id) to resend its full report
  with the machine blocks; launch a new vetter only if that fails. An id no
  vetter was ever given needs a new package-vetter launch, not a SendMessage;
- run `decline` for a rejected prompt, an interruption, or your own
  preference; only after the user says never to install it;
- install the alternative without its own review — it goes through the same
  gate, unpinned;
- describe any package as "safe". The guard checked evidence; it did not
  establish safety.

**The mode belongs to the user.** Package Guard runs in `enforce`, `warn` or
`off` (`cli.py mode` shows which, and why). Never change the mode unless the
user asks. You may run `cli.py mode` and `cli.py mode enforce [--project]`.
`mode warn` and `mode off` from you are refused
(`PACKAGE_GUARD_MODE_HUMAN_ONLY`) and need a terminal: when the user wants the
guard down, give them the short `sh .claude/hooks/package_guard/pg …` command
from the denial, to run in a separate terminal window in the project folder,
not with `!`. Never run `pg` yourself; it is refused. In `warn`, a refusal arrives as a warning and the
user's own permission prompt still decides; follow this protocol anyway. When
`enforce` returns, packages that arrived while it was down become open
findings; handle them like any other.

**Read what an opaque executor runs before you run it.** `npm run <script>`,
`npm start`, `make <target>`, `just <recipe>`, `bash ./x.sh` and a `uv run`
script all take their commands from a file, so the recognizer sees the outer
verb and nothing else. `pnpm run`, `pnpm exec`, `bun run`, `bun <file>`,
`bun test` and `yarn run` are the same kind of executor. Before running one, read the script body — the `scripts`
block of `package.json`, the Makefile or justfile target, the shell script — and
follow it into whatever it calls. If anything it runs acquires a package, run
that acquisition as its own bare command first, so the gate sees it. The disk
reconciliation layer will report the package afterwards either way, but only
once it is already installed. A script such as `"serve": "npx serve site"`
fetches and runs its package before any review can exist, so run that
acquisition as its own command first.

**`decline` is not "close this review".** It shows the user a permission prompt
marked PERMANENT, and it is permanent — a declined identity returns
`PACKAGE_GUARD_DECLINED` on every later attempt until the user reverses it with
`cli.py undecline <review-id>`, which prompts the same way. Use it for exactly
one thing: a package the user said never to install. Not for a `DO_NOT_RECOMMEND`
the user merely did not want today, not for a rejected prompt, not for a review
you would like off the list. If you simply chose not to install something, or
the user picked the alternative instead, say so in your reply and leave its
review for the user to close. Never decline reviews on your own, even ones
marked `RECOMMEND`, and never offer a permanent decline for a package that was
merely passed over: once its alternative is approved, that approval has
already settled the review. Withdrawing an approval the user already gave is
`cli.py revoke <review-id>` — its own prompt, and it declines nothing.

Scope limits, so you do not over-promise. The guard vets exactly what a gated
manifest declares, plus what you name on the command line. How much of the
dependency tree that covers depends on the manifest:

- **npm**: direct dependencies only. `package-lock.json` keeps transitive
  packages nested under their parents, so they are installed without an
  individual review.
- **requirements files**: whatever the file lists. A file produced by
  `uv pip compile` is *flattened* — every transitive dependency appears as its
  own pinned line, so each one gets its own review. Coverage there is the full
  tree, not just the top level.
- **uv projects**: direct dependencies only. `uv.lock` names the project's own
  dependencies; the rest of the lock is transitive and out of scope.

Transitive packages are not reviewed, but they are checked: once a lockfile
exists, every package it would install is sent to OSV in one batch before the
install is allowed. Known malware anywhere in the tree denies the install;
other advisories come back in the allow message — relay them to the user.

Approval is not permanent either: the approved set is re-checked against OSV
once a day before an install, and a malware hit on something already approved
denies and names the `revoke` command to run.

Installing a local project (`pip install .` or `pip install -e .`) is
**refused**: its `pyproject.toml` dependencies are ranges with no lockfile to
pin them from, so the guard cannot vet what would land. The denial names the
gated path, each as its own command: `uv pip compile pyproject.toml -o
requirements.txt`, then `pip install -r requirements.txt`, then
`pip install --no-deps .`. The `--no-deps` form is allowed because it acquires
nothing external.
