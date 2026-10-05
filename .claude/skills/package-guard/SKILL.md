---
name: package-guard
description: >-
  Package Guard protocol for this project. Invoke BEFORE any command that
  acquires, adds, or syncs a dependency (npm/npx/pip/uv), before writing or
  editing package.json / pyproject.toml / requirements / a lockfile, and before
  running anything that executes commands from a file (npm run, npm start, make,
  just, bash *.sh, uv run <script>). Also invoke on any PACKAGE_GUARD_ denial.
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
`npm create`, `pip`, `uv add`, `uv pip`, `uvx`, or `uv tool` command that
acquires a package is blocked unless the **exact version** is already vetted in
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
     script, no advisory, allowed license, not fresh). The id needs no vetter.
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
   paste each package's human block **verbatim** — the `VERDICT` line, the
   `Why` facts, the `Red flags` block and the `Alternative` line. Never
   summarise it, never soften it, never drop a red flag.
   - For every package with `RECOMMEND`, run the approve command with all of
     those review ids in one call. Copy it **verbatim from the denial message**
     — it gives an absolute path to `cli.py`, so it works from any directory:
     `uv run --no-project --no-config --no-python-downloads <ABSOLUTE>/.claude/hooks/package_guard/cli.py approve <id> <id> ...`
     Run it as a **simple standalone command**. Never prefix it with `cd`,
     never join it with `&&` or `;`, never wrap it in a subshell — the hook
     refuses any compound form, because a wrapped approve would skip the
     human prompt. Claude Code will show the user a permission prompt, and
     that prompt now carries the vetter's verdict, confidence and red flags.
     Never bypass it.
   - For `DO_NOT_RECOMMEND` or `NEEDS_HUMAN_REVIEW`, do not approve, and keep
     the id out of the batch. Ask the user one direct question per package
     with exactly these options: **use the alternative** — the established
     alternative the subagent named, installed unpinned so it gets its own
     review — **approve anyway** (then run a separate approve for that id),
     or **not now** (leave the review open). Choosing the alternative settles
     the original review once the alternative is approved: it stops counting
     as open and needs no decline, and the same holds for a review of another
     version of a package the user has since approved. If the user says never
     to install it, run `decline` (step 4).

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
     `package.json` of its working directory; so do `npm update`, `npm dedupe`
     and `npm audit fix`, which re-resolve from the registry;
   - `pip install -r <file>` (also `python -m pip`, `uv pip install`,
     `uv pip sync`) installs everything that file lists;
   - `uv sync` installs the locked project, and so does `uv run` in a project
     (it syncs before running) unless you pass `--no-sync` or `--no-project`;
     `uv add` re-syncs it too. In a uv project, always run `uv sync --locked`
     / `uv run --locked …` — without `--locked` uv re-resolves pyproject.toml
     and installs versions nobody reviewed, so the plain form is refused.
     `--extra` / `--all-extras` put the extras up for review as well.

   **Decoration does not change any of this.** A pipe, a redirect, a `;`, a
   `&&`, a leading `VAR=value`, `sudo`, or `sh -c "..."` are all parsed through
   to the command underneath — `uv sync 2>&1 | tail` is gated exactly like a
   bare `uv sync`. Two things still refuse rather than gate: a `cd` in the same
   command (run it as its own command first), and a package name built from a
   variable or glob (name the exact package and version).

   `pnpm`, `yarn`, `bun`, `pipx`, `poetry`, `conda` and friends are now
   **refused by the hook**, not merely discouraged in this file.

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
  if the report has no verdict for an id, say so, then ask the same vetter
  (SendMessage to its agent id) to resend its full report with the machine
  blocks; launch a new vetter only if it cannot be reached. An id no vetter
  was ever given needs a new package-vetter launch, not a SendMessage;
- run `decline` for a rejected prompt, an interruption, or your own
  preference; only after the user says never to install it;
- install the alternative without its own review — it goes through the same
  gate, unpinned;
- describe any package as "safe". The guard checked evidence; it did not
  establish safety.

**Read what an opaque executor runs before you run it.** `npm run <script>`,
`npm start`, `make <target>`, `just <recipe>`, `bash ./x.sh` and a `uv run`
script all take their commands from a file, so the recognizer sees the outer
verb and nothing else. Before running one, read the script body — the `scripts`
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
