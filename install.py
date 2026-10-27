#!/usr/bin/env python3
# /// script
# requires-python = "==3.11.*"
# ///
"""Install Package Guard into a project, or remove it.

    python3 install.py <project-dir>              install or upgrade
    python3 install.py <project-dir> --sandbox    the same, plus the strict sandbox
    python3 install.py <project-dir> --check      report what is present, change nothing
    python3 install.py <project-dir> --uninstall  remove the guard, keep vetted.json / declined.json
    python3 install.py <project-dir> --plugin     project state only, for the Claude Code plugin
    python3 install.py <project-dir> --plugin --check

Run from a clone of the Package Guard repository; the guard files are copied from
the clone this script lives in. Standard library only -- a tool that
installs a dependency gate must not acquire dependencies. Python 3.11+, the same
floor as the guard; install.sh runs it on 3.11, the guard's pinned interpreter.

What one run does, in the order the README's manual procedure lists:

  1. copies .claude/hooks/package_guard/, .claude/agents/package-vetter.md and
     .claude/skills/package-guard/ (replacing any previous copy, so a re-run is
     an upgrade);
  2. merges the guard's hooks and permissions.deny rules, plus the LOCK_DENY
     rules that lock the guard's own files and, with --sandbox only, the strict
     sandbox block, into .claude/settings.json, keeping every
     unrelated key and never adding an entry that is already there;
  3. appends the `## Packages` section to CLAUDE.md if it is absent;
  4. seeds .claude/package-guard/ with empty vetted.json / declined.json and
     the reports/.gitignore -- existing state is never touched;
  5. adds the machine-local ignore lines (guard state, the hook's __pycache__) to .gitignore;
  6. adds .gitattributes lines that keep the guard's files LF on a Windows
     checkout -- a CRLF run.sh makes every hook exit 2, which blocks every
     command and traps the Stop hook (Docker Sandboxes on a Windows host
     mounts that checkout straight into the Linux sandbox).

It does not commit; it prints the `git add` to run. Every step is idempotent, so
re-running is safe and is the upgrade path. Nothing outside <project-dir> is
written.

--plugin is the setup for the Claude Code plugin (`/package-guard:setup` runs it). The
plugin carries the hooks, so this seeds only project state: vetted.json /
declined.json when absent, reports/.gitignore, the `## Packages` CLAUDE.md
section (worded without file-install paths) and the .gitignore lines. It copies no
hooks and merges no hook entries. A project that already has the file-based install
is migrated: the old hook entries, deny rules and copied code are removed so the
hooks never run twice, and vetted.json / declined.json are kept.

The install never goes through Claude: a Claude session in a guarded project
cannot write .claude/package-guard/ (README step 4 is denied with
PACKAGE_GUARD_UNSUPPORTED by design), so this is the human's command.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent

HOOK_DIR = Path(".claude/hooks/package_guard")
AGENT_FILE = Path(".claude/agents/package-vetter.md")
SKILL_DIR = Path(".claude/skills/package-guard")
STATE_DIR = Path(".claude/package-guard")
SETTINGS = Path(".claude/settings.json")

COMPONENTS = (HOOK_DIR, AGENT_FILE, SKILL_DIR)
# Written inside the hook copy, so it is committed and removed with it.
VERSION_FILE = HOOK_DIR / "VERSION"

# The guard's own settings are the source of truth: entries are recognised by
# these substrings, so the installer carries no copy of a hook command that
# could drift from the one this repository runs.
HOOK_MARK = ".claude/hooks/package_guard/"
DENY_MARK = "(.claude/package-guard/**)"
TRUST_DENY_MARK = "(~/.config/package-guard/**)"
SEED_DENY_MARK = "(.claude/hooks/package_guard/trusted-packages.json)"

# Installed projects only: the guard's own files are locked against
# the file tools. The last two keep Claude from deleting these rules. They are
# not in this repository's settings because a deny cannot be lifted per session
# and this repository develops the guard. hook.py reads the first rule as the
# lock switch for its Bash check.
LOCK_DENY = (
    "Edit(.claude/hooks/package_guard/**)",
    "Edit(.claude/agents/package-vetter.md)",
    "Edit(.claude/skills/package-guard/**)",
    "Edit(.claude/settings.json)",
    "Edit(.claude/settings.local.json)",
)

# A Frappe bench target only, and only while the Frappe switch is on (`parser.FRAPPE_ENABLED`):
# the installer files the guard writes for a bench (`bench_config.apply`) are locked against
# the file tools like the guard's own. Separate from LOCK_DENY, which every install must have:
# `--check` asks every project for all of LOCK_DENY, and a project that is not a bench has
# no such files. The hook's lock on a recorded file is the one that matters; these rules
# are the file tools' half in an installed project.
BENCH_LOCK_DENY = (
    "Edit(**/.yarnrc)",
    "Edit(**/env/pip.conf)",
    "Edit(**/uv.toml)",
)
BENCH_GITATTRIBUTES_LINES = (
    ".claude/package-guard/constraints/** text eol=lf",
)

# Opt-in (--sandbox), installed projects only, like LOCK_DENY: the Claude Code
# sandbox is the OS-level boundary the hook's text checks cannot be. It stops a
# Bash write the command text hides (a script file, an interpreter one-liner,
# git, a link alias). That file protection is all the guard wants from it:
# network stays open (SANDBOX_ALLOW_RULE), because the hook already gates
# acquisition and a host list is upkeep nobody needs. It is off by default
# because it still confines every Bash command: git over SSH on macOS, docker
# and writes outside the project and SANDBOX_ALLOW_WRITE stop working. Keys
# follow Claude Code's sandboxing and settings reference.
#
# The sandbox already protects .claude/settings*.json and .claude/{hooks,
# agents,skills} on its own; they are listed so the policy does not depend on
# that list. Guard state and the user catalog are not on it.
SANDBOX_FLAGS = {
    "enabled": True,
    # Missing bubblewrap/socat, or native Windows, refuses to start rather
    # than running every command unsandboxed.
    "failIfUnavailable": True,
    # No dangerouslyDisableSandbox retry.
    "allowUnsandboxedCommands": False,
}
SANDBOX_DENY_WRITE = (
    ".claude/package-guard",
    "~/.config/package-guard",
    ".claude/hooks/package_guard",
    ".claude/agents",
    ".claude/skills",
    ".claude/settings.json",
    ".claude/settings.local.json",
)
# The package managers' own caches. npm and uv cannot install without them. Yarn Classic
# keeps its cache, global folder and user config under ~/.cache/yarn, ~/.yarn and
# ~/.config/yarn, and writes `lastUpdateCheck` into ~/.yarnrc after an install; bench caches
# the apps it fetches under ~/.cache/bench. The guard reads those yarn files on every yarn
# command, so a sandboxed write to them is checked before the next install.
SANDBOX_ALLOW_WRITE = (
    "~/.npm", "~/.cache/uv", "~/.cache/pip", "~/Library/Caches/pip",
    "~/.cache/yarn", "~/.yarn", "~/.config/yarn", "~/.yarnrc", "~/.cache/bench",
)
# Every host is reachable from a sandboxed command. The sandbox honours a bare
# `*` only in a WebFetch(domain:...) allow rule (Claude Code v2.1.186+); the
# rule also lets the WebFetch tool reach any host without a prompt.
SANDBOX_ALLOW_RULE = "WebFetch(domain:*)"
# The host list an older install wrote instead. Recognised so --check and
# --uninstall still handle such a project; never written any more.
LEGACY_SANDBOX_DOMAINS = (
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "api.osv.dev",
)
# The guard CLI's state-writing verbs are the one thing that leaves the
# sandbox: it is the only writer of guard state, behind its own
# prompt. Claude Code matches these on text, so hook._clean_project_cli is the
# real check: only the project's own cli.py, with exactly these three flags.
CLI_PREFIX = "uv run --no-project --no-config --no-python-downloads"
SANDBOX_EXCLUDED = tuple(
    f"{CLI_PREFIX} *.claude/hooks/package_guard/cli.py {verb} *"
    for verb in ("approve", "decline", "undecline", "revoke", "reconcile", "audit", "mode")
)
SANDBOX_LISTS = (
    (("excludedCommands",), SANDBOX_EXCLUDED),
    (("filesystem", "denyWrite"), SANDBOX_DENY_WRITE),
    (("filesystem", "allowWrite"), SANDBOX_ALLOW_WRITE),
)
LEGACY_SANDBOX_LISTS = ((("network", "allowedDomains"), LEGACY_SANDBOX_DOMAINS),)

CLAUDE_MD_HEADING = "## Packages"

GITIGNORE_HEADER = "# Package Guard -- machine-local state, not project state"
GITIGNORE_LINES = (
    ".claude/package-guard/.stop-state.json",
    ".claude/package-guard/.disk-state.json",
    ".claude/package-guard/.disk-findings.json",
    ".claude/package-guard/.transitive-state.json",
    ".claude/package-guard/.environments.json",
    ".claude/package-guard/.mode.local.json",
    ".claude/package-guard/.mode-log.jsonl",
    ".claude/package-guard/.mode-seen.json",
    ".claude/package-guard/.mode-snapshot.json",
    ".claude/hooks/package_guard/__pycache__/",
)
# Machine-local mode files; --uninstall removes them and keeps the committed
# mode.json, which is the team's decision.
MODE_LOCAL_FILES = (".mode.local.json", ".mode-log.jsonl", ".mode-seen.json",
                    ".mode-snapshot.json")

# The clause v1.10.0 retired ("never use pnpm/yarn/bun") and its replacement;
# re-running the installer swaps one for the other in an existing section.
OLD_MANAGER_CLAUSE = "use `pnpm`/`yarn`/`bun`,"
NEW_MANAGER_CLAUSE = (
    "use a package manager other than `npm`/`npx`, `pip`, `uv`, `pnpm`, `bun` or "
    "Yarn Berry 4.14+ (`pipx`, `poetry`, `conda`, `corepack` and Yarn Plug'n'Play "
    "are refused; Yarn Classic and `bench` are gated),")

# Plugin projects: the guard's code lives in the plugin, so the section names no
# file-install hook path. The plugin's own hook enforces the file locks.
PLUGIN_PACKAGES_SECTION = """\
## Packages

User trust catalogs identify established packages; they never grant project
installation approval. Never change `~/.config/package-guard/` or the bundled
`trusted-packages.json` to make an installation pass. Human permission is
required for every new project package/version approval.

Every Bash command passes the Package Guard plugin's PreToolUse hook, and every
one is reconciled against disk afterwards. Before adding, syncing, or running any
dependency-touching command, invoke the `package-guard` skill and follow it.

Never: hand-edit `package.json` / `pyproject.toml` / lockfiles to add a
dependency, use a package manager other than `npm`/`npx`, `pip`, `uv`, `pnpm`,
`bun` or Yarn Berry 4.14+ (`pipx`, `poetry`, `conda`, `corepack` and Yarn
Plug'n'Play are refused; Yarn Classic and `bench` are gated), wrap installs in
`sh -c`/`eval`, use any
other installer or wrapper to get packages onto disk, edit the project's
Package Guard state directory, or disable or uninstall the `package-guard`
plugin. Package Guard is the only gate in this project; if a Bash denial does
not start with `PACKAGE_GUARD_`, it did not come from this project — tell the
user and stop.
"""

GITATTRIBUTES_HEADER = "# Package Guard -- LF on every checkout; run.sh fails on CRLF"
GITATTRIBUTES_LINES = (
    ".claude/hooks/package_guard/** text eol=lf",
    ".claude/skills/package-guard/** text eol=lf",
    ".claude/agents/package-vetter.md text eol=lf",
    # what the guard writes for the baselines is LF on every checkout
    ".claude/package-guard/baselines/** text eol=lf",
    ".claude/package-guard/git-owners.json text eol=lf",
)

EMPTY_VETTED = {"schema_version": 1, "packages": []}
EMPTY_DECLINED = {"schema_version": 1, "reviews": []}
REPORTS_GITIGNORE = "*\n!.gitignore\n"


class InstallError(Exception):
    pass


# ---------------------------------------------------------------------------
# Source side: what the clone provides
# ---------------------------------------------------------------------------

def _is_bench(target: Path) -> bool:
    """A Frappe bench root: `apps/` and `sites/` side by side (bench_config.bench_root)."""
    return (target / "apps").is_dir() and (target / "sites").is_dir()


def _frappe_enabled() -> bool:
    """The Frappe switch, read from the parser this repository installs."""
    guard = SOURCE / HOOK_DIR
    if not guard.is_dir():
        guard = SOURCE / "guard" / "package_guard"
    try:
        sys.path.insert(0, str(guard))
        import parser as pg_parser
        return bool(pg_parser.FRAPPE_ENABLED)
    except Exception:  # noqa: BLE001 - an unreadable switch is off
        return False
    finally:
        sys.path.pop(0)


def _bench_above(target: Path) -> Path | None:
    """The bench root whose `apps/` holds `target` (an app repository), or None."""
    for parent in target.parents:
        if (parent / "apps").is_dir() and (parent / "sites").is_dir():
            try:
                target.relative_to(parent / "apps")
            except ValueError:
                continue
            return parent
    return None


def refuse_app_target(target: Path) -> str | None:
    """Why the guard is not installed inside an app repository of a Frappe bench, or None.

    Claude Code loads a project's `.claude/` for a session started in that project; whether it loads
    the bench root's for a session started in `apps/<app>` is not assumed (the plugin, which loads
    everywhere, is the primary install). A guard inside the app would also never see the bench's
    baselines and configuration, which live at the root where it is installed. Only while the Frappe
    switch is on."""
    if not _frappe_enabled():
        return None
    bench = _bench_above(target)
    if bench is None:
        return None
    return (f"{target} is inside the apps/ of the Frappe bench at {bench}: open Claude at the bench root "
            f"and install there (python3 install.py {bench}), or use the plugin, which loads for every "
            "project.")


def _bench_rows(target: Path) -> tuple[tuple, tuple]:
    """(deny rules, attribute lines) this target needs for a bench; empty for any other."""
    if _is_bench(target) and _frappe_enabled():
        return BENCH_LOCK_DENY, BENCH_GITATTRIBUTES_LINES
    return (), ()


def _guard_settings() -> tuple[dict[str, list], list[str]]:
    """The guard's hook entries per event and its deny rules, from this clone."""
    settings = json.loads((SOURCE / SETTINGS).read_text(encoding="utf-8"))
    hooks = {}
    for event, entries in settings.get("hooks", {}).items():
        mine = [
            e for e in entries
            if any(HOOK_MARK in h.get("command", "") for h in e.get("hooks", []))
        ]
        if mine:
            hooks[event] = mine
    deny = [r for r in settings.get("permissions", {}).get("deny", [])
            if any(mark in r for mark in (DENY_MARK, TRUST_DENY_MARK, SEED_DENY_MARK))]
    if not hooks or not deny:
        raise InstallError(f"{SOURCE / SETTINGS} carries no Package Guard registration")
    return hooks, deny


def _packages_section() -> str:
    """The `## Packages` section of this clone's CLAUDE.md, heading included."""
    text = (SOURCE / "CLAUDE.md").read_text(encoding="utf-8")
    start = text.find(CLAUDE_MD_HEADING)
    if start < 0:
        raise InstallError(f"{SOURCE / 'CLAUDE.md'} has no '{CLAUDE_MD_HEADING}' section")
    end = text.find("\n## ", start + len(CLAUDE_MD_HEADING))
    section = text[start:] if end < 0 else text[start:end]
    return section.rstrip() + "\n"


def _check_source() -> None:
    missing = [str(c) for c in COMPONENTS if not (SOURCE / c).exists()]
    if missing:
        raise InstallError(
            f"{SOURCE} is not a Package Guard clone; missing: {', '.join(missing)}"
        )
    if not (SOURCE / HOOK_DIR / "run.sh").is_file():
        raise InstallError(
            f"{SOURCE / HOOK_DIR} has no run.sh; this checkout predates the runner. "
            "Install from the main branch."
        )


# ---------------------------------------------------------------------------
# Target side: each step reports whether it changed anything
# ---------------------------------------------------------------------------

def _copy_components(target: Path) -> list[str]:
    changed = []
    for component in COMPONENTS:
        src, dst = SOURCE / component, target / component
        existed = dst.exists()
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            if existed:
                shutil.rmtree(dst)
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(src, dst)
        # A clone made with core.autocrlf=true carries CRLF; never pass it on.
        for script in (dst.rglob("*.sh") if dst.is_dir() else ()):
            data = script.read_bytes()
            if b"\r\n" in data:
                script.write_bytes(data.replace(b"\r\n", b"\n"))
        changed.append(f"{'upgraded' if existed else 'installed'}  {component}")
    return changed


def _load_json(path: Path, what: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InstallError(f"{path} is not valid JSON ({exc}); fix it and re-run") from exc
    if not isinstance(data, dict):
        raise InstallError(f"{path} must hold a JSON object to merge {what} into")
    return data


def _merge_settings(target: Path, sandbox: bool = False) -> list[str]:
    path = target / SETTINGS
    settings = _load_json(path, "the guard") if path.exists() else {}
    hooks, deny = _guard_settings()
    changed = []

    permissions = settings.setdefault("permissions", {})
    rules = permissions.setdefault("deny", [])
    for rule in (*deny, *LOCK_DENY, *_bench_rows(target)[0]):
        if rule not in rules:
            rules.append(rule)
            changed.append(f"deny rule  {rule}")

    registered = settings.setdefault("hooks", {})
    for event, entries in hooks.items():
        existing = registered.setdefault(event, [])
        present = {
            h.get("command") for e in existing for h in e.get("hooks", [])
        }
        for entry in entries:
            commands = [h["command"] for h in entry["hooks"]]
            if any(c in present for c in commands):
                continue
            existing.append(json.loads(json.dumps(entry)))
            changed.append(f"hook  {event}")

    if sandbox:
        changed += _merge_sandbox(settings)

    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return changed


def _sandbox_list(sandbox: dict, keys: tuple[str, ...], create: bool) -> list | None:
    node = sandbox
    for key in keys[:-1]:
        node = node.setdefault(key, {}) if create else node.get(key)
        if not isinstance(node, dict):
            return None
    return node.setdefault(keys[-1], []) if create else node.get(keys[-1])


def _merge_sandbox(settings: dict) -> list[str]:
    """Turn the sandbox on and add the guard's entries; keep the rest."""
    sandbox = settings.setdefault("sandbox", {})
    if not isinstance(sandbox, dict):
        raise InstallError(f"{SETTINGS} 'sandbox' must be a JSON object")
    changed = []
    for key, value in SANDBOX_FLAGS.items():
        if sandbox.get(key) is not value:
            sandbox[key] = value
            changed.append(f"sandbox  {key} = {json.dumps(value)}")
    for keys, entries in SANDBOX_LISTS:
        present = _sandbox_list(sandbox, keys, create=True)
        if not isinstance(present, list):
            raise InstallError(f"{SETTINGS} sandbox.{'.'.join(keys)} must be a JSON array")
        for entry in entries:
            if entry not in present:
                present.append(entry)
                changed.append(f"sandbox  {'.'.join(keys)}  {entry}")
    allow = settings.setdefault("permissions", {}).setdefault("allow", [])
    if not isinstance(allow, list):
        raise InstallError(f"{SETTINGS} permissions.allow must be a JSON array")
    if SANDBOX_ALLOW_RULE not in allow:
        allow.append(SANDBOX_ALLOW_RULE)
        changed.append(f"allow rule  {SANDBOX_ALLOW_RULE}")
    return changed


def _allow_rules(settings: dict) -> list:
    permissions = settings.get("permissions")
    allow = permissions.get("allow") if isinstance(permissions, dict) else None
    return allow if isinstance(allow, list) else []


def _sandbox_ok(settings: dict) -> bool:
    sandbox = settings.get("sandbox")
    if not isinstance(sandbox, dict):
        return False
    if any(sandbox.get(k) is not v for k, v in SANDBOX_FLAGS.items()):
        return False
    for keys, entries in SANDBOX_LISTS:
        present = _sandbox_list(sandbox, keys, create=False)
        if not isinstance(present, list) or not set(entries) <= set(present):
            return False
    return SANDBOX_ALLOW_RULE in _allow_rules(settings)


def _sandbox_missing(settings: dict) -> list[str]:
    """The guard's sandbox entries a settings file lacks (an install from before an entry was
    added), as `list.path  entry` strings."""
    sandbox = settings.get("sandbox")
    sandbox = sandbox if isinstance(sandbox, dict) else {}
    missing = []
    for keys, entries in SANDBOX_LISTS:
        present = _sandbox_list(sandbox, keys, create=False)
        present = present if isinstance(present, list) else []
        missing += [f"{'.'.join(keys)}  {entry}" for entry in entries if entry not in present]
    return missing


def _sandbox_present(settings: dict) -> bool:
    """Any of the guard's sandbox flags or entries: the project opted in once."""
    sandbox = settings.get("sandbox")
    if not isinstance(sandbox, dict):
        return False
    for keys, entries in (*SANDBOX_LISTS, *LEGACY_SANDBOX_LISTS):
        present = _sandbox_list(sandbox, keys, create=False)
        if isinstance(present, list) and set(entries) & set(present):
            return True
    return False


def _remove_sandbox(settings: dict) -> bool:
    """Remove the guard's flags, entries and allow rule; drop containers left empty."""
    removed = False
    allow = _allow_rules(settings)
    if SANDBOX_ALLOW_RULE in allow:
        allow.remove(SANDBOX_ALLOW_RULE)
        if not allow:
            del settings["permissions"]["allow"]
        removed = True
    sandbox = settings.get("sandbox")
    if not isinstance(sandbox, dict):
        return removed
    for key, value in SANDBOX_FLAGS.items():
        if sandbox.get(key) is value:
            del sandbox[key]
            removed = True
    for keys, entries in (*SANDBOX_LISTS, *LEGACY_SANDBOX_LISTS):
        present = _sandbox_list(sandbox, keys, create=False)
        if not isinstance(present, list):
            continue
        kept = [e for e in present if e not in entries]
        if len(kept) == len(present):
            continue
        removed = True
        parent = sandbox
        for key in keys[:-1]:
            parent = parent[key]
        if kept:
            parent[keys[-1]] = kept
        else:
            del parent[keys[-1]]
            if len(keys) > 1 and not sandbox[keys[0]]:
                del sandbox[keys[0]]
    if not sandbox:
        del settings["sandbox"]
    return removed


def _section_of(text: str) -> str:
    start = text.find(CLAUDE_MD_HEADING)
    if start < 0:
        return ""
    end = text.find("\n## ", start + len(CLAUDE_MD_HEADING))
    return text[start:] if end < 0 else text[start:end]


def _append_claude_md(target: Path, plugin: bool = False) -> list[str]:
    path = target / "CLAUDE.md"
    section = PLUGIN_PACKAGES_SECTION if plugin else _packages_section()
    if path.exists():
        text = path.read_text(encoding="utf-8")
        if CLAUDE_MD_HEADING in text:
            if plugin and HOOK_MARK in _section_of(text):
                # Migration: the file-install wording names paths that are gone.
                start = text.find(CLAUDE_MD_HEADING)
                end = text.find("\n## ", start + len(CLAUDE_MD_HEADING))
                tail = "" if end < 0 else "\n" + text[end + 1:]
                path.write_text(text[:start] + section + tail, encoding="utf-8")
                return [f"updated  CLAUDE.md {CLAUDE_MD_HEADING} (plugin wording)"]
            # Upgrade: swap only the retired manager clause, so a section the
            # project has edited keeps its own wording.
            if OLD_MANAGER_CLAUSE in _section_of(text):
                start = text.find(CLAUDE_MD_HEADING)
                end = text.find("\n## ", start + len(CLAUDE_MD_HEADING))
                end = len(text) if end < 0 else end
                body = text[start:end].replace(OLD_MANAGER_CLAUSE, NEW_MANAGER_CLAUSE)
                path.write_text(text[:start] + body + text[end:], encoding="utf-8")
                return [f"updated  CLAUDE.md {CLAUDE_MD_HEADING} (package manager wording)"]
            return []
        joiner = "" if text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
        path.write_text(text + joiner + section, encoding="utf-8")
    else:
        path.write_text("# Project instructions\n\n" + section, encoding="utf-8")
    return [f"section  CLAUDE.md {CLAUDE_MD_HEADING}"]


def _seed_state(target: Path) -> list[str]:
    state = target / STATE_DIR
    (state / "reports").mkdir(parents=True, exist_ok=True)
    changed = []
    for name, payload in (("vetted.json", EMPTY_VETTED), ("declined.json", EMPTY_DECLINED)):
        path = state / name
        if not path.exists():
            path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            changed.append(f"seeded  {STATE_DIR / name}")
    ignore = state / "reports" / ".gitignore"
    if not ignore.exists():
        ignore.write_text(REPORTS_GITIGNORE, encoding="utf-8")
        changed.append(f"seeded  {STATE_DIR / 'reports' / '.gitignore'}")
    return changed


def _append_gitignore(target: Path) -> list[str]:
    path = target / ".gitignore"
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    present = {line.strip() for line in text.splitlines()}
    missing = [line for line in GITIGNORE_LINES if line not in present]
    if not missing:
        return []
    block = "\n".join([GITIGNORE_HEADER, *missing]) + "\n"
    joiner = "" if not text or text.endswith("\n") else "\n"
    path.write_text(text + joiner + block, encoding="utf-8")
    return [f"ignored  {line}" for line in missing]


def _append_gitattributes(target: Path) -> list[str]:
    path = target / ".gitattributes"
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    present = {line.strip() for line in text.splitlines()}
    missing = [line for line in (*GITATTRIBUTES_LINES, *_bench_rows(target)[1])
               if line not in present]
    if not missing:
        return []
    block = "\n".join([GITATTRIBUTES_HEADER, *missing]) + "\n"
    joiner = "" if not text or text.endswith("\n") else "\n"
    path.write_text(text + joiner + block, encoding="utf-8")
    return [f"attributes  {line}" for line in missing]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def install(target: Path, sandbox: bool = False) -> list[str]:
    _check_source()
    changed = []
    changed += _copy_components(target)
    changed += _merge_settings(target, sandbox)
    changed += _append_claude_md(target)
    changed += _seed_state(target)
    changed += _append_gitignore(target)
    changed += _append_gitattributes(target)
    (target / VERSION_FILE).write_text(source_version() + "\n", encoding="utf-8")
    return changed


def _settings_commands(settings: dict) -> list[str]:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return []
    return [
        h.get("command", "")
        for entries in hooks.values() if isinstance(entries, list)
        for e in entries
        for h in e.get("hooks", [])
    ]


def has_file_install(target: Path) -> bool:
    """The file-based install is present: copied hook code or guard hook entries."""
    if (target / HOOK_DIR).exists():
        return True
    try:
        settings = _load_json(target / SETTINGS, "the guard")
    except (InstallError, OSError):
        return False
    return any(HOOK_MARK in c for c in _settings_commands(settings))


def install_plugin(target: Path) -> list[str]:
    """Seed project state for the plugin; migrate a file-based install away."""
    changed = []
    if has_file_install(target):
        changed += _remove_file_install(target)
    changed += _append_claude_md(target, plugin=True)
    changed += _seed_state(target)
    changed += _append_gitignore(target)
    return changed


def check_plugin(target: Path) -> list[tuple[bool, str]]:
    rows = [(not has_file_install(target),
             "no file-based install left (its hooks would run twice beside the plugin)")]
    claude_md = target / "CLAUDE.md"
    text = claude_md.read_text(encoding="utf-8") if claude_md.exists() else ""
    rows.append((CLAUDE_MD_HEADING in text and HOOK_MARK not in _section_of(text),
                 f"CLAUDE.md has the plugin {CLAUDE_MD_HEADING} section"))
    for name in ("vetted.json", "declined.json"):
        rows.append(((target / STATE_DIR / name).is_file(), str(STATE_DIR / name)))
    reports_ignore = STATE_DIR / "reports" / ".gitignore"
    rows.append(((target / reports_ignore).is_file(), str(reports_ignore)))
    gitignore = target / ".gitignore"
    present = set(gitignore.read_text(encoding="utf-8").splitlines()) if gitignore.exists() else set()
    rows.append((all(l in present for l in GITIGNORE_LINES), ".gitignore lists the local state files"))
    rows.append(mode_row(target))
    app_target = refuse_app_target(target)
    if app_target is not None:
        rows.append((False, app_target))
    return rows


def source_version() -> str:
    """The release this clone holds; a development checkout has no VERSION."""
    try:
        return (SOURCE / "VERSION").read_text(encoding="utf-8").strip() or "dev"
    except OSError:
        return "dev"


def installed_version(target: Path) -> str | None:
    try:
        return (target / VERSION_FILE).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def seed_user_catalog(path: Path | None = None) -> str:
    """Human-run setup; never replace a user's existing catalog decisions."""
    path = path or Path.home() / ".config/package-guard/trusted-packages.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as output:
            output.write((SOURCE / HOOK_DIR / "trusted-packages.json").read_text(encoding="utf-8"))
    except FileExistsError:
        return f"kept     {path} (user catalog already exists)"
    return f"seeded   {path} (identity trust only; no installation approval)"


def check(target: Path, sandbox: bool = False) -> list[tuple[bool, str]]:
    rows = [((target / c).exists(), str(c)) for c in COMPONENTS]
    rows.append(((target / HOOK_DIR / "run.sh").is_file(), f"{HOOK_DIR}/run.sh"))

    path = target / SETTINGS
    hooks_ok = deny_ok = False
    if path.exists():
        try:
            settings = _load_json(path, "the guard")
        except InstallError:
            settings = {}
        commands = [
            h.get("command", "")
            for entries in settings.get("hooks", {}).values()
            for e in entries
            for h in e.get("hooks", [])
        ]
        wanted = {
            h["command"]
            for entries in _guard_settings()[0].values()
            for e in entries
            for h in e["hooks"]
        }
        hooks_ok = wanted.issubset(commands)
        deny_ok = all(
            r in settings.get("permissions", {}).get("deny", []) for r in _guard_settings()[1]
        )
    rows.append((hooks_ok, f"{SETTINGS} registers the three hooks via run.sh"))
    rows.append((deny_ok, f"{SETTINGS} denies Edit/Write under {STATE_DIR}"))
    lock_ok = path.exists() and all(
        r in settings.get("permissions", {}).get("deny", []) for r in LOCK_DENY
    )
    rows.append((lock_ok, f"{SETTINGS} locks the guard's own files against Edit/Write"))
    bench_deny, bench_attributes = _bench_rows(target)
    if bench_deny:
        rows.append((path.exists() and all(
            r in settings.get("permissions", {}).get("deny", []) for r in bench_deny),
            f"{SETTINGS} locks the bench's installer files (pip.conf, uv.toml, .yarnrc)"))
    # A project that opted in (--sandbox now, or any guard entry already there)
    # is held to the whole block; a loosened one fails. Otherwise it is off.
    if sandbox or (path.exists() and _sandbox_present(settings)):
        ok = path.exists() and _sandbox_ok(settings)
        what = f"{SETTINGS} turns on the strict sandbox (guard CLI excluded, guard files write-denied)"
        missing = _sandbox_missing(settings) if path.exists() else []
        if not ok and missing:
            # An install from before an entry existed: say which, and the one command that adds them.
            what += (f"; missing {len(missing)} entr{'y' if len(missing) == 1 else 'ies'} "
                     f"({'; '.join(missing[:6])}{'; ...' if len(missing) > 6 else ''}): "
                     "re-run the installer with --sandbox, which only adds")
        rows.append((ok, what))
    else:
        rows.append((True, f"{SETTINGS} sandbox off (opt in with --sandbox)"))

    claude_md = target / "CLAUDE.md"
    rows.append((
        claude_md.exists() and CLAUDE_MD_HEADING in claude_md.read_text(encoding="utf-8"),
        f"CLAUDE.md has {CLAUDE_MD_HEADING}",
    ))
    for name in ("vetted.json", "declined.json"):
        rows.append(((target / STATE_DIR / name).is_file(), str(STATE_DIR / name)))

    gitignore = target / ".gitignore"
    present = set(gitignore.read_text(encoding="utf-8").splitlines()) if gitignore.exists() else set()
    rows.append((all(l in present for l in GITIGNORE_LINES), ".gitignore lists the local state files"))

    attributes = target / ".gitattributes"
    present = set(attributes.read_text(encoding="utf-8").splitlines()) if attributes.exists() else set()
    rows.append((all(l in present for l in (*GITATTRIBUTES_LINES, *bench_attributes)),
                 ".gitattributes keeps the guard's files LF"))
    runner = target / HOOK_DIR / "run.sh"
    rows.append((not runner.is_file() or b"\r" not in runner.read_bytes(),
                 f"{HOOK_DIR}/run.sh has LF line endings (re-run install to repair)"))
    rows.append(mode_row(target))
    app_target = refuse_app_target(target)
    if app_target is not None:
        rows.append((False, app_target))
    return rows


def mode_row(target: Path) -> tuple[bool, str]:
    """The mode in force. warn and off are the user's choice, so they pass;
    a mode file the guard cannot read fails, though the guard reads it as
    enforce."""
    # A built plugin keeps the guard in guard/package_guard beside install.py.
    guard = SOURCE / HOOK_DIR
    if not guard.is_dir():
        guard = SOURCE / "guard" / "package_guard"
    try:
        sys.path.insert(0, str(guard))
        import mode as pg_mode
        current = pg_mode.effective(target)
    except Exception as exc:  # noqa: BLE001 - a check row, never a crash
        return False, f"mode could not be read ({exc})"
    finally:
        sys.path.pop(0)
    if current.problem:
        return False, f"mode: enforce (fail closed: {current.problem})"
    return True, f"mode: {pg_mode.describe(current)}"


def _remove_file_install(target: Path) -> list[str]:
    """Remove the copied code, hook entries, deny rules and sandbox block."""
    changed = []
    for component in COMPONENTS:
        path = target / component
        if path.is_dir():
            shutil.rmtree(path)
            changed.append(f"removed  {component}")
        elif path.exists():
            path.unlink()
            changed.append(f"removed  {component}")

    settings_path = target / SETTINGS
    if settings_path.exists():
        settings = _load_json(settings_path, "the guard")
        deny = settings.get("permissions", {}).get("deny")
        if deny is not None:
            kept = [r for r in deny if r not in LOCK_DENY and r not in BENCH_LOCK_DENY
                    and not any(
                mark in r for mark in (DENY_MARK, TRUST_DENY_MARK, SEED_DENY_MARK))]
            if len(kept) != len(deny):
                settings["permissions"]["deny"] = kept
                changed.append("removed  deny rules")
        for event in list(settings.get("hooks", {})):
            entries = settings["hooks"][event]
            kept = [
                e for e in entries
                if not any(HOOK_MARK in h.get("command", "") for h in e.get("hooks", []))
            ]
            if len(kept) != len(entries):
                changed.append(f"removed  hook {event}")
                if kept:
                    settings["hooks"][event] = kept
                else:
                    del settings["hooks"][event]
        if _remove_sandbox(settings):
            changed.append("removed  sandbox settings")
        if changed:
            settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return changed


def uninstall(target: Path) -> list[str]:
    changed = _remove_file_install(target)

    # Local state goes; the trust record stays. vetted.json and declined.json
    # are committed project history and deleting them is the owner's call.
    state = target / STATE_DIR
    if state.is_dir():
        for name in (".stop-state.json", ".disk-state.json", ".disk-findings.json",
                     ".transitive-state.json", ".environments.json") + MODE_LOCAL_FILES:
            if (state / name).exists():
                (state / name).unlink()
        reports = state / "reports"
        if reports.is_dir():
            shutil.rmtree(reports)
        changed.append(f"cleared  {STATE_DIR} (kept vetted.json, declined.json, mode.json)")

    claude_md = target / "CLAUDE.md"
    if claude_md.exists():
        text = claude_md.read_text(encoding="utf-8")
        if CLAUDE_MD_HEADING in text:
            start = text.find(CLAUDE_MD_HEADING)
            end = text.find("\n## ", start + len(CLAUDE_MD_HEADING))
            cut = text[:start].rstrip() + ("\n\n" + text[end + 1:] if end >= 0 else "\n")
            claude_md.write_text(cut, encoding="utf-8")
            changed.append(f"removed  CLAUDE.md {CLAUDE_MD_HEADING}")

    gitignore = target / ".gitignore"
    if gitignore.exists():
        lines = gitignore.read_text(encoding="utf-8").splitlines()
        drop = set(GITIGNORE_LINES) | {GITIGNORE_HEADER}
        kept = [l for l in lines if l.strip() not in drop]
        if len(kept) != len(lines):
            gitignore.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            changed.append("removed  .gitignore lines")

    attributes = target / ".gitattributes"
    if attributes.exists():
        lines = attributes.read_text(encoding="utf-8").splitlines()
        drop = set(GITATTRIBUTES_LINES) | set(BENCH_GITATTRIBUTES_LINES) | {GITATTRIBUTES_HEADER}
        kept = [l for l in lines if l.strip() not in drop]
        if len(kept) != len(lines):
            if kept:
                attributes.write_text("\n".join(kept) + "\n", encoding="utf-8")
            else:
                attributes.unlink()
            changed.append("removed  .gitattributes lines")
    return changed


GIT_ADD = (
    "git add .claude/hooks/package_guard .claude/agents/package-vetter.md "
    ".claude/skills/package-guard .claude/settings.json "
    ".claude/package-guard/vetted.json .claude/package-guard/declined.json "
    ".claude/package-guard/reports/.gitignore CLAUDE.md .gitignore .gitattributes"
)


def _settings_or_empty(target: Path) -> dict:
    try:
        return _load_json(target / SETTINGS, "the guard")
    except (InstallError, OSError):
        return {}


def _next_steps(target: Path, sandboxed: bool) -> list[str]:
    """What the person who ran the installer does next, in order."""
    lines = ["", f"Package Guard installed in {target}: {source_version()}", ""]
    if sandboxed:
        lines += [
            "Sandbox: ON. Bash cannot write the guard's files or approvals; every host",
            "stays reachable. macOS needs nothing; Linux and WSL2 need bubblewrap and",
            "socat, or Claude Code will not start in this project.",
        ]
    else:
        lines += [
            "Sandbox: off. The guard gates every install, but a script Claude runs could",
            "still rewrite the guard's files. Re-run with --sandbox to close that.",
        ]
    lines += ["", "Next:"]
    step = 1
    if Path.cwd().resolve() != target:
        lines.append(f"  {step}. cd {target}")
        step += 1
    lines += [
        f"  {step}. Commit the guard, so teammates who clone the repo get it:",
        f"       {GIT_ADD}",
        '       git commit -m "Add Package Guard"',
        f"  {step + 1}. Start Claude Code here (restart it if it is open) and run /hooks:",
        "       PreToolUse -> Bash must be listed.",
        f"  {step + 2}. Ask Claude to add a package. You approve each new package once,",
        "       at a permission prompt that shows its evidence.",
        "",
        "Every machine that runs Claude Code here needs uv with Python 3.11",
        "(uv python install 3.11), or a python3.11 on PATH.",
        f"Check the install any time: python3 {SOURCE / 'install.py'} {target} --check",
    ]
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("project", help="root of the project to guard")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="report, change nothing")
    mode.add_argument("--uninstall", action="store_true", help="remove the guard")
    parser.add_argument("--plugin", action="store_true",
                        help="seed project state for the Claude Code plugin; copies no hooks, "
                             "and migrates a file-based install away")
    parser.add_argument("--sandbox", action="store_true",
                        help="also turn on the strict Claude Code sandbox; "
                             "it confines every Bash command in the project")
    parser.add_argument("--init-user-trust", action="store_true",
                        help="seed the shared per-user identity catalog if absent; never overwrite")
    args = parser.parse_args(argv)

    if sys.version_info < (3, 11):
        print("install.py: needs Python 3.11 or newer (the guard's own floor).", file=sys.stderr)
        return 2

    target = Path(args.project).expanduser().resolve()
    if not target.is_dir():
        print(f"install.py: {target} is not a directory.", file=sys.stderr)
        return 2
    if target == SOURCE:
        print("install.py: the target is this clone; pick the project to guard.", file=sys.stderr)
        return 2

    if args.plugin and (args.sandbox or args.uninstall or args.init_user_trust):
        print("install.py: --plugin takes only --check.", file=sys.stderr)
        return 2

    if not (args.check or args.uninstall):
        refused = refuse_app_target(target)
        if refused:
            print(f"install.py: {refused}", file=sys.stderr)
            return 2

    try:
        if args.plugin:
            if args.check:
                rows = check_plugin(target)
                for ok, what in rows:
                    print(f"{'pass' if ok else 'MISSING'}  {what}")
                return 0 if all(ok for ok, _ in rows) else 1
            for line in install_plugin(target):
                print(line)
            print("")
            print(f"Package Guard project state is set up in {target}.")
            print("Commit it so teammates share it:")
            print(f"  git add {STATE_DIR / 'vetted.json'} {STATE_DIR / 'declined.json'} "
                  f"{STATE_DIR / 'reports' / '.gitignore'} CLAUDE.md .gitignore")
            print("If this project had the file-based install, restart Claude Code so its old hooks unload.")
            return 0
        if args.check:
            rows = check(target, args.sandbox)
            print(f"installed {installed_version(target) or 'unknown (installed before v1.8.2)'}"
                  f"; this clone is {source_version()}")
            for ok, what in rows:
                print(f"{'pass' if ok else 'MISSING'}  {what}")
            return 0 if all(ok for ok, _ in rows) else 1
        if args.uninstall:
            for line in uninstall(target):
                print(line)
            print("Restart the Claude Code session for the hooks to unload.")
            return 0
        changed = install(target, args.sandbox)
        seed_error = None
        if args.init_user_trust:
            # The project install is complete by now; a seed that cannot
            # write (read-only HOME, HOME unset) must not end in a traceback
            # that hides the guidance below.
            try:
                changed.append(seed_user_catalog())
            except (OSError, RuntimeError) as exc:
                seed_error = exc
        for line in changed:
            print(line)
        for line in _next_steps(target, args.sandbox or _sandbox_present(_settings_or_empty(target))):
            print(line)
        if seed_error is not None:
            print(f"install.py: the user catalog was not seeded ({seed_error}); "
                  "the project install is complete. Fix the home directory and re-run "
                  "with --init-user-trust.", file=sys.stderr)
            return 1
        return 0
    except InstallError as exc:
        print(f"install.py: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
