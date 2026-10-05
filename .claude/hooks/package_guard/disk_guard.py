"""Reconcile what is declared against what is installed.

The second enforcement layer.

The PreToolUse gate decides from a Bash command string whether packages are
being acquired. That is provably incomplete: `npm run serve` runs `npx serve`
out of package.json, `uv sync 2>&1 | tail` installs a locked project
through a pipe, and `make`, `bash ./setup.sh` and every other re-executor
that reads its commands from a file are invisible by construction. Closing them
one at a time means enumerating every such verb forever.

So this module never looks at a command. It compares sets:

    direct_set(manifest) INTERSECT installed(disk) MINUS vetted MINUS watermark

Detection is therefore independent of how the packages arrived, which is the
only property that makes it complete against that whole class.

**This module MUST NOT import `parser`**. The moment it can see command text,
it acquires the parser's blind spot.

It also never removes anything. Removal is a command printed for
the agent; a guard that deleted files could destroy work on a false positive,
and the machine-global caches it reads guarantee false positives are possible.

Standard library only.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory  # noqa: E402
import manifest as pg_manifest  # noqa: E402
import store  # noqa: E402

MESSAGE_CODE = store.MESSAGE_UNREVIEWED_ON_DISK

# Directories the scope walk never descends into. node_modules and .venv are
# the INSTALL roots -- descending into them would discover a dependency's own
# package.json and treat a transitive as a project.
SKIP_DIRECTORIES = frozenset({
    ".claude", ".git", ".hg", ".mypy_cache", ".next", ".pytest_cache", ".ruff_cache",
    ".svn", ".tox", "__pycache__", "build", "dist", "node_modules", "site-packages",
    "venv", ".venv", ".worktrees",
})

# A project is a handful of directories deep. Unbounded recursion over a
# monorepo would make the PreToolUse advance a cost the gate has to budget for,
# and this layer makes no network call precisely so it never needs a budget.
MAX_SCAN_DEPTH = 5

_IDENTITY_KEYS = ("ecosystem", "name", "version", "registry")

# The sources whose roots are shared by every project on the machine.
MACHINE_GLOBAL = frozenset({inventory.NPX_CACHE, inventory.UV_TOOL, inventory.UVX_ENV})


class Scope(NamedTuple):
    """One manifest and the environment it installs into."""

    kind: str          # "npm" | "uv-project" | "requirements"
    directory: str
    manifest: str


class Result(NamedTuple):
    """What one reconciliation decided.

    `seeded` is True on the one invocation that establishes the watermark; it
    produces no findings by definition.
    """

    findings: tuple = ()       # every open finding after this run
    new_findings: tuple = ()   # the subset first detected by THIS run
    closed: tuple = ()         # (finding, reason) pairs dropped by this run
    seeded: bool = False
    scopes: tuple = ()
    # Every in-scope package this run saw on disk, seeded or not. Carried so a
    # caller that already paid for the scan can answer "is this identity
    # installed" without walking the tree again.
    installed: tuple = ()


# ---------------------------------------------------------------------------
# Scope discovery
# ---------------------------------------------------------------------------

def discover_scopes(project_root, max_depth: int = MAX_SCAN_DEPTH) -> list:
    """Every manifest in the project tree, with the environment it fills."""
    root = Path(project_root)
    scopes = []
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        names = {child.name for child in children}
        if "package.json" in names:
            scopes.append(Scope("npm", str(directory), str(directory / "package.json")))
        if "uv.lock" in names:
            scopes.append(Scope("uv-project", str(directory), str(directory / "uv.lock")))
        elif "pyproject.toml" in names:
            scopes.append(
                Scope("uv-project", str(directory), str(directory / "pyproject.toml"))
            )
        for child in children:
            if child.is_file() and child.name.startswith("requirements") and \
                    child.name.endswith(".txt"):
                scopes.append(Scope("requirements", str(directory), str(child)))
        if depth >= max_depth:
            continue
        for child in children:
            if not child.is_dir() or child.name in SKIP_DIRECTORIES:
                continue
            if child.name.startswith("."):
                continue
            # A nested checkout (a git worktree, a vendored repository) is
            # another project with its own guard state.
            if (child / ".git").exists():
                continue
            stack.append((child, depth + 1))
    return scopes


def direct_names(scope: Scope) -> set:
    """The names a scope's manifest declares as its own dependencies.

    Always from the manifest, never from listing the install directory, and
    always through the function the PreToolUse gate uses. A manifest that cannot be read yields an empty set: the
    direct set is unknown, so nothing from that scope is a candidate. The
    PreToolUse gate denies loudly on the same file when an install is
    attempted, which is where a hard failure belongs.
    """
    try:
        if scope.kind == "npm":
            return set(pg_manifest.npm_direct_names(scope.directory))
        if scope.kind == "uv-project":
            return set(pg_manifest.uv_project_direct_names(scope.directory))
        if scope.kind == "requirements":
            return set(pg_manifest.requirements_direct_names(scope.manifest))
    except pg_manifest.ManifestError:
        return set()
    return set()


def scope_packages(scope: Scope) -> list:
    """Installed packages of a scope, already intersected with its direct set."""
    wanted = direct_names(scope)
    if not wanted:
        return []
    if scope.kind == "npm":
        installed = inventory.node_modules_packages(scope.directory)
    else:
        installed = inventory.dist_info_packages(Path(scope.directory) / ".venv")
    return [package for package in installed if package.name in wanted]


def collect(project_root, npx_cache_root=None, uv_tools_root=None,
            uv_environments_root=None):
    """(packages, scopes): every in-scope installed package, deduplicated.

    Three of the five sources are their own direct set: the npx cache records
    what was asked for, a uv tool receipt names its requirement, and the uvx
    bin/ proxy stands in for a receipt that does not exist. Those roots are
    machine-GLOBAL -- they hold packages from unrelated projects, and only the
    one-time seed keeps those out of the finding set.
    """
    scopes = discover_scopes(project_root)
    packages = []
    for scope in scopes:
        packages.extend(scope_packages(scope))
    packages.extend(inventory.npx_cache_packages(npx_cache_root))
    packages.extend(inventory.uv_tool_packages(uv_tools_root))
    packages.extend(inventory.uvx_environment_packages(uv_environments_root))

    unique, seen = [], set()
    for package in packages:
        if package in seen:
            continue
        seen.add(package)
        unique.append(package)
    unique.sort(key=lambda p: (p.ecosystem, p.name, p.version, p.source, p.path))
    return unique, tuple(scopes)


# ---------------------------------------------------------------------------
# The watermark
# ---------------------------------------------------------------------------

def entry_key(package) -> str:
    """`<source>|<ecosystem>:<name>@<version>|<absolute path>`.

    The version is in the key on purpose. Keying on the path alone would let an
    in-place upgrade pass unexamined, because `node_modules/<name>` is the same
    path at every version.
    """
    return (
        f"{package.source}|{package.ecosystem}:{package.name}@{package.version}"
        f"|{package.path}"
    )


def _identity_key(identity: dict):
    return tuple(identity.get(key) for key in _IDENTITY_KEYS)


def _finding_identity(finding: dict) -> dict:
    return {key: finding.get(key) for key in _IDENTITY_KEYS}


def _commit(root, findings, seeded_at: str, entries: dict) -> None:
    """The ONLY writer of either reconciliation artifact.

    Findings first, state second, and never the other way round. A crash
    between the two leaves the finding recorded and the entry un-absorbed, so
    the next scan re-detects the same identity: idempotent, and in the
    fail-closed direction. The reverse order is the laundering hole -- an entry
    absorbed with no finding is invisible forever.

    There is deliberately no code path that writes the state file alone, which
    is what makes "absorbing an entry and deciding on it are one operation"
    a property of the module rather than a convention.
    """
    store.save_disk_findings(root, findings)
    store.save_disk_state(root, seeded_at, entries)


def open_findings(root) -> list:
    """The open finding set, without scanning anything.

    Both hooks call this on the hot path, so it must stay a single small read.
    Raises StoreError when the file is malformed: this fails closed, because an unreadable record that something unreviewed is installed must
    not read as "nothing is wrong".
    """
    return list(store.load_disk_findings(root)["findings"])


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

def reconcile(root, project_root=None, detected_by: str = "PostToolUse",
              session_id=None, command=None, npx_cache_root=None,
              uv_tools_root=None, uv_environments_root=None, now=None,
              session_started=None) -> Result:
    """Compare disk against the declared, vetted and already-decided sets.

    `session_started` (a datetime, from `transcript.session_started`) is the
    session cutoff: a new machine-global entry whose mtime and ctime are both
    before it was put there by something other than this session, and is
    absorbed without a finding. An entry that cannot be dated is not absorbed.
    None applies no cutoff.

    Raises store.StoreError if guard state is unreadable; every caller decides
    its own failure policy for that, because they differ (the Stop hook fails
    soft, the PreToolUse gate fails closed, the PostToolUse scan fails open).
    """
    project_root = Path(project_root) if project_root is not None else Path(root)
    packages, scopes = collect(
        project_root,
        npx_cache_root=npx_cache_root,
        uv_tools_root=uv_tools_root,
        uv_environments_root=uv_environments_root,
    )
    state = store.load_disk_state(root)
    existing = open_findings(root)
    stamps = inventory.mtimes(packages)
    timestamp = now or store.utcnow()

    seeding = state["seeded_at"] is None
    cutoff = int(session_started.timestamp() * 1_000_000_000) if session_started else None
    # The cutoff alone reads the ctime: a backdated mtime must not absorb.
    changed = inventory.changed_at(packages) if cutoff is not None else {}
    previous_entries = state["entries"]
    entries = {}
    fresh = []

    for package in packages:
        key = entry_key(package)
        observed = stamps[package]
        recorded = previous_entries.get(key)
        # `entries` is rebuilt from what is on disk, so an entry
        # whose package is gone is pruned. That is what makes a reinstall after
        # a removal a fresh detection rather than a silent absorption.
        entries[key] = max(observed, recorded) if recorded is not None else observed
        if seeding:
            continue
        if recorded is not None and observed <= recorded:
            continue  # already decided, unchanged
        if store.is_vetted(root, package.identity):
            continue  # decided by a human, absorbed silently
        if (cutoff is not None and package.source in MACHINE_GLOBAL
                and changed.get(package) is not None and changed[package] < cutoff):
            continue  # another project's or an earlier run's, not this session's
        fresh.append(package)

    observed_identities = {_identity_key(p.identity) for p in packages}
    paths_by_identity = {}
    for package in packages:
        paths_by_identity.setdefault(_identity_key(package.identity), []).append(package.path)

    kept, closed = [], []
    for finding in existing:
        identity = _finding_identity(finding)
        if store.is_vetted(root, identity):
            closed.append((finding, "vetted"))          # approved since
            continue
        key = _identity_key(identity)
        if key not in observed_identities:
            closed.append((finding, "absent"))          # removed since
            continue
        finding = dict(finding)
        finding["paths"] = sorted(set(paths_by_identity.get(key, finding.get("paths") or [])))
        kept.append(finding)

    known = {_identity_key(_finding_identity(f)) for f in kept}
    new_findings = []
    for package in fresh:
        key = _identity_key(package.identity)
        if key in known:
            continue
        known.add(key)
        identity = package.identity
        new_findings.append({
            "finding_id": store.new_finding_id(),
            "ecosystem": identity["ecosystem"],
            "name": identity["name"],
            "version": identity["version"],
            "registry": identity["registry"],
            "source": package.source,
            "paths": sorted(set(paths_by_identity.get(key, [package.path]))),
            "detected_at": timestamp,
            "detected_by": detected_by,
            "session_id": session_id,
            "command": command,
            "review_id": None,
        })

    findings = kept + new_findings
    findings.sort(key=lambda f: (f["ecosystem"], f["name"], f["version"]))
    # Nothing moved: skip the write rather than churn two files on every Bash
    # command. The single-writer property is unaffected -- this
    # only decides whether _commit runs, never what it writes or in what order.
    if seeding or entries != previous_entries or findings != existing:
        _commit(root, findings, state["seeded_at"] or timestamp, entries)
    return Result(
        findings=tuple(findings),
        new_findings=tuple(new_findings),
        closed=tuple(closed),
        seeded=seeding,
        scopes=scopes,
        installed=tuple(packages),
    )


def record_review(root, identity: dict, review_id: str) -> bool:
    """Attach a review id to the finding for `identity`. Used by cli reconcile.

    Touches the findings file only -- it neither absorbs nor releases a
    watermark entry, so the single-writer invariant is unaffected.
    """
    data = store.load_disk_findings(root)
    changed = False
    for finding in data["findings"]:
        if _identity_key(_finding_identity(finding)) == _identity_key(identity):
            finding["review_id"] = review_id
            changed = True
    if changed:
        store.save_disk_findings(root, data["findings"])
    return changed


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _label(finding: dict) -> str:
    return f"{finding['ecosystem']}:{finding['name']}@{finding['version']}"


def removal_command(finding: dict) -> str:
    """How to get one package off disk.

    Every one of these is classified `ignore` by the recognizer, which is the
    whole reason the gate denies only `package`/`unsupported` commands while a
    finding is open: a blanket Bash block would make the fix unreachable.
    """
    source, name = finding["source"], finding["name"]
    if source == inventory.NODE_MODULES:
        return f"npm uninstall {name}"
    if source == inventory.VENV:
        return f"uv remove {name}"
    if source == inventory.UV_TOOL:
        return f"uv tool uninstall {name}"
    # The npx and uvx caches have no uninstaller; the entry is just a directory.
    # Quoted: a human may paste this, and a space would split one path in two.
    return "rm -rf " + " ".join(shlex.quote(path) for path in finding.get("paths") or [])


def render_block(findings, root, header: str | None = None,
                 declined_check=None) -> str:
    """The PACKAGE_GUARD_UNREVIEWED_ON_DISK body, shared by all three hooks."""
    count = len(findings)
    lines = [MESSAGE_CODE]
    lines.append(
        header
        or (
            f"{count} direct dependenc{'y is' if count == 1 else 'ies are'} installed that "
            "no human approved. Package Guard found "
            f"{'it' if count == 1 else 'them'} on disk, not in a command, so "
            f"{'it' if count == 1 else 'they'} got there without passing the gate."
        )
    )
    for finding in findings:
        lines.append(f"- {_label(finding)}  [{finding['source']}]")
        for path in finding.get("paths") or []:
            lines.append(f"    {path}")
        if finding.get("command"):
            lines.append(f"    noticed after running: {finding['command']}")
        if finding.get("source") in MACHINE_GLOBAL:
            # The scan sees a shared root, not who wrote to it. A finding can
            # name an unrelated command (an `ls`) and read as the agent's own
            # install when another project put the package there.
            lines.append(
                "    machine-global cache shared by every project: that command did not "
                "necessarily put it there"
            )
        if declined_check is not None and declined_check(_finding_identity(finding)):
            lines.append(
                "    THE USER ALREADY DECLINED THIS EXACT VERSION. It must be removed; "
                "it cannot be approved."
            )
    lines += [
        "",
        "Close every one of these. Two routes, and Package Guard will not choose for you:",
        "  (a) REVIEW it — open reviews with this simple standalone command "
        f"(no `cd`, no `&&`):\n      {store.cli_command(root, 'reconcile', '')}".rstrip(),
        "      then the usual loop: Agent tool -> package-vetter with the review ids, "
        "then one approve command for every RECOMMEND.",
        "  (b) REMOVE it — Package Guard never deletes anything itself:",
    ]
    for finding in findings:
        lines.append(f"      {removal_command(finding)}    ({_label(finding)})")
    if any(finding.get("source") in MACHINE_GLOBAL for finding in findings):
        # A user-level Bash hook may refuse `rm -rf` under the home directory,
        # and such a refusal is not this guard's to work around.
        lines.append(
            "      A cache path is outside this project: if your removal is refused, ask the "
            "user to run it (they can type `! <command>`)."
        )
    lines += [
        "",
        "Removal closes the finding with no permanent record: nothing is written to "
        "declined.json, and the package can be installed again later through the normal "
        "review path. Uninstall commands are not gated — run them directly.",
    ]
    return "\n".join(lines)
