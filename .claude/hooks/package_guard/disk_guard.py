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

import os
import shlex
import sys
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_config  # noqa: E402
import bench_gate  # noqa: E402
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
MACHINE_GLOBAL = frozenset({
    inventory.NPX_CACHE, inventory.UV_TOOL, inventory.UVX_ENV,
    inventory.PNPM_STORE, inventory.PNPM_DLX, inventory.BUN_CACHE, inventory.BUNX_CACHE,
    inventory.YARN_CACHE,
})

# Whether a finding for a pnpm, Bun or Yarn project may print that manager's own
# `remove` command. THIS MIRRORS `parser.PNPM_BUN_YARN_ENABLED` and this module
# cannot import the parser, so a test pins the two together. While it is False
# the parser refuses those `remove` forms, so printing one would hand the agent a
# fix the gate rejects; the block then prints a plain `rm -rf` of the paths,
# which is always allowed.
PM_REMOVAL_COMMANDS = True

# Whether a Yarn Classic (v1) project counts as a Yarn one here. THIS MIRRORS
# `parser.YARN_CLASSIC_ENABLED` (a test pins the two together). While it is False a Classic
# lock names no manager, as before Classic was supported.
YARN_CLASSIC_DISK = True

# The sources of a project's own direct dependencies that sit outside its node_modules: a
# finding from one of them carries the project's node_modules path too when the package was
# also installed there.
_PM_CACHE_SOURCES = frozenset({inventory.PNPM_STORE, inventory.BUN_CACHE, inventory.YARN_CACHE,
                               inventory.YARN_LOCAL_CACHE})

# The lock files that name a project's package manager (the inventory markers
# are consulted when no lock exists).
_PM_LOCKS = {"pnpm-lock.yaml": "pnpm", "bun.lock": "bun", "bun.lockb": "bun"}

# Whether a Frappe bench's env is scanned in full (every distribution, not only what a manifest
# declares). THIS MIRRORS `parser.FRAPPE_ENABLED`, which this module cannot import, and a test pins
# the two together. While it is False a bench is reconciled as before.
BENCH_ENV_DISK = True


class Scope(NamedTuple):
    """One manifest and the environment it installs into."""

    kind: str          # "npm" | "uv-project" | "requirements" | "bench-env"
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
        if BENCH_ENV_DISK and "apps" in names and "sites" in names \
                and (directory / "env" / "pyvenv.cfg").is_file():
            # A bench's apps are repositories of their own, which this walk skips: its env is
            # read in full instead (every distribution, `bench_gate.env_residue`).
            scopes.append(Scope("bench-env", str(directory), str(directory / "env")))
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
                if BENCH_ENV_DISK and (child / "apps").is_dir() and (child / "sites").is_dir() \
                        and (child / "env" / "pyvenv.cfg").is_file():
                    # The gate accepts a bench inside the guard root whether or not it is a git
                    # checkout, so its env is read in full as well.
                    scopes.append(Scope("bench-env", str(child), str(child / "env")))
                continue
            stack.append((child, depth + 1))
    return scopes


def _berry_lock(path: Path) -> bool:
    """A yarn.lock that is Berry's: it carries `__metadata`. The Classic header
    (`# yarn lockfile v1`) and an unreadable file are not."""
    try:
        with path.open("rb") as handle:
            head = handle.read(8192).decode("utf-8", "replace")
    except OSError:
        return False
    return "\n__metadata:" in "\n" + head and "yarn lockfile v1" not in head


def managers_of(directory) -> set:
    """The npm-family managers a project directory shows signs of, from its lock
    files first and its install markers second: a subset of
    {"npm", "pnpm", "bun", "yarn"}. A Yarn Classic (v1) lock counts as "yarn" while
    `YARN_CLASSIC_DISK` is on; an empty set means no sign at all."""
    directory = Path(directory)
    found = set()
    for name, manager in _PM_LOCKS.items():
        if (directory / name).is_file():
            found.add(manager)
    if (directory / "yarn.lock").is_file() and (
            _berry_lock(directory / "yarn.lock")
            or (YARN_CLASSIC_DISK and pg_manifest.yarn_classic_lock_file(directory / "yarn.lock"))):
        found.add("yarn")
    if (directory / "package-lock.json").is_file() or (directory / "npm-shrinkwrap.json").is_file():
        found.add("npm")
    if found:
        return found
    if inventory.has_pnpm_markers(directory):
        found.add("pnpm")
    if inventory.has_bun_markers(directory):
        found.add("bun")
    if inventory.has_berry_markers(directory) or (
            YARN_CLASSIC_DISK and inventory.has_classic_markers(directory)):
        found.add("yarn")
    return found


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
            # A pnpm or Bun project installs its root peerDependencies too (A7); npm's
            # and Yarn's direct set stays what it was.
            peers = bool(managers_of(scope.directory) & set(pg_manifest.PM_PEER_KINDS))
            return set(pg_manifest.npm_direct_names(scope.directory, peers=peers))
        if scope.kind == "uv-project":
            return set(pg_manifest.uv_project_direct_names(scope.directory))
        if scope.kind == "requirements":
            return set(pg_manifest.requirements_direct_names(scope.manifest))
    except pg_manifest.ManifestError:
        return set()
    return set()


def _bench_env(directory) -> Path | None:
    """`<bench>/env` when `directory` is a Frappe bench or anywhere inside one
    (`<bench>/apps/<app>/...`). bench pip-installs there from Python, where no
    command names it, so it is read like `.venv` (4.). `bench_config` is the one
    place that says where a bench is."""
    return bench_config.bench_env(directory)


def environments(directory, root=None, current=()) -> list:
    """The Python environments to reconcile for the scope in `directory`, in order.

    1. `current`: the environment the command being decided names, which the
       hook passes in -- this module never reads a command;
    2. the environments the hook recorded for this directory when it allowed
       a command naming one (`store.recorded_environments`);
    3. `<directory>/.venv`;
    4. a Frappe bench's `env` (`_bench_env`).

    Every one is read, not just the first that exists: a project can install
    into an outside environment and later into `.venv` again, and reading one
    would blind the scan to the other. Duplicates by real path are dropped.
    """
    candidates = [Path(p) for p in current]
    if root is not None:
        candidates += [Path(p) for p in store.recorded_environments(root, directory)]
    candidates.append(Path(directory) / ".venv")
    bench = _bench_env(directory)
    if bench is not None:
        candidates.append(bench)
    found, seen = [], set()
    for candidate in candidates:
        key = os.path.realpath(candidate)
        if key not in seen:
            seen.add(key)
            found.append(candidate)
    return found


def _node_modules_installed(directory, wanted) -> list:
    """A project's node_modules, read for whichever manager filled it.

    The top level is read for all of them (pnpm and Bun isolated installs link
    their direct dependencies there). pnpm's `.pnpm` and Bun's `.bun` stores and
    Yarn's `.yarn-state.yml` add the locations the top level cannot show. The
    transitive rule is npm's, unchanged: a store entry counts only for a DIRECT
    name, and only when it is the same version as that name's top-level entry or
    the name has no top-level entry at all. A second version of a direct name
    under `.pnpm` is nearly always another package's own dependency, and npm's
    nested `node_modules/<x>/node_modules/<name>` is not read either.
    """
    top = inventory.node_modules_packages(directory)
    extra = []
    for store_name in (".pnpm", ".bun"):
        extra.extend(inventory.isolated_store_packages(directory, store_name))
    extra.extend(inventory.yarn_state_packages(directory))
    seen = {(p.name, p.version) for p in top}
    named = {p.name for p in top}
    for package in extra:
        if package.name not in wanted:
            continue
        if (package.name, package.version) in seen or package.name not in named:
            top.append(package)
    return top


def scope_packages(scope: Scope, root=None, current=()) -> list:
    """Installed packages of a scope, already intersected with its direct set. A bench's env is not
    intersected with anything: it is whatever nothing covers (`bench_gate.env_residue`)."""
    if scope.kind == "bench-env":
        installed = inventory.dist_info_packages(scope.manifest)
        return bench_gate.env_residue(
            root, scope.directory, installed,
            lambda package: root is not None and store.is_vetted(root, package.identity))
    wanted = direct_names(scope)
    if not wanted:
        return []
    if scope.kind == "npm":
        installed = _node_modules_installed(scope.directory, wanted)
    else:
        installed = []
        for environment in environments(scope.directory, root, current):
            installed.extend(inventory.dist_info_packages(environment))
    return [package for package in installed if package.name in wanted]


def _pm_cache_packages(scopes, pm_roots) -> list:
    """Cache entries for the direct names of the pnpm, Bun and Yarn projects.

    A cache is read only when a project of that manager exists, and only for
    that manager's direct names (the npm transitive rule). A Yarn project's own
    `.yarn/cache` is read per project; the global cache once, for the union.
    `pm_roots` overrides the roots by key (`pnpm_store`, `pnpm_dlx`,
    `bun_cache`, `bunx_cache`, `yarn_cache`) for tests, and `pnpm_mount_stores`, a function
    of a project directory that names the mount-point stores, so a test never walks to
    the real filesystem root.
    """
    roots = pm_roots or {}

    def root_for(key, default):
        value = roots.get(key)
        return default if value is None else value

    direct = {"pnpm": set(), "bun": set(), "yarn": set()}
    pnpm_projects = []
    packages = []
    for scope in scopes:
        if scope.kind != "npm":
            continue
        managers = managers_of(scope.directory)
        wanted = direct_names(scope)
        if not wanted:
            continue
        for manager in direct:
            if manager in managers:
                direct[manager] |= wanted
        if "pnpm" in managers:
            pnpm_projects.append(scope.directory)
        if "yarn" in managers:
            packages.extend(inventory.yarn_cache_packages(
                Path(scope.directory) / ".yarn" / "cache", inventory.YARN_LOCAL_CACHE, wanted))
    if direct["pnpm"]:
        stores = [root_for("pnpm_store", inventory.PNPM_STORE_ROOT)]
        # A project on another filesystem than the home store gets `<mount>/.pnpm-store` (B5).
        mount_stores = root_for("pnpm_mount_stores", inventory.pnpm_mount_stores)
        for directory in pnpm_projects:
            stores += [store_ for store_ in mount_stores(directory) if store_ not in stores]
        for store_root in stores:
            packages.extend(inventory.pnpm_store_packages(store_root, direct["pnpm"]))
    if direct["bun"]:
        packages.extend(inventory.bun_cache_packages(
            root_for("bun_cache", inventory.BUN_CACHE_ROOT), direct["bun"]))
    if direct["yarn"]:
        packages.extend(inventory.yarn_cache_packages(
            root_for("yarn_cache", inventory.YARN_GLOBAL_CACHE_ROOT),
            inventory.YARN_CACHE, direct["yarn"]))
    # Like the npx cache these name their own packages, so they are read whether
    # or not a project of that manager exists.
    packages.extend(inventory.pnpm_dlx_packages(root_for("pnpm_dlx", inventory.PNPM_DLX_ROOT)))
    packages.extend(inventory.bunx_cache_packages(root_for("bunx_cache", inventory.BUNX_TMP_ROOT)))
    return packages


def collect(project_root, npx_cache_root=None, uv_tools_root=None,
            uv_environments_root=None, root=None, current=None, pm_roots=None):
    """(packages, scopes): every in-scope installed package, deduplicated.

    Three of the five sources are their own direct set: the npx cache records
    what was asked for, a uv tool receipt names its requirement, and the uvx
    bin/ proxy stands in for a receipt that does not exist. Those roots are
    machine-GLOBAL -- they hold packages from unrelated projects, and only the
    one-time seed keeps those out of the finding set.

    `root` is the guard root whose recorded environments are read; `current`
    maps a directory to the environments the command being decided names.
    """
    scopes = discover_scopes(project_root)
    current = {os.path.realpath(d): tuple(paths) for d, paths in (current or {}).items()}
    packages = []
    for scope in scopes:
        packages.extend(scope_packages(
            scope, root, current.get(os.path.realpath(scope.directory), ())))
    packages.extend(inventory.npx_cache_packages(npx_cache_root))
    packages.extend(inventory.uv_tool_packages(uv_tools_root))
    packages.extend(inventory.uvx_environment_packages(uv_environments_root))
    packages.extend(_pm_cache_packages(scopes, pm_roots))

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
# Catching up after the guard was down (warn or off)
#
# Reconciliation sees only the direct dependencies a manifest declares, so a
# `--no-save` install or a `pip install` straight into a venv while the guard
# was down would never be reviewed. When the guard goes down, the projects'
# full installed set is snapshotted; when it is back to enforce, every package
# that is new, unvetted and accounted for by neither its manifest nor its
# lockfile becomes an open finding. What a lockfile lists is the tree under the
# declared dependencies, treated as enforce treats it: the OSV batch on the
# next allowed install, not one review per transitive.
# ---------------------------------------------------------------------------

# Put into a NEW venv by `python -m venv` itself (ensurepip), not by an install.
_VENV_BOOTSTRAP = frozenset({"pip", "setuptools"})


def _accounting(scope: Scope):
    """(names, (name, version) pairs) a scope accounts for: what its manifest
    declares and what its lockfile would install. An unreadable lock accounts
    for nothing, which errs towards a finding."""
    names, pairs = direct_names(scope), set()
    try:
        if scope.kind == "npm":
            for manager in managers_of(scope.directory) or {"npm"}:
                pairs.update(pg_manifest.npm_locked_tree(scope.directory) if manager == "npm"
                             else pg_manifest.pm_locked_tree(scope.directory, manager))
        elif scope.kind == "uv-project":
            pairs.update(pg_manifest.uv_locked_tree(scope.directory))
    except Exception:  # noqa: BLE001 - see the docstring
        pass
    return names, pairs


def _local_installed(project_root, root) -> list:
    """[(package, (names, pairs))]: every package in each project's top-level
    node_modules and Python environments, declared or not, with what its scope
    accounts for. Bounded like `collect` (`discover_scopes`); the
    machine-global caches are left out, as they are reconciled with the
    session cutoff."""
    found, accounted = {}, {}
    for scope in discover_scopes(project_root):
        names, pairs = _accounting(scope)
        if scope.kind == "npm":
            sources = [inventory.node_modules_packages(scope.directory)]
        else:
            sources = [inventory.dist_info_packages(env)
                       for env in environments(scope.directory, root)]
        for packages in sources:
            for package in packages:
                found.setdefault(package, None)
                have = accounted.setdefault(package, (set(), set()))
                have[0].update(names)
                have[1].update(pairs)
    return [(package, accounted[package]) for package in found]


def take_snapshot(root, now=None) -> bool:
    """Record what is installed when the guard goes down. The earliest
    snapshot of a down period is kept: switching between warn and off, or a
    second hook seeing the same period, never retakes it."""
    if store.mode_snapshot_path(root).exists():
        return False
    keys = {entry_key(p) for p, _accounted in _local_installed(root, root)}
    store.save_mode_snapshot(root, keys, now or store.utcnow())
    return True


def catch_up(root, session_id=None, now=None) -> list:
    """The guard is enforcing again: open a finding for every package that
    arrived while it was down and that nothing accounts for, then drop the
    snapshot. Returns the new findings. A snapshot that cannot be read counts
    as empty, so everything unaccounted is reviewed (fails closed). Raises
    StoreError when the findings record is unreadable; the snapshot then stays
    for the next try."""
    if not store.mode_snapshot_path(root).exists():
        return []
    before = store.load_mode_snapshot(root) or set()
    # The site-packages directories that existed at the snapshot. Only a venv
    # created while the guard was down gets the bootstrap exemption; pip or
    # setuptools changed in an existing one is reviewed like anything else.
    known_sites = {str(Path(entry.split("|", 2)[-1]).parent) for entry in before}
    existing = open_findings(root)
    known = {_identity_key(_finding_identity(f)) for f in existing}
    timestamp = now or store.utcnow()
    installed = _local_installed(root, root)
    paths_by_identity = {}
    for package, _accounted in installed:
        paths_by_identity.setdefault(_identity_key(package.identity), []).append(package.path)
    new_findings = []
    for package, (names, pairs) in installed:
        key = _identity_key(package.identity)
        if entry_key(package) in before or key in known:
            continue
        if package.name in names or (package.name, package.version) in pairs:
            continue
        if (package.ecosystem == "pypi" and package.name in _VENV_BOOTSTRAP
                and str(Path(package.path).parent) not in known_sites):
            continue
        if store.is_vetted(root, package.identity):
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
            "paths": sorted(set(paths_by_identity[key])),
            "detected_at": timestamp,
            "detected_by": "mode-catch-up",
            "session_id": session_id,
            "command": None,
            "review_id": None,
            # Not declared, so reconciliation's own scan cannot see it; it is
            # checked for presence with the full walk instead (`reconcile`).
            "undeclared": True,
        })
    if new_findings:
        state = store.load_disk_state(root)
        findings = sorted(existing + new_findings,
                          key=lambda f: (f["ecosystem"], f["name"], f["version"]))
        _commit(root, findings, state["seeded_at"], state["entries"])
    store.clear_mode_snapshot(root)
    return new_findings


def follow_mode(root, mode: str, session_id=None) -> list:
    """Called by every hook and the CLI with the mode in force: snapshot while
    the guard is down, catch up once it enforces again. The snapshot file is
    the marker, so a mode that changed without the CLI (a pulled mode.json, an
    expiry, a deleted file) is followed too. Returns the new findings."""
    if mode == "enforce":
        return catch_up(root, session_id)
    take_snapshot(root)
    return []


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

def reconcile(root, project_root=None, detected_by: str = "PostToolUse",
              session_id=None, command=None, npx_cache_root=None,
              uv_tools_root=None, uv_environments_root=None, now=None,
              session_started=None, environments=None, pm_roots=None) -> Result:
    """Compare disk against the declared, vetted and already-decided sets.

    `session_started` (a datetime, from `transcript.session_started`) is the
    session cutoff: a new machine-global entry whose mtime and ctime are both
    before it was put there by something other than this session, and is
    absorbed without a finding. An entry that cannot be dated is not absorbed.
    None applies no cutoff.

    `environments` maps a directory to the Python environments the command
    being decided names; the recorded ones are read whatever it says.

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
        root=root,
        current=environments,
        pm_roots=pm_roots,
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

    paths_by_identity = {}
    for package in packages:
        paths_by_identity.setdefault(_identity_key(package.identity), []).append(package.path)

    # A catch-up finding is for a package no manifest declares, which the scan
    # above never sees; its presence is read with the full walk, and only
    # while one is open.
    undeclared_paths = None
    if any(f.get("undeclared") for f in existing):
        undeclared_paths = {}
        for package, _accounted in _local_installed(project_root, root):
            undeclared_paths.setdefault(_identity_key(package.identity), []).append(package.path)

    kept, closed = [], []
    for finding in existing:
        identity = _finding_identity(finding)
        if store.is_vetted(root, identity):
            closed.append((finding, "vetted"))          # approved since
            continue
        key = _identity_key(identity)
        seen = (undeclared_paths if finding.get("undeclared") else paths_by_identity) or {}
        if key not in seen:
            closed.append((finding, "absent"))          # removed since
            continue
        finding = dict(finding)
        finding["paths"] = sorted(set(seen.get(key, finding.get("paths") or [])))
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


def _finding_project(finding: dict):
    """The project directory a node_modules finding sits in: the directory above the first
    `node_modules` component of its first path, or None."""
    for path in finding.get("paths") or []:
        parts = Path(path).parts
        if "node_modules" in parts:
            return Path(*parts[:parts.index("node_modules")]) if parts.index("node_modules") else Path(".")
    return None


def _finding_managers(finding: dict) -> set:
    """The managers of the project a node_modules finding sits in. Empty or
    {"npm"} reads as npm, which is today's behaviour."""
    project = _finding_project(finding)
    return (managers_of(project) or {"npm"}) if project is not None else {"npm"}


def _venv_removal(finding: dict, name: str) -> str:
    """`uv remove` edits pyproject.toml and uv.lock, so it fits only a uv project. A venv
    that pip filled (no uv project beside it) is cleaned with that venv's own pip: a bare
    `pip` could be another interpreter's. Found live: a pip + requirements.txt project was
    told to run `uv remove`, which has no project to edit there."""
    for path in finding.get("paths") or []:
        for parent in Path(path).parents:
            if (parent / "pyvenv.cfg").is_file():
                project = parent.parent
                if (project / "pyproject.toml").is_file() and (project / "uv.lock").is_file():
                    return f"uv remove {name}"
                python = parent / ("Scripts/python.exe" if (parent / "Scripts").is_dir() else "bin/python")
                return f"{shlex.quote(str(python))} -m pip uninstall -y {shlex.quote(name)}"
    return f"uv remove {name}"


def _venv_of(finding: dict) -> Path | None:
    """The environment a Python finding's dist-info sits in: the directory
    above `lib/<python>/site-packages` (or Windows' `Lib/site-packages`)."""
    for path in finding.get("paths") or []:
        site = Path(path).parent
        if site.name != "site-packages":
            continue
        lib = site.parent if site.parent.name in ("lib", "Lib") else site.parent.parent
        return lib.parent
    return None


def removal_command(finding: dict) -> str:
    """How to get one package off disk.

    Every one of these is classified `ignore` by the recognizer, which is the
    whole reason the gate denies only `package`/`unsupported` commands while a
    finding is open: a blanket Bash block would make the fix unreachable.
    """
    source, name = finding["source"], finding["name"]
    if finding.get("undeclared"):
        # Not a dependency of anything, so `uv remove` and `pnpm remove` have
        # nothing to remove. A Python finding's path is its dist-info, and
        # deleting that would leave the code importable: uninstall it from its
        # environment (uv, since a `uv venv` has no pip). An npm package is its
        # directory.
        environment = _venv_of(finding)
        if source == inventory.VENV and environment is not None:
            return (f"uv pip uninstall --python {shlex.quote(str(environment))} "
                    f"{shlex.quote(name)}")
        return "rm -rf " + " ".join(shlex.quote(path) for path in finding.get("paths") or [])
    # One identity found in several places is one finding, and its `source` is whichever
    # reader saw it first: for a Bun project that is often the machine cache, with the
    # project's node_modules among its paths. What decides the remedy is whether the
    # project's own tree holds it (A4).
    in_tree = any("node_modules" in Path(path).parts for path in finding.get("paths") or [])
    if source == inventory.NODE_MODULES or (in_tree and source in _PM_CACHE_SOURCES):
        managers = _finding_managers(finding)
        if managers <= {"npm"} and source == inventory.NODE_MODULES:
            return f"npm uninstall {name}"
        if len(managers) == 1 and managers <= {"pnpm", "bun", "yarn"} and PM_REMOVAL_COMMANDS:
            quoted = shlex.quote(name)
            manager = next(iter(managers))
            # No `--ignore-scripts` on pnpm (it rejects the flag on `remove`): the hook
            # allows the plain command only when the project has no root install scripts
            # and its build allow-list is satisfied (`hook._remove_denial`). Berry's
            # `--mode=skip-build` and Bun's `--ignore-scripts` turn every script off.
            if manager == "yarn":
                project = _finding_project(finding)
                if (YARN_CLASSIC_DISK and project is not None
                        and pg_manifest.yarn_classic_lock_file(project / "yarn.lock")):
                    # Yarn Classic: `--ignore-scripts` is the proof the hook looks for on `remove`.
                    return f"yarn remove {quoted} --ignore-scripts"
                return f"yarn remove {quoted} --mode=skip-build"
            if manager == "bun":
                return f"bun remove {quoted} --ignore-scripts"
            return f"{manager} remove {quoted}"
        # Mixed locks, or the switch is off: no manager command (`npm uninstall` would
        # re-lay a tree npm did not make). Fall through to a plain removal of the paths.
    if source == inventory.VENV:
        return _venv_removal(finding, name)
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
        if finding.get("undeclared"):
            lines.append(
                "    installed while Package Guard was down (warn or off); no manifest or "
                "lockfile accounts for it"
            )
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
