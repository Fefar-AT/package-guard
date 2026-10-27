"""Direct dependencies declared in an npm manifest.

Any `npm install` reconciles the WHOLE manifest, not just the packages named on
the command line — so a scaffolded package.json is an unguarded acquisition
path. This module answers one question for the hook: which exact versions would
this manifest put on disk?

It never resolves semver ranges itself. A hand-rolled matcher would have to
agree with npm's resolver forever, and a disagreement would silently vet a
version different from the one installed. Instead only two sources are trusted:

  * an exact pin in package.json (`"react": "19.2.8"`), or
  * the version npm already resolved into package-lock.json.

Anything else is reported as unresolved, and the hook asks for a lockfile —
which npm can produce without installing anything (`--package-lock-only`).

Standard library only.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import bun_lock
import pnpm_lock
import yarn_lock
from lock_errors import LockReadError

# A bare, fully-qualified semver: the only spec form we accept as an exact pin.
# Deliberately strict — `^1.2.3`, `~1.2.3`, `1.x`, `>=1`, `*`, `latest`, URLs,
# `npm:` aliases and git specs all fail this and fall through to the lockfile.
_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")

_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")
# pnpm (auto-install-peers) and Bun install the ROOT project's own peerDependencies; npm's
# reader and Yarn's do not read them here, and neither behaviour changes (v1.10.0 hardening, A7).
_PEER_FIELD = "peerDependencies"
PM_PEER_KINDS = ("pnpm", "bun")


class ManifestError(Exception):
    """The manifest or lockfile exists but could not be read."""


def _load_json(path: Path):
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise ManifestError(f"{path.name} could not be read ({exc})") from exc


# A PEP 440 release that pins exactly one version. Anything with a range
# operator, wildcard, or comma goes to unresolved.
_PY_EXACT = re.compile(r"^[0-9][0-9A-Za-z.!+\-_]*$")
# name[extras]==version, optionally followed by ; markers or --hash= fragments.
_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)"
    r"(?P<extras>\[[A-Za-z0-9._,\s\-]*\])?"
    r"\s*==\s*(?P<version>[^\s;#\\]+)\s*$"
)


_LOCAL_SOURCES = {"virtual", "editable", "directory"}


def _normalize_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# Public alias. inventory.py reads distribution names off `dist-info` directory
# names and must normalise them the same way, or `python_multipart-0.0.32`
# never matches the manifest's `python-multipart`. One function, imported --
# a second copy of this regex would drift from the first.
normalize_py = _normalize_py


def requirements_dependencies(path) -> tuple:
    """(resolved, unresolved) for one requirements file.

    Only `name==exact` pins are trusted. Includes (-r/-c), URLs, editable
    installs, ranges and bare names all land in unresolved -- the guard cannot
    know what version they would fetch.
    """
    path = Path(path)
    if not path.is_file():
        raise ManifestError(f"requirements file {path} does not exist")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"{path} could not be read ({exc})") from exc

    resolved, unresolved, seen = [], [], set()
    # Join backslash continuations before splitting into logical lines.
    for raw in text.replace("\\\n", " ").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            # -r/-c includes and option lines. Refuse rather than recurse:
            # a nested file is another manifest with its own trust question.
            unresolved.append((line.split()[0], line))
            continue
        # Environment markers and hashes do not change which version is taken.
        head = line.split(";", 1)[0].split("--hash", 1)[0].strip()
        match = _REQ_LINE.match(head)
        if match and _PY_EXACT.match(match.group("version")):
            name = _normalize_py(match.group("name"))
            if name in seen:
                continue
            seen.add(name)
            resolved.append((name, match.group("version"), "requirements"))
        else:
            # Report under the bare distribution name where one is recognisable,
            # so the denial reads as a package list rather than raw specs.
            lead = re.match(r"[A-Za-z0-9][A-Za-z0-9._\-]*", head)
            key = _normalize_py(lead.group(0)) if lead else head
            if key in seen:
                continue
            seen.add(key)
            unresolved.append((key, head))
    resolved.sort(key=lambda item: item[0])
    unresolved.sort(key=lambda item: item[0])
    return resolved, unresolved


def _uv_lock_data(directory):
    """(data, None) for a readable uv.lock, or (None, unresolved) when there is none."""
    lock = Path(directory) / "uv.lock"
    if not lock.is_file():
        project = Path(directory) / "pyproject.toml"
        if not project.is_file():
            return None, []
        return None, [("(project)", "no uv.lock; dependency versions are unresolved")]
    try:
        with lock.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"uv.lock could not be read ({exc})") from exc
    if not isinstance(data.get("package"), list):
        raise ManifestError("uv.lock has no package table")
    return data, None


def _uv_root_dependency_names(root: dict, extras=()):
    """Every name the uv.lock root declares as its OWN dependency, in order.

    `dependencies` plus EVERY group of `dev-dependencies`, which uv.lock writes
    as a table of group name -> list of {"name": ...}. `uv sync` installs dev
    groups by default, so a reader that took only `dependencies` would disagree
    with what lands on disk.

    `optional-dependencies` (extras) join only when the command asks for them
    (`extras`: group names, or "*" for `--all-extras`): `uv sync` does not
    install them otherwise.
    """
    blocks = [root.get("dependencies") or []]
    optional = root.get("optional-dependencies")
    if extras and isinstance(optional, dict):
        # uv normalises extra names (PEP 685) on both sides; `--extra
        # Dev_Tools` installs the `dev-tools` group.
        wanted = {_normalize_py(e) for e in extras if isinstance(e, str)}
        for group, deps in optional.items():
            if ("*" in extras or _normalize_py(str(group)) in wanted) and isinstance(deps, list):
                blocks.append(deps)
    dev = root.get("dev-dependencies")
    if isinstance(dev, dict):
        for group in dev.values():
            if isinstance(group, list):
                blocks.append(group)
    elif isinstance(dev, list):  # tolerated: a flat list rather than groups
        blocks.append(dev)

    names, seen = [], set()
    for block in blocks:
        for dep in block:
            if not isinstance(dep, dict) or not isinstance(dep.get("name"), str):
                continue
            name = _normalize_py(dep["name"])
            if name in seen:
                continue
            seen.add(name)
            names.append(name)
    return names


def uv_project_dependencies(directory, extras=()) -> tuple:
    """(resolved, unresolved) for a uv project, read from uv.lock.

    uv.lock records the root package with its direct dependencies by name, and
    every package with an exact version, so direct dependencies resolve without
    consulting pyproject.toml. No lock means nothing is pinned yet.

    Direct means `dependencies` + every `dev-dependencies` group; see
    _uv_root_dependency_names.
    """
    data, missing = _uv_lock_data(directory)
    if data is None:
        return [], missing

    versions, roots, local = {}, [], set()
    for entry in data["package"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            continue
        name = _normalize_py(entry["name"])
        version = entry.get("version")
        if isinstance(version, str):
            versions[name] = version
        source = entry.get("source") or {}
        # The project and its local members: virtual, editable or directory
        # sources. A member is the project's own code, never a registry
        # identity, and its own dependencies are direct.
        if isinstance(source, dict) and _LOCAL_SOURCES & set(source):
            roots.append(entry)
            local.add(name)

    resolved, unresolved, seen = [], [], set()
    for root in roots:
        for name in _uv_root_dependency_names(root, extras):
            if name in seen or name in local:
                continue
            seen.add(name)
            version = versions.get(name)
            if version and _PY_EXACT.match(version):
                resolved.append((name, version, "uv.lock"))
            else:
                unresolved.append((name, "no exact version in uv.lock"))
    resolved.sort(key=lambda item: item[0])
    unresolved.sort(key=lambda item: item[0])
    return resolved, unresolved


_DEFAULT_BACKEND = ("setuptools>=40.8.0",
                    "no [build-system]: built with setuptools' default backend, fetched unpinned; "
                    "declare [build-system] requires with an exact pin")


def build_requires(directory) -> tuple:
    """(resolved, unresolved) for pyproject.toml's `[build-system] requires`.

    An isolated build (pip/uv building the local project) fetches these
    from PyPI and runs them; no lock records them, so only an exact `==` pin
    is resolved.

    A project with no `[build-system]` table -- a
    pyproject.toml without one, or a bare setup.py / setup.cfg -- is still
    built, with setuptools' default backend (PEP 517's legacy fallback, which
    pip and uv both use) fetched unpinned. That is unresolved until the
    project declares an exact pin. Only a directory with none of the three
    fetches nothing (there is nothing to build).
    """
    base = Path(directory)
    path = base / "pyproject.toml"
    if not path.is_file():
        if (base / "setup.py").is_file() or (base / "setup.cfg").is_file():
            return [], [_DEFAULT_BACKEND]
        return [], []
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"pyproject.toml could not be read ({exc})") from exc
    system = data.get("build-system")
    if not isinstance(system, dict):
        return [], [_DEFAULT_BACKEND]
    requires = system.get("requires")
    resolved, unresolved = [], []
    for spec in requires if isinstance(requires, list) else []:
        if not isinstance(spec, str):
            continue
        match = _REQ_LINE.match(spec.strip())
        if match and _PY_EXACT.match(match.group("version")):
            resolved.append((_normalize_py(match.group("name")), match.group("version"),
                             "build-system"))
        else:
            unresolved.append((spec.strip(), "build-system.requires is not an exact pin"))
    return resolved, unresolved


def uv_built_directories(directory) -> list:
    """Every in-project directory uv.lock records as editable or as a path
    source: uv builds each on sync, fetching its own build-system.requires.
    The root (`editable = "."`) is one of them; a virtual entry is not built."""
    data, _missing = _uv_lock_data(directory)
    base = Path(directory).resolve()
    out = []
    for entry in (data or {}).get("package") or []:
        source = entry.get("source") if isinstance(entry, dict) else None
        if not isinstance(source, dict):
            continue
        relative = source.get("editable", source.get("directory"))
        if not isinstance(relative, str):
            continue
        target = (base / relative).resolve()
        if (target == base or base in target.parents) and target not in out:
            out.append(target)
    return out


def uv_root_is_built(directory) -> bool:
    """True when uv.lock's root is an editable (packaged) project, which uv
    builds -- and so fetches build-system.requires for -- on every sync."""
    data, _missing = _uv_lock_data(directory)
    for entry in (data or {}).get("package") or []:
        source = entry.get("source") if isinstance(entry, dict) else None
        if isinstance(source, dict) and source.get("editable") in (".", "./"):
            return True
    return False


def as_request(name: str, version: str, original_command: str, ecosystem: str = "npm"):
    """A manifest dependency, shaped like any other package request.

    Always exact-pinned, so it flows through the normal vetting path and gets a
    review id, a registry/OSV check and a human prompt exactly like a package
    named on the command line.
    """
    import parser as pg_parser  # local: avoids a circular import at module load

    npm = ecosystem == "npm"
    return pg_parser.PackageRequest(
        manager="npm" if npm else "pip",
        operation="install",
        ecosystem=ecosystem,
        name=name,
        display_name=name,
        requested_spec=version,
        exact_version=version,
        registry=pg_parser.NPM_REGISTRY if npm else pg_parser.PYPI_REGISTRY,
        original_command=original_command,
    )


def manifest_path(directory) -> Path:
    return Path(directory) / "package.json"


def has_manifest(directory) -> bool:
    return manifest_path(directory).is_file()


def _locked_versions(directory) -> dict:
    """name -> exact version, from package-lock.json (lockfile v2/v3)."""
    lock = Path(directory) / "package-lock.json"
    if not lock.is_file():
        return {}
    data = _load_json(lock)
    versions = {}
    packages = data.get("packages")
    if isinstance(packages, dict):
        # v2/v3: keys are paths like "node_modules/react". Only top-level
        # entries describe what a direct dependency resolves to; nested paths
        # ("node_modules/a/node_modules/b") are transitive and out of scope.
        for key, entry in packages.items():
            if not key.startswith("node_modules/") or not isinstance(entry, dict):
                continue
            name = key[len("node_modules/"):]
            if "/" in name and not name.startswith("@"):
                continue
            if name.startswith("@") and name.count("/") > 1:
                continue
            version = entry.get("version")
            if isinstance(version, str) and _EXACT.match(version):
                versions[name] = version
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        # v1 fallback.
        for name, entry in dependencies.items():
            if name in versions or not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if isinstance(version, str) and _EXACT.match(version):
                versions[name] = version
    return versions


def _lock_root_specs(directory):
    """name -> spec the lock's root entry recorded (lockfile v2/v3), or None.

    npm writes the manifest's own specs into `packages[""]`, which is what
    `npm ci` compares against package.json to detect a stale lock. Exact
    string comparison: no range is ever interpreted (exact-pins-not-semver).
    """
    lock = Path(directory) / "package-lock.json"
    if not lock.is_file():
        return None
    packages = _load_json(lock).get("packages")
    root = packages.get("") if isinstance(packages, dict) else None
    if not isinstance(root, dict):
        return None  # a v1 lock records no root specs; nothing to compare
    if not any(isinstance(root.get(field), dict) for field in _DEP_FIELDS):
        return None  # a hand-built lock that records no specs; nothing to compare
    specs = {}
    for field in _DEP_FIELDS:
        block = root.get(field)
        if isinstance(block, dict):
            specs.update({k: v for k, v in block.items() if isinstance(v, str)})
    return specs


_LIFECYCLE = ("preinstall", "install", "postinstall", "prepublish", "preprepare",
              "prepare", "postprepare")


# pnpm also runs a root `pnpm:devPreinstall` before it installs.
_PNPM_LIFECYCLE = ("pnpm:devPreinstall",) + _LIFECYCLE


def npm_root_lifecycle_scripts(directory, kind="npm") -> list:
    """[(name, body)] of the lifecycle scripts `npm install` (or the pnpm, Bun
    or Yarn install of `kind`) runs from the root package.json itself. Each
    manager runs a subset of these; the union is checked. Empty without a
    manifest."""
    path = manifest_path(directory)
    if not path.is_file():
        return []
    data = _load_json(path)
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    names = _PNPM_LIFECYCLE if kind == "pnpm" else _LIFECYCLE
    return [(name, scripts[name]) for name in names if isinstance(scripts.get(name), str)]


def npm_install_script_packages(directory) -> list:
    """[(name, version)] of lock entries npm marks `hasInstallScript`."""
    lock = Path(directory) / "package-lock.json"
    if not lock.is_file():
        return []
    packages = _load_json(lock).get("packages")
    out = []
    for key, entry in (packages or {}).items() if isinstance(packages, dict) else ():
        if not key or "node_modules/" not in key or not isinstance(entry, dict):
            continue
        if entry.get("hasInstallScript") and isinstance(entry.get("version"), str):
            pair = (key.rsplit("node_modules/", 1)[1], entry["version"])
            if pair not in out:
                out.append(pair)
    return out


def npm_locked_tree(directory) -> list:
    """Every (name, version) package-lock.json v2/v3 would install,
    nested entries included, root excluded, de-duplicated. Empty when there is
    no lockfile: without one the tree is not known until npm resolves it.
    """
    lock = Path(directory) / "package-lock.json"
    if not lock.is_file():
        return []
    packages = _load_json(lock).get("packages")
    if not isinstance(packages, dict):
        return []
    seen, tree = set(), []
    for key, entry in packages.items():
        if not key or "node_modules/" not in key or not isinstance(entry, dict):
            continue
        if entry.get("link"):
            continue  # a workspace symlink, not a registry package
        name = key.rsplit("node_modules/", 1)[1]
        version = entry.get("version")
        if not name or not isinstance(version, str) or not _EXACT.match(version):
            continue
        if (name, version) not in seen:
            seen.add((name, version))
            tree.append((name, version))
    return tree


# ---------------------------------------------------------------------------
# pnpm, Bun and Yarn
#
# Their locks are read by bun_lock / pnpm_lock / yarn_lock, which fail closed.
# Unlike npm's, the lock is NEVER optional here: an exact pin in package.json
# does not stand in for a lock entry. Whatever the manager installs is the
# lock's tree, so a dependency the lock does not record (or records for another
# spec) is a stale lock, and the tree it would re-resolve is nobody's review.
# ---------------------------------------------------------------------------

PM_LOCKFILES = {"pnpm": "pnpm-lock.yaml", "bun": "bun.lock", "yarn": "yarn.lock"}
_PM_READERS = {"pnpm": pnpm_lock, "bun": bun_lock, "yarn": yarn_lock}


def pm_lock_path(directory, kind) -> Path:
    return Path(directory) / PM_LOCKFILES[kind]


def _pm_read(directory, kind, call):
    """`call(reader_module, lock_path)`, with any lock error as a ManifestError
    and a missing lock an error too: never an empty answer."""
    path = pm_lock_path(directory, kind)
    if not path.is_file():
        raise ManifestError(f"{path.name} does not exist")
    try:
        return call(_PM_READERS[kind], path)
    except LockReadError as exc:
        raise ManifestError(str(exc)) from exc


def pm_locked_tree(directory, kind) -> list:
    """Every registry (name, version) the lock would install. A directory that needs no
    lock (`no_lock_needed`) installs nothing: an empty tree, which is the one case where
    a missing lock is not an error."""
    if no_lock_needed(directory):
        return []
    return _pm_read(directory, kind, lambda reader, path: reader.locked_tree(path))


def pm_expected_spec(kind, spec: str) -> str:
    """The text a lock's root records for a package.json spec. Berry writes a
    bare range with an `npm:` prefix; pnpm and Bun record the spec as written."""
    if kind == "yarn" and ":" not in spec and "/" not in spec:
        return "npm:" + spec
    return spec


def pm_direct_dependencies(directory, kind):
    """(resolved, unresolved) for a pnpm, Bun or Yarn manifest, as
    `direct_dependencies` is for npm's, but only from the lock.

    A dependency resolves when the lock's root records exactly the spec
    package.json declares and a registry package of that name answers it.
    Anything else (absent, another spec, an alias, a non-registry source) is
    unresolved: the lock is stale or the dependency is not a registry one."""
    specs = _npm_dep_specs(directory, peers=kind in PM_PEER_KINDS)
    if not specs:
        return [], []
    peer_only, optional = _root_peers(directory) if kind in PM_PEER_KINDS else (set(), set())
    recorded, locked, skip = _pm_read(directory, kind, lambda reader, path: (
        reader.root_specs(path), reader.direct_specs(path),
        reader.skippable_root_peers(path, peer_only, optional) if peer_only else set()))
    specs = [(name, spec) for name, spec in specs if name not in skip]
    name_of_lock = PM_LOCKFILES[kind]
    resolved, unresolved = [], []
    for name, spec in specs:
        if not isinstance(spec, str):
            unresolved.append((name, repr(spec)))
        elif name not in recorded:
            unresolved.append((name, f"{spec} ({name_of_lock} does not list it)"))
        elif recorded[name] != pm_expected_spec(kind, spec):
            unresolved.append((name, f"{spec} ({name_of_lock} is stale: it was resolved for "
                                     f"{recorded[name]!r})"))
        elif name not in locked:
            unresolved.append((name, f"{spec} ({name_of_lock} resolves it to something other "
                                     "than a registry package of that name)"))
        else:
            resolved.append((name, locked[name], "lockfile"))
    resolved.sort(key=lambda item: item[0])
    unresolved.sort(key=lambda item: item[0])
    return resolved, unresolved


def _root_peers(directory):
    """(names only a root peerDependencies declares, names its peerDependenciesMeta marks
    optional). The first are what pnpm and Bun add beside the other fields; the lock may
    legitimately not record some of them (v1.10.0 hardening)."""
    data = _load_json(manifest_path(directory))
    if not isinstance(data, dict):
        return set(), set()
    other = {name for field in _DEP_FIELDS if isinstance(data.get(field), dict)
             for name in data[field]}
    peers = data.get(_PEER_FIELD)
    peer_only = {n for n in peers if isinstance(n, str) and n not in other} \
        if isinstance(peers, dict) else set()
    meta = data.get("peerDependenciesMeta")
    optional = {n for n, m in meta.items() if isinstance(m, dict) and m.get("optional") is True} \
        if isinstance(meta, dict) else set()
    return peer_only, optional


def pm_declares_dependencies(directory, kind=None) -> bool:
    return bool(_npm_dep_specs(directory, peers=kind in PM_PEER_KINDS))


def declares_any_dependencies(directory) -> bool:
    """True when package.json declares a dependency of ANY kind (dependencies,
    devDependencies, optionalDependencies, peerDependencies), whatever the manager."""
    return bool(_npm_dep_specs(directory, peers=True))


# Every lock file of the npm family: the presence of one of them means a manager already
# decided a tree for this directory.
_ANY_LOCK = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "bun.lock",
             "bun.lockb", "yarn.lock")


def no_lock_needed(directory) -> bool:
    """A directory with no lock of any manager whose package.json declares no dependency
    of any kind: its locked tree is empty, and a lock cannot exist for it (`bun install
    --lockfile-only` deletes an empty one: "No packages! Deleted empty lockfile"), so
    the first `add` could never otherwise be allowed (v1.10.0 hardening, B2)."""
    base = Path(directory)
    return not any((base / name).exists() for name in _ANY_LOCK) and not declares_any_dependencies(base)


def uv_locked_tree(directory) -> list:
    """Every (name, version) uv.lock records, the virtual root excluded."""
    data, _missing = _uv_lock_data(directory)
    if data is None:
        return []
    seen, tree = set(), []
    for package in data.get("package") or []:
        if not isinstance(package, dict):
            continue
        source = package.get("source") if isinstance(package.get("source"), dict) else {}
        if _LOCAL_SOURCES & set(source):
            continue
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not isinstance(version, str) or not _PY_EXACT.match(version):
            continue
        pair = (_normalize_py(name), version)
        if pair not in seen:
            seen.add(pair)
            tree.append(pair)
    return tree


def _npm_dep_specs(directory, peers=False):
    """[(name, spec)] declared by package.json's dependency fields, deduped.

    The single enumeration of "what this manifest declares". Both the pinning
    reader (direct_dependencies) and the names-only reader (npm_direct_names)
    go through it, so they can never disagree about the direct set. `peers` adds the
    root `peerDependencies`, which pnpm and Bun install; it is False for npm.
    """
    path = manifest_path(directory)
    if not path.is_file():
        return []
    data = _load_json(path)
    if not isinstance(data, dict):
        raise ManifestError("package.json is not a JSON object")
    out, seen = [], set()
    for field in _DEP_FIELDS + ((_PEER_FIELD,) if peers else ()):
        block = data.get(field)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(name, str) or name in seen:
                continue
            seen.add(name)
            out.append((name, spec))
    return out


def direct_dependencies(directory):
    """(resolved, unresolved) for the manifest in `directory`.

    resolved   -> list of (name, version, source) where source is 'manifest'
                  for an exact pin or 'lockfile' for a version npm resolved.
    unresolved -> list of (name, spec) that neither source could pin.

    Returns ([], []) when there is no manifest.
    """
    specs = _npm_dep_specs(directory)
    if not specs:
        return [], []
    locked = _locked_versions(directory)
    recorded = _lock_root_specs(directory)
    resolved, unresolved = [], []
    for name, spec in specs:
        if not isinstance(spec, str):
            unresolved.append((name, repr(spec)))
            continue
        if _EXACT.match(spec.strip()):
            resolved.append((name, spec.strip(), "manifest"))
        elif name in locked and recorded is not None and recorded.get(name) != spec:
            # The lock was resolved for a different spec, so its version
            # says nothing about what `npm install` will pick for this one.
            # `npm ci` refuses the same mismatch; `npm install` re-resolves.
            unresolved.append((name, f"{spec} (package-lock.json is stale: it was "
                                     f"resolved for {recorded.get(name)!r})"))
        elif name in locked:
            resolved.append((name, locked[name], "lockfile"))
        else:
            unresolved.append((name, spec))

    resolved.sort(key=lambda item: item[0])
    unresolved.sort(key=lambda item: item[0])
    return resolved, unresolved


# ---------------------------------------------------------------------------
# Direct sets, names only
#
# Reconciliation intersects the direct set with what is installed and reads the
# version off disk, so it needs the NAMES a manifest declares whether or not
# the manifest pins them. `^15.0.0` is unresolvable for the PreToolUse gate and
# perfectly reconcilable here: node_modules already says which version landed.
#
# These share their enumeration with the pinning readers above, so the two
# layers cannot drift into disagreeing about what "direct" means.
# ---------------------------------------------------------------------------

def npm_direct_names(directory, peers=False):
    """Every dependency name package.json declares, pinnable or not. `peers` adds the root
    peerDependencies, for a pnpm or Bun project that installs them."""
    return sorted({name for name, _spec in _npm_dep_specs(directory, peers=peers)})


def uv_project_direct_names(directory):
    """Every dependency name the uv.lock root declares, dev groups included."""
    data, _missing = _uv_lock_data(directory)
    if data is None:
        return []
    names, local = set(), set()
    for entry in data["package"]:
        if not isinstance(entry, dict):
            continue
        source = entry.get("source") or {}
        if isinstance(source, dict) and _LOCAL_SOURCES & set(source):
            names.update(_uv_root_dependency_names(entry))
            if isinstance(entry.get("name"), str):
                local.add(_normalize_py(entry["name"]))
    return sorted(names - local)


def requirements_direct_names(path):
    """Every distribution name a requirements file lists, pinned or not.

    A `uv pip compile` output is flattened, so this is the whole tree rather
    than a top level -- a coverage difference stated per ecosystem rather
    than claimed uniformly.
    """
    resolved, unresolved = requirements_dependencies(path)
    names = {name for name, _version, _source in resolved}
    # Include lines are another manifest, not a distribution: never a name.
    names.update(name for name, _spec in unresolved if not name.startswith("-"))
    return sorted(names)
