"""Reader for Bun's text lockfile, `bun.lock`.

`bun.lock` is JSONC: JSON plus `//` and `/* */` comments and trailing commas.
This module turns it into a small model the hook can ask three questions of:

  * which registry packages would be installed (the OSV transitive input),
  * which entries come from anywhere else (git, github, tarball, file, link,
    workspace, or a non-default registry URL), and
  * what the root manifest's direct dependencies resolved to.

It fails closed: any byte it cannot account for raises `BunLockError`, and no
partial model is ever returned. It never resolves ranges and never runs Bun.

Observed in real lockfiles (see tests/package_guard/fixtures/bun):
`lockfileVersion` 1, `configVersion` 1. Anything else is refused.

Standard library only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, NamedTuple

import protocols
from lock_errors import LockReadError

SUPPORTED_LOCKFILE_VERSIONS = (1,)
SUPPORTED_CONFIG_VERSIONS = (0, 1)  # absent counts as 0 (pre-1.3.2 Bun)

_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
_NAME = re.compile(r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$", re.IGNORECASE)
_ID = re.compile(r"^(@[^/@]+/[^/@]+|[^/@]+)@(.+)$", re.DOTALL)
_ARCHIVE = re.compile(r"\.(?:tgz|tar\.gz|tar)$", re.IGNORECASE)
_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_KNOWN_TOP = {"lockfileVersion", "configVersion", "workspaces", "packages", "overrides",
              "trustedDependencies", "patchedDependencies", "catalog", "catalogs"}

REGISTRY = "registry"
WORKSPACE, GITHUB, GIT, TARBALL, FILE, LINK = "workspace", "github", "git", "tarball", "file", "link"
OTHER = "other"
REGISTRY_URL = "registry-url"  # an exact version, but not from the default registry


class BunLockError(LockReadError):
    """The lockfile is unreadable, malformed, or in a shape this reader will
    not guess at."""


class Entry(NamedTuple):
    key: str       # the lock's package key; "parent/child" when nested
    name: str      # the package name from the tuple (differs from the key's
                   # last segment for `npm:` aliases)
    spec: str      # the text after `name@` in the tuple's first element
    kind: str      # REGISTRY, REGISTRY_URL, WORKSPACE, GITHUB, GIT, TARBALL, FILE, LINK
    registry: str  # the tuple's registry URL ("" = default); registry kinds only
    integrity: str = ""  # the tuple's last element for a registry package


class BunLock(NamedTuple):
    lockfile_version: int
    config_version: int
    root: dict               # the "" workspace: name, dependencies, ...
    workspaces: tuple        # paths of the non-root workspaces
    entries: tuple           # of Entry, in file order
    trusted_dependencies: tuple
    patched_dependencies: tuple = ()   # the `name@version` keys of the top-level map


# -- JSONC -> JSON ---------------------------------------------------------


def _skip_trivia(text: str, i: int) -> int:
    """Index of the next non-space, non-comment character at or after `i`."""
    n = len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise BunLockError("unterminated /* comment")
            i = end + 2
        else:
            break
    return i


def _string_end(text: str, i: int) -> int:
    """Index just past the string literal opening at `i`."""
    n = len(text)
    i += 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
        elif c == '"':
            return i + 1
        else:
            i += 1
    raise BunLockError("unterminated string")


def _last_significant(out: list) -> str:
    for piece in reversed(out):
        piece = piece.strip()
        if piece:
            return piece[-1]
    return ""


def jsonc_to_json(text: str) -> str:
    """Strip comments and trailing commas, only ever outside string literals."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            end = _string_end(text, i)
            out.append(text[i:end])
            i = end
        elif text.startswith("//", i) or text.startswith("/*", i):
            i = _skip_trivia(text, i)
            out.append(" ")
        elif c == ",":
            j = _skip_trivia(text, i + 1)
            if j < n and text[j] in "}]":
                if _last_significant(out) in "[{,":
                    raise BunLockError("comma without a preceding value")
                i += 1  # trailing comma: drop it
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _no_duplicates(pairs: list) -> dict:
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise BunLockError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _refuse_constant(token: str):
    raise BunLockError(f"non-JSON constant {token}")


def parse_text(text: str) -> Any:
    try:
        return json.loads(jsonc_to_json(text), object_pairs_hook=_no_duplicates,
                          parse_constant=_refuse_constant)
    except BunLockError:
        raise
    except (ValueError, RecursionError) as error:
        raise BunLockError(f"not valid JSONC: {error}") from None


# -- the model -------------------------------------------------------------


def _expect(cond: bool, message: str) -> None:
    if not cond:
        raise BunLockError(message)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _split_id(key: str, ident) -> tuple:
    _expect(isinstance(ident, str) and ident, f"{key}: first element is not a package id")
    match = _ID.match(ident)
    _expect(match is not None, f"{key}: package id {ident!r} is not name@spec")
    name, spec = match.group(1), match.group(2)
    _expect(len(name) <= 214 and _NAME.match(name) is not None, f"{key}: invalid package name {name!r}")
    return name, spec


def _classify_spec(key: str, spec: str) -> str:
    if _EXACT.match(spec):
        return REGISTRY
    if spec.startswith("workspace:"):
        return WORKSPACE
    if spec.startswith("github:"):
        return GITHUB
    if spec.startswith(("git+", "git:", "git@", "gitlab:", "bitbucket:", "ssh://")):
        return GIT
    if spec.startswith(("http://", "https://")):
        return TARBALL
    if spec.startswith("file:"):
        return FILE
    if spec.startswith("link:"):
        return LINK
    if _ARCHIVE.search(spec) and not spec.startswith("npm:"):
        return TARBALL  # a local archive path, e.g. vendor/x.tgz
    if protocols.names_other_source(spec) and not spec.startswith("npm:"):
        return OTHER  # jsr:, patch:, exec:, portal:, catalog:, ... (an npm: alias stays unrecognised)
    raise BunLockError(f"{key}: unrecognised spec {spec!r}")


def _entry(key: str, tup) -> Entry:
    _expect(isinstance(key, str) and key != "", "empty package key")
    _expect(isinstance(tup, list) and 1 <= len(tup) <= 4, f"{key}: unrecognised tuple shape")
    name, spec = _split_id(key, tup[0])
    kind = _classify_spec(key, spec)
    if kind == OTHER:
        return Entry(key, name, spec, kind, "")  # refused by the caller; the shape is moot
    if kind == WORKSPACE:
        _expect(len(tup) == 1, f"{key}: unrecognised workspace tuple")
        return Entry(key, name, spec, kind, "")
    if kind == REGISTRY:
        ok = (len(tup) == 4 and isinstance(tup[1], str) and isinstance(tup[2], dict)
              and isinstance(tup[3], str) and tup[3] != "")
        _expect(ok, f"{key}: unrecognised registry tuple (need registry, metadata, integrity)")
        return Entry(key, name, spec, REGISTRY_URL if tup[1] and not protocols.is_official_registry(tup[1]) else REGISTRY, tup[1], tup[3])
    # git, github, tarball, file, link: [id, metadata, (hash,) (integrity)]
    _expect(len(tup) >= 2 and isinstance(tup[1], dict)
            and all(isinstance(x, str) for x in tup[2:]),
            f"{key}: unrecognised {kind} tuple")
    return Entry(key, name, spec, kind, "")


def _root(workspaces) -> dict:
    _expect(isinstance(workspaces, dict) and isinstance(workspaces.get(""), dict),
            "no root workspace")
    for path, workspace in workspaces.items():
        _expect(isinstance(workspace, dict), f"workspace {path!r} is not an object")
        for field in _DEP_FIELDS:
            block = workspace.get(field)
            _expect(block is None or (isinstance(block, dict)
                                      and all(isinstance(v, str) for v in block.values())),
                    f"workspace {path!r}: {field} is not a name->spec map")
    return workspaces[""]


def _trusted(value) -> tuple:
    if value is None:
        return ()
    _expect(isinstance(value, list) and all(isinstance(v, str) for v in value),
            "trustedDependencies is not a list of names")
    return tuple(value)


def _patched(value) -> tuple:
    if value is None:
        return ()
    _expect(isinstance(value, dict), "patchedDependencies is not an object")
    return tuple(value)


def build(data: Any) -> BunLock:
    _expect(isinstance(data, dict), "top level is not an object")
    version = data.get("lockfileVersion")
    _expect(_is_int(version) and version in SUPPORTED_LOCKFILE_VERSIONS,
            f"unsupported lockfileVersion {version!r}")
    config = data.get("configVersion", 0)
    _expect(_is_int(config) and config in SUPPORTED_CONFIG_VERSIONS,
            f"unsupported configVersion {config!r}")
    unknown = sorted(set(data) - _KNOWN_TOP)
    _expect(not unknown, f"unknown top-level key(s): {', '.join(map(repr, unknown))}")
    root = _root(data.get("workspaces"))
    packages = data.get("packages")
    _expect(isinstance(packages, dict), "packages is not an object")
    entries = tuple(_entry(key, tup) for key, tup in packages.items())
    return BunLock(
        lockfile_version=version,
        config_version=config,
        root=root,
        workspaces=tuple(p for p in data["workspaces"] if p),
        entries=entries,
        trusted_dependencies=_trusted(data.get("trustedDependencies")),
        patched_dependencies=_patched(data.get("patchedDependencies")),
    )


def read_bun_lock(path) -> BunLock:
    """Parse `path` (a bun.lock file). Raises BunLockError on anything off."""
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as error:
        raise BunLockError(f"cannot read {path}: {error}") from None
    return build(parse_text(text))


# -- the three questions ---------------------------------------------------


def locked_tree(path) -> list:
    """Every (name, version) the default registry would serve, de-duplicated,
    nested entries included. Aliases report the real package name. Entries from
    other sources are in `non_registry_entries`, never here."""
    seen, tree = set(), []
    for entry in read_bun_lock(path).entries:
        pair = (entry.name, entry.spec)
        if entry.kind == REGISTRY and pair not in seen:
            seen.add(pair)
            tree.append(pair)
    return tree


def artifacts(path) -> list:
    """(name, version, [integrity], missing) for each default-registry package."""
    seen, out = set(), []
    for entry in read_bun_lock(path).entries:
        pair = (entry.name, entry.spec)
        if entry.kind == REGISTRY and pair not in seen:
            seen.add(pair)
            out.append((entry.name, entry.spec, [entry.integrity] if entry.integrity else [],
                        not entry.integrity))
    return out


def non_registry_entries(path) -> list:
    """Entries that are not plain default-registry packages: git, github,
    tarball, file, link, workspace, and exact versions pinned to another
    registry URL. The hook refuses or reviews these."""
    return [e for e in read_bun_lock(path).entries if e.kind != REGISTRY]


def direct_specs(path) -> dict:
    """name -> exact version for each root-workspace dependency whose top-level
    lock entry is a default-registry package under that same name. Anything
    else (git, workspace, alias, missing) is left out, so it reads as
    unresolved."""
    lock = read_bun_lock(path)
    top = {e.key: e for e in lock.entries}
    resolved = {}
    for field in _DEP_FIELDS:
        for name in lock.root.get(field) or ():
            entry = top.get(name)
            if entry is not None and entry.kind == REGISTRY and entry.name == name:
                resolved[name] = entry.spec
    return resolved


def root_specs(path) -> dict:
    """name -> the spec string the root workspace declares (the analogue of
    npm's `_lock_root_specs`), for comparing against package.json."""
    root = read_bun_lock(path).root
    specs = {}
    for field in _DEP_FIELDS:
        for name, spec in (root.get(field) or {}).items():
            # The first field wins, as in package.json's own reader: a name that is
            # a dev dependency AND a peer is the dev spec (v1.10.0 hardening).
            specs.setdefault(name, spec)
    return specs


def skippable_root_peers(path, peer_only, optional) -> set:
    """Root peers Bun records with no `packages` entry: the optional ones, listed in the
    root workspace's `optionalPeers`. Only a name package.json also marks optional is
    skipped, so a lock that disagrees with the manifest stays unresolved."""
    listed = read_bun_lock(path).root.get("optionalPeers") or []
    _expect(isinstance(listed, list) and all(isinstance(v, str) for v in listed),
            "root workspace: optionalPeers is not a list of names")
    return {name for name in peer_only if name in optional and name in listed}


def patched_dependencies(path) -> list:
    """The `name@version` keys under top-level patchedDependencies (patched code
    runs); the hook refuses them."""
    return list(read_bun_lock(path).patched_dependencies)


def trusted_dependencies(path) -> list:
    """The lock's top-level trustedDependencies: the names Bun runs scripts for."""
    return list(read_bun_lock(path).trusted_dependencies)


def lockb_only(directory) -> bool:
    """True when the directory has the binary bun.lockb and no bun.lock."""
    base = Path(directory)
    return (base / "bun.lockb").exists() and not (base / "bun.lock").exists()
