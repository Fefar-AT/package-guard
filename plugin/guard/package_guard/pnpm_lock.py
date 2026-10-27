"""A fail-closed reader for pnpm-lock.yaml (lockfileVersion '9.0').

pnpm records the whole resolved tree in its lockfile, so the lockfile answers
the same question for pnpm that package-lock.json answers for npm: which exact
versions would an install put on disk? This module reads it WITHOUT a YAML
library (standard library only) by parsing the small YAML subset pnpm emits:

  * block mappings, indented exactly two spaces per level
  * block sequences of scalars, indented two spaces under their key
  * plain, 'single-quoted' and "double-quoted" scalars
  * single-line flow mappings `{a: b}` and flow sequences `[x64]`, `{}`, `[]`
  * a `---` header, and the two-document layout pnpm 11+ writes (an
    "environment" lockfile for pnpm itself, then the project lockfile)

Anything else raises PnpmLockError: anchors, aliases, tags, block scalars,
comments, tabs, CRLF, duplicate keys, odd indentation, multi-line flow
collections, a third document, unknown top-level keys, an unsupported
lockfileVersion. The reader never returns partial data and never guesses; a
refusal is always safe, a wrong answer never is.

Facts observed in real v9 lockfiles (see tests/package_guard/fixtures/pnpm):

  * `packages:` keys are `name@version` (scoped keys single-quoted), never
    carrying a peer suffix; `snapshots:` keys and importer versions do, as
    `1.0.0(peer@2.0.0)(other@1.0.0)`.
  * A package fetched from a URL is keyed `alias@https://...tgz`. A package
    from a non-default registry keeps its `name@version` key but carries
    `resolution: {integrity: ..., tarball: https://other-host/...}`.
  * `requiresBuild` is NOT written to v9 lockfiles that we have seen. Whether
    a dependency runs install scripts is decided by pnpm at install time, so
    requires_build() can only report the field if some lockfile does carry it.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import NamedTuple

import protocols
from lock_errors import LockReadError

SUPPORTED_VERSION = "9.0"
REGISTRY_HOST = "registry.npmjs.org"  # registry.yarnpkg.com is the same registry (D11)

_MAX_BYTES = 32 * 1024 * 1024
_MAX_DEPTH = 12

_NPM_EXACT = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?")
_NPM_NAME = re.compile(r"(@[a-z0-9\-_.~]+/)?[a-z0-9\-_.~]+", re.IGNORECASE)
_INTEGRITY = re.compile(r"sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}")

_TOP_KEYS = frozenset({
    "lockfileVersion", "settings", "overrides", "catalogs",
    "patchedDependencies", "importers", "packages", "snapshots",
    "packageExtensionsChecksum", "pnpmfileChecksum",
    "ignoredOptionalDependencies",
})
_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
_ENV_SECTIONS = ("configDependencies", "packageManagerDependencies")
_IMPORTER_KEYS = frozenset(_DEP_SECTIONS + _ENV_SECTIONS)
_LINK_PREFIXES = protocols.NON_REGISTRY_PREFIXES  # shared with the parser, sources and the other readers
_PLAIN_FORBIDDEN_FIRST = frozenset("&*!|>'\"%@`#,[]{}")


class PnpmLockError(LockReadError):
    """pnpm-lock.yaml is unreadable or outside the subset this reader trusts."""


class NonRegistryEntry(NamedTuple):
    kind: str    # "git" | "directory" | "tarball" | "link"
    name: str
    spec: str    # the key's version part, the importer version, or the source
    where: str   # "packages", "snapshots:<key>", or "importers:<name>"


class PnpmLock(NamedTuple):
    """The validated lockfile. `docs` is every YAML document, env first."""
    docs: tuple
    main: dict   # the project lockfile (the last document)


# -- YAML subset ------------------------------------------------------------


def _fail(message, lineno=None):
    where = f" (line {lineno})" if lineno else ""
    raise PnpmLockError(f"pnpm-lock.yaml: {message}{where}")


def _resolve_plain(text, lineno):
    if text in ("true", "false"):
        return text == "true"
    if text in ("null", "Null", "NULL", "~"):
        _fail("null values are not supported", lineno)
    return text


def _check_plain(text, lineno):
    if not text:
        _fail("empty value", lineno)
    first = text[0]
    if first in _PLAIN_FORBIDDEN_FIRST:
        _fail(f"unsupported scalar starting with {first!r}", lineno)
    if first in "-?:" and (len(text) == 1 or text[1] == " "):
        _fail("unsupported scalar indicator", lineno)
    if " #" in text or ": " in text or text.endswith(":"):
        _fail("ambiguous plain scalar", lineno)


def _read_quoted(text, i, lineno):
    """Parse a quoted scalar starting at text[i]; return (value, next index)."""
    quote = text[i]
    out = []
    i += 1
    while i < len(text):
        c = text[i]
        if quote == "'":
            if c == "'":
                if text[i + 1:i + 2] == "'":
                    out.append("'")
                    i += 2
                    continue
                return "".join(out), i + 1
        else:
            if c == '"':
                return "".join(out), i + 1
            if c == "\\":
                nxt = text[i + 1:i + 2]
                if nxt not in ('"', "\\"):
                    _fail("unsupported escape in double-quoted scalar", lineno)
                out.append(nxt)
                i += 2
                continue
        out.append(c)
        i += 1
    _fail("unterminated quoted scalar", lineno)


def _skip(text, i):
    while i < len(text) and text[i] == " ":
        i += 1
    return i


def _flow_value(text, i, lineno, depth):
    if depth > _MAX_DEPTH:
        _fail("flow collection nested too deeply", lineno)
    i = _skip(text, i)
    if i >= len(text):
        _fail("multi-line or unterminated flow collection", lineno)
    c = text[i]
    if c == "{":
        return _flow_map(text, i, lineno, depth)
    if c == "[":
        return _flow_seq(text, i, lineno, depth)
    if c in "'\"":
        return _read_quoted(text, i, lineno)
    j = i
    while j < len(text) and text[j] not in ",}]":
        j += 1
    if j >= len(text):
        _fail("multi-line or unterminated flow collection", lineno)
    raw = text[i:j].rstrip(" ")
    _check_plain(raw, lineno)
    return _resolve_plain(raw, lineno), j


def _flow_key(text, i, lineno):
    if text[i] in "'\"":
        return _read_quoted(text, i, lineno)
    j = i
    while j < len(text) and not (text[j] == ":" and text[j + 1:j + 2] == " "):
        if text[j] in ",{}[]":
            _fail("malformed flow mapping", lineno)
        j += 1
    if j >= len(text):
        _fail("multi-line or unterminated flow collection", lineno)
    raw = text[i:j].rstrip(" ")
    _check_plain(raw, lineno)
    return raw, j


def _flow_map(text, i, lineno, depth):
    result = {}
    i = _skip(text, i + 1)
    if text[i:i + 1] == "}":
        return result, i + 1
    while True:
        i = _skip(text, i)
        if i >= len(text):
            _fail("multi-line or unterminated flow collection", lineno)
        key, i = _flow_key(text, i, lineno)
        i = _skip(text, i)
        if text[i:i + 1] != ":":
            _fail("malformed flow mapping", lineno)
        value, i = _flow_value(text, i + 1, lineno, depth + 1)
        if key in result:
            _fail(f"duplicate key {key!r}", lineno)
        result[key] = value
        i = _skip(text, i)
        if text[i:i + 1] == "}":
            return result, i + 1
        if text[i:i + 1] != ",":
            _fail("malformed flow mapping", lineno)
        i += 1


def _flow_seq(text, i, lineno, depth):
    result = []
    i = _skip(text, i + 1)
    if text[i:i + 1] == "]":
        return result, i + 1
    while True:
        value, i = _flow_value(text, i, lineno, depth + 1)
        result.append(value)
        i = _skip(text, i)
        if text[i:i + 1] == "]":
            return result, i + 1
        if text[i:i + 1] != ",":
            _fail("malformed flow sequence", lineno)
        i += 1


def _inline(text, lineno):
    """A scalar or single-line flow collection occupying the rest of a line."""
    c = text[0]
    if c in "'\"":
        value, end = _read_quoted(text, 0, lineno)
    elif c in "{[":
        value, end = _flow_value(text, 0, lineno, 0)
    else:
        _check_plain(text, lineno)
        return _resolve_plain(text, lineno)
    if _skip(text, end) != len(text):
        _fail("unexpected text after value", lineno)
    return value


def _split_yaml_key(text, lineno):
    """`key: rest` -> (key, rest); rest is "" when a child block follows."""
    if text[0] in "'\"":
        key, end = _read_quoted(text, 0, lineno)
        if text[end:end + 1] != ":" or text[end + 1:end + 2] not in ("", " "):
            _fail("malformed mapping key", lineno)
        return key, text[end + 1:].strip(" ")
    idx = text.find(": ")
    if idx < 0:
        if not text.endswith(":"):
            _fail("expected 'key: value'", lineno)
        idx = len(text) - 1
    key = text[:idx]
    _check_plain(key, lineno)
    return key, text[idx + 1:].strip(" ")


def _block(lines, pos, indent, depth):
    if depth > _MAX_DEPTH:
        _fail("nested too deeply", lines[pos][2])
    first = lines[pos][1]
    if first == "-" or first.startswith("- "):
        return _block_seq(lines, pos, indent)
    return _block_map(lines, pos, indent, depth)


def _block_seq(lines, pos, indent):
    result = []
    while pos < len(lines) and lines[pos][0] == indent:
        _, text, lineno = lines[pos]
        if not text.startswith("- ") or not text[2:].strip(" "):
            _fail("unsupported sequence item", lineno)
        item = _inline(text[2:].strip(" "), lineno)
        if isinstance(item, (dict, list)):
            _fail("nested collections in a sequence are not supported", lineno)
        result.append(item)
        pos += 1
    if pos < len(lines) and lines[pos][0] > indent:
        _fail("inconsistent indentation", lines[pos][2])
    return result, pos


def _block_map(lines, pos, indent, depth):
    result = {}
    while pos < len(lines) and lines[pos][0] == indent:
        _, text, lineno = lines[pos]
        if text == "-" or text.startswith("- "):
            _fail("sequence item inside a mapping", lineno)
        key, rest = _split_yaml_key(text, lineno)
        if key in result:
            _fail(f"duplicate key {key!r}", lineno)
        pos += 1
        if rest:
            result[key] = _inline(rest, lineno)
            if pos < len(lines) and lines[pos][0] > indent:
                _fail("inconsistent indentation", lines[pos][2])
            continue
        if pos >= len(lines) or lines[pos][0] != indent + 2:
            _fail(f"key {key!r} has no value", lineno)
        result[key], pos = _block(lines, pos, indent + 2, depth + 1)
    if pos < len(lines) and lines[pos][0] > indent:
        _fail("inconsistent indentation", lines[pos][2])
    return result, pos


def _parse_document(lines):
    if not lines:
        _fail("empty document")
    if lines[0][0] != 0:
        _fail("document does not start at column 0", lines[0][2])
    value, pos = _block(lines, 0, 0, 0)
    if pos != len(lines):
        _fail("inconsistent indentation", lines[pos][2])
    if not isinstance(value, dict):
        _fail("document is not a mapping")
    return value


def parse_yaml(text) -> list:
    """Parse the supported YAML subset into a list of documents (1 or 2)."""
    if not isinstance(text, str):
        _fail("not text")
    if "\r" in text:
        _fail("CRLF line endings are not supported")
    if text.startswith("﻿"):
        _fail("byte-order mark is not supported")
    documents, current = [], []
    seen_content = False
    for lineno, raw in enumerate(text.split("\n"), 1):
        if "\t" in raw or any(ord(ch) < 0x20 for ch in raw):
            _fail("tabs and control characters are not supported", lineno)
        line = raw.rstrip(" ")
        if not line:
            continue
        if line == "---":
            if seen_content:
                documents.append(current)
                current = []
            seen_content = True
            continue
        if line.startswith("---") or line.startswith("..."):
            _fail("unsupported document marker", lineno)
        seen_content = True
        stripped = line.lstrip(" ")
        if stripped.startswith("#"):
            _fail("comments are not supported", lineno)
        current.append((len(line) - len(stripped), stripped, lineno))
    documents.append(current)
    if len(documents) > 2:
        _fail("more than two YAML documents")
    return [_parse_document(doc) for doc in documents]


# -- lockfile model ---------------------------------------------------------


def _strip_peers(version, what):
    """`1.0.0(a@1)(b@2)` -> `1.0.0`, rejecting unbalanced or trailing text."""
    idx = version.find("(")
    if idx < 0:
        return version
    depth = 0
    for pos in range(idx, len(version)):
        ch = version[pos]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                _fail(f"malformed peer suffix in {what}")
        elif depth == 0:
            _fail(f"malformed peer suffix in {what}")
        elif ch in " \t'\"":
            _fail(f"malformed peer suffix in {what}")
    if depth != 0:
        _fail(f"malformed peer suffix in {what}")
    return version[:idx]


def _valid_name(name, what):
    if not isinstance(name, str) or len(name) > 214 or not _NPM_NAME.fullmatch(name):
        _fail(f"invalid package name in {what}: {name!r}")
    return name


def _exact(version, what):
    if not isinstance(version, str) or not _NPM_EXACT.fullmatch(version):
        _fail(f"version is not an exact semver in {what}: {version!r}")
    return version


def _split_dep_key(key, what):
    """`name@rest` / `@scope/name@rest` -> (name, rest)."""
    if not isinstance(key, str):
        _fail(f"non-text key in {what}")
    idx = key.find("@", 1)
    if idx <= 0 or idx == len(key) - 1:
        _fail(f"malformed package key in {what}: {key!r}")
    return _valid_name(key[:idx], what), key[idx + 1:]


def _mapping(value, what):
    if not isinstance(value, dict):
        _fail(f"{what} is not a mapping")
    return value


def _pkg_ref(name, value, pkg_keys, what):
    """The `packages:` key a dependency edge `name: value` points at."""
    if f"{name}@{value}" in pkg_keys:
        return f"{name}@{value}"
    if value[:1].isdigit():
        return f"{name}@{_exact(_strip_peers(value, what), what)}"
    # `real@1.0.0(...)` (an npm alias) or `real@file:...` (a non-registry key):
    # the edge names the real package.
    real, rest = _split_dep_key(value, what)
    if rest[:1].isdigit():
        rest = _exact(_strip_peers(rest, what), what)
    else:
        rest = _strip_peers(rest, what)
    return f"{real}@{rest}"


def _check_importer_dep(name, entry, pkg_keys, importer):
    what = f"importer {importer!r} dependency {name!r}"
    _valid_name(name, what)
    entry = _mapping(entry, what)
    if set(entry) != {"specifier", "version"}:
        _fail(f"{what} must have exactly specifier and version")
    spec, version = entry["specifier"], entry["version"]
    if not isinstance(spec, str) or not isinstance(version, str):
        _fail(f"{what} has a non-text specifier or version")
    if version.startswith(_LINK_PREFIXES):
        return
    ref = _pkg_ref(name, version, pkg_keys, what)
    if ref not in pkg_keys:
        _fail(f"{what} is not in packages: {ref}")


def _classify(key, name, rest, resolution):
    """(kind, detail) of one packages entry; kind "registry" is the safe case."""
    res = _mapping(resolution, f"resolution of {key!r}")
    keys = set(res)
    if "type" in res:
        kind = res["type"]
        if kind == "git":
            if not keys <= {"type", "repo", "commit", "path"} or not (
                    isinstance(res.get("repo"), str) and isinstance(res.get("commit"), str)):
                _fail(f"unsupported git resolution for {key!r}")
            return "git", f"{res['repo']}#{res['commit']}"
        if kind == "directory":
            if keys != {"type", "directory"} or not isinstance(res["directory"], str):
                _fail(f"unsupported directory resolution for {key!r}")
            return "directory", res["directory"]
        _fail(f"unsupported resolution type for {key!r}: {kind!r}")
    tarball = res.get("tarball")
    integrity = res.get("integrity")
    if not keys or not keys <= {"integrity", "tarball"}:
        _fail(f"unsupported resolution for {key!r}")
    if integrity is not None and (
            not isinstance(integrity, str) or not _INTEGRITY.fullmatch(integrity)):
        _fail(f"invalid integrity for {key!r}")
    if tarball is None:
        if integrity is None:
            _fail(f"resolution of {key!r} has no integrity")
        return ("registry" if rest[:1].isdigit() else "tarball"), key
    if not isinstance(tarball, str):
        _fail(f"invalid tarball for {key!r}")
    if integrity is not None and rest[:1].isdigit() and _is_registry_tarball(name, rest, tarball):
        return "registry", tarball
    return "tarball", tarball


def _is_registry_tarball(name, version, url):
    """True only for the exact URL an official registry host serves name@version at."""
    return protocols.is_registry_tarball(name, version, url)


class _Doc(NamedTuple):
    importers: dict
    packages: dict    # raw key -> (name, rest, kind, detail, entry)
    snapshots: dict
    top: dict


def _validate_doc(doc, index):
    if not isinstance(doc, dict):
        _fail("document is not a mapping")
    version = doc.get("lockfileVersion")
    if version != SUPPORTED_VERSION:
        _fail(f"unsupported lockfileVersion {version!r}; only '{SUPPORTED_VERSION}' is read")
    unknown = set(doc) - _TOP_KEYS
    if unknown:
        _fail(f"unsupported top-level key(s): {', '.join(sorted(unknown))}")
    for field in ("settings", "overrides", "catalogs", "patchedDependencies"):
        if field in doc:
            _mapping(doc[field], field)
    ignored = doc.get("ignoredOptionalDependencies", [])
    if not isinstance(ignored, list):
        _fail("ignoredOptionalDependencies is not a list")

    raw_packages = _mapping(doc.get("packages", {}), "packages")
    packages = {}
    for key, entry in raw_packages.items():
        what = f"packages entry {key!r}"
        name, rest = _split_dep_key(key, what)
        if rest[:1].isdigit():
            _exact(_strip_peers(rest, what), what)
            if "(" in rest:
                _fail(f"peer suffix in a packages key: {key!r}")
        elif ":" not in rest:
            _fail(f"{what} is neither an exact version nor a URL/path source")
        entry = _mapping(entry, what)
        if "requiresBuild" in entry and not isinstance(entry["requiresBuild"], bool):
            _fail(f"requiresBuild is not a boolean in {what}")
        kind, detail = _classify(key, name, rest, entry.get("resolution"))
        packages[key] = (name, rest, kind, detail, entry)

    snapshots = {}
    for key, entry in _mapping(doc.get("snapshots", {}), "snapshots").items():
        what = f"snapshots entry {key!r}"
        entry = _mapping(entry, what)
        if key in packages:
            base = key
        else:
            name, rest = _split_dep_key(key, what)
            stripped = _strip_peers(rest, what)
            base = f"{name}@{_exact(stripped, what) if rest[:1].isdigit() else stripped}"
            if base not in packages:
                _fail(f"{what} has no packages entry")
        for section in ("dependencies", "optionalDependencies"):
            deps = _mapping(entry.get(section, {}), f"{what} {section}")
            for dep, value in deps.items():
                dwhat = f"{what} dependency {dep!r}"
                _valid_name(dep, dwhat)
                if not isinstance(value, str):
                    _fail(f"{dwhat} is not text")
                if value.startswith(_LINK_PREFIXES):
                    continue
                ref = _pkg_ref(dep, value, packages, dwhat)
                if ref not in packages:
                    _fail(f"{dwhat} is not in packages: {ref}")
        snapshots[key] = (base, entry)

    importers = _mapping(doc.get("importers", {}), "importers")
    for importer, body in importers.items():
        what = f"importer {importer!r}"
        body = _mapping(body, what)
        unexpected = set(body) - _IMPORTER_KEYS
        if unexpected:
            _fail(f"{what} has unsupported key(s): {', '.join(sorted(unexpected))}")
        for section, deps in body.items():
            for dep, entry in _mapping(deps, f"{what} {section}").items():
                _check_importer_dep(dep, entry, packages, importer)
    return _Doc(importers, packages, snapshots, doc)


def _is_env_doc(doc):
    importers = doc.get("importers", {})
    return (set(doc) <= {"lockfileVersion", "importers", "packages", "snapshots"}
            and set(importers) <= {"."}
            and set(importers.get(".", {})) <= set(_ENV_SECTIONS))


def read_pnpm_lock(path) -> PnpmLock:
    """Parse and fully validate a v9.0 pnpm-lock.yaml, or raise PnpmLockError."""
    path = Path(path)
    try:
        if path.stat().st_size > _MAX_BYTES:
            _fail("file is too large to read")
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        _fail("not valid UTF-8")
    except OSError as exc:
        raise PnpmLockError(f"pnpm-lock.yaml: cannot read {path}: {exc}") from exc
    documents = parse_yaml(text)
    if len(documents) == 2 and not _is_env_doc(documents[0]):
        _fail("a second document is only allowed after pnpm's environment lockfile")
    docs = tuple(_validate_doc(doc, i) for i, doc in enumerate(documents))
    return PnpmLock(docs=docs, main=docs[-1])


def _lock(source) -> PnpmLock:
    return source if isinstance(source, PnpmLock) else read_pnpm_lock(source)


# -- readers (shaped like manifest.npm_locked_tree and friends) --------------


def locked_tree(path) -> list:
    """Every registry (name, version) the lockfile would install, de-duplicated.

    Peer suffixes are stripped. Entries fetched from git, a directory or a
    tarball URL are not registry packages: non_registry_entries() reports them
    and the caller must refuse or review them; they are not in this list.
    """
    seen, tree = set(), []
    for doc in _lock(path).docs:
        for name, rest, kind, _detail, _entry in doc.packages.values():
            if kind != "registry":
                continue
            pair = (name, _strip_peers(rest, name))
            if pair not in seen:
                seen.add(pair)
                tree.append(pair)
    return tree


def non_registry_entries(path) -> list:
    """NonRegistryEntry for everything not served by registry.npmjs.org.

    Covers git/directory/tarball resolutions, packages keyed by URL, tarballs
    on another host (or at an unexpected registry path), and `link:`/`file:`/
    `workspace:` versions in importers and snapshots.
    """
    out = []
    for doc in _lock(path).docs:
        for key, (name, rest, kind, detail, _entry) in doc.packages.items():
            if kind != "registry":
                out.append(NonRegistryEntry(kind, name, detail, "packages"))
        for importer, body in doc.importers.items():
            for section, deps in body.items():
                for dep, entry in deps.items():
                    if entry["version"].startswith(_LINK_PREFIXES):
                        out.append(NonRegistryEntry("link", dep, entry["version"], f"importers:{importer}"))
        for key, (_base, entry) in doc.snapshots.items():
            for section in ("dependencies", "optionalDependencies"):
                for dep, value in entry.get(section, {}).items():
                    if value.startswith(_LINK_PREFIXES):
                        out.append(NonRegistryEntry("link", dep, value, f"snapshots:{key}"))
    return out


def importer_names(path) -> list:
    """The importer keys of the project lockfile ('.' plus any workspace paths)."""
    return list(_lock(path).main.importers)


def direct_specs(path) -> dict:
    """name -> exact resolved version for the root importer's direct dependencies.

    Raises when the lockfile has importers other than '.' (workspaces are
    refused by design) or when a direct dependency does not resolve to a plain
    registry semver (link:/file:/alias/URL): those are for the caller to refuse.
    """
    main = _lock(path).main
    extra = [name for name in main.importers if name != "."]
    if extra:
        _fail(f"workspace importers are not supported: {', '.join(extra)}")
    specs = {}
    for section in _DEP_SECTIONS:
        for name, entry in main.importers.get(".", {}).get(section, {}).items():
            version = entry["version"]
            what = f"importer '.' dependency {name!r}"
            if not version[:1].isdigit() or main.packages[f"{name}@{_strip_peers(version, what)}"][2] != "registry":
                _fail(f"{what} is not a registry version: {version!r}")
            if name in specs:
                _fail(f"{what} is declared twice")
            specs[name] = _exact(_strip_peers(version, what), what)
    return specs


def root_specs(path) -> dict:
    """name -> the specifier the root importer recorded (what package.json said
    when pnpm wrote the lock), for comparing with package.json exactly, as
    `pnpm install --frozen-lockfile` does."""
    specs = {}
    for section in _DEP_SECTIONS:
        for name, entry in _lock(path).main.importers.get(".", {}).get(section, {}).items():
            specs[name] = entry["specifier"]
    return specs


def skippable_root_peers(path, peer_only, _optional) -> set:
    """Root peers the lock is not expected to record: with `settings.autoInstallPeers: false`
    pnpm installs none of them (importer `.` is `{}`), so a peer-only name is not missing
    (v1.10.0 hardening). Absent, the setting is pnpm 9+'s default, true."""
    settings = _lock(path).main.top.get("settings") or {}
    if settings.get("autoInstallPeers") in (False, "false"):
        return set(peer_only)
    return set()


def artifacts(path) -> list:
    """(name, version, [integrity], missing) for each registry package: the
    digest npm's registry publishes for the tarball, which an approval records."""
    seen, out = set(), []
    for doc in _lock(path).docs:
        for name, rest, kind, _detail, entry in doc.packages.values():
            if kind != "registry":
                continue
            version = _strip_peers(rest, name)
            integrity = (entry.get("resolution") or {}).get("integrity")
            if (name, version) not in seen:
                seen.add((name, version))
                out.append((name, version, [integrity] if isinstance(integrity, str) else [],
                            not isinstance(integrity, str)))
    return out


def env_dependencies(path) -> list:
    """(name, version) of configDependencies and packageManagerDependencies.

    These are fetched by pnpm itself (config packages, the pinned pnpm), outside
    the project's own dependency sections; the hook should vet them too.
    """
    seen, out = set(), []
    for doc in _lock(path).docs:
        for body in doc.importers.values():
            for section in _ENV_SECTIONS:
                for name, entry in body.get(section, {}).items():
                    version = entry["version"]
                    what = f"{section} {name!r}"
                    if version.startswith(_LINK_PREFIXES) or not version[:1].isdigit():
                        _fail(f"{what} is not a registry version: {version!r}")
                    pair = (name, _exact(_strip_peers(version, what), what))
                    if pair not in seen:
                        seen.add(pair)
                        out.append(pair)
    return out


def env_dependency_sections(path) -> dict:
    """{section: [(name, version)]} for `configDependencies` and
    `packageManagerDependencies`, over every document of the lock (the environment
    lockfile pnpm writes first, and the importers of the main one). `env_dependencies`
    answers "what does pnpm itself fetch"; the hook also needs to know WHICH section a
    package is in, because the pnpm release must be the reviewed pin and a config
    dependency is refused outright."""
    found = {section: [] for section in _ENV_SECTIONS}
    for doc in _lock(path).docs:
        for body in doc.importers.values():
            for section in _ENV_SECTIONS:
                for name, entry in body.get(section, {}).items():
                    version = entry["version"]
                    what = f"{section} {name!r}"
                    if version.startswith(_LINK_PREFIXES) or not version[:1].isdigit():
                        _fail(f"{what} is not a registry version: {version!r}")
                    pair = (name, _exact(_strip_peers(version, what), what))
                    if pair not in found[section]:
                        found[section].append(pair)
    return found


def patched_dependencies(path) -> list:
    """The `name@version` keys under patchedDependencies (patched code runs)."""
    seen, out = set(), []
    for doc in _lock(path).docs:
        for key in doc.top.get("patchedDependencies", {}):
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def requires_build(path) -> list:
    """(name, version) of packages whose entry carries `requiresBuild: true`.

    pnpm v9 lockfiles do not normally write this field (it is absent from every
    real lockfile we sampled), so an empty list does NOT mean no package runs
    install scripts; the caller must not read it as a clean bill of health.
    """
    seen, out = set(), []
    for doc in _lock(path).docs:
        for name, rest, kind, _detail, entry in doc.packages.values():
            if entry.get("requiresBuild") is True and kind == "registry":
                pair = (name, _strip_peers(rest, name))
                if pair not in seen:
                    seen.add(pair)
                    out.append(pair)
    return out
