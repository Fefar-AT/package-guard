"""Reader for Yarn Berry's `yarn.lock` (4.x).

A Berry lock is a small YAML subset that Yarn itself writes: leading `#`
comments, a `__metadata` map, then one block per group of descriptors. This
module parses only that subset, by hand, and turns it into a model the hook can
ask four questions of:

  * which registry packages would be installed (the OSV transitive input),
  * which entries come from anywhere else (patch:, exec:, portal:, link:,
    file:, git, URL, jsr:, workspaces) -- the hook refuses these,
  * what the root workspace's direct dependencies resolved to, and
  * which dependencies the manifest lets run a build script (D12).

It fails closed: any byte it cannot account for raises `YarnLockError`, and no
partial model is ever returned. A Classic (v1) lock, or one with no
`__metadata`, is refused (D8): Berry would migrate it on the next install and
nobody would have reviewed the result. Never a regex over the raw text as a
whole, never resolves ranges, never runs Yarn.

The writer subset accepted, and nothing else:
  * 2-space indentation, one map per level, no tabs;
  * keys and scalars either bare or JSON-quoted (`json.loads`);
  * the explicit `? <key>` / `: <value>` form Yarn uses for very long keys;
  * a fixed allow-list of entry fields.
Anchors and aliases, flow maps and sequences, block scalars, tags, comments
after the header, duplicate keys and unknown fields are refused.

Standard library only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote

import protocols
from lock_errors import LockReadError

SUPPORTED_METADATA_VERSIONS = range(8, 11)  # 8 (Yarn 4.0) .. 10 (Yarn 4.18)
_MAX_BYTES = 64 * 1024 * 1024

_ENTRY_FIELDS = frozenset({
    "version", "resolution", "dependencies", "peerDependencies", "dependenciesMeta",
    "peerDependenciesMeta", "bin", "checksum", "conditions", "languageName", "linkType",
})
_SCALAR_FIELDS = frozenset({"version", "resolution", "checksum", "conditions",
                            "languageName", "linkType"})
_MAP_FIELDS = frozenset({"dependencies", "peerDependencies", "bin"})
_NESTED_MAP_FIELDS = frozenset({"dependenciesMeta", "peerDependenciesMeta"})
_METADATA_FIELDS = frozenset({"version", "cacheKey"})

_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
_NAME = re.compile(r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$", re.IGNORECASE)
_IDENT = re.compile(r"^(@[^/@]+/[^/@]+|[^/@]+)@(.+)$", re.DOTALL)
# Yarn's own compatibility patch: `#optional!builtin<compat/fsevents>`, then the
# `::version=..&hash=..` tail it appends to a resolution.
_BUILTIN_PATCH = re.compile(
    r"^patch:(?P<inner>[^#]+)#optional!builtin<compat/[a-z0-9._-]+>"
    r"(?:::version=[0-9A-Za-z.+\-]+&hash=[0-9a-f]+)?$")
# Characters that open a YAML construct we do not read, as the first character
# of a plain scalar or key.
_PLAIN_FORBIDDEN_FIRST = frozenset("&*!|>'%@`#{[]},?")

REGISTRY = "registry"
WORKSPACE, PATCH, EXEC, PORTAL, LINK, FILE = "workspace", "patch", "exec", "portal", "link", "file"
GIT, URL, JSR, OTHER, SOFT = "git", "url", "jsr", "other", "soft-link"


class YarnLockError(LockReadError):
    """yarn.lock is unreadable, is Classic, or is outside the subset this reader trusts."""


class Entry(NamedTuple):
    descriptors: tuple   # the comma-joined key, split: ("lodash@npm:^4.17.21", ...)
    name: str            # the package name from `resolution` (the real one for npm: aliases)
    version: str         # the `version` field
    resolution: str      # the full `resolution` value
    kind: str            # REGISTRY, or the protocol that makes it non-registry
    link_type: str       # "hard" | "soft"
    dependencies: dict   # name -> range as written in the lock ("npm:^1.0.0")
    dependencies_meta: dict
    fields: frozenset    # the field names the entry carried


class YarnLock(NamedTuple):
    metadata_version: int
    cache_key: str
    entries: tuple       # of Entry, in file order, root workspace included
    root: Entry          # the `@workspace:.` entry


def _fail(message, lineno=None):
    where = f" (line {lineno})" if lineno else ""
    raise YarnLockError(f"yarn.lock: {message}{where}")


# -- the YAML subset ---------------------------------------------------------


class _Line(NamedTuple):
    no: int
    indent: int
    text: str  # without the indent


def _tokenise(text):
    """The meaningful lines. Comments are only allowed before the first one."""
    if "\r" in text.replace("\r\n", "\n"):
        _fail("a bare carriage return")
    lines, seeking_header = [], True
    for no, raw in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        if "\t" in raw:
            _fail("tab character", no)
        if any(ord(c) < 32 for c in raw):
            _fail("control character", no)
        stripped = raw.lstrip(" ")
        if not stripped:
            continue
        if stripped.startswith("#"):
            if not seeking_header or raw[0] != "#":
                _fail("comment outside the file header", no)
            continue
        seeking_header = False
        indent = len(raw) - len(stripped)
        if indent % 2:
            _fail("odd indentation", no)
        if stripped.rstrip(" ") == ":":
            stripped = ":"  # the value line of an explicit key; `: ` is the same thing
        if stripped != stripped.rstrip(" "):
            _fail("trailing whitespace", no)
        lines.append(_Line(no, indent, stripped))
    return lines


def _check_plain(text, no, what):
    if not text:
        _fail(f"empty {what}", no)
    if text[0] in _PLAIN_FORBIDDEN_FIRST or text.startswith(("- ", "-\t")) or text == "-":
        _fail(f"{what} {text!r} starts a YAML construct this reader does not accept "
              "(anchor, alias, tag, flow collection, block scalar or quote)", no)
    if ": " in text or text.endswith(":") or " #" in text:
        _fail(f"{what} {text!r} contains a YAML indicator", no)
    return text


def _scalar(text, no, what):
    """A bare or JSON-quoted scalar occupying all of `text`."""
    if text.startswith('"'):
        try:
            value, end = json.JSONDecoder().raw_decode(text)
        except ValueError:
            _fail(f"unterminated or invalid quoted {what}", no)
        if end != len(text) or not isinstance(value, str):
            _fail(f"unexpected text after a quoted {what}", no)
        return value
    return _check_plain(text, no, what)


def _split_key(text, no):
    """(key, rest) of a `key: value` or `key:` line."""
    if text.startswith('"'):
        try:
            key, end = json.JSONDecoder().raw_decode(text)
        except ValueError:
            _fail("unterminated or invalid quoted key", no)
        if not isinstance(key, str):
            _fail("a key that is not text", no)
        rest = text[end:]
        if not rest.startswith(":"):
            _fail("a quoted key must be followed by a colon", no)
        rest = rest[1:]
    else:
        index = text.find(": ")
        if index < 0:
            if not text.endswith(":"):
                _fail("a line that is not `key: value`", no)
            index = len(text) - 1
        key, rest = text[:index], text[index + 1:]
        _check_plain(key, no, "key")
    if rest and not rest.startswith(" "):
        _fail("a colon must be followed by a space", no)
    return key, rest.strip(" ")


class _Parser:
    def __init__(self, lines):
        self.lines = lines
        self.pos = 0

    def peek(self):
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def block(self, indent, depth):
        """A mapping whose keys all sit at `indent`."""
        if depth > 4:
            _fail("nesting is deeper than a Berry lock goes")
        result = {}
        while True:
            line = self.peek()
            if line is None or line.indent < indent:
                return result
            if line.indent > indent:
                _fail("unexpected indentation", line.no)
            self.pos += 1
            if line.text.startswith("? "):
                key, value = self.explicit(line, indent, depth)
            else:
                key, rest = _split_key(line.text, line.no)
                value = self.value(rest, line, indent, depth)
            if key in result:
                _fail(f"duplicate key {key!r}", line.no)
            result[key] = value

    def value(self, rest, line, indent, depth):
        if rest:
            return _scalar(rest, line.no, "value")
        nxt = self.peek()
        if nxt is None or nxt.indent <= indent:
            _fail("key with no value", line.no)
        if nxt.indent != indent + 2:
            _fail("odd indentation", nxt.no)
        return self.block(indent + 2, depth + 1)

    def explicit(self, line, indent, depth):
        """`? <key>` then `: <value>` at the same indent (Yarn's form for keys
        over 1024 characters)."""
        key = _scalar(line.text[2:], line.no, "key")
        colon = self.peek()
        if colon is None or colon.indent != indent or not (
                colon.text == ":" or colon.text.startswith(": ")):
            _fail("an explicit `? ` key needs a `: ` value line", line.no)
        self.pos += 1
        return key, self.value(colon.text[1:].strip(" "), colon, indent, depth)


def parse_text(text):
    """The document as nested dicts of strings. Raises YarnLockError."""
    stripped = text.lstrip("﻿")
    if re.search(r"^#\s*yarn lockfile v1", stripped, re.MULTILINE):
        _fail("this is a Yarn Classic (v1) lockfile; Berry would migrate it on the next "
              "install and nobody would have reviewed the result (D8)")
    lines = _tokenise(stripped)
    if not lines:
        _fail("empty file")
    parser = _Parser(lines)
    if lines[0].indent != 0:
        _fail("odd indentation", lines[0].no)
    document = parser.block(0, 0)
    if parser.peek() is not None:
        _fail("unparsed trailing content", parser.peek().no)
    return document


# -- the model ---------------------------------------------------------------


def _split_ident(text, what):
    match = _IDENT.match(text)
    if match is None:
        _fail(f"{what} {text!r} is not name@reference")
    name, reference = match.group(1), match.group(2)
    if len(name) > 214 or not _NAME.match(name):
        _fail(f"{what} has an invalid package name {name!r}")
    return name, reference


def _classify(resolution, version, link_type):
    """(name, kind, version-from-the-resolution-or-None) for one entry."""
    name, reference = _split_ident(resolution, "resolution")
    if reference.startswith("npm:"):
        exact = reference[4:]
        if _EXACT.match(exact):
            if exact != version:
                _fail(f"{resolution!r}: resolution version differs from version {version!r}")
            return name, (REGISTRY if link_type == "hard" else SOFT)
        # `1.2.3::__archiveUrl=...`: a tarball Yarn fetched from its recorded URL. The
        # registry's own conventional path on an official host is still the registry (D11).
        base, _, _tail = exact.partition("::")
        archive = protocols.archive_url_of(exact)
        if (archive is not None and _EXACT.match(base) and base == version
                and protocols.is_registry_tarball(name, base, archive)):
            return name, (REGISTRY if link_type == "hard" else SOFT)
        return name, URL if "::" in exact or "://" in exact else OTHER
    if reference.startswith("workspace:"):
        return name, WORKSPACE
    if reference.startswith("patch:"):
        built = _BUILTIN_PATCH.match(reference)
        if built is None:
            return name, PATCH
        # Yarn's own compat patch on a registry package: the registry package
        # is what gets fetched, so it is judged as that package.
        inner_name, inner_ref = _split_ident(unquote(built.group("inner")), "patch source")
        if inner_name != name or not inner_ref.startswith("npm:") \
                or inner_ref[4:] != version or not _EXACT.match(version):
            return name, PATCH
        return name, (REGISTRY if link_type == "hard" else SOFT)
    for prefix, kind in (("exec:", EXEC), ("portal:", PORTAL), ("link:", LINK),
                         ("file:", FILE), ("jsr:", JSR)):
        if reference.startswith(prefix):
            return name, kind
    if reference.startswith(("git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "ssh:")):
        return name, GIT
    if reference.startswith(("http:", "https:")):
        return name, GIT if "commit=" in reference or ".git#" in reference else URL
    # Every protocol in protocols.NON_REGISTRY_PREFIXES that is not a kind above
    # (catalog:, crate:, pypi:, pkg:, runtime:, gist:), and any protocol nobody
    # knows, is OTHER: refused all the same.
    return name, OTHER


def _descriptors(key, no):
    parts = key.split(", ")
    for part in parts:
        _split_ident(part, "descriptor")
    if len(set(parts)) != len(parts):
        _fail(f"duplicate descriptor in {key!r}", no)
    return tuple(parts)


def _entry(key, body):
    if not isinstance(body, dict):
        _fail(f"entry {key!r} is not a map")
    unknown = sorted(set(body) - _ENTRY_FIELDS)
    if unknown:
        _fail(f"entry {key!r} has unknown field(s): {', '.join(unknown)}")
    for field in ("version", "resolution", "linkType"):
        if field not in body:
            _fail(f"entry {key!r} has no {field}")
    for field in _SCALAR_FIELDS & set(body):
        if not isinstance(body[field], str):
            _fail(f"entry {key!r}: {field} is not a scalar")
    for field in _MAP_FIELDS & set(body):
        value = body[field]
        if not isinstance(value, dict) or not all(isinstance(v, str) for v in value.values()):
            _fail(f"entry {key!r}: {field} is not a name->text map")
    for field in _NESTED_MAP_FIELDS & set(body):
        value = body[field]
        if not isinstance(value, dict) or not all(
                isinstance(v, dict) and all(isinstance(x, str) for x in v.values())
                for v in value.values()):
            _fail(f"entry {key!r}: {field} is not a map of maps")
    link_type = body["linkType"]
    if link_type not in ("hard", "soft"):
        _fail(f"entry {key!r}: linkType {link_type!r}")
    name, kind = _classify(body["resolution"], body["version"], link_type)
    return Entry(
        descriptors=_descriptors(key, None), name=name, version=body["version"],
        resolution=body["resolution"], kind=kind, link_type=link_type,
        dependencies=dict(body.get("dependencies", {})),
        dependencies_meta={k: dict(v) for k, v in body.get("dependenciesMeta", {}).items()},
        fields=frozenset(body))


def build(document):
    meta = document.get("__metadata")
    if meta is None:
        _fail("no __metadata block: this is not a Berry lockfile (Berry would migrate it on "
              "the next install) (D8)")
    if not isinstance(meta, dict) or set(meta) - _METADATA_FIELDS or "version" not in meta \
            or not all(isinstance(v, str) for v in meta.values()):
        _fail("__metadata is not {version, cacheKey}")
    if not re.fullmatch(r"\d+", meta["version"]) or int(meta["version"]) not in SUPPORTED_METADATA_VERSIONS:
        _fail(f"__metadata.version {meta['version']!r} is outside "
              f"{SUPPORTED_METADATA_VERSIONS.start}..{SUPPORTED_METADATA_VERSIONS.stop - 1}")
    entries, seen = [], set()
    for key, body in document.items():
        if key == "__metadata":
            continue
        entry = _entry(key, body)
        for descriptor in entry.descriptors:
            if descriptor in seen:
                _fail(f"descriptor {descriptor!r} appears in two entries")
            seen.add(descriptor)
        entries.append(entry)
    roots = [e for e in entries if e.resolution.partition("@workspace:")[2] == "."
             and e.kind == WORKSPACE]
    if len(roots) != 1:
        _fail(f"expected one root workspace entry, found {len(roots)}")
    return YarnLock(metadata_version=int(meta["version"]), cache_key=meta.get("cacheKey", ""),
                    entries=tuple(entries), root=roots[0])


def read_yarn_lock(path) -> YarnLock:
    """Parse and validate `path` (a Berry yarn.lock), or raise YarnLockError."""
    path = Path(path)
    try:
        if path.stat().st_size > _MAX_BYTES:
            _fail("file is too large to read")
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        _fail("not valid UTF-8")
    except OSError as exc:
        raise YarnLockError(f"yarn.lock: cannot read {path}: {exc}") from None
    try:
        return build(parse_text(text))
    except RecursionError:
        _fail("nesting too deep")


def _lock(source) -> YarnLock:
    return source if isinstance(source, YarnLock) else read_yarn_lock(source)


# -- the questions ------------------------------------------------------------


def locked_tree(path) -> list:
    """Every (name, version) the default registry would serve, de-duplicated.
    `npm:` aliases report the real package name; Yarn's own compat patches report
    the package they patch. Everything else is in `non_registry_entries`."""
    seen, tree = set(), []
    for entry in _lock(path).entries:
        pair = (entry.name, entry.version)
        if entry.kind == REGISTRY and pair not in seen:
            seen.add(pair)
            tree.append(pair)
    return tree


def non_registry_entries(path) -> list:
    """Entries that are not plain registry packages: patch:, exec:, portal:, link:,
    file:, git, URL, jsr:, soft links, and every workspace but the root (D13).
    The hook refuses these."""
    lock = _lock(path)
    return [e for e in lock.entries if e.kind != REGISTRY and e is not lock.root]


def root_specs(path) -> dict:
    """name -> the range the root workspace entry records (`npm:^1.2.3`), for
    comparing with package.json the way `npm ci` compares a lock's root."""
    return dict(_lock(path).root.dependencies)


def direct_specs(path) -> dict:
    """name -> exact version for each root-workspace dependency whose descriptor
    resolves to a registry entry of that same name. Anything else (an alias, a
    patch, a git source, a missing descriptor) is left out, so it reads as
    unresolved."""
    lock = _lock(path)
    index = {d: e for e in lock.entries for d in e.descriptors}
    resolved = {}
    for name, rng in lock.root.dependencies.items():
        entry = index.get(f"{name}@{rng}")
        if entry is not None and entry.kind == REGISTRY and entry.name == name:
            resolved[name] = entry.version
    return resolved


def built_allowlist(package_json_path) -> list:
    """Names the manifest's `dependenciesMeta.<pkg>.built` sets to true: the
    reviewed allow-list of dependency build scripts (D12). Raises on a manifest
    that cannot be read."""
    try:
        data = json.loads(Path(package_json_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise YarnLockError(f"package.json: cannot read {package_json_path}: {exc}") from None
    if not isinstance(data, dict):
        raise YarnLockError("package.json is not a JSON object")
    meta = data.get("dependenciesMeta", {})
    if not isinstance(meta, dict):
        raise YarnLockError("package.json: dependenciesMeta is not an object")
    names = []
    for name, value in meta.items():
        if not isinstance(value, dict):
            raise YarnLockError(f"package.json: dependenciesMeta.{name} is not an object")
        if value.get("built") is True:
            names.append(name)
    return sorted(names)
