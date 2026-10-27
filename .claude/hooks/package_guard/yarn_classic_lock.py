"""Reader for Yarn Classic's `yarn.lock` (v1, Yarn 1.22).

Frappe v11 to v16 (and ERPNext, HRMS) all lock their JavaScript with Classic v1,
which `yarn_lock.py` refuses by design. This reader is the other half: it parses
the v1 format by hand and turns it into a model the hook can ask questions of:

  * which exact `(name, version)` identities the lock holds (`identities`),
  * which of them the official registry would serve (`locked_tree`),
  * which entries come from anywhere else (`non_registry_entries`): a GitHub
    codeload tarball, a GitHub git source, or something this reader will not
    name (the hook refuses the last kind), and
  * which dependency specs have no entry at all (`dangling`).

It never decides policy and never assumes the lock is closed. HRMS's root
`yarn.lock` is stale: 231 of its 781 dependency lines name a spec with no entry
(168 distinct). `dangling` reports each occurrence and the caller decides.

It fails closed: any byte it cannot account for raises `YarnClassicLockError`
and no partial model is returned. A Berry lock (`__metadata`) and anything that
is not a Classic v1 lock is refused. Standard library only; never a regex over
the text as a whole, never resolves ranges, never runs Yarn.

No parser differential with Yarn
--------------------------------
Yarn 1.22's own parser (`src/lockfile/parse.js`) is looser than the file it
writes: a repeated key silently overwrites the first, a bare `\\r` is a line break, a
digit-led or `true`/`false`-led bare word is a number or a boolean, a comma
needs no space, a comment may sit anywhere, and a parse failure falls back to a
YAML reader. Whatever Yarn would read differently from this reader is a way to
show one lock to a reviewer and install another, so this reader accepts only
what `stringify.js` writes and refuses the rest, including every case above.

The grammar accepted, and nothing else:
  * UTF-8; one leading BOM is dropped (Yarn drops it too); LF line ends, or CRLF (Git for
    Windows writes it; every CRLF is read as LF before anything else, as Yarn reads it). A
    CR that is not part of a CRLF is refused: Yarn would break a line there. No tabs, no
    control characters, no trailing whitespace, no odd indentation;
  * the header: `#` lines before the first entry, one of which is exactly
    `# yarn lockfile v1`. A comment anywhere else is refused. A header with no
    entries is a valid empty lock;
  * blank lines between entries (and in the header), never inside one;
  * an entry: a key line at column 0, `spec(, spec)*:`; fields at 2 spaces;
    dependency lines at 4 spaces;
  * a token is JSON-quoted, or bare and then exactly what Yarn leaves bare: it
    starts with a letter, holds no whitespace, `:`, `,`, `"`, `[`, `]` or `\\`,
    and does not start with `true` or `false`. Quoting is per specifier and
    cannot be inferred from content (`amdefine@>=0.0.4` is bare, `"x@*"` is
    not), so both forms are read. Bare values keep `#`, `/`, `+` and `=`
    (`integrity sha512-..==`, `parchment quilljs/parchment#<sha>`);
  * specifiers are joined with exactly `, `;
  * a duplicate specifier (in one key or across entries), a duplicate field, and
    a duplicate dependency name are refused.

Fields, by what real locks contain (frappe v11..v16, erpnext, hrms: all ten):
only `version`, `resolved`, `integrity`, `dependencies`, `optionalDependencies`.
Any other field (`uid`, `bin`, `os`, `cpu`, `peerDependencies`, ...) is refused.
`version` is required and must be an exact semver. `resolved` is optional in the
reader: an entry without one is classified OTHER, never REGISTRY. `integrity`
is optional (a registry entry without one reports `integrity=None`): one value
`sha1|sha256|sha384|sha512-<base64>`, decoded and length-checked. When a
registry entry's `integrity` is sha1 and its URL has a `#<sha1>` fragment, they must
be equal (compared as decoded bytes); a mismatch is a malformed lock.

Names and aliases. The name is split from the range at the first `@` after
column 0, so scoped names (`@babel/runtime@^7`) and ranges that contain `@`
split correctly. `x@npm:real@range` is an alias: the entry describes `real`
(`Entry.name`), every descriptor of one entry must agree on that name, and the
alias spec (`x`) is only a descriptor. `x@npm:real` with no range is refused, on
purpose: Yarn accepts it, no real lock holds one, and guessing which version the
missing range means would put an unreviewed package into the tree.

A quoted token may hold no backslash (refused): Yarn's quote scanner looks only
two characters back, so `\"` ends a string for Yarn and not for JSON, and a real
lock has no escape at all.

Source of each entry (`Entry.kind`), judged from `resolved` AND from its descriptors.
Yarn resolves from the DESCRIPTOR: `a@file:./local` installs a local folder whatever
`resolved` says, so an entry with any descriptor that names a non-registry source (`file:`,
`link:`, `portal:`, `exec:`, `patch:`, `workspace:`, a path, an `http(s):` URL, a git URL, a
`github:` / `owner/repo` shorthand) is never REGISTRY. It is CODELOAD or GIT only when its
`resolved` matches those forms exactly AND every such descriptor is a GitHub spec of the same
owner and repository (a `#<40 hex>` in it must equal the commit); otherwise it is OTHER.
  * REGISTRY: `https://registry.yarnpkg.com|registry.npmjs.org/<name>/-/<base>-
    <version>.tgz`, the exact path for this name and version, with a `#<40 hex
    sha1>` fragment, which is a sha1 of the tarball (`tarball_sha1`). The
    fragment is optional because real locks omit it: the two `registry.npmjs.org`
    entries in frappe v13 and v14 (caniuse-lite) have none and carry sha512
    integrity (`tarball_sha1` is None). A tarball URL for a different package
    or version, or with a fragment that is not 40 hex, is OTHER, not REGISTRY.
  * CODELOAD: `https://codeload.github.com/<owner>/<repo>/tar.gz/<40 hex>`, no
    fragment: Yarn fetches a tarball whose bytes nothing in the lock verifies.
  * GIT: `git+https://github.com/<owner>/<repo>[.git]#<40 hex>`: Yarn runs git.
  * OTHER: everything else.
For CODELOAD and GIT the entry exposes `owner`, `repo` and `commit`. The commit
is never a content hash, and these entries carry no `tarball_sha1`.

API mirrors `yarn_lock.py` where the meaning carries over: `read_yarn_lock`,
`locked_tree`, `non_registry_entries`, `parse_text`, `build`. Differences:
Classic has no root entry, so `direct_specs` takes the manifest's specs as
input and there is no `root_specs`; `built_allowlist` (a Berry
`dependenciesMeta` feature) has no Classic equivalent and is not provided.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import NamedTuple

import protocols
from lock_errors import LockReadError

_MAX_BYTES = 64 * 1024 * 1024

HEADER = "# yarn lockfile v1"
_FIELDS = frozenset({"version", "resolved", "integrity", "dependencies", "optionalDependencies"})
_BLOCK_FIELDS = ("dependencies", "optionalDependencies")

_EXACT = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?")
_NAME = re.compile(r"(?:@[a-z0-9~._-]+/)?[a-z0-9~._-]+", re.IGNORECASE)
_SHA1 = re.compile(r"[0-9a-f]{40}")
_INTEGRITY = re.compile(r"(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})")
_DIGEST_BYTES = {"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}
_BARE = re.compile(r"[A-Za-z][^\s:,\"\[\]\\]*")
_CODELOAD = re.compile(
    r"https://codeload\.github\.com/(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+)"
    r"/tar\.gz/(?P<commit>[0-9a-f]{40})")
_GIT = re.compile(
    r"git\+https://github\.com/(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?"
    r"#(?P<commit>[0-9a-f]{40})")

REGISTRY, CODELOAD, GIT, OTHER = "registry", "codeload", "git", "other"


class YarnClassicLockError(LockReadError):
    """yarn.lock is unreadable, is not a Classic v1 lock, or is outside the subset this reader trusts."""


class Entry(NamedTuple):
    descriptors: tuple   # the key, split: ("lodash@^4.17.21", "lodash@^4.17.20"); alias specs as written
    name: str            # the real package name (the target of an `npm:` alias)
    version: str         # the `version` field
    resolved: object     # the `resolved` URL as written, or None
    kind: str            # REGISTRY, CODELOAD, GIT or OTHER
    integrity: object    # the `integrity` value as written, or None
    integrity_algorithm: object  # "sha512", "sha1", ... or None
    tarball_sha1: object  # REGISTRY only: the 40-hex fragment of `resolved`
    owner: object        # CODELOAD / GIT only
    repo: object         # CODELOAD / GIT only (no `.git` suffix)
    commit: object       # CODELOAD / GIT only: the 40-hex commit, never a content hash
    dependencies: dict   # name -> range as written
    optional_dependencies: dict
    fields: frozenset    # the field names the entry carried


class YarnClassicLock(NamedTuple):
    entries: tuple       # of Entry, in file order


class Dangling(NamedTuple):
    parent_name: str     # the entry that lists the spec
    parent_version: str
    name: str            # the dependency name as written
    range: str           # the dependency range as written; `name@range` has no entry
    optional: bool       # listed under optionalDependencies


def _fail(message, lineno=None):
    where = f" (line {lineno})" if lineno else ""
    raise YarnClassicLockError(f"yarn.lock: {message}{where}")


# -- the grammar -------------------------------------------------------------


class _Line(NamedTuple):
    no: int
    indent: int
    text: str  # without the indent


def _tokenise(text):
    """(header comments, the entry lines). Comments are only allowed before the
    first entry; a blank line is only allowed between entries."""
    if text.startswith("\ufeff"):
        text = text[1:]
    # Git for Windows checks files out with CRLF, and Yarn reads CRLF and a bare CR as line
    # breaks. CRLF is read as LF; a CR left over after that is one Yarn would break a line at
    # and this reader will not guess where, so it is refused.
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        _fail("a bare carriage return (not part of a CRLF line end)")
    comments, lines, seeking_header, blank_before = [], [], True, None
    for no, raw in enumerate(text.split("\n"), 1):
        if "\t" in raw:
            _fail("tab character", no)
        if any(ord(c) < 32 or ord(c) == 127 for c in raw):
            _fail("control character", no)
        if raw != raw.rstrip(" "):
            _fail("trailing whitespace", no)
        if not raw:
            blank_before = blank_before or no
            continue
        if raw.lstrip(" ").startswith("#"):
            if not seeking_header or raw[0] != "#":
                _fail("comment outside the file header", no)
            comments.append(raw)
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2:
            _fail("odd indentation", no)
        if indent and blank_before and lines:
            _fail("blank line inside an entry", blank_before)
        if indent == 0:
            seeking_header = False
        elif seeking_header:
            _fail("indented text before the first entry", no)
        blank_before = None
        lines.append(_Line(no, indent, raw[indent:]))
    return comments, lines


def _token(text, pos, no, what):
    """(value, end) of the bare or JSON-quoted token starting at `pos`."""
    if pos >= len(text):
        _fail(f"missing {what}", no)
    if text[pos] == '"':
        try:
            value, length = json.JSONDecoder().raw_decode(text[pos:])
        except ValueError:
            _fail(f"unterminated or invalid quoted {what}", no)
        if not isinstance(value, str):
            _fail(f"a quoted {what} that is not text", no)
        if not value:
            _fail(f"empty {what}", no)
        if "\\" in text[pos:pos + length]:
            # Yarn's own quote scanner looks only two characters back, so an escaped quote ends
            # the string for it and not for JSON. Real locks have no backslash at all.
            _fail(f"a backslash inside a quoted {what}", no)
        return value, pos + length
    match = _BARE.match(text, pos)
    if match is None:
        _fail(f"{what} {text[pos:].split(' ')[0]!r} is not a token Yarn writes bare "
              "(it must start with a letter; anything else is quoted)", no)
    value = match.group()
    if value.startswith(("true", "false")):
        _fail(f"bare {what} {value!r} reads as a boolean in Yarn", no)
    return value, match.end()


def _pair(text, no, what):
    """`name value` where both are tokens and the value ends the line."""
    name, end = _token(text, 0, no, f"{what} name")
    if text[end:end + 1] != " ":
        _fail(f"{what} line {text!r} is not `name value`", no)
    value, end = _token(text, end + 1, no, f"{what} value")
    if end != len(text):
        _fail(f"unexpected text after the {what} value", no)
    return name, value


def _key(line):
    """The specifiers of a `spec, spec:` key line."""
    if not line.text.endswith(":"):
        _fail("an entry key must end with a colon", line.no)
    body, specs, pos = line.text[:-1], [], 0
    while True:
        spec, pos = _token(body, pos, line.no, "specifier")
        specs.append(spec)
        if pos == len(body):
            return specs
        if body[pos:pos + 2] != ", ":
            _fail("specifiers must be separated by exactly `, `", line.no)
        pos += 2


class _Raw(NamedTuple):
    no: int
    specs: list
    fields: dict   # name -> str, or name -> dict for the two dependency blocks


def parse_text(text):
    """The file as a list of raw entries. Raises YarnClassicLockError."""
    comments, lines = _tokenise(text)
    headers = [c for c in comments if re.match(r"#\s*yarn lockfile v", c)]
    if headers != [HEADER]:
        if any(line.indent == 0 and line.text.startswith("__metadata:") for line in lines):
            _fail("this is a Yarn Berry lockfile (__metadata), not Classic v1")
        if headers:
            _fail(f"unsupported lockfile header {headers[0]!r}; only `{HEADER}` is read")
        _fail(f"no `{HEADER}` header: this is not a Yarn Classic lockfile")
    if any(line.indent == 0 and line.text.startswith("__metadata:") for line in lines):
        _fail("a `__metadata` key in a Classic lockfile: it is a Berry lockfile")
    raws, pos = [], 0
    while pos < len(lines):
        line = lines[pos]
        if line.indent != 0:
            _fail("unexpected indentation", line.no)
        specs, fields, pos = _key(line), {}, pos + 1
        while pos < len(lines) and lines[pos].indent:
            field_line = lines[pos]
            if field_line.indent != 2:
                _fail("unexpected indentation", field_line.no)
            pos += 1
            if field_line.text.endswith(":") and " " not in field_line.text:
                name = field_line.text[:-1]
                if name not in _BLOCK_FIELDS:
                    _fail(f"unknown or non-block field {name!r}", field_line.no)
                if name in fields:
                    _fail(f"duplicate field {name!r}", field_line.no)
                block = {}
                while pos < len(lines) and lines[pos].indent == 4:
                    dep, rng = _pair(lines[pos].text, lines[pos].no, "dependency")
                    if dep in block:
                        _fail(f"duplicate dependency {dep!r}", lines[pos].no)
                    block[dep] = rng
                    pos += 1
                if not block:
                    _fail(f"field {name!r} has no dependencies", field_line.no)
                if pos < len(lines) and lines[pos].indent > 2:
                    _fail("unexpected indentation", lines[pos].no)
                fields[name] = block
            else:
                name, value = _pair(field_line.text, field_line.no, "field")
                if name not in _FIELDS or name in _BLOCK_FIELDS:
                    _fail(f"unknown or block-only field {name!r}", field_line.no)
                if name in fields:
                    _fail(f"duplicate field {name!r}", field_line.no)
                fields[name] = value
        if not fields:
            _fail("an entry with no fields", line.no)
        raws.append(_Raw(line.no, specs, fields))
    return raws


# -- the model ---------------------------------------------------------------


def _check_name(name, what, no):
    if (len(name) > 214 or not _NAME.fullmatch(name)
            or any(part in (".", "..") for part in name.lstrip("@").split("/"))):
        _fail(f"{what} has an invalid package name {name!r}", no)


def _split_spec(spec, no):
    """(name, range) of `name@range`. A scoped name's own `@` is column 0, so the
    split is at the first `@` after it."""
    at = spec.find("@", 1)
    if at < 0 or at == len(spec) - 1:
        _fail(f"specifier {spec!r} is not name@range", no)
    name, rng = spec[:at], spec[at + 1:]
    _check_name(name, "specifier", no)
    return name, rng


def _real_name(spec, no):
    """The package a specifier describes: its own name, or the target of `npm:`."""
    name, rng = _split_spec(spec, no)
    if not rng.startswith("npm:"):
        return name
    target = rng[4:]
    at = target.find("@", 1)
    if at < 0 or at == len(target) - 1 or target[at + 1:].startswith("npm:"):
        _fail(f"alias {spec!r} is not x@npm:real@range", no)
    real = target[:at]
    _check_name(real, "alias", no)
    return real


def _integrity(value, no):
    match = _INTEGRITY.fullmatch(value)
    if match is None:
        _fail(f"integrity {value!r} is not <sha1|sha256|sha384|sha512>-<base64>", no)
    algorithm = match.group(1)
    try:
        digest = base64.b64decode(match.group(2), validate=True)
    except (binascii.Error, ValueError):
        _fail(f"integrity {value!r} is not valid base64", no)
    if len(digest) != _DIGEST_BYTES[algorithm]:
        _fail(f"integrity {value!r} is not a {algorithm} digest", no)
    return algorithm, digest


def _source(name, version, resolved):
    """(kind, tarball_sha1, owner, repo, commit) for one `resolved` value."""
    none = (OTHER, None, None, None, None)
    if resolved is None:
        return none
    base, sep, fragment = resolved.partition("#")
    if (not sep or _SHA1.fullmatch(fragment)) and protocols.is_registry_tarball(name, version, base):
        return REGISTRY, (fragment if sep else None), None, None, None
    for kind, pattern in ((CODELOAD, _CODELOAD), (GIT, _GIT)):
        match = pattern.fullmatch(resolved)
        if match is not None:
            repo = match.group("repo")
            if repo in (".", ".."):
                return none
            return kind, None, match.group("owner"), repo, match.group("commit")
    return none


_PROTOCOL_PREFIXES = ("file:", "link:", "portal:", "exec:", "patch:", "workspace:", "git+", "git:",
                      "git@", "github:", "gitlab:", "bitbucket:", "gist:", "ssh:", "http:", "https:",
                      "jsr:", "catalog:", "crate:", "pypi:", "pkg:", "runtime:")
_GITHUB_SPEC = re.compile(
    r"^(?:(?:git\+)?(?:https?|ssh|git)://(?:[^/@]+@)?github\.com[/:]|github:|git@github\.com:|)"
    r"(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?(?:#(?P<fragment>.*))?$")


def _registry_range(rng):
    """True when a descriptor range names the registry: a semver range, a tag, or the
    `npm:real@range` alias of one. Anything with a protocol, a path or an `owner/repo` shorthand
    is another source."""
    text = rng.strip()
    if text.lower().startswith("npm:"):
        target = text[4:]
        at = target.find("@", 1)
        text = target[at + 1:] if at > 0 else target
    return not (text.lower().startswith(_PROTOCOL_PREFIXES) or "/" in text or text in (".", "..", "~"))


def _descriptor_range(spec):
    return spec[spec.find("@", 1) + 1:]


def _github_descriptor_matches(rng, owner, repo, commit):
    match = _GITHUB_SPEC.match(rng.strip())
    if match is None:
        return False
    if (match.group("owner").lower(), match.group("repo").lower()) != (owner.lower(), repo.lower()):
        return False
    fragment = match.group("fragment")
    return not (fragment and re.fullmatch(r"[0-9a-f]{40}", fragment) and fragment != commit)


def _entry(raw):
    names = {_real_name(spec, raw.no) for spec in raw.specs}
    if len(names) != 1:
        _fail(f"one entry describes more than one package: {sorted(names)}", raw.no)
    if len(set(raw.specs)) != len(raw.specs):
        _fail(f"duplicate specifier in {', '.join(raw.specs)!r}", raw.no)
    name = names.pop()
    fields = raw.fields
    if "version" not in fields:
        _fail(f"entry {raw.specs[0]!r} has no version", raw.no)
    version = fields["version"]
    if not _EXACT.fullmatch(version):
        _fail(f"entry {raw.specs[0]!r}: version {version!r} is not an exact version", raw.no)
    for block in _BLOCK_FIELDS:
        for dep in fields.get(block, {}):
            _check_name(dep, f"{block} entry", raw.no)
    resolved = fields.get("resolved")
    kind, tarball_sha1, owner, repo, commit = _source(name, version, resolved)
    foreign = [spec for spec in raw.specs if not _registry_range(_descriptor_range(spec))]
    if foreign:
        # Yarn resolves from the descriptor, so a registry-looking `resolved` proves nothing.
        if kind == REGISTRY or not all(
                _github_descriptor_matches(_descriptor_range(spec), owner, repo, commit)
                for spec in foreign):
            kind, tarball_sha1, owner, repo, commit = OTHER, None, None, None, None
    integrity = fields.get("integrity")
    algorithm = None
    if integrity is not None:
        algorithm, digest = _integrity(integrity, raw.no)
        if kind == REGISTRY and algorithm == "sha1" and tarball_sha1 and digest.hex() != tarball_sha1:
            _fail(f"entry {raw.specs[0]!r}: the sha1 integrity differs from the sha1 in `resolved`",
                  raw.no)
    return Entry(
        descriptors=tuple(raw.specs), name=name, version=version, resolved=resolved, kind=kind,
        integrity=integrity, integrity_algorithm=algorithm, tarball_sha1=tarball_sha1,
        owner=owner, repo=repo, commit=commit,
        dependencies=dict(fields.get("dependencies", {})),
        optional_dependencies=dict(fields.get("optionalDependencies", {})),
        fields=frozenset(fields))


def build(raws):
    entries, seen = [], set()
    for raw in raws:
        entry = _entry(raw)
        for descriptor in entry.descriptors:
            if descriptor in seen:
                _fail(f"specifier {descriptor!r} appears in two entries", raw.no)
            seen.add(descriptor)
        entries.append(entry)
    return YarnClassicLock(entries=tuple(entries))


def read_yarn_lock(path) -> YarnClassicLock:
    """Parse and validate `path` (a Classic v1 yarn.lock), or raise YarnClassicLockError."""
    path = Path(path)
    try:
        if path.stat().st_size > _MAX_BYTES:
            _fail("file is too large to read")
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        _fail("not valid UTF-8")
    except OSError as exc:
        raise YarnClassicLockError(f"yarn.lock: cannot read {path}: {exc}") from None
    return build(parse_text(text))


def _lock(source) -> YarnClassicLock:
    return source if isinstance(source, YarnClassicLock) else read_yarn_lock(source)


# -- the questions ------------------------------------------------------------


def locked_tree(path) -> list:
    """Every (name, version) the official registry would serve, de-duplicated, in
    file order. `npm:` aliases report the real package name."""
    seen, tree = set(), []
    for entry in _lock(path).entries:
        pair = (entry.name, entry.version)
        if entry.kind == REGISTRY and pair not in seen:
            seen.add(pair)
            tree.append(pair)
    return tree


def non_registry_entries(path) -> list:
    """Entries that are not plain registry packages: CODELOAD, GIT and OTHER."""
    return [e for e in _lock(path).entries if e.kind != REGISTRY]


def identities(path) -> set:
    """The exact (name, version) of every entry, whatever its source. Two entries
    can share one identity (a registry copy and a git copy); `kind` tells them apart."""
    return {(e.name, e.version) for e in _lock(path).entries}


def dangling(path) -> list:
    """Each dependency (or optional dependency) occurrence whose `name@range` is
    not a specifier of any entry, in file order. Never an error: a stale lock is
    a fact the caller weighs (HRMS's root lock has 231 occurrences, 168 distinct)."""
    lock = _lock(path)
    known = {d for e in lock.entries for d in e.descriptors}
    missing = []
    for entry in lock.entries:
        for optional, block in ((False, entry.dependencies), (True, entry.optional_dependencies)):
            for name, rng in block.items():
                if f"{name}@{rng}" not in known:
                    missing.append(Dangling(entry.name, entry.version, name, rng, optional))
    return missing


def direct_specs(path, specs) -> dict:
    """name -> exact version for each manifest spec (`specs`: name -> range from
    package.json) whose `name@range` is a specifier of a REGISTRY entry of that
    same name. Anything else (an alias, a git or codeload source, a missing
    entry) is left out, so it reads as unresolved."""
    index = {d: e for e in _lock(path).entries for d in e.descriptors}
    resolved = {}
    for name, rng in specs.items():
        entry = index.get(f"{name}@{rng}")
        if entry is not None and entry.kind == REGISTRY and entry.name == name:
            resolved[name] = entry.version
    return resolved
