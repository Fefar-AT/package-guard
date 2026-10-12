"""Deterministic vetting: official registry metadata + OSV lookup.

Produces an immutable review report per unknown package. Never downloads
or executes candidate package code — metadata only.

Standard library only.
"""
from __future__ import annotations

import ast
import configparser
import json
import re
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import store  # noqa: E402
import trusted_catalog  # noqa: E402

USER_AGENT = "package-guard/1.0"
TIMEOUT_SECONDS = 8.0
# Full npm packuments for popular packages can be tens of megabytes.
MAX_BODY_BYTES = 64 * 1024 * 1024
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
# OSV accepts up to 1000 queries per batch call.
OSV_BATCH_SIZE = 1000
_OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}

# Thresholds for the deterministic risk signals derived from registry metadata
# the review already fetched. Each one is evidence the approval prompt renders
# for the human; none changes the verdict and none is a score.
FRESH_PACKAGE_DAYS = 90
FRESH_VERSION_DAYS = 7
STALE_PUBLISH_DAYS = 3 * 365
MIN_RELEASES = 3
_PYPI_INACTIVE = "Development Status :: 7 - Inactive"

# The reputation tier: deterministic facts that say whether a package is the
# established thing under its name, so the human can approve it without an
# LLM research pass. `established` is not a verdict and not a score: every
# criterion is a threshold the prompt renders, and one unmet criterion sends
# the review to the vetter.
# npm reads the registry's own downloads and search endpoints. PyPI serves
# neither, so both its own count and its near-name giants come from the
# top-15,000 list that hugovk publishes monthly from PyPI's public download
# data (30-day counts; the list's cut-off sits above the established floor,
# so a package outside the list cannot pass the floor and its count is
# bounded above by the cut-off). A third party, and one that can only make a
# package unresolved: a wrong or missing number sends it to the vetter, never
# past it. Per-package download APIs rate-limit a batch, so one list is
# fetched instead.
NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-week/"
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
# The list moved from hugovk.github.io, which now answers with a redirect to
# this host. A cross-host redirect is refused (`_request_json`), so the URL
# names the host that serves the list.
PYPI_TOP_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
GITHUB_RAW_URL = "https://raw.githubusercontent.com"
ESTABLISHED_MIN_AGE_DAYS = 365
ESTABLISHED_MIN_RELEASES = 5
ESTABLISHED_MIN_WEEKLY_DOWNLOADS = 10_000
# A name one edit from a package with this many times its downloads is the
# lookalike shape (the vetter's D2 rule, computed here).
LOOKALIKE_DOWNLOAD_RATIO = 100
NEAR_NAME_SEARCH_SIZE = 20
# The bulk downloads endpoint takes at most 128 names; searched neighbours
# come first, then the enumerated mutations.
NEAR_NAME_BULK_LIMIT = 100
# License is evidence for the human, never a criterion of the tier: a license
# is policy, not identity, and no license string tells a lookalike from the
# real package. The review records a short display string and one of these
# classes. Ids are SPDX, matched case-insensitively.
LICENSE_CLASSES = ("permissive", "weak-copyleft", "strong-copyleft", "proprietary", "unknown")
PERMISSIVE_LICENSES = frozenset({
    "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "PSF-2.0", "Python-2.0",
    "0BSD", "Unlicense", "CC0-1.0", "Zlib", "MIT-0", "X11", "BlueOak-1.0.0", "Unicode-3.0",
    "Unicode-DFS-2016", "BSD-1-Clause", "BSD-2-Clause-Patent", "BSD-3-Clause-Clear", "BSL-1.0",
    "NCSA", "UPL-1.0", "WTFPL", "MIT-CMU", "HPND", "PostgreSQL", "curl", "Python-2.0.1",
    "zlib-acknowledgement", "libpng-2.0", "CC-BY-3.0", "CC-BY-4.0", "AFL-3.0", "Artistic-2.0",
    # Not SPDX ids: what a bare "BSD License" classifier or a public-domain
    # dedication is shown as.
    "BSD", "Public Domain",
})
# Version families by prefix, after an `-only`, `-or-later` or `+` suffix is
# dropped.
_COPYLEFT_FAMILIES = (
    ("agpl", "strong-copyleft"), ("gpl", "strong-copyleft"), ("sspl", "strong-copyleft"),
    ("osl", "strong-copyleft"), ("lgpl", "weak-copyleft"), ("mpl", "weak-copyleft"),
    ("epl", "weak-copyleft"), ("cddl", "weak-copyleft"), ("eupl", "weak-copyleft"),
    ("cpl", "weak-copyleft"), ("ms-rl", "weak-copyleft"),
)
# Exceptions that let code link against a GPL library without taking its terms.
_LINKING_EXCEPTIONS = frozenset({
    "classpath-exception-2.0", "gcc-exception-2.0", "gcc-exception-3.1", "llvm-exception",
    "linking-exception", "openjdk-assembly-exception-1.0",
})
# Free-text names (trove classifiers, and what authors write in a short PyPI
# `license` field) mapped to an SPDX id, lower case.
_LICENSE_NAMES = {
    "mit": "MIT", "mit license": "MIT", "the mit license": "MIT", "mit licence": "MIT",
    "expat": "MIT", "mit no attribution license (mit-0)": "MIT-0",
    "bsd": "BSD", "bsd license": "BSD", "bsd licence": "BSD",
    "new bsd": "BSD-3-Clause", "new bsd license": "BSD-3-Clause", "modified bsd license": "BSD-3-Clause",
    "3-clause bsd license": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause",
    "bsd 3-clause license": "BSD-3-Clause", "bsd-3": "BSD-3-Clause",
    "2-clause bsd license": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause",
    "bsd 2-clause license": "BSD-2-Clause", "simplified bsd": "BSD-2-Clause", "bsd-2": "BSD-2-Clause",
    "apache": "Apache-2.0", "apache 2": "Apache-2.0", "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0", "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0", "apache software license": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0", "asl 2.0": "Apache-2.0",
    "isc": "ISC", "isc license": "ISC", "isc license (iscl)": "ISC",
    "psf": "PSF-2.0", "psf license": "PSF-2.0", "python software foundation license": "PSF-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
    "mpl 2.0": "MPL-2.0", "mozilla public license 1.1 (mpl 1.1)": "MPL-1.1",
    "the unlicense": "Unlicense", "the unlicense (unlicense)": "Unlicense", "unlicense": "Unlicense",
    "zlib": "Zlib", "zlib/libpng license": "Zlib",
    "cc0 1.0 universal (cc0 1.0) public domain dedication": "CC0-1.0",
    "boost software license 1.0 (bsl-1.0)": "BSL-1.0",
    "universal permissive license (upl)": "UPL-1.0", "blue oak model license (blueoak-1.0.0)": "BlueOak-1.0.0",
    "public domain": "Public Domain",
    "gnu general public license (gpl)": "GPL", "gpl": "GPL",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
    "gnu library or lesser general public license (lgpl)": "LGPL", "lgpl": "LGPL",
    "eclipse public license 1.0 (epl-1.0)": "EPL-1.0", "eclipse public license 2.0 (epl-2.0)": "EPL-2.0",
    "other/proprietary license": "Proprietary", "proprietary": "Proprietary",
}
# The longest display string the report keeps.
_LICENSE_DISPLAY_MAX = 80
# Calls the reputation step can add to one review. npm: downloads (1), the
# repository manifest (up to 2), the near-name search (1) and the neighbours'
# downloads in one bulk call (1). PyPI: the top list (1, once per process)
# and the repository build files (up to 3: pyproject.toml, then setup.cfg and
# setup.py). hook._REVIEW_CALLS carries the per-review total the review budget
# bounds; PyPI's three mandatory calls plus four fit under the same seven.
REPUTATION_CALLS = 5
_SAFE_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+")
_SAFE_PATH = re.compile(r"[A-Za-z0-9_./@-]+")
_NPM_UNSCOPED = re.compile(r"[a-z0-9][a-z0-9._-]*")


class ProviderError(Exception):
    """A mandatory evidence provider failed. Unknown packages fail closed."""


class TransientProviderError(ProviderError):
    """A timeout or a connection reset: the one failure a mandatory call
    retries (`_mandatory_json`). An HTTP status is never transient."""


class ResponseTooLarge(ProviderError):
    """A provider answered with more than MAX_BODY_BYTES. Only the npm
    packument has a smaller document to fall back to (`_vet_npm`); anywhere
    else this fails closed like any provider failure."""


class HardDeny(Exception):
    """Deterministic evidence that forbids this package outright."""


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to HTTPS on the host that was asked.

    Every provider host is named in this module, and a sandbox egress
    allowlist names the same hosts. A redirect to another host would read
    evidence from a source nobody chose, or fail somewhere the report cannot
    explain, so it is a provider failure. A same-host redirect (PyPI
    normalising a project name) is followed.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, newurl))
        if new.scheme != "https" or (new.hostname or "").lower() != (old.hostname or "").lower():
            raise ProviderError(f"{req.full_url}: HTTP {code} redirect to another host "
                                f"({new.scheme}://{new.hostname}) refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirect())

# Documents the review reads as text rather than JSON: the build files of a
# repository's Python project.
_TEXT_SUFFIXES = (".toml", ".cfg", ".py")


def _transient(exc) -> bool:
    """A timeout or a connection reset, raised directly or wrapped by urllib."""
    if isinstance(exc, urllib.error.HTTPError):
        return False
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    return isinstance(reason, (TimeoutError, ConnectionResetError))


def _declared_length(response) -> int | None:
    headers = getattr(response, "headers", None)
    try:
        value = headers.get("Content-Length") if headers is not None else None
        return int(value) if value is not None else None
    except (TypeError, ValueError, AttributeError):
        return None


def _request_json(url: str, data=None):
    """HTTPS GET/POST returning parsed JSON. 404 returns None."""
    if not url.startswith("https://"):
        raise ProviderError(f"refusing non-HTTPS provider URL: {url}")
    body = None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            # A declared length over the cap is refused before the body is
            # read: the 68 MB packument of @prisma/client took 95 s to read.
            declared = _declared_length(response)
            if declared is not None and declared > MAX_BODY_BYTES:
                raise ResponseTooLarge(f"{url}: response of {declared} bytes exceeds the "
                                       f"{MAX_BODY_BYTES}-byte limit")
            raw = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ProviderError(f"{url}: HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if _transient(exc):
            raise TransientProviderError(f"{url}: {exc}")
        raise ProviderError(f"{url}: {exc}")
    if len(raw) > MAX_BODY_BYTES:
        raise ResponseTooLarge(f"{url}: response exceeds the {MAX_BODY_BYTES}-byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProviderError(f"{url}: response is not UTF-8")
    # One seam for every provider, so a test that replaces this function
    # replaces all of them. A repository's Python build files are the only
    # non-JSON documents the review reads; they are returned as text. Only on
    # the raw-file host: a registry name may itself end in `.py`.
    if url.startswith(GITHUB_RAW_URL + "/") and url.endswith(_TEXT_SUFFIXES):
        return text
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        raise ProviderError(f"{url}: response is not valid JSON")


# A mandatory provider call (the registry documents and OSV) is retried once
# after a timeout or a connection reset, never after an HTTP status. The hook
# sets the deadline (`set_retry_deadline`): a retry starts only when the
# backoff and one more full request still end before it, so every retry is
# over before the review deadline and the hook's budget arithmetic is
# unchanged. With no deadline set (a CLI process, outside any hook) the one
# retry is always allowed.
RETRY_BACKOFF_SECONDS = 1.0
_retry_deadline = None


def set_retry_deadline(deadline) -> None:
    """A time.monotonic() value no retry may run past, or None for no bound."""
    global _retry_deadline
    _retry_deadline = deadline


def _retry_fits() -> bool:
    deadline = _retry_deadline
    return deadline is None or time.monotonic() + RETRY_BACKOFF_SECONDS + TIMEOUT_SECONDS <= deadline


def _mandatory_json(url: str, data=None):
    """`_request_json` for a mandatory provider, with its one retry."""
    try:
        return _request_json(url, data)
    except TransientProviderError:
        if not _retry_fits():
            raise
    time.sleep(RETRY_BACKOFF_SECONDS)
    return _request_json(url, data)


# ---------------------------------------------------------------------------
# Registry providers
# ---------------------------------------------------------------------------

def _repository_from(value) -> str | None:
    if isinstance(value, dict):
        value = value.get("url")
    return value if isinstance(value, str) and value else None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _age_days(stamp, now: datetime) -> int | None:
    parsed = _parse_iso(stamp)
    if parsed is None:
        return None
    return max(0, int((now - parsed).total_seconds() // 86400))


def _text(value) -> str | None:
    """A registry field that is a string, or a dict carrying one under a known key."""
    if isinstance(value, dict):
        value = value.get("type") or value.get("name") or value.get("url")
    if isinstance(value, bool):
        return "yes" if value else None
    return value if isinstance(value, str) and value else None


def _count(value) -> int | None:
    return len(value) if isinstance(value, (dict, list)) else None


# ---------------------------------------------------------------------------
# License: a display string and a class, never a criterion
# ---------------------------------------------------------------------------

# AND keeps the lowest rank, OR the highest. An id the review does not know
# sits under every copyleft class: it may be anything.
_CLASS_RANK = {"permissive": 4, "weak-copyleft": 3, "strong-copyleft": 2, "unknown": 1, "proprietary": 0}
_LICENSE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:+-]*")
_CANONICAL_LICENSE = {name.lower(): name for name in PERMISSIVE_LICENSES}
_SPDX_OPERATORS = ("AND", "OR", "WITH")


def _license_id_class(license_id: str) -> str:
    """The class of one license id, ignoring an `-only`, `-or-later` or `+` suffix."""
    key = license_id.lower()
    if key in ("unlicensed", "proprietary") or key.startswith("see license in"):
        return "proprietary"
    base = re.sub(r"(-only|-or-later|\+)$", "", key)
    if key in _CANONICAL_LICENSE or base in _CANONICAL_LICENSE:
        return "permissive"
    for prefix, license_class in _COPYLEFT_FAMILIES:
        if base.startswith(prefix):
            return license_class
    return "unknown"


def _short(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _LICENSE_DISPLAY_MAX else text[:_LICENSE_DISPLAY_MAX - 1] + "…"


def _combine_licenses(parts: list, operator: str) -> tuple:
    """(display, class, every id recognised, compound) for parts joined by AND or OR."""
    if len(parts) == 1:
        return parts[0]
    display = f" {operator} ".join(f"({p[0]})" if p[3] else p[0] for p in parts)
    pick = min if operator == "AND" else max
    license_class = pick((p[1] for p in parts), key=_CLASS_RANK.__getitem__)
    return display, license_class, all(p[2] for p in parts), True


def _spdx(text) -> tuple | None:
    """(display, class, every id recognised) for an SPDX license expression,
    or None when the text is not one.

    Operators and ids are matched case-insensitively; WITH binds tighter than
    AND, which binds tighter than OR. WITH keeps the class of the license it
    qualifies, except that a linking exception makes a GPL weak copyleft.
    """
    tokens = re.findall(r"\(|\)|[^\s()]+", text or "")
    if not tokens or len(tokens) > 100:
        return None
    position = 0

    def peek():
        return tokens[position].upper() if position < len(tokens) else None

    def take():
        nonlocal position
        if position >= len(tokens):
            raise ValueError("expression ends early")
        position += 1
        return tokens[position - 1]

    def expression(depth):
        if depth > 20:
            raise ValueError("nested too deeply")
        parts = [term(depth)]
        while peek() == "OR":
            take()
            parts.append(term(depth))
        return _combine_licenses(parts, "OR")

    def term(depth):
        parts = [factor(depth)]
        while peek() == "AND":
            take()
            parts.append(factor(depth))
        return _combine_licenses(parts, "AND")

    def factor(depth):
        token = take()
        if token == "(":
            inner = expression(depth + 1)
            if take() != ")":
                raise ValueError("unbalanced parenthesis")
            return inner
        if token == ")" or token.upper() in _SPDX_OPERATORS or not _LICENSE_ID.fullmatch(token):
            raise ValueError(f"not a license id: {token}")
        license_class = _license_id_class(token)
        display = _CANONICAL_LICENSE.get(token.lower(), token)
        known = license_class != "unknown"
        if peek() == "WITH":
            take()
            exception = take()
            if exception.upper() in _SPDX_OPERATORS or not _LICENSE_ID.fullmatch(exception):
                raise ValueError(f"not a license exception: {exception}")
            if license_class == "strong-copyleft" and exception.lower() in _LINKING_EXCEPTIONS:
                license_class = "weak-copyleft"
            display = f"{display} WITH {exception}"
        return display, license_class, known, False

    try:
        display, license_class, known, _compound = expression(0)
    except ValueError:
        return None
    if position != len(tokens):
        return None
    return display, license_class, known


def _license_name(text) -> tuple | None:
    """(display, class) for a license written in words or as SPDX, or None."""
    if not isinstance(text, str) or not text.strip():
        return None
    named = _LICENSE_NAMES.get(" ".join(text.lower().split()))
    if named:
        return named, _license_id_class(named)
    parsed = _spdx(text)
    if parsed and parsed[2]:
        return _short(parsed[0]), parsed[1]
    return None


def _one_license(text: str) -> tuple:
    """(display, class) for one declared license string, whatever its shape."""
    text = text.strip()
    if text.upper().startswith("SEE LICENSE IN"):
        return _short(text), "proprietary"
    parsed = _spdx(text)
    if parsed:
        return _short(parsed[0]), parsed[1]
    return _license_name(text) or (_short(text), "unknown")


def _any_of(found: list) -> tuple:
    """Several declared licenses the user may choose between, as one OR."""
    if not found:
        return None, "unknown"
    parts = [(display, license_class, True, bool(re.search(r" (AND|OR) ", display)))
             for display, license_class in found]
    display, license_class, _known, _compound = _combine_licenses(parts, "OR")
    return _short(display), license_class


def _npm_license(version_meta: dict) -> tuple:
    """(display, class) from package.json: `license`, else the legacy
    `licenses[]`, several read as OR. (None, "unknown") when none is declared."""
    value = version_meta.get("license")
    if isinstance(value, dict):
        value = value.get("type")
    if isinstance(value, str) and value.strip():
        return _one_license(value)
    entries = version_meta.get("licenses")
    found = []
    for entry in entries if isinstance(entries, list) else []:
        name = _text(entry)
        if name and name.strip():
            found.append(_one_license(name))
    return _any_of(found)


def _pypi_license(info: dict) -> tuple:
    """(display, class) from PyPI metadata, first answer wins:

    1. the PEP 639 `license_expression`;
    2. a `license` field of at most 80 characters that parses as SPDX with
       every id recognised;
    3. the license classifiers, several read as OR;
    4. a short `license` field that names a license in words;
    5. otherwise unknown, shown as the field's first line.

    (None, "unknown") when nothing at all is declared.
    """
    expression = _text(info.get("license_expression"))
    if expression:
        parsed = _spdx(expression)
        return (_short(parsed[0]), parsed[1]) if parsed else (_short(expression), "unknown")
    declared = _text(info.get("license"))
    declared = declared.strip() if declared else None
    short = declared if declared and len(declared) <= _LICENSE_DISPLAY_MAX else None
    if short:
        parsed = _spdx(short)
        if parsed and parsed[2]:
            return _short(parsed[0]), parsed[1]
    found = []
    for classifier in info.get("classifiers") or []:
        if not isinstance(classifier, str) or not classifier.startswith("License ::"):
            continue
        name = classifier.split("::")[-1].strip()
        if name and name != "OSI Approved":
            entry = _license_name(name) or (_short(name), "unknown")
            if entry not in found:
                found.append(entry)
    if found:
        return _any_of(found)
    if short:
        return _license_name(short) or (_short(short), "unknown")
    if declared:
        first = next((line for line in declared.splitlines() if line.strip()), declared)
        return _short(first), "unknown"
    return None, "unknown"


# ---------------------------------------------------------------------------
# An unpinned request resolves past an unsigned fresh release
# ---------------------------------------------------------------------------

_NPM_STABLE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_PYPI_STABLE = re.compile(r"\d+(?:\.\d+)*(?:\.post\d+)?")


def _stable_key(ecosystem: str, version: str):
    """A comparable key for a final release, or None (prerelease, unparseable)."""
    if ecosystem == "npm":
        match = _NPM_STABLE.fullmatch(version)
        return tuple(int(part) for part in match.groups()) if match else None
    if not _PYPI_STABLE.fullmatch(version):
        return None
    head, _, post = version.partition(".post")
    parts = [int(part) for part in head.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()  # 1.0 == 1.0.0
    return (tuple(parts), int(post) if post else -1)


def _cooled(ecosystem: str, latest: str, published: dict, attested: bool,
            now: datetime | None = None):
    """(version to review, cooldown record or None) for an unpinned request.

    The latest release stands when it is at least FRESH_VERSION_DAYS old,
    when it carries a provenance attestation, or when its date is unknown.
    Otherwise the answer is the highest final release ranked at or below it
    that is at least that old. `published` maps a candidate version to its
    publish time; the caller leaves out what must never be chosen (deprecated,
    yanked). With no such release the latest stands and the vetter and the
    human judge it.

    A days-old unsigned release asks the human a question they cannot answer.
    Compromised releases of established packages (chalk and debug, September
    2025) came from the real
    maintainer's account with changes inside existing files, and were pulled
    within hours, so age is the signal a release diff cannot replace.
    """
    now = now or datetime.now(timezone.utc)
    age = _age_days(published.get(latest), now)
    ceiling = _stable_key(ecosystem, latest)
    if attested or age is None or age >= FRESH_VERSION_DAYS:
        return latest, None
    # A latest that does not rank (a prerelease under the latest tag, a
    # PyPI epoch) is chosen by whoever publishes it; it gets no ceiling, so the
    # highest settled final release is picked instead.
    best, best_key = None, None
    for version, stamp in published.items():
        key = _stable_key(ecosystem, version)
        days = _age_days(stamp, now)
        if key is None or days is None or days < FRESH_VERSION_DAYS or (
                ceiling is not None and key > ceiling):
            continue
        if best_key is None or key > best_key:
            best, best_key = version, key
    if best is None:
        return latest, None
    return best, {"latest": latest, "latest_age_days": age, "chosen": best,
                  "min_age_days": FRESH_VERSION_DAYS}


def _cooldown_unavailable_signal(reason: str, version: str) -> str:
    """The risk signal when the cool-down could not run."""
    return (f"cool-down unavailable ({reason}): {version} is reviewed "
            f"without checking it is at least {FRESH_VERSION_DAYS} days old")


def _settled_release(ecosystem: str, version: str, published: dict, now=None) -> str | None:
    """The newest final release ranked at or below `version` that is at least
    FRESH_VERSION_DAYS old, or None: what a fresh release is compared with.

    Never simply the previous release. An attacker who controls an account can
    publish two releases an hour apart, and the first would vouch for the
    second. The ranking is the cool-down's, without its attestation shortcut.
    """
    pick, record = _cooled(ecosystem, version, published, False, now=now)
    return pick if record else None


# ---------------------------------------------------------------------------
# npm release continuity: a fresh release against its settled baseline
# ---------------------------------------------------------------------------

def _attested(version_meta) -> bool:
    dist = version_meta.get("dist") if isinstance(version_meta, dict) else None
    return isinstance(dist, dict) and isinstance(dist.get("attestations"), dict) \
        and bool(dist["attestations"])


def _publisher_identity(version_meta) -> tuple | None:
    """Who published a version, as the packument records it.

    A trusted-publisher release is identified by its provider and OIDC
    configuration, an account release by the account name. npm wrote the
    configuration id with an `oidc:` prefix on older records and without it on
    newer ones, so the prefix is dropped; the approver and the email are not
    part of the identity.
    """
    user = version_meta.get("_npmUser") if isinstance(version_meta, dict) else None
    if not isinstance(user, dict):
        name = _text(user)
        return ("account", name) if name else None
    trusted = user.get("trustedPublisher")
    if isinstance(trusted, dict) and (trusted.get("id") or trusted.get("oidcConfigId")):
        config = trusted.get("oidcConfigId")
        config = config.removeprefix("oidc:") if isinstance(config, str) else None
        return ("trusted", str(trusted.get("id") or ""), config)
    name = user.get("name")
    return ("account", name) if isinstance(name, str) and name else None


def _trusted_publisher(version_meta) -> str | None:
    """The provider of an npm trusted-publishing release (`github`, `gitlab`),
    or None for an account release.

    The registry records this identity when the package's own maintainers
    configured OIDC publishing for it; a stolen token cannot produce it."""
    identity = _publisher_identity(version_meta)
    if not identity or identity[0] != "trusted":
        return None
    return identity[1] or "oidc"


def _known_publisher(evidence: dict, provenance) -> bool:
    """The npm publisher criterion: a listed maintainer published the version,
    or it carries a provenance attestation, or it came through trusted
    publishing."""
    publisher = evidence.get("publisher")
    attested = isinstance(provenance, dict) and bool(provenance.get("attested"))
    return bool(publisher) and (publisher in (evidence.get("maintainers") or [])
                                or attested or bool(evidence.get("trusted_publisher")))


def _trusted_publisher_record(version_meta) -> tuple | None:
    """The trusted-publishing configuration that released a version, in full,
    or None unless the record names both its provider and its configuration.

    The registry writes `_npmUser.trustedPublisher` as `{"id": "github",
    "oidcConfigId": "<uuid>"}`; older records prefix the configuration id with
    `oidc:`, which is dropped. Any other key in the record is kept as given, so
    two records match only when everything in them does. The configuration
    is what the package's own maintainers set up: it binds publishing to one
    repository and workflow. A stolen token publishes as an account, never
    through it, even with a provenance attestation from a repository the
    attacker controls. Stricter than `_publisher_identity`, which also reads
    a record that names only one of the two: this is the comparison a fresh
    release must pass.
    """
    user = version_meta.get("_npmUser") if isinstance(version_meta, dict) else None
    record = user.get("trustedPublisher") if isinstance(user, dict) else None
    if not isinstance(record, dict):
        return None
    provider, config = record.get("id"), record.get("oidcConfigId")
    if not (isinstance(provider, str) and provider and isinstance(config, str)):
        return None
    config = config.removeprefix("oidc:")
    if not config:
        return None
    rest = tuple(sorted((key, json.dumps(value, sort_keys=True)) for key, value in record.items()
                        if key not in ("id", "oidcConfigId")))
    return provider, config, rest


def _repository_key(version_meta) -> str | None:
    """The repository a version itself declares, normalised for comparison:
    a GitHub repository as `github.com/owner/repo` in lower case (GitHub
    ignores case) whatever shape it was declared in; any other URL without a
    `git+` prefix, a `.git` suffix or a trailing slash. None when the version
    declares none; the packument-level fallback is not read."""
    value = _repository_from(version_meta.get("repository")) if isinstance(version_meta, dict) else None
    if value is None:
        return None
    located = _github_repo(value, shorthand=True)
    if located is not None:
        return f"github.com/{located[0]}/{located[1]}".lower()
    text = value.strip().removeprefix("git+").rstrip("/").removesuffix(".git")
    return text or None


# What npm runs when it installs a registry tarball. `prepare` joins them for
# a package that builds native code (`gypfile`).
_INSTALL_LIFECYCLE = ("preinstall", "install", "postinstall")


def _install_scripts(version_meta) -> dict:
    """{lifecycle key: command} npm runs for a registry tarball. A binding.gyp
    with no install script is npm's implicit `node-gyp rebuild`."""
    scripts = version_meta.get("scripts") if isinstance(version_meta.get("scripts"), dict) else {}
    found = {key: scripts[key] for key in _INSTALL_LIFECYCLE if key in scripts}
    if version_meta.get("gypfile"):
        found.setdefault("install", "node-gyp rebuild")
        if "prepare" in scripts:
            found["prepare"] = scripts["prepare"]
    return found


def _changed_install_scripts(current, base) -> list:
    """Lifecycle keys new in `current` or whose command changed, and `gypfile`
    when the native build was switched on or off."""
    mine, theirs = _install_scripts(current), _install_scripts(base)
    changed = [key for key, command in mine.items() if key not in theirs or theirs[key] != command]
    if bool(current.get("gypfile")) != bool(base.get("gypfile")):
        changed.append("gypfile")
    return sorted(changed)


def _dependency_groups(version_meta) -> dict:
    """{group: {name: spec}} for everything npm installs with a version.

    `optionalDependencies` is read into `dependencies`, overriding an entry of
    the same name, as npm reads them. `peerDependencies` is its own group (npm
    7 and later install peers). The bundled names, under either spelling, are
    a group whose spec is `bundled`; `true` bundles every dependency and reads
    as `*`. A field of any other shape is kept whole under `(malformed)`, so
    a change to it still counts.
    """
    def entries(value) -> dict:
        if value is None:
            return {}
        if isinstance(value, dict):
            return {name: spec for name, spec in value.items() if isinstance(name, str)}
        return {"(malformed)": value}

    dependencies = entries(version_meta.get("dependencies"))
    dependencies.update(entries(version_meta.get("optionalDependencies")))
    bundle = version_meta.get("bundleDependencies")
    if bundle is None:
        bundle = version_meta.get("bundledDependencies")
    if bundle is True:
        bundled = {"*": "bundled"}
    elif isinstance(bundle, list):
        bundled = {name: "bundled" for name in bundle if isinstance(name, str)}
    else:
        bundled = entries(bundle) if bundle not in (None, False) else {}
    return {"dependencies": dependencies, "peerDependencies": entries(version_meta.get("peerDependencies")),
            "bundleDependencies": bundled}


# A version, a range or a dist-tag: what npm resolves from the registry under
# the dependency's own name. Anything with `/`, `:`, `#`, `@` or `\` is a URL,
# an `npm:` alias, git or a github shorthand, `file:`, `link:`,
# `workspace:` or a path; a leading `.` or a tarball suffix is a path too.
_REGISTRY_SPEC = re.compile(r"[A-Za-z0-9 .*^~<>=|+_-]*")
_TARBALL_SPEC = re.compile(r"\.(?:tgz|tar\.gz|tar)$", re.IGNORECASE)


def _registry_spec(spec) -> bool:
    """True for a spec npm fetches from the registry under the same name."""
    if not isinstance(spec, str):
        return False
    text = spec.strip()
    return bool(_REGISTRY_SPEC.fullmatch(text)) and not text.startswith(".") \
        and not _TARBALL_SPEC.search(text)


def _dependency_changes(current, base) -> tuple:
    """(new names, changed entries, kind) of a fresh release against its baseline.

    A name is new when no install-time group of the baseline has it. An entry,
    `group:name`, is changed when that group of the baseline lacks the name or
    holds another spec string for it; every new name is a changed entry too.
    A removed name is neither.

    `kind` is `none` with no changed entry; `registry-bumps` when every change
    swaps one registry spec for another under an existing name (`^4.1.0` to
    `^4.2.0`, `4.63.5` to `4.63.6`, a name moved between groups with a
    registry spec), which is the same package from the same registry; and
    `new-or-nonregistry` for a new name, a newly bundled name, or a change
    whose old or new spec is anything else (`_registry_spec`): a URL, an
    `npm:` alias, git, a github shorthand, `file:`, `link:`, a tarball path,
    `workspace:`.
    """
    mine, theirs = _dependency_groups(current), _dependency_groups(base)
    known = {name for group in ("dependencies", "peerDependencies") for name in theirs[group]}
    new = sorted({name for group in ("dependencies", "peerDependencies") for name in mine[group]} - known)
    changed, other = [], False
    for group, specs in mine.items():
        for name, spec in specs.items():
            before = theirs[group].get(name, theirs["dependencies"].get(name, theirs["peerDependencies"].get(name)))
            if name in theirs[group] and theirs[group][name] == spec:
                continue
            changed.append(f"{group}:{name}")
            if name in new or group == "bundleDependencies" or not (
                    _registry_spec(spec) and _registry_spec(before)):
                other = True
    kind = "new-or-nonregistry" if other or new else "registry-bumps" if changed else "none"
    return new, sorted(changed), kind


def _release_continuity(versions: dict, version: str, baseline) -> dict:
    """What changed between a fresh npm release and its settled baseline.

    Every fact comes from the packument already in hand. With no baseline the
    comparison fields are null: there is nothing to compare with.
    """
    current = versions.get(version) if isinstance(versions.get(version), dict) else {}
    base = versions.get(baseline) if baseline is not None else None
    if not isinstance(base, dict):
        return {"baseline": None, "attested": _attested(current), "baseline_attested": None,
                "same_publisher": None, "same_trusted_publisher": None, "same_repository": None,
                "new_install_scripts": None, "new_dependencies": None, "changed_dependencies": None,
                "dependency_changes_kind": None}
    mine = _publisher_identity(current)
    trusted = _trusted_publisher_record(current)
    repository = _repository_key(current)
    new, changed, kind = _dependency_changes(current, base)
    return {
        "baseline": baseline,
        "attested": _attested(current),
        "baseline_attested": _attested(base),
        "same_publisher": mine is not None and mine == _publisher_identity(base),
        "same_trusted_publisher": trusted is not None and trusted == _trusted_publisher_record(base),
        "same_repository": repository is not None and repository == _repository_key(base),
        "new_install_scripts": _changed_install_scripts(current, base),
        "new_dependencies": new,
        "changed_dependencies": changed,
        "dependency_changes_kind": kind,
    }


def continuity_holds(continuity) -> bool:
    """A fresh release that continues its settled baseline. Every one of:

    - both it and the baseline came through the same trusted-publishing
      configuration (`_trusted_publisher_record`); an account publish never
      qualifies, whoever the account is;
    - it carries a provenance attestation;
    - it declares the same repository as the baseline;
    - no dependency is new, newly bundled, or given a spec that is not a
      registry version, range or tag (`_dependency_changes`); a registry
      version bump of an existing dependency is allowed;
    - no install-time script is new or changed, and the native build was not
      switched on or off.

    Its age is then not held against it; the cool-down and the OSV re-check
    of an approved fresh version still apply. A record missing any of these
    fields (one written before they existed) never holds."""
    return (isinstance(continuity, dict) and continuity.get("baseline") is not None
            and continuity.get("attested") is True
            and continuity.get("same_publisher") is True
            and continuity.get("same_trusted_publisher") is True
            and continuity.get("same_repository") is True
            and continuity.get("new_install_scripts") == []
            and continuity.get("new_dependencies") == []
            and isinstance(continuity.get("changed_dependencies"), list)
            and continuity.get("dependency_changes_kind") in ("none", "registry-bumps"))


# What a review of a package whose full packument is over MAX_BODY_BYTES
# cannot know, said as a risk signal and as an unmet criterion.
HISTORY_TOO_LARGE = ("registry history too large to read: package age, version age and "
                     "release count unknown")


def _vet_npm(request, mandatory):
    """(version, evidence, provenance, risk, repository, continuity, history)
    for one npm request. `history` is False when the review could not read
    the package's release history (`_vet_npm_version_document`)."""
    encoded = urllib.parse.quote(request.display_name, safe="@")
    try:
        meta = _mandatory_json(f"{store_registry(request)}/{encoded}")
    except ResponseTooLarge:
        return _vet_npm_version_document(request, mandatory, encoded)
    mandatory["registry"]["ok"] = True
    if meta is None:
        mandatory["registry"]["exists"] = False
        raise HardDeny(f"package '{request.display_name}' does not exist on registry.npmjs.org")
    mandatory["registry"]["exists"] = True
    version = request.exact_version or (meta.get("dist-tags") or {}).get("latest")
    if not version:
        raise HardDeny(f"could not resolve a latest version for '{request.display_name}'")
    versions = meta.get("versions") or {}
    times = meta.get("time") or {}
    cooldown = None
    cooldown_unavailable = None
    if not request.exact_version and isinstance(versions.get(version), dict):
        dist = versions[version].get("dist")
        attested = isinstance(dist, dict) and isinstance(dist.get("attestations"), dict) \
            and bool(dist["attestations"])
        if not attested and _parse_iso(times.get(version)) is None:
            # An undated, unattested latest stands, and the report says the
            # cool-down could not judge it.
            cooldown_unavailable = f"the registry lists no publish time for {version}"
        candidates = {v: times.get(v) for v, m in versions.items()
                      if isinstance(m, dict) and not m.get("deprecated")}
        candidates[version] = times.get(version)
        version, cooldown = _cooled("npm", version, candidates, attested)
    version_meta = versions.get(version)
    if version_meta is None:
        raise HardDeny(f"version {version} of '{request.display_name}' does not exist on registry.npmjs.org")
    # A version under a week old, however it was chosen, is compared with the
    # newest release at least a week old.
    now = _utcnow()
    age = _age_days(times.get(version), now)
    settled, continuity = None, None
    if age is not None and age < FRESH_VERSION_DAYS and isinstance(version_meta, dict):
        candidates = {v: times.get(v) for v, m in versions.items()
                      if isinstance(m, dict) and not m.get("deprecated")}
        candidates[version] = times.get(version)
        settled = _settled_release("npm", version, candidates, now=now)
        continuity = _release_continuity(versions, version, settled)
    evidence, provenance, risk, repository = _npm_evidence(
        meta, version, version_meta, versions, times, cooldown, cooldown_unavailable, settled)
    return version, evidence, provenance, risk, repository, continuity, True


def _vet_npm_version_document(request, mandatory, encoded):
    """The review of a package whose full packument is over MAX_BODY_BYTES
    (@prisma/client's is 68.5 MB), from the one version's document.

    The version is the one named, or for an unpinned request the `latest`
    dist-tag. That document carries the publisher, the maintainers, the
    repository, scripts, dependencies, the license and the attestation, but
    no release history: package age, version age, release count, the settled
    release and the cool-down are unknown, and a risk signal says so. The
    caller never lets such a review be established.
    """
    registry = store_registry(request)
    version = request.exact_version
    cooldown_unavailable = None
    if not version:
        tags = _mandatory_json(f"{registry}/-/package/{encoded}/dist-tags")
        if not isinstance(tags, dict):
            raise ProviderError(f"{registry}/-/package/{encoded}/dist-tags: no dist-tags for a "
                                "package whose packument exists")
        version = tags.get("latest")
        if not isinstance(version, str) or not version:
            raise HardDeny(f"could not resolve a latest version for '{request.display_name}'")
        cooldown_unavailable = "the registry history is too large to read"
    url = f"{registry}/{encoded}/{urllib.parse.quote(version, safe='')}"
    version_meta = _mandatory_json(url)
    mandatory["registry"]["ok"] = True
    mandatory["registry"]["exists"] = True
    if version_meta is None:
        raise HardDeny(f"version {version} of '{request.display_name}' does not exist on registry.npmjs.org")
    if not isinstance(version_meta, dict) or version_meta.get("version") != version:
        raise ProviderError(f"{url}: the registry answered with another version's document")
    evidence, provenance, risk, repository = _npm_evidence(
        version_meta, version, version_meta, None, {}, None, cooldown_unavailable, None)
    risk.insert(0, HISTORY_TOO_LARGE)
    return version, evidence, provenance, risk, repository, None, False


def _npm_evidence(meta, version, version_meta, versions, times, cooldown, cooldown_unavailable,
                  settled):
    """(evidence, provenance, risk, repository) from one version's metadata.

    `meta` is the packument (or, without one, the version document itself),
    `versions` and `times` its history (None and {} when it could not be
    read)."""
    scripts = version_meta.get("scripts") or {}
    # Only what npm runs when it installs a registry tarball. `prepare` and
    # `prepack` run on pack, publish, a git install or a local install in the
    # package's own checkout; a git source is refused outright. Counting them
    # would send packages to the vetter and the human for code that never runs
    # here. A binding.gyp with no install script is the opposite: npm runs
    # `node-gyp rebuild`.
    lifecycle = [
        f"{key}: {value}"
        for key, value in scripts.items()
        if key in ("preinstall", "install", "postinstall")
    ]
    if version_meta.get("gypfile") and "install" not in scripts:
        lifecycle.append("install: node-gyp rebuild (implicit, binding.gyp)")
    # Everything below comes from the packument already in hand: no extra
    # request, so the review's call budget is untouched.
    dist = version_meta.get("dist") if isinstance(version_meta.get("dist"), dict) else {}
    attestations = dist.get("attestations")
    published = [times.get(v) for v in versions or () if _parse_iso(times.get(v))]
    license_display, license_class = _npm_license(version_meta)
    evidence = {
        "package_created_at": times.get("created"),
        "version_published_at": times.get(version),
        "last_published_at": max(published) if published else None,
        "repository_url": _repository_display(
            _repository_from(version_meta.get("repository") or meta.get("repository")), shorthand=True),
        "maintainers": [
            m.get("name") for m in (meta.get("maintainers") or []) if isinstance(m, dict) and m.get("name")
        ],
        "publisher": _text(version_meta.get("_npmUser")),
        "trusted_publisher": _trusted_publisher(version_meta),
        "install_scripts": lifecycle,
        "deprecated": _text(version_meta.get("deprecated")),
        "license": license_display,
        "license_class": license_class,
        "dependency_count": _count(version_meta.get("dependencies") or {}),
        "release_count": _count(versions),
        "integrity": _text(dist.get("integrity")),
        "distribution": None,
        "npm_weekly_downloads": None,
        "cooldown": cooldown,
        "cooldown_unavailable": cooldown_unavailable,
        "settled_release": settled,
    }
    provenance = {
        "attested": isinstance(attestations, dict) and bool(attestations),
        "url": _text((attestations or {}).get("url")) if isinstance(attestations, dict) else None,
    }
    risk = []
    if cooldown_unavailable:
        risk.append(_cooldown_unavailable_signal(cooldown_unavailable, version))
    if lifecycle:
        risk.append("package declares npm lifecycle/install scripts")
    repository = version_meta.get("repository") or meta.get("repository")
    return evidence, provenance, risk, repository


# ---------------------------------------------------------------------------
# The reputation tier (npm)
# ---------------------------------------------------------------------------

# First path segments on github.com that are pages, not an owner.
_GITHUB_NOT_OWNERS = frozenset({
    "sponsors", "orgs", "users", "settings", "marketplace", "topics", "features", "apps",
    "collections", "about", "pricing", "login", "search",
})
_NPM_SHORTHAND = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def _github_repo(url, shorthand: bool = False) -> tuple | None:
    """(owner, repo) for a repository on github.com, else None.

    Takes the shapes registries carry: `git+https://…/repo.git`,
    `git@github.com:owner/repo`, `ssh://`, a `#branch` or `?query` suffix, a
    deeper path such as `/issues` or `/tree/main/pkg`, and npm's
    `github:owner/repo`. With `shorthand`, npm's bare `owner/repo` too.
    """
    if not isinstance(url, str):
        return None
    text = url.strip().split("#", 1)[0].split("?", 1)[0]
    if text.startswith("github:"):
        text = "github.com/" + text[len("github:"):]
    elif shorthand and _NPM_SHORTHAND.fullmatch(text):
        text = "github.com/" + text
    for prefix in ("git+", "git://", "ssh://", "https://", "http://", "git@"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = text.replace("github.com:", "github.com/", 1)
    if text.startswith("www."):
        text = text[4:]
    if not text.startswith("github.com/"):
        return None
    parts = text[len("github.com/"):].split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not (owner and repo and _SAFE_SEGMENT.fullmatch(owner) and _SAFE_SEGMENT.fullmatch(repo)):
        return None
    if owner in (".", "..") or repo in (".", "..") or owner.lower() in _GITHUB_NOT_OWNERS:
        return None
    return owner, repo


def _repository_display(value, shorthand: bool = False) -> str | None:
    """The declared repository as the report records it: a GitHub repository
    as `https://github.com/owner/repo` whatever shape it was declared in, so
    the catalog comparison and the prompt read the same thing; any other
    value unchanged."""
    located = _github_repo(value, shorthand=shorthand)
    if located is not None:
        return f"https://github.com/{located[0]}/{located[1]}"
    return value if isinstance(value, str) and value else None


def _safe_directory(value) -> str | None:
    """A repository-relative directory that is safe to put in a raw URL."""
    if not isinstance(value, str):
        return None
    value = value.strip().removeprefix("./").strip("/")
    if value and _SAFE_PATH.fullmatch(value) and ".." not in value.split("/"):
        return value
    return None


def _workspace_path(root_manifest, name: str) -> str | None:
    """`<dir>/<name>/package.json` from the first `<dir>/*` workspaces pattern."""
    workspaces = root_manifest.get("workspaces") if isinstance(root_manifest, dict) else None
    if isinstance(workspaces, dict):
        workspaces = workspaces.get("packages")
    for pattern in workspaces if isinstance(workspaces, list) else []:
        if isinstance(pattern, str) and pattern.strip().endswith("/*"):
            parent = _safe_directory(pattern.strip()[:-2])
            if parent:
                return f"{parent}/{name.split('/')[-1]}/package.json"
    return None


def _manifest_names_package(name: str, repository) -> dict:
    """Does a package.json in the declared repository name this package?

    `{"url", "names_package"}`. True when a manifest names it. False only when
    a published manifest the review reached names a DIFFERENT package. None
    when no manifest for it could be read: no GitHub repository, nothing at
    the paths tried, or a failed fetch. A `private` manifest is a workspace
    root or an unpublished build package, so its name says nothing either way.

    At most two fetches. With a `repository.directory`, that manifest, then
    the root. Without one, the root, then the one place the root points to:
    its `workspaces` pattern, else `packages/<name>`; and when the repository
    has no root manifest at all, `npm/<name>`, the layout of packages that
    publish per-platform builds from one repository.
    """
    located = _github_repo(_repository_from(repository), shorthand=True)
    if located is None:
        return {"url": None, "names_package": None}
    owner, repo = located
    base = name.split("/")[-1]
    directory = _safe_directory(repository.get("directory") if isinstance(repository, dict) else None)
    path = f"{directory}/package.json" if directory else "package.json"
    tried, url, other = [], None, None
    while path and path not in tried and len(tried) < 2:
        url = f"{GITHUB_RAW_URL}/{owner}/{repo}/HEAD/{path}"
        try:
            manifest = _request_json(url)
        except ProviderError:
            return {"url": url, "names_package": None}
        tried.append(path)
        if isinstance(manifest, dict) and manifest.get("name") == name:
            return {"url": url, "names_package": True}
        if (isinstance(manifest, dict) and isinstance(manifest.get("name"), str)
                and manifest.get("private") is not True and other is None):
            other = url
        if directory:
            path = "package.json"
        elif manifest is None:
            path = f"npm/{name}/package.json"
        else:
            path = _workspace_path(manifest, name) or f"packages/{base}/package.json"
    if other is not None:
        return {"url": other, "names_package": False}
    return {"url": url, "names_package": None}


def _edit_distance_le_one(a: str, b: str) -> bool:
    """One insertion, deletion, substitution or adjacent transposition apart."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diffs = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(diffs) == 1:
            return True
        return (len(diffs) == 2 and diffs[1] == diffs[0] + 1
                and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]])
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    index = 0
    while index < len(short) and short[index] == long_[index]:
        index += 1
    return short[index:] == long_[index + 1:]


def _one_edit_apart(a: str, b: str) -> bool:
    """The vetter's D2 shapes: one edit, a separator swap, or a dropped scope."""
    if a == b:
        return False
    if a.split("/")[-1] == b.split("/")[-1] and a.startswith("@") != b.startswith("@"):
        return True
    if re.sub(r"[-_.]", "-", a) == re.sub(r"[-_.]", "-", b):
        return True
    return _edit_distance_le_one(a, b)


def _weekly_downloads(name: str) -> int | None:
    data = _request_json(NPM_DOWNLOADS_URL + urllib.parse.quote(name, safe="@/"))
    if not isinstance(data, dict):
        return None
    value = data.get("downloads")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


_MUTATION_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_."


def _mutations(name: str, wide: bool = False) -> list:
    """The unscoped one-edit shapes a lookalike is usually built from.

    Deletions, adjacent transpositions, separator swaps and the dropped
    scope: the shapes an attacker registers, enumerated rather than searched
    for, because the registry search ranks by relevance and can leave out
    `express` when asked about `expresss`. With `wide`,
    insertions and substitutions too -- affordable when the check is a local
    dictionary lookup (PyPI's top list), too many for npm's bulk endpoint,
    where the search results cover those shapes.
    """
    base = name.split("/")[-1] if name.startswith("@") else name
    out = set()
    if name.startswith("@"):
        out.add(base)
    for i in range(len(base)):
        out.add(base[:i] + base[i + 1:])
        if i + 1 < len(base) and base[i] != base[i + 1]:
            out.add(base[:i] + base[i + 1] + base[i] + base[i + 2:])
    for sep, other in (("-", "_"), ("_", "-"), ("-", "."), (".", "-")):
        if sep in base:
            out.add(base.replace(sep, other))
    if wide:
        for i in range(len(base) + 1):
            for char in _MUTATION_ALPHABET:
                out.add(base[:i] + char + base[i:])
                if i < len(base) and base[i] != char:
                    out.add(base[:i] + char + base[i + 1:])
    out.discard(name)
    out.discard(base) if not name.startswith("@") else None
    return sorted(m for m in out if _NPM_UNSCOPED.fullmatch(m))


def _near_names(name: str, own_downloads) -> tuple:
    """Neighbours one edit from `name` on the registry, with their downloads.

    Returns (near_names, lookalike_of). One search call, then one bulk
    downloads call for the unscoped neighbours it returned plus the enumerated
    `_mutations` (the bulk endpoint takes no scoped names, and answers with
    an error entry for a name that does not exist). Raises ProviderError when
    either call fails.
    """
    query = urllib.parse.urlencode({"text": name, "size": NEAR_NAME_SEARCH_SIZE})
    found = _request_json(f"{NPM_SEARCH_URL}?{query}")
    # A missing or malformed answer is "could not check", never "no
    # neighbours" -- the latter silently drops the lookalike criterion.
    if not isinstance(found, dict) or not isinstance(found.get("objects"), list):
        raise ProviderError("npm search returned a malformed response")
    neighbours = []
    for entry in found["objects"]:
        candidate = ((entry or {}).get("package") or {}).get("name") if isinstance(entry, dict) else None
        if isinstance(candidate, str) and candidate not in neighbours and _one_edit_apart(name, candidate):
            neighbours.append(candidate)
    for candidate in _mutations(name):
        if candidate not in neighbours:
            neighbours.append(candidate)
    counts = {}
    unscoped = [n for n in neighbours if _NPM_UNSCOPED.fullmatch(n)][:NEAR_NAME_BULK_LIMIT]
    if unscoped:
        bulk = _request_json(NPM_DOWNLOADS_URL + ",".join(unscoped))
        if isinstance(bulk, dict) and "downloads" in bulk and "package" in bulk:
            bulk = {bulk["package"]: bulk}
        if bulk is None and len(unscoped) == 1:
            bulk = {}  # one name that does not exist: a 404 is the honest answer
        if not isinstance(bulk, dict) or not all(
                isinstance(k, str) and k in unscoped and (v is None or isinstance(v, dict))
                for k, v in bulk.items()):
            raise ProviderError("npm bulk downloads returned a malformed response")
        for candidate, value in bulk.items():
            if value is None or (isinstance(value, dict) and "error" in value and "downloads" not in value):
                continue  # a name that does not exist: null today, an error entry earlier
            downloads = value.get("downloads")
            if not isinstance(downloads, int) or isinstance(downloads, bool):
                raise ProviderError("npm bulk downloads returned a malformed count")
            counts[candidate] = downloads
    # Report what exists: a counted neighbour, or a scoped one the search
    # returned (the bulk endpoint cannot count those).
    near = [
        {"name": n, "weekly_downloads": counts.get(n)}
        for n in neighbours if n in counts or not _NPM_UNSCOPED.fullmatch(n)
    ]
    return near, _lookalike(near, own_downloads)


def _lookalike(near: list, own_downloads) -> str | None:
    """The neighbour with LOOKALIKE_DOWNLOAD_RATIO times this package's downloads, if any.

    No own count means no ratio: the neighbours are still reported, but a
    giant cannot be named against an unknown -- with a floor of 100 every
    neighbour of a package like `requests` would look like one. The missing
    count is already an unmet criterion of its own.
    """
    if not isinstance(own_downloads, int) or isinstance(own_downloads, bool):
        return None
    floor = LOOKALIKE_DOWNLOAD_RATIO * max(own_downloads, 1)
    giants = [n for n in near if n["weekly_downloads"] is not None and n["weekly_downloads"] >= floor]
    return max(giants, key=lambda n: n["weekly_downloads"])["name"] if giants else None


# Exceptions a provider answer of the wrong shape raises inside the parsers
# (a list where a dict belongs, an int where a string does, absurd nesting).
_SHAPE_ERRORS = (AttributeError, TypeError, KeyError, IndexError, ValueError, RecursionError)


def _empty_reputation() -> dict:
    return {
        "tier": "unresolved",
        "weekly_downloads": None,
        "manifest": {"url": None, "names_package": None},
        "near_names": [],
        "lookalike_of": None,
        "unmet": [],
        "checked_at": store.utcnow(),
    }


def _shared_unmet(evidence: dict, osv_ids: list, continuity=None) -> list:
    """The criteria both ecosystems read from the report already in hand.

    A version under FRESH_VERSION_DAYS old is a criterion unless `continuity`
    holds (`continuity_holds`): an attested npm release through the same
    trusted-publishing configuration as its settled baseline, from the same
    repository, with no new dependency, no dependency spec that left the
    registry, and no install script new or changed. The license is not a
    criterion; the report shows it as a class instead.
    """
    unmet = []
    package_age = evidence.get("package_age_days")
    if package_age is None or package_age < ESTABLISHED_MIN_AGE_DAYS:
        unmet.append(f"package age {package_age if package_age is not None else 'unknown'} day(s), "
                     f"under {ESTABLISHED_MIN_AGE_DAYS}")
    releases = evidence.get("release_count")
    if releases is None or releases < ESTABLISHED_MIN_RELEASES:
        unmet.append(f"{releases if releases is not None else 'unknown'} release(s), "
                     f"under {ESTABLISHED_MIN_RELEASES}")
    version_age = evidence.get("version_age_days")
    if (version_age is None or version_age < FRESH_VERSION_DAYS) and not (
            version_age is not None and continuity_holds(continuity)):
        unmet.append(f"version age {version_age if version_age is not None else 'unknown'} day(s), "
                     f"under {FRESH_VERSION_DAYS}")
    if evidence.get("deprecated"):
        unmet.append("deprecated on the registry")
    if osv_ids:
        unmet.append(f"{len(osv_ids)} OSV record(s) for this version")
    return unmet


def _downloads_floor(result: dict, unmet: list, downloads, source: str) -> None:
    result["weekly_downloads"] = downloads
    if downloads is None:
        if not unmet:
            unmet.append(f"no weekly download count from {source}")
    elif downloads < ESTABLISHED_MIN_WEEKLY_DOWNLOADS:
        unmet.append(f"weekly downloads {downloads} under {ESTABLISHED_MIN_WEEKLY_DOWNLOADS}")


def _manifest_unmet(result: dict, unmet: list, manifest: dict) -> None:
    """Unknown is never a mismatch: only a manifest that names a different
    package says so; one that could not be read says that instead."""
    result["manifest"] = manifest
    if manifest["names_package"] is None:
        if manifest["url"] is None:
            unmet.append("repository manifest could not be read (no GitHub repository declared)")
        else:
            unmet.append("repository manifest could not be read (none found for this package, "
                         "or the fetch failed)")
    elif not manifest["names_package"]:
        unmet.append("repository manifest names a different package")


def _reputation_npm(name: str, evidence: dict, provenance, osv_ids: list, repository,
                    continuity=None, read_manifest: bool = True) -> dict:
    """The deterministic reputation block for one npm identity.

    `tier` is `established` only when every criterion below holds; otherwise
    `unresolved`, with `unmet` naming each failed or unavailable check. A
    provider failure here is never a hard finding -- it only leaves the tier
    unresolved, which sends the review to the vetter. Without `read_manifest`
    (a review whose registry history was too large to read, which already
    spent two extra registry calls and can never be established) the
    repository manifest is not fetched; the near-name check still runs.
    """
    result = _empty_reputation()
    unmet = result["unmet"]
    try:
        downloads = _weekly_downloads(name)
    except ProviderError as exc:
        downloads = None
        unmet.append(f"weekly downloads unavailable ({exc})")
    evidence["npm_weekly_downloads"] = downloads
    _downloads_floor(result, unmet, downloads, "the registry")
    if read_manifest:
        _manifest_unmet(result, unmet, _manifest_names_package(name, repository))
    try:
        near, lookalike = _near_names(name, downloads)
        result["near_names"], result["lookalike_of"] = near, lookalike
        if lookalike:
            unmet.append(
                f"one edit from '{lookalike}', which has at least "
                f"{LOOKALIKE_DOWNLOAD_RATIO}x its weekly downloads"
            )
    except ProviderError as exc:
        unmet.append(f"near-name check unavailable ({exc})")
    unmet.extend(_shared_unmet(evidence, osv_ids, continuity))
    if evidence.get("install_scripts"):
        unmet.append("declares install scripts")
    publisher = evidence.get("publisher")
    if not publisher:
        unmet.append("publisher not recorded")
    elif not _known_publisher(evidence, provenance):
        unmet.append(f"published by '{publisher}', not a listed maintainer, without provenance "
                     "or trusted publishing")
    if not unmet:
        result["tier"] = "established"
    return result


# --- PyPI ------------------------------------------------------------------

def _pypi_normalise(name: str) -> str:
    """PEP 503: case-folded, runs of `-`, `_` and `.` collapsed to one `-`."""
    return re.sub(r"[-_.]+", "-", name).lower()


_TOP_CACHE: dict = {}
_TOP_LOCK = threading.Lock()


def _reset_caches() -> None:
    """Tests only: forget the per-process top-list fetch."""
    with _TOP_LOCK:
        _TOP_CACHE.clear()


def _pypi_top_list() -> dict:
    """normalised name -> monthly downloads, from the top-15,000 list.

    Fetched once per process and shared by every review in the batch (the
    hook is one process per invocation, so this is one call per install). A
    failure is cached too, so a batch of twenty does not spend twenty
    timeouts on the same outage. Raises ProviderError on failure.
    """
    with _TOP_LOCK:
        if "rows" in _TOP_CACHE:
            return _TOP_CACHE["rows"]
        if "error" in _TOP_CACHE:
            raise ProviderError(_TOP_CACHE["error"])
        try:
            data = _request_json(PYPI_TOP_URL)
        except ProviderError as exc:
            _TOP_CACHE["error"] = str(exc)
            raise
        rows = {}
        for row in (data or {}).get("rows") or []:
            project = row.get("project") if isinstance(row, dict) else None
            count = row.get("download_count") if isinstance(row, dict) else None
            if isinstance(project, str) and isinstance(count, int) and not isinstance(count, bool):
                rows[_pypi_normalise(project)] = count
        if not rows:
            _TOP_CACHE["error"] = f"{PYPI_TOP_URL}: no rows"
            raise ProviderError(_TOP_CACHE["error"])
        _TOP_CACHE["rows"] = rows
        _TOP_CACHE["cutoff"] = min(rows.values())
        return rows


def _pypi_monthly(name: str) -> tuple:
    """(monthly downloads or None, the list's cut-off) for one PyPI name.

    None means the package is not in the top list, so its 30-day count is
    somewhere under the cut-off -- the bound the lookalike ratio then uses.
    Raises ProviderError when the list is unavailable.
    """
    top = _pypi_top_list()
    return top.get(_pypi_normalise(name)), _TOP_CACHE["cutoff"]


# setup.py is parsed, never run, and only up to this size.
_SETUP_PY_MAX_CHARS = 512 * 1024
_PROJECT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _pyproject_name(text) -> tuple:
    """(project name or None, is a uv workspace root) from pyproject.toml text."""
    if not isinstance(text, str):
        return None, False
    try:
        document = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return None, False
    project = document.get("project") if isinstance(document.get("project"), dict) else {}
    tool = document.get("tool") if isinstance(document.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
    declared = project.get("name") or poetry.get("name")
    named = declared.strip() if isinstance(declared, str) and declared.strip() else None
    return named, isinstance(uv.get("workspace"), dict)


def _setup_cfg_name(text) -> str | None:
    """`[metadata] name` from setup.cfg text, when it is a plain name."""
    if not isinstance(text, str):
        return None
    config = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        config.read_string(text)
        value = config.get("metadata", "name", fallback=None)
    except (configparser.Error, ValueError):
        return None
    value = value.strip() if isinstance(value, str) else None
    return value if value and _PROJECT_NAME.fullmatch(value) else None


def _setup_py_name(text) -> str | None:
    """The `name=` of the `setup()` call in setup.py text, read and never run.

    A string literal, or a module-level constant the keyword names
    (`NAME = "PyYAML"` ... `setup(name=NAME)`). Anything computed is None.
    """
    if not isinstance(text, str) or len(text) > _SETUP_PY_MAX_CHARS:
        return None
    try:
        tree = ast.parse(text)
        constants = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = node.value.value
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not ((isinstance(func, ast.Name) and func.id == "setup")
                    or (isinstance(func, ast.Attribute) and func.attr == "setup")):
                continue
            for keyword in node.keywords:
                if keyword.arg != "name":
                    continue
                value = keyword.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    found = value.value
                elif isinstance(value, ast.Name):
                    found = constants.get(value.id)
                else:
                    found = None
                return found if found and _PROJECT_NAME.fullmatch(found) else None
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    return None


def _pyproject_names_package(name: str, repository) -> dict:
    """Does the declared repository's Python build configuration name this package?

    `{"url", "names_package"}`, both names PEP 503-normalised. At most three
    fetches, in order:
    - `pyproject.toml`, by `[project].name` or `[tool.poetry].name`; when it
      names another project, `<name>/pyproject.toml` for a repository that
      holds several;
    - when it names none (a setuptools build, or no file), `setup.cfg`
      `[metadata] name`, then the `setup()` call of `setup.py`.

    False only when pyproject.toml or setup.cfg names a different project. A
    uv workspace root names the workspace, not a package, and a setup.py name
    is read without running the file, so neither can contradict: both leave
    the answer unknown. None when nothing that names a project could be read.
    """
    located = _github_repo(_repository_from(repository))
    if located is None:
        return {"url": None, "names_package": None}
    owner, repo = located
    wanted = _pypi_normalise(name)
    last = {"url": None}

    def fetch(path):
        last["url"] = f"{GITHUB_RAW_URL}/{owner}/{repo}/HEAD/{path}"
        return last["url"], _request_json(last["url"])

    try:
        url, text = fetch("pyproject.toml")
        declared, workspace = _pyproject_name(text)
        if declared is not None:
            if _pypi_normalise(declared) == wanted:
                return {"url": url, "names_package": True}
            nested_url, nested = fetch(f"{name}/pyproject.toml")
            nested_name, _ = _pyproject_name(nested)
            if nested_name is not None and _pypi_normalise(nested_name) == wanted:
                return {"url": nested_url, "names_package": True}
            return {"url": url, "names_package": None if workspace else False}
        url, text = fetch("setup.cfg")
        declared = _setup_cfg_name(text)
        if declared is not None:
            return {"url": url, "names_package": _pypi_normalise(declared) == wanted}
        url, text = fetch("setup.py")
        declared = _setup_py_name(text)
        if declared is not None and _pypi_normalise(declared) == wanted:
            return {"url": url, "names_package": True}
        return {"url": url, "names_package": None}
    except ProviderError:
        return {"url": last["url"], "names_package": None}


def _pypi_near_names(name: str, own_monthly) -> tuple:
    """Neighbours one edit from `name` among the top packages, with monthly downloads.

    No search endpoint and no bulk downloads on PyPI, so the enumerated
    shapes are matched against the cached top list: a giant a lookalike
    rides on is in that list by definition. Raises ProviderError when the
    list is unavailable.
    """
    top = _pypi_top_list()
    wanted = _pypi_normalise(name)
    near = []
    for candidate in _mutations(wanted, wide=True):
        key = _pypi_normalise(candidate)
        if key != wanted and key in top and not any(n["name"] == key for n in near):
            near.append({"name": key, "weekly_downloads": top[key]})
    return near, _lookalike(near, own_monthly)


def _reputation_pypi(name: str, evidence: dict, osv_ids: list, repository, yanked: bool) -> dict:
    """The reputation block for one PyPI identity.

    PyPI records no publisher and no lifecycle scripts, so those two npm
    criteria become: a wheel exists (no setup.py runs on install) and the
    version is not yanked. Downloads are the top list's 30-day count;
    `weekly_downloads` is that count over four, and `near_names[]` carries
    the neighbours' MONTHLY counts, so the lookalike ratio compares month to
    month. A package outside the list has an unknown count under the list's
    cut-off, which is the bound the ratio uses for it.
    """
    result = _empty_reputation()
    unmet = result["unmet"]
    monthly, bound = None, None
    try:
        monthly, cutoff = _pypi_monthly(name)
        bound = monthly if monthly is not None else cutoff
    except ProviderError as exc:
        unmet.append(f"weekly downloads unavailable ({exc})")
    if monthly is None and not unmet:
        unmet.append("not in the top-15,000 list (under its monthly cut-off)")
        result["weekly_downloads"] = None
    else:
        _downloads_floor(result, unmet, monthly // 4 if monthly is not None else None, "the top-15,000 list")
    _manifest_unmet(result, unmet, _pyproject_names_package(name, repository))
    try:
        near, lookalike = _pypi_near_names(name, bound)
        result["near_names"], result["lookalike_of"] = near, lookalike
        if lookalike:
            unmet.append(
                f"one edit from '{lookalike}', which has at least "
                f"{LOOKALIKE_DOWNLOAD_RATIO}x its monthly downloads"
            )
    except ProviderError as exc:
        unmet.append(f"near-name check unavailable ({exc})")
    unmet.extend(_shared_unmet(evidence, osv_ids))
    if evidence.get("distribution") != "wheel":
        unmet.append("no wheel for this version (setup.py may run on install)")
    if yanked:
        unmet.append("version is yanked")
    if not unmet:
        result["tier"] = "established"
    return result


def is_established(report: dict) -> bool:
    """True when the report (or a refreshed view of it) carries an established tier."""
    reputation = (report.get("optional_checks") or {}).get("reputation")
    return isinstance(reputation, dict) and reputation.get("tier") == "established"


def _apply_trust(reputation: dict, trust: dict, evidence: dict, risk_signals: list) -> None:
    """What a catalog result does to a tier it did not compute.

    `identity_mismatch` is the one status that suppresses the tier: the
    catalog pins a repository and the registry declares another, which is the
    takeover shape and belongs on the prompt as a risk signal rather than as
    one unmet criterion among five. `expired` and `unavailable` are faults in
    the *catalog*, not claims about the package: they withdraw the shortcut
    and leave the tier the package's own evidence earned. Suppressing it there
    would disable the deterministic tier -- which needs no catalog -- on every
    installed copy the day the bundled seed expires.

    Both repositories reach the human through `repository_id`, so what the
    prompt renders is a validated `https://github.com/owner/repo` and never
    the registry's free text.
    """
    reputation["trust"] = trust
    if trust["status"] != "identity_mismatch":
        return
    reputation["tier"] = "unresolved"
    reputation["unmet"].append(trust["reason"])
    declared = trusted_catalog.repository_id(evidence.get("repository_url"))
    risk_signals.append(
        f"the user trust catalog pins {trust['repository']} for this package and the registry "
        f"declares {declared or 'no usable repository'}"
    )


def _catalog_reputation(trust: dict, request, evidence: dict, provenance, ids: list,
                        pypi_extra, continuity=None) -> dict:
    """Trusted identity replaces popularity research, never release checks."""
    result = _empty_reputation()
    result["trust"] = trust
    unmet = result["unmet"]
    unmet.extend(_shared_unmet(evidence, ids, continuity))
    if request.ecosystem == "npm":
        if evidence.get("install_scripts"):
            unmet.append("declares install scripts")
        if not evidence.get("publisher"):
            unmet.append("publisher not recorded")
        elif not _known_publisher(evidence, provenance):
            unmet.append("publisher is not a listed maintainer and has no provenance "
                         "or trusted publishing")
    else:
        if evidence.get("distribution") != "wheel":
            unmet.append("no wheel for this version (setup.py may run on install)")
        if pypi_extra["yanked"]:
            unmet.append("version is yanked")
    if not unmet:
        result["tier"] = "established"
    return result


# project_urls labels that name the source repository, compared after
# lower-casing and dropping everything but letters and digits, in the order
# they are preferred.
_SOURCE_LABELS = ("source", "sourcecode", "sourcerepository", "repository", "repo", "code", "git",
                  "github", "githubrepository")
_HOME_LABELS = ("homepage", "home")


def _pypi_repository(info: dict) -> str | None:
    """The source repository a PyPI project declares, as the report records it.

    project_urls labels are free text (`Source`, `source`, `Source code`,
    `Code`, `GitHub`, `Repository`...), so they are matched case-insensitively.
    Order:
    1. a source label, whatever its host, by the order of `_SOURCE_LABELS`
       and then as listed. A repository the project says moved off GitHub is
       what the catalog and the manifest check read, never a GitHub link
       left elsewhere on the page;
    2. with no source label, a home page (label or `home_page`) naming a
       GitHub repository;
    3. any other project URL on a GitHub repository (`…/issues`,
       `…/blob/main/CHANGES`), cut to the repository;
    4. the first home page, as given.
    """
    urls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
    labelled = [(re.sub(r"[^a-z0-9]", "", str(k).lower()), v) for k, v in urls.items()
                if isinstance(v, str) and v.strip()]
    sources = [v for k, v in sorted(((k, v) for k, v in labelled if k in _SOURCE_LABELS),
                                    key=lambda item: _SOURCE_LABELS.index(item[0]))]
    if sources:
        return _repository_display(sources[0]) if _github_repo(sources[0]) else sources[0].strip()
    homes = [v for k, v in labelled if k in _HOME_LABELS]
    home_page = _text(info.get("home_page"))
    if home_page:
        homes.append(home_page)
    for value in homes + [v for _k, v in labelled]:
        if _github_repo(value) is not None:
            return _repository_display(value)
    return homes[0].strip() if homes else None


def _requirement_count(requires_dist) -> int:
    """Requirements an install of the package itself pulls: lines guarded by
    an `extra == ...` marker belong to an optional extra and are not counted."""
    if not isinstance(requires_dist, list):
        return 0
    return sum(1 for line in requires_dist
               if isinstance(line, str) and not re.search(r"\bextra\s*==", line.partition(";")[2]))


def _pypi_candidates(releases: dict) -> dict:
    """A release is dated by its newest live file; a fully yanked
    release is never a candidate. PyPI provenance is not fetched here, so no
    release counts as attested."""
    candidates = {}
    for candidate, files in releases.items():
        live = [f.get("upload_time_iso_8601") for f in files or []
                if isinstance(f, dict) and not f.get("yanked")
                and _parse_iso(f.get("upload_time_iso_8601"))]
        if live:
            candidates[candidate] = max(live)
    return candidates


# ---------------------------------------------------------------------------
# The exact pin a build requirement denial suggests
# ---------------------------------------------------------------------------

# Advice only. The gate never trusts a range (it reviews the exact pin the
# project then declares, and the installer installs exactly that), so a
# suggestion that differed from what a resolver would pick can only cost a
# second look, never install an unreviewed version. Anything this cannot read
# exactly (markers, URLs, pre-release or epoch versions, `===`) gets no
# suggestion.
_BUILD_REQUIREMENT = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?P<extras>\[[A-Za-z0-9._,\s-]*\])?"
    r"\s*\(?(?P<specs>[^;@()]*?)\)?\s*$")
_SPECIFIER = re.compile(r"^\s*(?P<op>~=|==|!=|<=|>=|<|>)\s*(?P<version>\d+(?:\.\d+)*(?:\.\*|\.post\d+)?)\s*$")


def _release_parts(version: str) -> tuple:
    return tuple(int(part) for part in version.partition(".post")[0].split("."))


def _specifier_allows(version: str, op: str, bound: str) -> bool:
    """A final release against one PEP 440 specifier."""
    key, bound_key = _stable_key("pypi", version), None
    if bound.endswith(".*"):
        prefix = _release_parts(bound[:-2])
        parts = _release_parts(version)
        parts += (0,) * max(0, len(prefix) - len(parts))
        matches = parts[:len(prefix)] == prefix
        return matches if op == "==" else not matches if op == "!=" else False
    bound_key = _stable_key("pypi", bound)
    if key is None or bound_key is None:
        return False
    if op == "~=":
        prefix = _release_parts(bound)[:-1]
        return len(_release_parts(bound)) >= 2 and key >= bound_key and \
            _specifier_allows(version, "==", ".".join(map(str, prefix)) + ".*")
    if op == ">":
        # A post-release of the bound itself is not "greater" (PEP 440).
        if key[0] == bound_key[0] and bound_key[1] < 0 <= key[1]:
            return False
        return key > bound_key
    return {"==": key == bound_key, "!=": key != bound_key, ">=": key >= bound_key,
            "<=": key <= bound_key, "<": key < bound_key}[op]


def suggest_build_pin(requirement: str, registry: str = "https://pypi.org"):
    """(name with extras, version) the denial of an unpinned build requirement
    names, or None.

    The newest final release the requirement's range admits, then the
    cool-down of an unpinned request (`_cooled`): a release under
    FRESH_VERSION_DAYS old gives way to the newest settled one in the range.
    One PyPI call, never retried; any failure is None and the denial says to
    pin by hand.
    """
    if not isinstance(requirement, str):
        return None
    match = _BUILD_REQUIREMENT.match(requirement)
    if not match:
        return None
    specifiers = []
    for part in [p for p in match.group("specs").split(",") if p.strip()]:
        found = _SPECIFIER.match(part)
        if not found or (found.group("version").endswith(".*") and found.group("op") not in ("==", "!=")):
            return None
        specifiers.append((found.group("op"), found.group("version")))
    name = match.group("name")
    try:
        meta = _request_json(f"{registry}/pypi/{_pypi_normalise(name)}/json")
        releases = meta.get("releases") if isinstance(meta, dict) else None
        if not isinstance(releases, dict):
            return None
        candidates = {version: stamp for version, stamp in _pypi_candidates(releases).items()
                      if _stable_key("pypi", version) is not None
                      and all(_specifier_allows(version, op, bound) for op, bound in specifiers)}
    except (ProviderError, *_SHAPE_ERRORS):
        return None
    if not candidates:
        return None
    latest = max(candidates, key=lambda version: _stable_key("pypi", version))
    pick, _record = _cooled("pypi", latest, candidates, False)
    return name + re.sub(r"\s+", "", match.group("extras") or ""), pick


def _vet_pypi(request, mandatory, python=None, source=None, assume=None):
    """The PyPI review. `python` and `source` are the interpreter the wheels
    are judged against and where it came from (`PYTHON_SOURCES`). When it is
    unknown and the release has only interpreter-specific wheels, `assume`
    (if given) is asked for ((major, minor), source) of the interpreter the
    installer most likely runs."""
    meta = _mandatory_json(f"{request.registry}/pypi/{request.name}/json")
    mandatory["registry"]["ok"] = True
    if meta is None:
        mandatory["registry"]["exists"] = False
        raise HardDeny(f"package '{request.display_name}' does not exist on pypi.org")
    mandatory["registry"]["exists"] = True
    version = request.exact_version or (meta.get("info") or {}).get("version")
    if not version:
        raise HardDeny(f"could not resolve a latest version for '{request.display_name}'")
    cooldown = None
    cooldown_unavailable = None
    if not request.exact_version:
        # The cool-down needs the release history. Without it the latest
        # stands, but the report says so instead of
        # reading like a release that had nothing to cool.
        if not isinstance(meta.get("releases"), dict):
            cooldown_unavailable = "PyPI returned no release history"
        else:
            candidates = _pypi_candidates(meta["releases"])
            if version in candidates:
                version, cooldown = _cooled("pypi", version, candidates, False)
            else:
                cooldown_unavailable = f"PyPI lists no upload time for {version}"
    settled = None
    if request.exact_version and isinstance(meta.get("releases"), dict):
        candidates = _pypi_candidates(meta["releases"])
        if version in candidates:
            pick, record = _cooled("pypi", version, candidates, False)
            settled = pick if record else None
    version_meta = _mandatory_json(f"{request.registry}/pypi/{request.name}/{version}/json")
    if version_meta is None:
        raise HardDeny(f"version {version} of '{request.display_name}' does not exist on pypi.org")
    info = version_meta.get("info") or {}
    urls = [u for u in (version_meta.get("urls") or []) if isinstance(u, dict)]
    # The NEWEST file dates the release. A wheel uploaded yesterday to a
    # two-year-old version is a new artifact and must read as fresh.
    file_times = [u.get("upload_time_iso_8601") for u in urls if _parse_iso(u.get("upload_time_iso_8601"))]
    uploaded = max(file_times) if file_times else None
    repository = _pypi_repository(info)
    # The project document lists every release with its files, so
    # first-upload and release count come for free; the version document's
    # `urls` say whether a wheel exists (an sdist runs setup.py on install).
    releases = meta.get("releases") if isinstance(meta.get("releases"), dict) else {}
    uploads = [
        f.get("upload_time_iso_8601")
        for files in releases.values() if isinstance(files, list)
        for f in files if isinstance(f, dict) and _parse_iso(f.get("upload_time_iso_8601"))
    ]
    live = [u for u in urls if not u.get("yanked")]
    kinds = {u.get("packagetype") for u in live}
    wheels = [u.get("filename") for u in live if u.get("packagetype") == "bdist_wheel"]
    if python is None and assume is not None and wheels \
            and not any(wheel_compatible(name) for name in wheels):
        # Only interpreter-specific wheels, and the project names no Python:
        # judge them against the interpreter the installer here most likely runs.
        python, source = assume()
    source = source if python is not None else None
    if any(wheel_compatible(name, python=python) for name in wheels):
        distribution = "wheel"
    elif "sdist" in kinds and "bdist_wheel" in kinds:
        # Wheels exist, none for this machine -- pip builds the sdist.
        distribution = "sdist-build"
    elif "sdist" in kinds:
        distribution = "sdist-only"
    else:
        distribution = None
    artifacts = sorted({u["digests"]["sha256"] for u in live
                        if isinstance(u.get("digests"), dict)
                        and isinstance(u["digests"].get("sha256"), str)})
    classifiers = [c for c in (info.get("classifiers") or []) if isinstance(c, str)]
    license_display, license_class = _pypi_license(info)
    evidence = {
        "package_created_at": min(uploads) if uploads else None,
        "version_published_at": uploaded,
        "last_published_at": max(uploads) if uploads else None,
        "repository_url": repository,
        "maintainers": [a for a in [info.get("author"), info.get("maintainer")] if a],
        "publisher": None,
        "install_scripts": [],
        "deprecated": _PYPI_INACTIVE if _PYPI_INACTIVE in classifiers else None,
        "license": license_display,
        "license_class": license_class,
        "dependency_count": _requirement_count(info.get("requires_dist")),
        "release_count": _count(releases) if releases else None,
        "integrity": None,
        "distribution": distribution,
        "requires_python": info.get("requires_python"),
        "artifacts": artifacts,
        "cooldown": cooldown,
        "cooldown_unavailable": cooldown_unavailable,
        "settled_release": settled,
        "target_python": f"{python[0]}.{python[1]}" if python else None,
        "target_python_source": source,
    }
    risk = []
    if info.get("yanked"):
        risk.append(f"version {version} is yanked on PyPI: {info.get('yanked_reason') or 'no reason given'}")
    for vuln in version_meta.get("vulnerabilities") or []:
        if isinstance(vuln, dict) and vuln.get("id"):
            risk.append(f"PyPI-reported vulnerability: {vuln['id']}")
    if cooldown_unavailable:
        risk.append(_cooldown_unavailable_signal(cooldown_unavailable, version))
    if distribution == "sdist-only":
        risk.append("sdist only: setup.py may execute on install")
    elif distribution == "sdist-build" and python is None:
        risk.append("no wheel for this platform known to match this project's Python (unknown); "
                    "a source build may run")
    elif distribution == "sdist-build":
        target = f"Python {python[0]}.{python[1]}"
        if source == "path-python3":
            target += " (python3 on PATH; the project names no Python)"
        elif source == "uv-python-find":
            target += " (the interpreter uv finds; the project names no Python)"
        risk.append(f"no wheel for this platform and {target}: pip builds the sdist, "
                    "so setup.py may execute on install")
    if distribution in ("sdist-only", "sdist-build"):
        # The build fetches whatever backend the sdist's own
        # pyproject.toml names, unpinned, and runs it. PyPI's JSON does not
        # carry it and the review never downloads package code, so it is
        # named as unreviewed rather than guessed.
        risk.append("the sdist's build backend (named inside the sdist, which the review does not "
                    "download) is fetched from PyPI and run at install time, unreviewed")
    # PyPI attestations live behind a separate integrity endpoint the review
    # does not call, so provenance is unknown here rather than absent.
    return version, evidence, None, risk, {"repository": repository, "yanked": bool(info.get("yanked"))}


def is_fresh_version(report: dict, now: datetime | None = None) -> bool:
    """The version this report reviewed is under FRESH_VERSION_DAYS old.

    False when the report carries no publish date -- the re-check
    is a backstop for the window in which a malicious version is usually
    pulled, and an undated report is not evidence of freshness.
    """
    age = _age_days((report.get("evidence") or {}).get("version_published_at"), now or _utcnow())
    return age is not None and age < FRESH_VERSION_DAYS


def recheck_malware(identity: dict):
    """The OSV query alone, for an already-approved identity.

    Returns the list of MAL-* ids (empty when clean). Raises ProviderError on
    failure, which the caller turns into a denial.
    """
    ids, _details = _query_osv(identity["ecosystem"], identity["name"], identity["version"])
    return [i for i in ids if i.startswith("MAL-")]


_WHEEL = re.compile(r"^(?P<name>.+?)-(?P<ver>[^-]+)(?:-\d[^-]*)?-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^-]+)\.whl$")


def _version_pair(text) -> tuple | None:
    match = re.match(r"\s*(\d+)\.(\d+)", text or "")
    return (int(match.group(1)), int(match.group(2))) if match else None


def _platform_tags() -> tuple:
    """(os family, arch, os version) of this machine, as wheel tags spell them.

    The version is macOS's (major, minor) or glibc's on Linux, the floor a
    `macosx_X_Y` or `manylinux_X_Y` tag sets; None when it cannot be read.
    """
    import os
    import platform
    machine = platform.machine().lower()
    arch = {"amd64": "x86_64", "aarch64": "arm64" if sys.platform == "darwin" else "aarch64"}.get(machine, machine)
    family = "macosx" if sys.platform == "darwin" else "win" if sys.platform.startswith("win") else "linux"
    version = None
    if family == "macosx":
        version = _version_pair(platform.mac_ver()[0])
    elif family == "linux":
        try:
            libc = os.confstr("CS_GNU_LIBC_VERSION") or ""  # "glibc 2.35"; absent on musl
        except (AttributeError, ValueError, OSError):
            libc = ""
        if libc.startswith("glibc "):
            version = _version_pair(libc[6:])
    return family, arch, version


_PROJECT_MARKERS = ("pyproject.toml", ".python-version", ".venv")


def _project_dir(directory, stop=None) -> Path:
    """The Python project a command in `directory` acts on: the nearest
    directory at or above it holding a pyproject.toml, a .python-version or
    a .venv, as uv finds it, climbing no higher than `stop` (the guarded
    project). With no `stop`, or a `directory` outside it, only `directory`
    itself is read: a user-wide pin above the project is not the project's.
    `directory` itself when nothing is found."""
    start = Path(directory)
    limit = Path(stop) if stop is not None else start
    try:
        start.relative_to(limit)
    except ValueError:
        limit = start
    current = start
    while True:
        try:
            if any((current / marker).exists() for marker in _PROJECT_MARKERS):
                return current
        except OSError:
            return start
        if current == limit or current.parent == current:
            return start
        current = current.parent


def _venv_python(environment) -> tuple | None:
    """(major, minor) from an environment's pyvenv.cfg; None when it cannot be
    read or is not CPython."""
    try:
        cfg = (Path(environment) / "pyvenv.cfg").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    fields = {}
    for line in cfg.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip().lower()] = value.strip()
    if fields.get("implementation", "cpython").lower() != "cpython":
        return None
    return _version_pair(fields.get("version_info") or fields.get("version"))


# Where `evidence.target_python` came from. The first five are the project
# naming its Python; the last two are an interpreter the review assumed the
# installer runs, because the project names none.
PYTHON_SOURCES = ("command-environment", "project-venv", "recorded-environment", "python-version",
                  "requires-python", "uv-python-find", "path-python3")
ASSUMED_PYTHON_SOURCES = ("uv-python-find", "path-python3")


def project_interpreter(root, stop=None, environments=()) -> tuple:
    """((major, minor), source) of the CPython the project installs into, or
    (None, None).

    `root` is the directory the command runs in (the guarded project when no
    command names one); the project is found from there (`_project_dir`), so
    an app in a subdirectory is judged by its own interpreter. The hook runs
    under its own `uv run --no-project` interpreter, so its
    `sys.version_info` says nothing about the project.
    Read in order: the `pyvenv.cfg` of an environment the command names
    (`environments`: a literal UV_PROJECT_ENVIRONMENT, or VIRTUAL_ENV with
    `--active`), the project's `.venv/pyvenv.cfg`, the `pyvenv.cfg` of an
    environment outside the tree that an earlier command in this directory
    installed into (recorded under `stop`, the guarded project), uv's
    `.python-version` pin, then a `requires-python` that names exactly one
    minor (`==3.12.*`, `~=3.12.0`). A non-CPython environment falls through. A
    floor such as `>=3.11` names no single interpreter and reads as unknown.
    The source is one of the first five `PYTHON_SOURCES`.
    """
    if root is None:
        return None, None
    base = _project_dir(root, stop)
    recorded = []
    if stop is not None:
        try:
            recorded = store.recorded_environments(stop, root)
        except Exception:  # noqa: BLE001 - the record fails soft; the pin is still read
            recorded = []
    candidates = [(environment, "command-environment") for environment in environments]
    candidates.append((base / ".venv", "project-venv"))
    candidates += [(environment, "recorded-environment") for environment in recorded]
    for environment, source in candidates:
        found = _venv_python(environment)
        if found:
            return found, source
    try:
        pin = (base / ".python-version").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        pin = ""
    match = re.match(r"(?:cpython[-@])?(\d+)\.(\d+)(?:[.\-]|$)", pin.splitlines()[0] if pin else "")
    if match:
        return (int(match.group(1)), int(match.group(2))), "python-version"
    try:
        with (base / "pyproject.toml").open("rb") as handle:
            declared = (tomllib.load(handle).get("project") or {}).get("requires-python")
    except (OSError, tomllib.TOMLDecodeError, AttributeError):
        declared = None
    if isinstance(declared, str):
        match = re.fullmatch(r"\s*(?:==\s*(\d+)\.(\d+)(?:\.\*|\.\d+)?|~=\s*(\d+)\.(\d+)\.\d+)\s*", declared)
        if match:
            major, minor = match.group(1, 2) if match.group(1) else match.group(3, 4)
            return (int(major), int(minor)), "requires-python"
    return None, None


def project_python(root, stop=None, environments=()) -> tuple | None:
    """(major, minor) of the CPython the project installs into, or None
    (`project_interpreter` without its source)."""
    return project_interpreter(root, stop, environments)[0]


# When the project names no Python, the interpreter a bare `pip` or `uv`
# most likely runs is the `python3` on PATH. It is asked once per process,
# with `-I` so nothing in the environment or the working directory loads
# into it, and given a short deadline.
_PATH_PYTHON_NAME = "python3"
_PATH_PYTHON_TIMEOUT_SECONDS = 2.0
_PATH_PYTHON_CODE = ("import sys, sysconfig; print(sys.implementation.name, sys.version_info[0], "
                     "sys.version_info[1], 1 if sysconfig.get_config_var('Py_GIL_DISABLED') else 0)")
_PATH_PYTHON = {"probed": False, "value": None}
_PATH_PYTHON_LOCK = threading.Lock()


def _probe_interpreter(found) -> tuple | None:
    """(major, minor) of the interpreter at `found`, run with `-I`, or None:
    not an absolute path, not CPython, a free-threaded build, slow, or a
    failure of any kind."""
    import os
    import subprocess
    if not found or not os.path.isabs(found):
        return None
    try:
        done = subprocess.run([found, "-I", "-c", _PATH_PYTHON_CODE], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=_PATH_PYTHON_TIMEOUT_SECONDS, check=False)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    match = re.fullmatch(r"(\w+) (\d+) (\d+) ([01])", (done.stdout or "").strip())
    if done.returncode != 0 or not match or match.group(1) != "cpython" or match.group(4) != "0":
        return None
    return int(match.group(2)), int(match.group(3))


def _probe_path_python() -> tuple | None:
    """(major, minor) of the `python3` on PATH, or None: not found, or
    `_probe_interpreter` refused it."""
    import shutil
    return _probe_interpreter(shutil.which(_PATH_PYTHON_NAME))


def path_python() -> tuple | None:
    """(major, minor) of the CPython `python3` on PATH, probed once per
    process and then cached; None when the probe failed. Only read when the
    project's own Python is unknown and only CPython-specific wheels exist."""
    with _PATH_PYTHON_LOCK:
        if not _PATH_PYTHON["probed"]:
            _PATH_PYTHON["value"] = _probe_path_python()
            _PATH_PYTHON["probed"] = True
        return _PATH_PYTHON["value"]


# uv does not take the `python3` on PATH: by default it prefers an
# interpreter it manages, and reads a global pin and the project's
# configuration. For a uv command, uv itself is asked which interpreter it
# would use, from the project's directory, once per directory per process.
# An active environment is left out of the child's environment: `uv sync`,
# `uv add` and `uvx` ignore it, and the hook's own runner may have set it.
# Nothing is downloaded.
_UV_NAME = "uv"
_UV_FIND_TIMEOUT_SECONDS = 3.0
_UV_FIND_ARGS = ("python", "find", "--no-python-downloads")
_UV_FIND_UNSET = ("VIRTUAL_ENV", "CONDA_PREFIX")
_UV_PYTHON = {}
_UV_PYTHON_LOCK = threading.Lock()


def _probe_uv_python(directory) -> tuple | None:
    """(major, minor) of the interpreter `uv python find` names when run in
    `directory`, or None: uv not found, not an absolute path, a non-zero
    exit, slow, an answer that is not an absolute path to a file, or an
    interpreter `_probe_interpreter` refuses."""
    import os
    import shutil
    import subprocess
    uv = shutil.which(_UV_NAME)
    if not uv or not os.path.isabs(uv):
        return None
    env = {key: value for key, value in os.environ.items() if key not in _UV_FIND_UNSET}
    try:
        done = subprocess.run([uv, *_UV_FIND_ARGS], cwd=str(directory), env=env, capture_output=True,
                              text=True, stdin=subprocess.DEVNULL, timeout=_UV_FIND_TIMEOUT_SECONDS,
                              check=False)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    lines = (done.stdout or "").strip().splitlines()
    found = lines[-1].strip() if lines else ""
    if done.returncode != 0 or not os.path.isabs(found) or not os.path.isfile(found):
        return None
    return _probe_interpreter(found)


def uv_python(directory) -> tuple | None:
    """(major, minor) of the CPython uv would use in `directory`, asked once
    per directory per process and then cached; None when the probe failed.
    Only read for a uv command when the project's own Python is unknown and
    only CPython-specific wheels exist."""
    import os
    if directory is None:
        return None
    key = os.path.realpath(directory)
    with _UV_PYTHON_LOCK:
        if key not in _UV_PYTHON:
            _UV_PYTHON[key] = _probe_uv_python(key)
        return _UV_PYTHON[key]


def assumed_wheel(evidence) -> str | None:
    """The install-time line for a release judged `wheel` against an
    interpreter the review assumed, or None. Only CPython-specific wheels
    sent the review to an assumed interpreter, so that wheel holds only if
    the installer runs it; the line says so instead of "no install-time
    code"."""
    if not isinstance(evidence, dict) or evidence.get("distribution") != "wheel":
        return None
    if evidence.get("target_python_source") not in ASSUMED_PYTHON_SOURCES:
        return None
    python = _version_pair(evidence.get("target_python"))
    if python is None:
        return None
    return f"wheel for CPython {python[0]}.{python[1]} (assumed interpreter)"


def _default_root():
    """The guarded project, for callers that do not name one (the approve-time
    refresh): CLAUDE_PROJECT_DIR, else this file's install site."""
    try:
        return store.project_root(__file__)
    except (store.StoreError, IndexError):
        return None


_CP = re.compile(r"cp3(\d+)")


def _python_tag_ok(py: str, abi: str, python) -> bool:
    """One (python tag, ABI tag) pair against the project's CPython, as pip's
    own tag list ranks them. Unknown Python accepts only `py3-none` and
    `abi3`: a `cp3x` wheel fits one interpreter, and nothing says the
    installer runs that one. PyPy and free-threaded tags never match a
    CPython project."""
    cp = _CP.fullmatch(py)
    if abi == "none":
        if py == "py3":
            return True
        minor = re.fullmatch(r"py3(\d+)", py)
        if minor:
            return python is not None and (3, int(minor.group(1))) <= python
        return bool(cp) and python == (3, int(cp.group(1)))
    if abi == "abi3":
        return bool(cp) and (python is None or (3, int(cp.group(1))) <= python)
    own = re.fullmatch(r"cp3(\d+)[mdu]?", abi)
    return bool(cp and own) and own.group(1) == cp.group(1) and python == (3, int(cp.group(1)))


_LEGACY_MANYLINUX = {"manylinux1": (2, 5), "manylinux2010": (2, 12), "manylinux2014": (2, 17)}


def _platform_tag_ok(plat: str, family: str, arch: str, os_version) -> bool:
    if plat == "any":
        return True
    if family == "macosx":
        match = re.fullmatch(r"macosx_(\d+)_(\d+)_(\w+)", plat)
        return bool(match) and os_version is not None \
            and (int(match.group(1)), int(match.group(2))) <= os_version \
            and (match.group(3) in (arch, "universal2") or (arch == "x86_64" and match.group(3) == "intel"))
    if family == "linux":
        if plat == "linux_" + arch:
            return True
        match = re.fullmatch(r"manylinux_(\d+)_(\d+)_(\w+)", plat)
        floor = (int(match.group(1)), int(match.group(2))) if match else None
        tag_arch = match.group(3) if match else None
        for legacy, legacy_floor in _LEGACY_MANYLINUX.items():
            if plat.startswith(legacy + "_"):
                floor, tag_arch = legacy_floor, plat[len(legacy) + 1:]
        return floor is not None and tag_arch == arch and os_version is not None and floor <= os_version
    if family == "win":
        return plat == {"x86_64": "win_amd64", "arm64": "win_arm64"}.get(arch, "win32")
    return False


def wheel_compatible(filename, tags=None, python=None) -> bool:
    """Whether pip could install this wheel into the
    project rather than build the sdist.

    `tags` is (os family, arch, os version) and defaults to this machine;
    `python` is the project's (major, minor) from `project_python` (or an
    assumed interpreter, `uv_python` or `path_python`), never the hook's own, and None when it
    is unknown, which accepts only `py3-none` and `abi3` wheels. A
    wheel counts only when one of its (python, ABI) pairs fits that Python and
    one platform tag fits this machine, including the macOS or glibc minimum
    the tag sets. Anything else unknown -- the host's OS version, a musllinux
    or PyPy tag, an unparseable name -- reads as incompatible, which only ever
    makes the release `sdist-build`.
    """
    match = _WHEEL.match(filename or "")
    if not match:
        return False
    family, arch, *rest = tags or _platform_tags()
    os_version = rest[0] if rest else None
    if not any(_python_tag_ok(py, abi, python)
               for py in match.group("py").split(".") for abi in match.group("abi").split(".")):
        return False
    return any(_platform_tag_ok(plat, family, arch, os_version) for plat in match.group("plat").split("."))


def _metadata_signals(evidence: dict, provenance, now: datetime | None = None) -> list:
    """Deterministic risk signals from dates, counts and names.

    Ecosystem-neutral: both providers fill the same evidence keys. A missing
    value yields no signal -- silence is not an all-clear, and the prompt
    renders the field as unknown rather than as clean.
    """
    now = now or _utcnow()
    signals = []
    package_age = _age_days(evidence.get("package_created_at"), now)
    version_age = _age_days(evidence.get("version_published_at"), now)
    last_age = _age_days(evidence.get("last_published_at"), now)
    evidence["package_age_days"] = package_age
    evidence["version_age_days"] = version_age
    if package_age is not None and package_age < FRESH_PACKAGE_DAYS:
        signals.append(f"package first published {package_age} day(s) ago")
    releases = evidence.get("release_count")
    if releases is not None and releases < MIN_RELEASES:
        signals.append(f"only {releases} release(s) on the registry")
    if version_age is not None and version_age < FRESH_VERSION_DAYS:
        note = f"version published {version_age} day(s) ago"
        if isinstance(provenance, dict) and not provenance.get("attested"):
            note += ", no provenance attestation"
        signals.append(note)
    if last_age is not None and last_age > STALE_PUBLISH_DAYS:
        signals.append(f"last publish {last_age // 365} year(s) ago")
    if evidence.get("deprecated"):
        signals.append(f"deprecated on the registry: {evidence['deprecated']}")
    publisher = evidence.get("publisher")
    maintainers = evidence.get("maintainers") or []
    # A trusted-publisher release names the CI identity ("GitHub Actions") as
    # publisher, usually with an attestation; that is the expected shape, not
    # a takeover, and the same test as the tier's publisher criterion.
    if publisher and maintainers and not _known_publisher(evidence, provenance):
        signals.append(f"version published by '{publisher}', who is not a listed maintainer")
    if evidence.get("license") is None:
        signals.append("no license declared")
    return signals


def store_registry(request) -> str:
    return request.registry


def _osv_vulns(result) -> list:
    """The `vulns` of one OSV answer, or ProviderError when it is not one.

    `{}` is OSV's clean answer, so anything that is not
    exactly that shape -- an error object on a 200, a dict where the list
    belongs, an id that is not a string, a paginated answer we do not follow --
    must fail the mandatory check rather than read as "no advisories".
    """
    if not isinstance(result, dict) or set(result) - {"vulns"}:
        raise ProviderError("OSV returned a malformed or error response")
    vulns = result.get("vulns", [])
    if not isinstance(vulns, list) or not all(
            isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"] for v in vulns):
        raise ProviderError("OSV returned malformed vulnerability records")
    return vulns


def _query_osv(ecosystem: str, name: str, version: str):
    payload = {
        "package": {"name": name, "ecosystem": _OSV_ECOSYSTEM[ecosystem]},
        "version": version,
    }
    result = _mandatory_json(OSV_QUERY_URL, data=payload)
    if result is None:
        raise ProviderError("OSV query returned no response")
    vulns = _osv_vulns(result)
    ids = [v["id"] for v in vulns]
    details = [{"id": v["id"], "summary": v.get("summary")} for v in vulns]
    return ids, details


def query_osv_batch(ecosystem: str, pairs) -> dict:
    """{(name, version): [advisory ids]} for one chunk of packages.

    One POST to querybatch, at most OSV_BATCH_SIZE queries; the caller chunks
    and counts calls. Results come back aligned with the queries. Raises
    ProviderError on failure, which the caller turns into a denial.
    """
    pairs = list(pairs)
    if len(pairs) > OSV_BATCH_SIZE:
        raise ValueError(f"at most {OSV_BATCH_SIZE} queries per batch")
    if not pairs:
        return {}
    payload = {"queries": [
        {"package": {"name": name, "ecosystem": _OSV_ECOSYSTEM[ecosystem]}, "version": version}
        for name, version in pairs
    ]}
    result = _mandatory_json(OSV_BATCH_URL, data=payload)
    results = (result or {}).get("results")
    if not isinstance(results, list) or len(results) != len(pairs):
        raise ProviderError("OSV batch query returned a malformed response")
    found = {}
    for pair, entry in zip(pairs, results):
        found[pair] = [v["id"] for v in _osv_vulns(entry)]
    return found


def audit_batches(entries):
    """The OSV batch plan for a vetted set, [(ecosystem, pairs), ...].

    Grouped by ecosystem because `query_osv_batch` sends one ecosystem per
    POST, then chunked at OSV_BATCH_SIZE. Entries with an ecosystem OSV does
    not know, or with a missing name or version, are dropped rather than
    raising: vetted.json is durable state and a shape the auditor cannot query
    must not turn every install into an internal failure. The caller checks
    the plan against its call budget BEFORE spending any of it.
    """
    by_ecosystem = {}
    for entry in entries or ():
        if not isinstance(entry, dict):
            continue
        ecosystem = entry.get("ecosystem")
        name, version = entry.get("name"), entry.get("version")
        if ecosystem not in _OSV_ECOSYSTEM or not name or not version:
            continue
        pair = (name, version)
        pairs = by_ecosystem.setdefault(ecosystem, [])
        if pair not in pairs:
            pairs.append(pair)
    plan = []
    for ecosystem in sorted(by_ecosystem):
        pairs = by_ecosystem[ecosystem]
        for start in range(0, len(pairs), OSV_BATCH_SIZE):
            plan.append((ecosystem, pairs[start:start + OSV_BATCH_SIZE]))
    return plan


def audit_vetted(entries):
    """({"eco:name@version": [advisory ids]}, batch calls made).

    Re-asks OSV about versions a human already approved. vetted.json is
    committed and travels with the repo, so an approval made in March installs
    with no network call in July — by which time the version may
    have gained a MAL record. Only packages with at least one advisory appear
    in the mapping. ProviderError propagates: the caller fails closed.
    """
    findings = {}
    calls = 0
    for ecosystem, chunk in audit_batches(entries):
        calls += 1
        for (name, version), ids in query_osv_batch(ecosystem, chunk).items():
            if ids:
                findings[f"{ecosystem}:{name}@{version}"] = ids
    return findings, calls


# ---------------------------------------------------------------------------
# Review creation
# ---------------------------------------------------------------------------

def _retry_command(request, version: str) -> str:
    name = request.display_name
    if request.ecosystem == "npm":
        spec = f"{name}@{version}"
        return f"npx {spec}" if request.operation == "exec" else f"npm install {spec}"
    if request.operation == "tool":
        return f"uvx {name}@{version}"
    if request.operation == "tool-install":
        return f"uv tool install {name}=={version}"
    if request.manager == "uv" and request.operation == "add":
        return f"uv add {name}=={version}"
    if request.manager == "uv pip":
        return f"uv pip install {name}=={version}"
    if request.operation == "run-with":
        return f"uv run --with {name}=={version} <script>"
    return f"pip install {name}=={version}"


_FROM_PROJECT = object()


def reviewed_python(report: dict) -> tuple | None:
    """The Python a stored report judged the wheels against (the project's,
    or an interpreter assumed when the project names none), or None."""
    return _version_pair((report.get("evidence") or {}).get("target_python"))


def reviewed_python_source(report: dict) -> str | None:
    """Where that Python came from (`PYTHON_SOURCES`), or None."""
    source = (report.get("evidence") or {}).get("target_python_source")
    return source if source in PYTHON_SOURCES and reviewed_python(report) is not None else None


def gather(request, root=None, project=None, python=_FROM_PROJECT, environments=(),
           python_source=None, uv_project=False) -> dict:
    """The whole review in one pass: registry, then OSV, for one request.

    Returns the evidence the report carries -- `version`, `mandatory`,
    `evidence`, `provenance`, `reputation`, `release_continuity`,
    `hard_findings`, `risk_signals` -- without writing anything.
    `create_review` wraps it into an immutable report; the approve gate calls
    it again for a fresh view, because a report is a record of what was true
    at review time, not now.

    A wheel is judged against the interpreter of the project the command
    acts on: `project` is the command's directory, `root` the guarded
    project, which bounds the search for it and stands in when no directory
    is named. `environments` are the Python environments the command names
    outside the tree (`project_interpreter`). `python` overrides all three:
    the approve-time refresh passes the interpreter the review used and
    where it came from (`reviewed_python`, `reviewed_python_source`), so the
    prompt judges what the review judged, and nothing is probed again.

    With no Python known either way, a release that has only
    interpreter-specific wheels is judged against the interpreter the
    installer most likely runs. For a uv command (a request whose manager is
    uv's, or `uv_project`: a dependency of the uv project the command syncs)
    that is the one `uv python find` names in the project (`uv_python`);
    otherwise, or when uv does not answer, the `python3` on PATH
    (`path_python`). The report records the interpreter and its source in
    `target_python` and `target_python_source`; with neither probe answering,
    the Python stays unknown.
    """
    mandatory = {
        "registry": {"ok": False},
        "osv": {"ok": False, "ids": [], "malware_ids": []},
    }
    evidence = {
        "package_created_at": None,
        "version_published_at": None,
        "last_published_at": None,
        "repository_url": None,
        "maintainers": [],
        "publisher": None,
        "trusted_publisher": None,
        "install_scripts": [],
        "deprecated": None,
        "license": None,
        "license_class": None,
        "dependency_count": None,
        "release_count": None,
        "package_age_days": None,
        "version_age_days": None,
        "integrity": None,
        "distribution": None,
        "npm_weekly_downloads": None,
        "known_vulnerabilities": [],
        "cooldown": None,
        "cooldown_unavailable": None,
        "settled_release": None,
        "target_python": None,
        "target_python_source": None,
    }
    provenance = None
    reputation = None
    continuity = None
    hard_findings = []
    risk_signals = []
    version = None
    try:
        if request.ecosystem == "npm":
            version, found, provenance, risk, repository, continuity, history = _vet_npm(request, mandatory)
            pypi_extra = None
        else:
            assume = None
            if python is _FROM_PROJECT:
                guarded = root if root is not None else _default_root()
                directory = project if project is not None else guarded
                python, python_source = project_interpreter(directory, stop=guarded,
                                                            environments=tuple(environments))
                uv = uv_project or str(getattr(request, "manager", "") or "").startswith("uv")

                def assume():
                    found = uv_python(directory) if uv else None
                    if found is not None:
                        return found, "uv-python-find"
                    found = path_python()
                    return (found, "path-python3") if found is not None else (None, None)
            version, found, provenance, risk, pypi_extra = _vet_pypi(request, mandatory, python,
                                                                     python_source, assume)
            repository = pypi_extra["repository"]
            history = True
        evidence.update(found)
        risk_signals.extend(risk)
        risk_signals.extend(_metadata_signals(evidence, provenance))
        osv_name = request.display_name if request.ecosystem == "npm" else request.name
        ids, details = _query_osv(request.ecosystem, osv_name, version)
        malware_ids = [i for i in ids if i.startswith("MAL-")]
        mandatory["osv"] = {"ok": True, "ids": ids, "malware_ids": malware_ids}
        evidence["known_vulnerabilities"] = [d for d in details if not d["id"].startswith("MAL-")]
        if malware_ids:
            hard_findings.append(f"OSV malware record(s) for exact version: {', '.join(malware_ids)}")
        elif evidence["known_vulnerabilities"]:
            risk_signals.append(
                f"{len(evidence['known_vulnerabilities'])} known OSV vulnerability record(s) for this exact version"
            )
        # After the mandatory providers, never instead of them: a
        # malware record above already decided, and the tier is only computed
        # for a package that exists and has been asked of OSV.
        if not malware_ids:
            trust = trusted_catalog.lookup(request.ecosystem, request.name, request.registry,
                                           evidence.get("repository_url"))
            period = "weekly" if request.ecosystem == "npm" else "monthly"
            try:
                if trust["status"] == "trusted":
                    reputation = _catalog_reputation(trust, request, evidence, provenance, ids, pypi_extra,
                                                     continuity)
                elif request.ecosystem == "npm":
                    reputation = _reputation_npm(request.display_name, evidence, provenance, ids, repository,
                                                 continuity, read_manifest=history)
                else:
                    reputation = _reputation_pypi(request.name, evidence, ids, repository, pypi_extra["yanked"])
            except _SHAPE_ERRORS as exc:
                # An optional provider can only make a package
                # unresolved. A malformed answer is not a reason to deny every
                # install, and never a reason to call it established.
                reputation = _empty_reputation()
                reputation["unmet"] = [f"reputation evidence was malformed ({type(exc).__name__})"]
            _apply_trust(reputation, trust, evidence, risk_signals)
            if not history:
                # Never established: the ages, the release count and the
                # settled release the tier reads are unknown.
                reputation["tier"] = "unresolved"
                reputation["unmet"].insert(0, HISTORY_TOO_LARGE)
            if reputation.get("lookalike_of"):
                risk_signals.append(
                    f"name is one edit from '{reputation['lookalike_of']}', which has at least "
                    f"{LOOKALIKE_DOWNLOAD_RATIO}x its {period} downloads (possible lookalike)"
                )
    except HardDeny as exc:
        hard_findings.append(str(exc))
    except ProviderError as exc:
        hard_findings.append(f"mandatory provider failure: {exc}")
    except _SHAPE_ERRORS as exc:
        # Registry metadata of the wrong shape is a failed mandatory
        # check, reported as one -- not an internal failure of the hook.
        hard_findings.append(f"mandatory provider returned malformed evidence ({type(exc).__name__})")
    return {
        "version": version,
        "mandatory": mandatory,
        "evidence": evidence,
        "provenance": provenance,
        "reputation": reputation,
        "release_continuity": continuity,
        "hard_findings": hard_findings,
        "risk_signals": risk_signals,
    }


def create_review(request, root, session_id: str | None = None, project=None,
                  environments=(), uv_project=False) -> dict:
    """Vet one package request, write the review report, return it.

    `session_id` (from the hook event) lets the Stop hook find reviews that
    were opened in the current session and are still unresolved. `project`
    is the directory the command runs in, `environments` the outside
    environments it names and `uv_project` whether the request is a
    dependency of the uv project it syncs (see `gather`); the report is
    written under `root`.
    """
    review_id = store.new_review_id()
    found = gather(request, root, project=project, environments=environments, uv_project=uv_project)
    version = found["version"]
    mandatory, evidence, provenance = found["mandatory"], found["evidence"], found["provenance"]
    hard_findings, risk_signals = found["hard_findings"], found["risk_signals"]

    verdict = "hard_deny" if hard_findings else "review_required"
    resolved_version = version or request.exact_version or request.requested_spec or "unresolved"
    report = {
        "schema_version": store.SCHEMA_VERSION,
        "review_id": review_id,
        "created_at": store.utcnow(),
        "session_id": session_id if isinstance(session_id, str) and session_id else None,
        "request": {
            "manager": request.manager,
            "operation": request.operation,
            "original_package": request.display_name,
            "requested_spec": request.requested_spec,
        },
        "resolved_identity": {
            "ecosystem": request.ecosystem,
            "name": request.name,
            "version": resolved_version,
            "registry": request.registry,
        },
        "mandatory_checks": mandatory,
        "evidence": evidence,
        "optional_checks": {
            "openssf_scorecard": None,
            "provenance": provenance,
            "reputation": found["reputation"],
            "release_continuity": found["release_continuity"],
        },
        "hard_findings": hard_findings,
        "risk_signals": risk_signals,
        "verdict": verdict,
        "retry_command": _retry_command(request, version) if version else None,
    }
    store.write_report(root, report)
    return report
