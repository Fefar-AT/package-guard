"""Deterministic vetting: official registry metadata + OSV lookup.

Produces an immutable review report per unknown package. Never downloads
or executes candidate package code — metadata only.

Standard library only.
"""
from __future__ import annotations

import json
import re
import sys
import threading
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
PYPI_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
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
ALLOWED_LICENSES = frozenset({
    "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "PSF-2.0",
    "Python-2.0", "MPL-2.0", "0BSD", "Unlicense", "CC0-1.0",
})
# Calls the reputation step can add to one review. npm: downloads (1), the
# repository manifest (up to 2), the near-name search (1) and the neighbours'
# downloads in one bulk call (1). PyPI: the top list (1, once per process)
# and the repository pyproject (up to 2). hook._REVIEW_CALLS carries the
# per-review total the review budget bounds; PyPI's three mandatory calls plus
# three fit under the same seven.
REPUTATION_CALLS = 5
_SAFE_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+")
_SAFE_PATH = re.compile(r"[A-Za-z0-9_./@-]+")
_NPM_UNSCOPED = re.compile(r"[a-z0-9][a-z0-9._-]*")


class ProviderError(Exception):
    """A mandatory evidence provider failed. Unknown packages fail closed."""


class HardDeny(Exception):
    """Deterministic evidence that forbids this package outright."""


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
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ProviderError(f"{url}: HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"{url}: {exc}")
    if len(raw) > MAX_BODY_BYTES:
        raise ProviderError(f"{url}: response exceeds size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProviderError(f"{url}: response is not UTF-8")
    # One seam for every provider, so a test that replaces this function
    # replaces all of them. A pyproject.toml is the one non-JSON document the
    # review reads; it is returned as text for tomllib.
    if url.endswith(".toml"):
        return text
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        raise ProviderError(f"{url}: response is not valid JSON")


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


def _vet_npm(request, mandatory):
    encoded = urllib.parse.quote(request.display_name, safe="@")
    meta = _request_json(f"{store_registry(request)}/{encoded}")
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
    settled = None
    if request.exact_version and isinstance(versions.get(version), dict):
        dist = versions[version].get("dist")
        attested = isinstance(dist, dict) and isinstance(dist.get("attestations"), dict) \
            and bool(dist["attestations"])
        candidates = {v: times.get(v) for v, m in versions.items()
                      if isinstance(m, dict) and not m.get("deprecated")}
        candidates[version] = times.get(version)
        pick, record = _cooled("npm", version, candidates, attested)
        settled = pick if record else None
    version_meta = versions.get(version)
    if version_meta is None:
        raise HardDeny(f"version {version} of '{request.display_name}' does not exist on registry.npmjs.org")
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
    published = [times.get(v) for v in versions if _parse_iso(times.get(v))]
    evidence = {
        "package_created_at": times.get("created"),
        "version_published_at": times.get(version),
        "last_published_at": max(published) if published else None,
        "repository_url": _repository_from(version_meta.get("repository") or meta.get("repository")),
        "maintainers": [
            m.get("name") for m in (meta.get("maintainers") or []) if isinstance(m, dict) and m.get("name")
        ],
        "publisher": _text(version_meta.get("_npmUser")),
        "install_scripts": lifecycle,
        "deprecated": _text(version_meta.get("deprecated")),
        "license": _text(version_meta.get("license")),
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
    return version, evidence, provenance, risk, repository


# ---------------------------------------------------------------------------
# The reputation tier (npm)
# ---------------------------------------------------------------------------

def _github_repo(url) -> tuple | None:
    """(owner, repo) for a repository URL on github.com, else None."""
    if not isinstance(url, str):
        return None
    text = url.strip()
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
    if owner in (".", "..") or repo in (".", ".."):
        return None
    return owner, repo


def _manifest_names_package(name: str, repository) -> dict:
    """Does the declared repository's package.json name this package?

    `{"url", "names_package"}`: True / False, or None when the check could
    not run (no GitHub repository declared, or the fetch failed). At most two
    fetches: the manifest at the declared `repository.directory`, else the
    root manifest and then the monorepo convention `packages/<name>`.
    """
    located = _github_repo(_repository_from(repository))
    if located is None:
        return {"url": None, "names_package": None}
    owner, repo = located
    directory = repository.get("directory") if isinstance(repository, dict) else None
    if isinstance(directory, str) and directory.strip("/") and _SAFE_PATH.fullmatch(directory) \
            and ".." not in directory:
        candidates = [directory.strip("/") + "/package.json"]
    else:
        candidates = ["package.json", f"packages/{name.split('/')[-1]}/package.json"]
    url = None
    for path in candidates:
        url = f"{GITHUB_RAW_URL}/{owner}/{repo}/HEAD/{path}"
        try:
            manifest = _request_json(url)
        except ProviderError:
            return {"url": url, "names_package": None}
        if isinstance(manifest, dict) and manifest.get("name") == name:
            return {"url": url, "names_package": True}
    return {"url": url, "names_package": False}


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


def _shared_unmet(evidence: dict, osv_ids: list) -> list:
    """The criteria both ecosystems read from the report already in hand."""
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
    if version_age is None or version_age < FRESH_VERSION_DAYS:
        unmet.append(f"version age {version_age if version_age is not None else 'unknown'} day(s), "
                     f"under {FRESH_VERSION_DAYS}")
    if evidence.get("deprecated"):
        unmet.append("deprecated on the registry")
    if osv_ids:
        unmet.append(f"{len(osv_ids)} OSV record(s) for this version")
    if evidence.get("license") not in ALLOWED_LICENSES:
        unmet.append(f"license {evidence.get('license') or 'none declared'} not in the allowed set")
    return unmet


def _downloads_floor(result: dict, unmet: list, downloads, source: str) -> None:
    result["weekly_downloads"] = downloads
    if downloads is None:
        if not unmet:
            unmet.append(f"no weekly download count from {source}")
    elif downloads < ESTABLISHED_MIN_WEEKLY_DOWNLOADS:
        unmet.append(f"weekly downloads {downloads} under {ESTABLISHED_MIN_WEEKLY_DOWNLOADS}")


def _manifest_unmet(result: dict, unmet: list, manifest: dict) -> None:
    result["manifest"] = manifest
    if manifest["names_package"] is None:
        unmet.append("repository manifest not checked (no GitHub repository declared, or unreachable)")
    elif not manifest["names_package"]:
        unmet.append("repository manifest does not name this package")


def _reputation_npm(name: str, evidence: dict, provenance, osv_ids: list, repository) -> dict:
    """The deterministic reputation block for one npm identity.

    `tier` is `established` only when every criterion below holds; otherwise
    `unresolved`, with `unmet` naming each failed or unavailable check. A
    provider failure here is never a hard finding -- it only leaves the tier
    unresolved, which sends the review to the vetter.
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
    unmet.extend(_shared_unmet(evidence, osv_ids))
    if evidence.get("install_scripts"):
        unmet.append("declares install scripts")
    publisher = evidence.get("publisher")
    maintainers = evidence.get("maintainers") or []
    attested = isinstance(provenance, dict) and bool(provenance.get("attested"))
    if not publisher:
        unmet.append("publisher not recorded")
    elif publisher not in maintainers and not attested:
        unmet.append(f"published by '{publisher}', not a listed maintainer, without provenance")
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


def _pyproject_names_package(name: str, repository) -> dict:
    """Does the declared repository's pyproject.toml name this package?

    Same shape as `_manifest_names_package`: root `pyproject.toml`, then
    `<name>/pyproject.toml`; `[project].name` or `[tool.poetry].name`,
    compared after PEP 503 normalisation. A repository that builds from
    setup.py alone comes back unchecked (None), never confirmed.
    """
    located = _github_repo(_repository_from(repository))
    if located is None:
        return {"url": None, "names_package": None}
    owner, repo = located
    wanted = _pypi_normalise(name)
    url = None
    for path in ("pyproject.toml", f"{name}/pyproject.toml"):
        url = f"{GITHUB_RAW_URL}/{owner}/{repo}/HEAD/{path}"
        try:
            text = _request_json(url)
        except ProviderError:
            return {"url": url, "names_package": None}
        if not isinstance(text, str):
            continue
        try:
            document = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            continue
        declared = ((document.get("project") or {}).get("name")
                    or ((document.get("tool") or {}).get("poetry") or {}).get("name"))
        if isinstance(declared, str) and _pypi_normalise(declared) == wanted:
            return {"url": url, "names_package": True}
    return {"url": url, "names_package": False}


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
                        pypi_extra) -> dict:
    """Trusted identity replaces popularity research, never release checks."""
    result = _empty_reputation()
    result["trust"] = trust
    unmet = result["unmet"]
    unmet.extend(_shared_unmet(evidence, ids))
    if request.ecosystem == "npm":
        if evidence.get("install_scripts"):
            unmet.append("declares install scripts")
        publisher = evidence.get("publisher")
        attested = isinstance(provenance, dict) and bool(provenance.get("attested"))
        if not publisher:
            unmet.append("publisher not recorded")
        elif publisher not in (evidence.get("maintainers") or []) and not attested:
            unmet.append("publisher is not a listed maintainer and has no provenance")
    else:
        if evidence.get("distribution") != "wheel":
            unmet.append("no wheel for this version (setup.py may run on install)")
        if pypi_extra["yanked"]:
            unmet.append("version is yanked")
    if not unmet:
        result["tier"] = "established"
    return result


def _pypi_license(info: dict) -> str | None:
    declared = _text(info.get("license_expression")) or _text(info.get("license"))
    if declared and len(declared) <= 80:
        return declared
    for classifier in info.get("classifiers") or []:
        if isinstance(classifier, str) and classifier.startswith("License ::"):
            return classifier.split("::")[-1].strip()
    return declared[:80] if declared else None


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


def _vet_pypi(request, mandatory, python=None):
    meta = _request_json(f"{request.registry}/pypi/{request.name}/json")
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
    version_meta = _request_json(f"{request.registry}/pypi/{request.name}/{version}/json")
    if version_meta is None:
        raise HardDeny(f"version {version} of '{request.display_name}' does not exist on pypi.org")
    info = version_meta.get("info") or {}
    urls = [u for u in (version_meta.get("urls") or []) if isinstance(u, dict)]
    # The NEWEST file dates the release. A wheel uploaded yesterday to a
    # two-year-old version is a new artifact and must read as fresh.
    file_times = [u.get("upload_time_iso_8601") for u in urls if _parse_iso(u.get("upload_time_iso_8601"))]
    uploaded = max(file_times) if file_times else None
    project_urls = info.get("project_urls") or {}
    repository = None
    for key in ("Source", "Source Code", "Repository", "Homepage", "Home"):
        if _repository_from(project_urls.get(key)):
            repository = project_urls[key]
            break
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
    if any(u.get("packagetype") == "bdist_wheel" and wheel_compatible(u.get("filename"), python=python)
           for u in live):
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
    evidence = {
        "package_created_at": min(uploads) if uploads else None,
        "version_published_at": uploaded,
        "last_published_at": max(uploads) if uploads else None,
        "repository_url": repository,
        "maintainers": [a for a in [info.get("author"), info.get("maintainer")] if a],
        "publisher": None,
        "install_scripts": [],
        "deprecated": _PYPI_INACTIVE if _PYPI_INACTIVE in classifiers else None,
        "license": _pypi_license(info),
        "dependency_count": _count(info.get("requires_dist")) if info.get("requires_dist") is not None else 0,
        "release_count": _count(releases) if releases else None,
        "integrity": None,
        "distribution": distribution,
        "requires_python": info.get("requires_python"),
        "artifacts": artifacts,
        "cooldown": cooldown,
        "cooldown_unavailable": cooldown_unavailable,
        "settled_release": settled,
        "target_python": f"{python[0]}.{python[1]}" if python else None,
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
    elif distribution == "sdist-build":
        target = f"Python {python[0]}.{python[1]}" if python else "an unknown project Python"
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


def project_python(root) -> tuple | None:
    """(major, minor) of the CPython the project installs into, or None.

    The hook runs under its own `uv run --no-project`
    interpreter, so its `sys.version_info` says nothing about the project.
    Read in order: `.venv/pyvenv.cfg` (a non-CPython venv falls through),
    uv's `.python-version` pin, then a `requires-python` that names exactly
    one minor (`==3.12.*`, `~=3.12.0`). A floor such as `>=3.11` names no
    single interpreter and reads as unknown.
    """
    if root is None:
        return None
    base = Path(root)
    try:
        cfg = (base / ".venv" / "pyvenv.cfg").read_text(encoding="utf-8", errors="replace")
    except OSError:
        cfg = ""
    fields = {}
    for line in cfg.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip().lower()] = value.strip()
    if fields.get("implementation", "cpython").lower() == "cpython":
        found = _version_pair(fields.get("version_info") or fields.get("version"))
        if found:
            return found
    try:
        pin = (base / ".python-version").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        pin = ""
    match = re.match(r"(?:cpython[-@])?(\d+)\.(\d+)(?:[.\-]|$)", pin.splitlines()[0] if pin else "")
    if match:
        return int(match.group(1)), int(match.group(2))
    try:
        with (base / "pyproject.toml").open("rb") as handle:
            declared = (tomllib.load(handle).get("project") or {}).get("requires-python")
    except (OSError, tomllib.TOMLDecodeError, AttributeError):
        declared = None
    if isinstance(declared, str):
        match = re.fullmatch(r"\s*(?:==\s*(\d+)\.(\d+)(?:\.\*|\.\d+)?|~=\s*(\d+)\.(\d+)\.\d+)\s*", declared)
        if match:
            major, minor = match.group(1, 2) if match.group(1) else match.group(3, 4)
            return int(major), int(minor)
    return None


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
    `abi3`; PyPy and free-threaded tags never match a CPython project."""
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
    `python` is the project's (major, minor) from `project_python`, never the
    hook's own. A wheel counts only when one of its (python, ABI) pairs fits
    that Python and one platform tag fits this machine, including the macOS
    or glibc minimum the tag sets. Anything unknown -- the project's Python,
    the host's OS version, a musllinux or PyPy tag, an unparseable name --
    reads as incompatible, which only ever makes the release `sdist-build`.
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
    attested = isinstance(provenance, dict) and bool(provenance.get("attested"))
    # A trusted-publisher release names the CI identity ("GitHub Actions") as
    # publisher and carries an attestation; that is the expected shape, not a
    # takeover.
    if publisher and maintainers and publisher not in maintainers and not attested:
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
    result = _request_json(OSV_QUERY_URL, data=payload)
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
    result = _request_json(OSV_BATCH_URL, data=payload)
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


def gather(request, root=None) -> dict:
    """The whole review in one pass: registry, then OSV, for one request.

    Returns the evidence the report carries -- `version`, `mandatory`,
    `evidence`, `provenance`, `hard_findings`, `risk_signals` -- without
    writing anything. `create_review` wraps it into an immutable report; the
    approve gate calls it again for a fresh view, because a report is a
    record of what was true at review time, not now.

    `root` is the project: a wheel is judged against its
    interpreter. The approve-time refresh names none and gets the guarded
    project, so the prompt judges the same interpreter the review did.
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
        "install_scripts": [],
        "deprecated": None,
        "license": None,
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
    }
    provenance = None
    reputation = None
    hard_findings = []
    risk_signals = []
    version = None
    try:
        if request.ecosystem == "npm":
            version, found, provenance, risk, repository = _vet_npm(request, mandatory)
            pypi_extra = None
        else:
            python = project_python(root if root is not None else _default_root())
            version, found, provenance, risk, pypi_extra = _vet_pypi(request, mandatory, python)
            repository = pypi_extra["repository"]
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
                    reputation = _catalog_reputation(trust, request, evidence, provenance, ids, pypi_extra)
                elif request.ecosystem == "npm":
                    reputation = _reputation_npm(request.display_name, evidence, provenance, ids, repository)
                else:
                    reputation = _reputation_pypi(request.name, evidence, ids, repository, pypi_extra["yanked"])
            except _SHAPE_ERRORS as exc:
                # An optional provider can only make a package
                # unresolved. A malformed answer is not a reason to deny every
                # install, and never a reason to call it established.
                reputation = _empty_reputation()
                reputation["unmet"] = [f"reputation evidence was malformed ({type(exc).__name__})"]
            _apply_trust(reputation, trust, evidence, risk_signals)
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
        "hard_findings": hard_findings,
        "risk_signals": risk_signals,
    }


def create_review(request, root, session_id: str | None = None) -> dict:
    """Vet one package request, write the review report, return it.

    `session_id` (from the hook event) lets the Stop hook find reviews that
    were opened in the current session and are still unresolved.
    """
    review_id = store.new_review_id()
    found = gather(request, root)
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
        },
        "hard_findings": hard_findings,
        "risk_signals": risk_signals,
        "verdict": verdict,
        "retry_command": _retry_command(request, version) if version else None,
    }
    store.write_report(root, report)
    return report
