"""Baselines of upstream Frappe apps (v1.12, P4).

A baseline is the dependency set of ONE upstream app at ONE commit, approved by a
human as a unit. This module is the part the hook and the CLI both
read: the document's canonical form and id, the storage, the git-owners
allowlist, how a working tree is matched to a baseline by manifest digests, what
a baseline covers, the custom-app per-package check, the acceptance of a git source
inside a baseline, the audit cache and the approval prompt. `baseline_plan.py` builds a
proposal (it needs the network and uv); nothing here does.

The rules this file protects:

  * A baseline exists only for an upstream app: its repository is
    https://github.com/<owner>/<repo> with <owner> in the allowlist. A custom
    app is never baselined; every package it adds is reviewed one by one.
  * Coverage comes from ONE thing: the manifest digests of the tree equal the
    digests the baseline recorded. The commit is a name, never a match.
  * `MAL-` always blocks. Advisories are information and never block.
  * The id is derived from the identity content, so a changed file is a
    different baseline (and `show` and `approve` recompute it).

Standard library only.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import time
import tomllib
from pathlib import Path

import bench_config
import legacy
import store

SCHEMA_VERSION = 1

# Bounds, defaults and deadlines of the baseline feature. Not in the constants block the
# constants check binds to the hook modules.
BASELINE_MAX_PACKAGES = 3000
BASELINE_MAX_BYTES = 8 * 1024 * 1024
GIT_OWNERS_DEFAULT = ("frappe", "quilljs")
GIT_HOSTS_DEFAULT = ("github.com",)
BASELINE_PLAN_DEADLINE = 600
BASELINE_FETCH_CONCURRENCY = 8
# The cache `cli.py audit` writes is read by the hook for at most this long.
AUDIT_CACHE_SECONDS = 24 * 3600
# Frappe app names that are local in every bench and every plan,
# whether or not they are present. The release refreshes
# the list with the applications under github.com/frappe that have a hooks.py.
FRAPPE_APP_NAMES = (
    "frappe", "erpnext", "hrms", "payments", "webshop", "crm", "builder", "drive",
    "insights", "wiki", "lms", "helpdesk", "healthcare", "lending", "education",
    "non_profit", "bench_manager",
)

BASELINES_DIRNAME = "baselines"
PROPOSALS_DIRNAME = "proposals"
OWNERS_FILENAME = "git-owners.json"
AUDIT_CACHE_FILENAME = "audit-cache.json"
MALWARE_LATCH_FILENAME = "malware-latch.json"

_JOINT_KEYS = {"git_url", "commit", "names", "version", "release"}
IDENTITY_KEYS = ("schema_version", "kind", "app", "base", "manifests", "python", "js", "legacy")
# Never part of the identity: they change between a proposal and its approval and
# with the date of the query.
OUTSIDE_IDENTITY = ("id", "document_sha256", "approval", "approvable", "evidence")

_ID = re.compile(r"bl-[0-9a-f]{12}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_REPO_URL = re.compile(r"https://(?P<host>github\.com)/(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?\Z")
_REGISTRY_HOSTS = ("registry.yarnpkg.com", "registry.npmjs.org")


class BaselineError(Exception):
    """A baseline document or store is unusable. The message names why."""


def normalize_py(name: str) -> str:
    """PEP 503 normalisation: for Python names only. npm names are case and
    punctuation sensitive (`lodash.merge` is not `lodash-merge`)."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


# ---------------------------------------------------------------------------
# Text: CRLF to LF, a bare CR refused
# ---------------------------------------------------------------------------

def normalized_bytes(data: bytes, where: str = "file") -> bytes:
    """`data` with each CRLF replaced by LF. A CR that remains refuses the file."""
    out = data.replace(b"\r\n", b"\n")
    if b"\r" in out:
        raise BaselineError(f"{where} holds a bare carriage return; Package Guard reads LF or CRLF only")
    return out


def sha256_text_file(data: bytes, where: str = "file") -> str:
    return hashlib.sha256(normalized_bytes(data, where)).hexdigest()


# ---------------------------------------------------------------------------
# The canonical form and the id
# ---------------------------------------------------------------------------

_PY_NAME_PATHS = (
    ("python", "pins"), ("python", "git"), ("python", "needs_build"),
)


def _reject_floats(value, where="$"):
    if isinstance(value, float):
        raise BaselineError(f"{where}: a float is not allowed in a baseline (integers only)")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_floats(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_floats(item, f"{where}[{index}]")


def _sort_arrays(value):
    """Every array sorted by the canonical text of its elements, so the order
    uv or the lock happened to report never changes the id."""
    if isinstance(value, dict):
        return {key: _sort_arrays(item) for key, item in value.items()}
    if isinstance(value, list):
        items = [_sort_arrays(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False,
                                                         separators=(",", ":")))
    return value


def identity_content(doc: dict) -> dict:
    """The part of `doc` the id is derived from, normalised: PEP 503 names for
    Python packages, every array sorted, integers only."""
    content = {}
    for key in IDENTITY_KEYS:
        if key not in doc:
            raise BaselineError(f"the document has no {key!r}")
        content[key] = copy.deepcopy(doc[key])
    _reject_floats(content)
    python = content["python"]
    if not isinstance(python, dict):
        raise BaselineError("python is not an object")
    for section, field in _PY_NAME_PATHS:
        for item in python.get(field) or []:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                item["name"] = normalize_py(item["name"])
    if isinstance(python.get("excluded_local_names"), list):
        python["excluded_local_names"] = [normalize_py(n) for n in python["excluded_local_names"]]
    compile_ = python.get("compile")
    if isinstance(compile_, dict):
        for field in ("dependency_metadata_override", "overrides"):
            if isinstance(compile_.get(field), list):
                compile_[field] = [normalize_py(n) for n in compile_[field]]
    return _sort_arrays(content)


def canonical_bytes(doc: dict) -> bytes:
    """Sorted keys, no insignificant whitespace, UTF-8 with ensure_ascii off."""
    return json.dumps(identity_content(doc), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def document_sha256(doc: dict) -> str:
    return hashlib.sha256(canonical_bytes(doc)).hexdigest()


def baseline_id(doc: dict) -> str:
    return "bl-" + document_sha256(doc)[:12]


def seal(doc: dict) -> dict:
    """`doc` with `document_sha256` and `id` set from its identity content."""
    sealed = dict(doc)
    sealed["document_sha256"] = document_sha256(doc)
    sealed["id"] = "bl-" + sealed["document_sha256"][:12]
    return sealed


# ---------------------------------------------------------------------------
# Shape: what a reader needs to be true before it trusts a document
# ---------------------------------------------------------------------------

def _is_str(v):
    return isinstance(v, str) and v != ""


def shape_problems(doc) -> list:
    """Every way `doc` is not a baseline this version reads. The check is the
    one the baseline JSON schema states; a test holds the two together."""
    if not isinstance(doc, dict):
        return ["the document is not a JSON object"]
    problems = []

    def need(cond, msg):
        if not cond:
            problems.append(msg)

    need(doc.get("schema_version") == SCHEMA_VERSION, f"schema_version is not {SCHEMA_VERSION}")
    need(doc.get("kind") == "upstream", "kind is not 'upstream' (there are no baselines of custom apps)")
    need(isinstance(doc.get("id"), str) and _ID.match(doc["id"]), "id is not bl-<12 hex>")
    need(isinstance(doc.get("document_sha256"), str) and _SHA256.match(doc["document_sha256"]),
         "document_sha256 is not 64 hex")
    app = doc.get("app")
    if not isinstance(app, dict):
        problems.append("app is not an object")
    else:
        for key in ("name", "dir_name", "git_url", "commit", "commit_date"):
            need(_is_str(app.get(key)), f"app.{key} is missing")
        need(isinstance(app.get("git_url"), str) and _REPO_URL.match(app["git_url"]),
             "app.git_url is not https://github.com/<owner>/<repo>")
        need(isinstance(app.get("commit"), str) and _COMMIT.match(app["commit"]),
             "app.commit is not a full 40-hex commit")
        need(isinstance(app.get("commit_date"), str) and _DATE.match(app["commit_date"]),
             "app.commit_date is not a UTC timestamp")
    need(isinstance(doc.get("base"), list) and all(isinstance(b, str) and _ID.match(b) for b in doc["base"]),
         "base is not a list of baseline ids")
    manifests = doc.get("manifests")
    if not isinstance(manifests, list) or not all(
            isinstance(m, dict) and _is_str(m.get("path")) and isinstance(m.get("sha256"), str)
            and _SHA256.match(m["sha256"]) and set(m) == {"path", "sha256"} for m in manifests):
        problems.append("manifests is not a list of {path, sha256}")
    python = doc.get("python")
    if not isinstance(python, dict):
        problems.append("python is not an object")
    else:
        for key in ("requires_python", "compile", "pins", "git", "excluded_local_names", "needs_build"):
            need(key in python, f"python.{key} is missing")
        need(all(isinstance(p, dict) and _is_str(p.get("name")) and _is_str(p.get("version"))
                 and p.get("section") in ("run", "dev", "build") for p in python.get("pins") or []),
             "python.pins holds an entry without name, version or section")
        need(isinstance(python.get("pins"), list), "python.pins is not a list")
        need(all(isinstance(g, dict) and _is_str(g.get("name")) and _is_str(g.get("owner"))
                 and _is_str(g.get("repo")) and isinstance(g.get("commit"), str)
                 and _COMMIT.match(g["commit"]) for g in python.get("git") or []),
             "python.git holds an entry that is not name, owner, repo and a full commit")
        for entry in python.get("needs_build") or []:
            if not (isinstance(entry, dict) and _is_str(entry.get("name")) and _is_str(entry.get("reason"))):
                problems.append("python.needs_build holds a malformed entry")
                continue
            need(("commit" in entry) != ("sdist_sha256" in entry),
                 f"needs_build {entry['name']}: exactly one of commit and sdist_sha256")
            need(not ("commit" in entry) or (isinstance(entry["commit"], str) and _COMMIT.match(entry["commit"])),
                 f"needs_build {entry['name']}: commit is not 40 hex")
            need(not ("sdist_sha256" in entry) or (isinstance(entry["sdist_sha256"], str)
                                                   and _SHA256.match(entry["sdist_sha256"])),
                 f"needs_build {entry['name']}: sdist_sha256 is not 64 hex")
        compile_ = python.get("compile")
        need(isinstance(compile_, dict) and compile_.get("no_build") is True,
             "python.compile.no_build is not true")
        joint_with = compile_.get("joint_with") if isinstance(compile_, dict) else None
        need(joint_with is None or (isinstance(joint_with, list) and all(
            isinstance(j, dict) and set(j) in ({"git_url", "commit"}, _JOINT_KEYS) and isinstance(j["git_url"], str)
            and _REPO_URL.match(j["git_url"]) and isinstance(j["commit"], str) and _COMMIT.match(j["commit"])
            and (set(j) == {"git_url", "commit"} or (
                isinstance(j["names"], list) and all(isinstance(n, str) and n for n in j["names"])
                and isinstance(j["version"], str) and isinstance(j["release"], str)))
            for j in joint_with)),
             "python.compile.joint_with is not a list of {git_url, commit, names, version, release}")
        dev = python.get("dev")
        need(dev is None or (isinstance(dev, dict) and set(dev) == {"pinned", "names", "reason"}
                             and isinstance(dev["pinned"], bool) and isinstance(dev["reason"], str)
                             and isinstance(dev["names"], list) and all(isinstance(n, str) and n for n in dev["names"])
                             and (dev["pinned"] or dev["reason"])),
             "python.dev is not {pinned, names, reason} (a reason is required when pinned is false)")
    js = doc.get("js")
    if not isinstance(js, dict) or not isinstance(js.get("locks"), list):
        problems.append("js.locks is not a list")
    else:
        for lock in js["locks"]:
            if not (isinstance(lock, dict) and _is_str(lock.get("path"))
                    and lock.get("format") == "yarn-classic-v1"
                    and isinstance(lock.get("packages"), list) and isinstance(lock.get("git"), list)
                    and isinstance(lock.get("scripts"), list)):
                problems.append("js.locks holds a malformed lock")
                continue
            for pkg in lock["packages"]:
                if not (isinstance(pkg, dict) and _is_str(pkg.get("name")) and _is_str(pkg.get("version"))
                        and isinstance(pkg.get("integrity"), str) and re.match(r"(sha512|sha1)-", pkg["integrity"])
                        and pkg.get("host") in _REGISTRY_HOSTS):
                    problems.append(f"{lock['path']}: a package entry is malformed or from another host")
                    break
            for git in lock["git"]:
                if not (isinstance(git, dict) and _is_str(git.get("name")) and _is_str(git.get("owner"))
                        and _is_str(git.get("repo")) and isinstance(git.get("commit"), str)
                        and _COMMIT.match(git["commit"]) and git.get("form") in ("codeload", "git")):
                    problems.append(f"{lock['path']}: a git entry is malformed")
                    break
    need(isinstance(doc.get("legacy"), dict), "legacy is not an object")
    approval = doc.get("approval")
    if approval is not None:
        need(isinstance(approval, dict) and approval.get("approved_by") == "human"
             and isinstance(approval.get("review_id"), str) and _ID.match(approval["review_id"])
             and isinstance(approval.get("approved_at"), str) and _DATE.match(approval["approved_at"])
             and isinstance(approval.get("allowed_builds"), list)
             and all(isinstance(b, str) and b for b in approval["allowed_builds"])
             and isinstance(approval.get("builds_sha256"), str) and _SHA256.match(approval["builds_sha256"]),
             "approval is malformed")
    return problems


def approval_problems(doc: dict) -> list:
    """Why the approval of `doc` is not the approval of its needs_build list: the
    recorded list must be exactly the document's, and its digest must match."""
    approval = doc.get("approval")
    if approval is None:
        return []
    builds = all_builds(doc)
    problems = []
    if approval.get("allowed_builds") != builds:
        problems.append("the approval's build list is not the baseline's needs_build list")
    if approval.get("builds_sha256") != builds_digest(builds):
        problems.append("the approval's builds_sha256 does not match the build list")
    return problems


def package_count(doc: dict) -> int:
    python = doc.get("python") or {}
    count = len(python.get("pins") or []) + len(python.get("git") or []) + len(python.get("needs_build") or [])
    for lock in (doc.get("js") or {}).get("locks") or []:
        count += len(lock.get("packages") or []) + len(lock.get("git") or [])
    return count


def verify(doc, expected_id=None) -> list:
    """Every reason `doc` is not a sound baseline: shape, then the id and digest
    recomputed from the content (a tampered file fails here), then the bounds."""
    problems = shape_problems(doc)
    if problems:
        return problems
    try:
        recomputed = document_sha256(doc)
    except BaselineError as exc:
        return [str(exc)]
    if doc["document_sha256"] != recomputed:
        problems.append("document_sha256 does not match the content (the file was changed)")
    if doc["id"] != "bl-" + recomputed[:12]:
        problems.append("id does not match the content (the file was changed or renamed)")
    if expected_id is not None and doc["id"] != expected_id:
        problems.append(f"the file holds {doc['id']}, not {expected_id}")
    if package_count(doc) > BASELINE_MAX_PACKAGES:
        problems.append(f"more than {BASELINE_MAX_PACKAGES} packages")
    problems += approval_problems(doc)
    return problems


# ---------------------------------------------------------------------------
# Storage: baselines/<id>.json approved, baselines/proposals/<id>.json planned
# ---------------------------------------------------------------------------

def baselines_dir(root) -> Path:
    return store.guard_dir(root) / BASELINES_DIRNAME


def proposals_dir(root) -> Path:
    return baselines_dir(root) / PROPOSALS_DIRNAME


def owners_path(root) -> Path:
    return store.guard_dir(root) / OWNERS_FILENAME


def latch_path(root) -> Path:
    return baselines_dir(root) / MALWARE_LATCH_FILENAME


def _load_latch(root):
    """{baseline id: [malware labels]}, or None when the file cannot be read: which the caller treats
    as every baseline being latched (fail closed)."""
    try:
        data = json.loads(latch_path(root).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("latched"), dict):
        return None
    return data["latched"]


def clear_latch(root, baseline_id_) -> None:
    """A person revoked or re-approved the baseline: the malware revocation ends here and nowhere else."""
    latched = _load_latch(root)
    if latched is not None and latched.pop(baseline_id_, None) is not None:
        _write_json(latch_path(root), {"schema_version": SCHEMA_VERSION, "latched": latched})


def audit_cache_path(root) -> Path:
    return baselines_dir(root) / AUDIT_CACHE_FILENAME


def _read_json_file(path: Path):
    try:
        size = path.stat().st_size
        if size > BASELINE_MAX_BYTES:
            raise BaselineError(f"{path.name} is larger than {BASELINE_MAX_BYTES} bytes")
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except BaselineError:
        raise
    except (OSError, ValueError, RecursionError) as exc:
        raise BaselineError(f"{path.name} cannot be read ({exc.__class__.__name__}: {exc})") from None


def _write_json(path: Path, data) -> None:
    store._atomic_write_json(path, data)


def load(root, baseline_id_, proposal=False) -> dict:
    """The verified document, or BaselineError."""
    if not isinstance(baseline_id_, str) or not _ID.match(baseline_id_):
        raise BaselineError(f"{baseline_id_!r} is not a baseline id (bl-<12 hex>)")
    path = (proposals_dir(root) if proposal else baselines_dir(root)) / f"{baseline_id_}.json"
    try:
        doc = _read_json_file(path)
    except FileNotFoundError:
        raise BaselineError(f"no {'proposal' if proposal else 'approved baseline'} {baseline_id_}") from None
    problems = verify(doc, baseline_id_)
    if problems:
        raise BaselineError(f"{baseline_id_}: " + "; ".join(problems))
    if proposal and "approval" in doc:
        raise BaselineError(f"{baseline_id_}: a proposal carries no approval")
    if not proposal and "approval" not in doc:
        raise BaselineError(f"{baseline_id_}: an approved baseline carries its approval")
    return doc


def _ids_in(directory: Path) -> list:
    try:
        names = sorted(p.name[:-5] for p in directory.iterdir() if p.is_file() and p.name.endswith(".json"))
    except OSError:
        return []
    return [n for n in names if _ID.match(n)]


def list_ids(root, proposals=False) -> list:
    return _ids_in(proposals_dir(root) if proposals else baselines_dir(root))


def load_approved(root):
    """([documents], [problems]): every approved baseline that verifies, and why
    each file that does not was left out. An unreadable file covers nothing."""
    docs, problems = [], []
    for bid in list_ids(root):
        try:
            docs.append(load(root, bid))
        except BaselineError as exc:
            problems.append(str(exc))
    return docs, problems


def save_proposal(root, doc: dict) -> Path:
    problems = verify(doc)
    if problems:
        raise BaselineError("; ".join(problems))
    clean = {k: v for k, v in doc.items() if k != "approval"}
    path = proposals_dir(root) / f"{clean['id']}.json"
    _write_json(path, clean)
    return path


def all_builds(doc: dict) -> list:
    """Every needs_build item of `doc`, as the exact strings an approval records:
    `<name>@<version>#sha256:<hex>` for a registry sdist, `<name>@<commit>` for a
    git source. This is the list a person confirms, once, when they approve."""
    return sorted(registry_builds(doc) + git_builds(doc))


def builds_digest(items) -> str:
    """The sha256 of the sorted build list: the approval is bound to exactly it."""
    return hashlib.sha256("\n".join(sorted(items)).encode("utf-8")).hexdigest()


def approve_document(doc: dict, now=None) -> dict:
    """`doc` (a verified proposal) with its approval. The approval is outside the id,
    and it carries exactly the document's needs_build list and its digest: a person
    confirms the whole list in one typed act or approves nothing, so there is no
    approval of some of the builds."""
    approved = {k: v for k, v in doc.items() if k != "approvable"}
    builds = all_builds(doc)
    approved["approval"] = {
        "review_id": doc["id"], "approved_at": now or store.utcnow(), "approved_by": "human",
        "allowed_builds": builds, "builds_sha256": builds_digest(builds),
    }
    return approved


def write_approved(root, approved: dict) -> Path:
    problems = verify(approved)
    if problems or "approval" not in approved:
        raise BaselineError("; ".join(problems) or "no approval to write")
    path = baselines_dir(root) / f"{approved['id']}.json"
    _write_json(path, approved)
    try:
        (proposals_dir(root) / f"{approved['id']}.json").unlink()
    except OSError:
        pass
    return path


def revoke(root, baseline_id_) -> bool:
    """Withdraw an approval. The document returns to proposals, without its
    approval; nothing is declined. True when an approval existed."""
    try:
        doc = load(root, baseline_id_)
    except BaselineError:
        path = baselines_dir(root) / f"{baseline_id_}.json"
        try:
            path.unlink()
            clear_latch(root, baseline_id_)
            return True
        except OSError:
            return False
    proposal = {k: v for k, v in doc.items() if k != "approval"}
    proposal["approvable"] = not (doc.get("evidence", {}).get("osv", {}).get("malware"))
    _write_json(proposals_dir(root) / f"{baseline_id_}.json", proposal)
    (baselines_dir(root) / f"{baseline_id_}.json").unlink()
    cache = _load_audit_cache(root)
    if cache["checked"].pop(baseline_id_, None) is not None:
        _write_json(audit_cache_path(root), cache)
    clear_latch(root, baseline_id_)
    return True


def export_document(root, baseline_id_) -> dict:
    """The document as a team shares it: identity content and evidence, never the approval."""
    try:
        doc = load(root, baseline_id_)
    except BaselineError:
        doc = load(root, baseline_id_, proposal=True)
    return {k: v for k, v in doc.items() if k not in ("approval", "approvable")}


def proposal_from_import(data) -> dict:
    """What `import` writes: the identity content only. `approval`, `approvable`
    and `evidence` are dropped; the id is recomputed, never trusted."""
    problems = shape_problems(data)
    if problems:
        raise BaselineError("not a baseline this version reads: " + "; ".join(problems))
    doc = {k: v for k, v in data.items() if k in IDENTITY_KEYS}
    doc["evidence"] = {
        "osv": {"checked_at": "1970-01-01T00:00:00Z", "entries_checked": 0, "malware": [],
                "advisory_count": 0, "worst": []},
        "sha1_crosscheck": {"checked": 0, "mismatches": []},
    }
    sealed = seal(doc)
    if sealed["id"] != data.get("id") or sealed["document_sha256"] != data.get("document_sha256"):
        raise BaselineError("the file's id does not match its content; it was changed")
    sealed["approvable"] = False
    return sealed


# ---------------------------------------------------------------------------
# The git-owners allowlist
# ---------------------------------------------------------------------------

def load_owners(root):
    """(owners, hosts). Absent file: the defaults. A file that cannot be read is
    an error, never an empty-means-everything list."""
    path = owners_path(root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return tuple(GIT_OWNERS_DEFAULT), tuple(GIT_HOSTS_DEFAULT)
    except (OSError, ValueError, RecursionError) as exc:
        raise BaselineError(f"{OWNERS_FILENAME} cannot be read ({exc}); fix or remove it") from None
    owners, hosts = data.get("owners") if isinstance(data, dict) else None, data.get("hosts") if isinstance(data, dict) else None
    if (not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION
            or not isinstance(owners, list) or not isinstance(hosts, list)
            or not all(isinstance(o, str) and re.fullmatch(r"[A-Za-z0-9-]+", o) for o in owners)
            or not all(h == "github.com" for h in hosts) or not hosts):
        raise BaselineError(f"{OWNERS_FILENAME} is malformed; fix or remove it")
    return tuple(owners), tuple(hosts)


def save_owners(root, owners) -> None:
    _write_json(owners_path(root), {"schema_version": SCHEMA_VERSION, "owners": sorted(set(owners)),
                                    "hosts": list(GIT_HOSTS_DEFAULT)})


def edit_distance(a: str, b: str) -> int:
    a, b = a.lower(), b.lower()
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def nearest_owner(owner: str, owners) -> tuple:
    """(the allowlisted name nearest to `owner`, its edit distance), or (None, None)."""
    best = None
    for candidate in owners:
        distance = edit_distance(owner, candidate)
        if best is None or distance < best[1]:
            best = (candidate, distance)
    return best if best else (None, None)


def repo_parts(url) -> tuple | None:
    """(owner, repo) of an https://github.com/<owner>/<repo> URL, else None."""
    match = _REPO_URL.match(url) if isinstance(url, str) else None
    return (match.group("owner"), match.group("repo")) if match else None


def owner_problem(url, owners) -> str | None:
    parts = repo_parts(url)
    if parts is None:
        return f"{url!r} is not https://github.com/<owner>/<repo>"
    if parts[0] not in owners:
        near, distance = nearest_owner(parts[0], owners)
        hint = f" (nearest allowlisted name: {near!r}, {distance} edit(s) away)" if near else ""
        return (f"the owner {parts[0]!r} is not in the git-owners allowlist{hint}; a baseline exists only "
                "for an upstream app, and only a person adds an owner")
    return None


# ---------------------------------------------------------------------------
# Manifests: what the installer reads, and its digests
# ---------------------------------------------------------------------------

_SKIP_DIRS = frozenset({"node_modules", ".git", "__pycache__", ".hg", ".svn"})
_ROOT_FILES = ("pyproject.toml", "setup.py", "setup.cfg")
_REQUIREMENTS_NAME = re.compile(r"(?:.*[-_.])?requirements[^/]*\.txt\Z", re.IGNORECASE)
_INCLUDE = re.compile(r"^(?:-r|-c|--requirement|--constraint)(?:\s+|=)(\S+)\s*(?:#.*)?$")
_OPTION = re.compile(r"^-")


class FsTree:
    """A checked-out app directory, read as the installer would."""

    def __init__(self, root):
        self.root = Path(root)

    def paths(self):
        found = []
        for current, dirs, files in os.walk(self.root):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
            base = Path(current).relative_to(self.root)
            for name in sorted(files):
                found.append((base / name).as_posix())
        return found

    def read(self, path):
        target = self.root / path
        if target.is_symlink():
            raise BaselineError(f"{path} is a symbolic link")
        return target.read_bytes()


class MapTree:
    """A tree held in memory ({path: bytes}): a fetched commit, or a test."""

    def __init__(self, files):
        self.files = dict(files)

    def paths(self):
        return sorted(self.files)

    def read(self, path):
        try:
            return self.files[path]
        except KeyError:
            raise FileNotFoundError(path) from None


def _is_doctype_json(data: bytes) -> bool:
    """A Frappe DocType definition is also called package.json when the doctype is
    named Package; no installer reads it."""
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return False
    return isinstance(parsed, dict) and "doctype" in parsed


def requirement_lines(text: str):
    """(requirement lines, include paths, option lines) of a requirements file."""
    lines, includes, options = [], [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        include = _INCLUDE.match(line)
        if include:
            includes.append(include.group(1))
        elif _OPTION.match(line):
            options.append(line)
        else:
            lines.append(re.split(r"\s+#", line, maxsplit=1)[0].strip())
    return lines, includes, options


def requirement_parts(text: str):
    """(requirement lines, `-r` includes, `-c` includes, option lines): a `-r` file adds
    requirements, a `-c` file only constrains versions and adds none."""
    lines, requirements, constraints, options = [], [], [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        include = _INCLUDE.match(line)
        if include:
            (constraints if line.startswith(("-c", "--constraint")) else requirements).append(include.group(1))
        elif _OPTION.match(line):
            options.append(line)
        else:
            lines.append(re.split(r"\s+#", line, maxsplit=1)[0].strip())
    return lines, requirements, constraints, options


_SETUP_KEYS = ("install_requires", "extras_require", "setup_requires", "tests_require")


def _opens_requirements(node) -> bool:
    import ast
    return (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "open" and bool(node.args)
            and isinstance(node.args[0], ast.Constant) and node.args[0].value == "requirements.txt")


def _requirements_readers(tree) -> set:
    """Names assigned from a read of requirements.txt: `X = open("requirements.txt").read()...`, or
    `with open("requirements.txt") as f: X = f.read()...`."""
    import ast
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(_opens_requirements(n) for n in ast.walk(node.value)):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        if isinstance(node, ast.With):
            handles = {i.optional_vars.id for i in node.items
                       if _opens_requirements(i.context_expr) and isinstance(i.optional_vars, ast.Name)}
            for inner in node.body:
                for assign in ast.walk(inner):
                    if isinstance(assign, ast.Assign) and any(isinstance(n, ast.Name) and n.id in handles
                                                              for n in ast.walk(assign.value)):
                        names |= {t.id for t in assign.targets if isinstance(t, ast.Name)}
    return names


def setup_py_problems(text: str, allow_dependency_links=False) -> tuple:
    """(reads_requirements_txt, [why not]) for a setup.py, read as syntax and never run.

    The one shape accepted is the one `bench new-app` and Frappe write: `install_requires`
    handed a name that is assigned from a read of `requirements.txt`, and no other dependency
    keyword. Anything else that mentions a dependency keyword (a literal list, extras,
    setup_requires, tests_require, `**kwargs`, a name assigned from something else, or a setup()
    that cannot be found) is refused: a harmless-looking setup.cfg beside it proves nothing about
    what setup.py reads. `dependency_links` is a source redirect modern pip ignores; refused for a
    custom app, tolerated for an upstream app whose setup.py a baseline hashes."""
    import ast
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as exc:
        return False, [f"setup.py cannot be read ({exc})"]
    problems = []
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and (getattr(n.func, "id", None) == "setup" or getattr(n.func, "attr", None) == "setup")]
    mentions = any(key in text for key in (*_SETUP_KEYS, "dependency_links"))
    if not calls:
        return False, (["setup.py has no setup() call the guard can read, and mentions dependencies"] if mentions else [])
    reads = False
    for call in calls:
        for keyword in call.keywords:
            if keyword.arg is None:
                problems.append("setup() is given **kwargs, so what it declares is not static")
            elif keyword.arg in ("extras_require", "setup_requires", "tests_require"):
                problems.append(f"setup() declares {keyword.arg}, which the guard does not read from setup.py")
            elif keyword.arg == "dependency_links" and not allow_dependency_links:
                problems.append("setup() declares dependency_links, a source redirect")
            elif keyword.arg == "install_requires":
                value = keyword.value
                if isinstance(value, ast.Name) and value.id in _requirements_readers(tree):
                    reads = True
                else:
                    problems.append("setup() declares install_requires in a form other than a read of requirements.txt")
    return reads, problems


def setup_cfg_requirements(text: str, extras=True) -> tuple:
    """([requirement lines], [requirements files named by `file:`], [problems]) of a setup.cfg:
    install_requires and, with `extras`, setup_requires, tests_require and every extra (a custom
    app's review reads them all; a baseline of an upstream app only what a bench installs)."""
    import configparser
    parser = configparser.ConfigParser(interpolation=None)
    lines, files, problems = [], [], []
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        return [], [], [f"setup.cfg cannot be read ({exc})"]
    if extras:
        if parser.has_option("options", "dependency_links"):
            problems.append("setup.cfg options dependency_links is a source redirect")
        for key in ("find_links", "index_url", "find-links", "index-url"):
            if parser.has_option("easy_install", key):
                problems.append(f"setup.cfg [easy_install] {key} changes where setup_requires packages come from")
    sources = []
    for key in ("install_requires", "setup_requires", "tests_require") if extras else ("install_requires",):
        sources.append((f"options {key}", parser.get("options", key, fallback="")))
    if extras and parser.has_section("options.extras_require"):
        for key, value in parser.items("options.extras_require"):
            sources.append((f"options.extras_require {key}", value))
    for where, raw in sources:
        stripped = raw.strip()
        if stripped.startswith("file:"):
            files += [p.strip() for p in stripped[5:].split(",") if p.strip()]
        elif stripped.startswith("attr:"):
            problems.append(f"setup.cfg {where} is read from `{stripped}`, which is not static")
        else:
            lines += [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
    return lines, files, problems


def discover_manifests(tree) -> tuple:
    """({path: sha256}, [problems]) for every file the installer reads.

    pyproject.toml, setup.py, setup.cfg and every requirements file at the app
    root; every file those include by -r or -c, transitively; every package.json
    (a DocType definition is not one) and yarn.lock under the app, node_modules
    excluded. Hashed after CRLF to LF. A file that cannot be read or holds a bare
    CR is a problem, never skipped: the set must be closed.
    """
    paths = {p for p in tree.paths() if not set(p.split("/")) & _SKIP_DIRS}
    wanted, problems = set(), []
    for path in paths:
        parts = path.split("/")
        name = parts[-1]
        if len(parts) == 1 and (name in _ROOT_FILES or _REQUIREMENTS_NAME.match(name)):
            wanted.add(path)
        elif name == "yarn.lock":
            wanted.add(path)
        elif name == "package.json":
            if len(parts) == 1:
                wanted.add(path)
            else:
                try:
                    if not _is_doctype_json(tree.read(path)):
                        wanted.add(path)
                except OSError:
                    wanted.add(path)
    digests, queue = {}, sorted(wanted)
    # Files in requirements format: the root-level ones and whatever they include.
    reqfiles = {p for p in wanted if "/" not in p and _REQUIREMENTS_NAME.match(p)}
    while queue:
        path = queue.pop(0)
        if path in digests:
            continue
        try:
            data = tree.read(path)
        except (OSError, BaselineError) as exc:
            problems.append(f"{path} cannot be read ({exc})")
            continue
        try:
            digests[path] = sha256_text_file(data, path)
        except BaselineError as exc:
            problems.append(str(exc))
            continue
        if path in reqfiles:
            try:
                _lines, includes, _options = requirement_lines(normalized_bytes(data, path).decode("utf-8"))
            except UnicodeDecodeError:
                problems.append(f"{path} is not UTF-8")
                continue
            for include in includes:
                target = os.path.normpath(os.path.join(os.path.dirname(path), include)).replace(os.sep, "/")
                if target.startswith("../") or target.startswith("/") or target == "..":
                    problems.append(f"{path} includes {include!r}, outside the app")
                elif target not in paths:
                    problems.append(f"{path} includes {include!r}, which is not in the app")
                elif target not in digests:
                    reqfiles.add(target)
                    queue.append(target)
    return digests, problems


def manifest_list(digests: dict) -> list:
    return [{"path": path, "sha256": digests[path]} for path in sorted(digests)]


# ---------------------------------------------------------------------------
# Matching a tree to a baseline: digests, never the commit
# ---------------------------------------------------------------------------

def tree_matches(doc: dict, tree) -> list:
    """Why `tree` is not the app `doc` describes; [] when every manifest digest
    is equal and no manifest is missing or extra."""
    digests, problems = discover_manifests(tree)
    if problems:
        return problems
    recorded = {m["path"]: m["sha256"] for m in doc["manifests"]}
    problems = []
    for path in sorted(set(recorded) | set(digests)):
        if path not in digests:
            problems.append(f"{path} is in the baseline and not in the app")
        elif path not in recorded:
            problems.append(f"{path} is in the app and not in the baseline")
        elif digests[path] != recorded[path]:
            problems.append(f"{path} differs from the baseline (the app is not at the approved commit, or was edited)")
    return problems


def usable_problems(root, doc: dict, now=None, owners=None, malware_only=False) -> list:
    """Why an approved baseline covers nothing right now: it is not approved, its
    owner left the allowlist, or the audit found malware / has not run lately.
    Local reads only."""
    problems = []
    if "approval" not in doc:
        return ["it is not approved"]
    try:
        allowed = owners if owners is not None else load_owners(root)[0]
    except BaselineError as exc:
        return [str(exc)]
    why = owner_problem(doc["app"]["git_url"], allowed)
    if why:
        problems.append(why)
    clashes = pin_conflicts(doc["python"]["pins"])
    if clashes:
        problems.append("it contradicts itself: " + "; ".join(f"{n} is pinned to {a} and to {b}" for n, a, b in clashes[:4])
                        + f" (planned by an earlier release). Plan the app again: the new plan is one resolution and "
                        f"gets a new id; approve that, and the old one can be revoked (`cli.py baseline revoke {doc['id']}`)")
    problems += audit_problems(root, doc, now, malware_only)
    return problems


def pin_conflicts(pins) -> list:
    """[(name, version, other version)] for one package pinned two ways where both apply: in the same
    constraint file (runtime or build; development pins go into the runtime file) and with markers that can
    hold at once (as `bench_config` unions them)."""
    runtime = lambda section: "build" if section == "build" else "runtime"
    found = []
    for i, pin in enumerate(pins):
        for other in pins[i + 1:]:
            if (normalize_py(other["name"]) == normalize_py(pin["name"]) and other["version"] != pin["version"]
                    and runtime(other["section"]) == runtime(pin["section"])
                    and (not other.get("markers") or not pin.get("markers") or other["markers"] == pin["markers"])):
                item = (normalize_py(pin["name"]), *sorted([pin["version"], other["version"]]))
                if item not in found:
                    found.append(item)
    return sorted(found)


def audit_problems(root, doc: dict, now=None, malware_only=False) -> list:
    """Why the audit cache says `doc` covers nothing: no entry, a stale entry, or
    malware. With `malware_only` only malware counts: what the constraint files
    are built from must not change because an audit is a day old."""
    latched = _load_latch(root)
    if latched is None:
        return ["the malware record of the baselines cannot be read; fix or remove it (a person decides)"]
    if latched.get(doc["id"]):
        return [f"OSV listed malware in {doc['id']} ({', '.join(map(str, latched[doc['id']][:3]))}); that stays in force "
                f"until a person revokes the baseline (`cli.py baseline revoke {doc['id']}`) and approves a new one: "
                "a later clean audit does not lift it"]
    entry = _load_audit_cache(root)["checked"].get(doc["id"])
    if not isinstance(entry, dict):
        return [] if malware_only else [f"the baseline audit has not run for {doc['id']}; run `cli.py audit`"]
    malware = entry.get("malware") or []
    if malware:
        return [f"OSV lists malware in {doc['id']}: {', '.join(map(str, malware[:5]))}; revoke the baseline "
                f"(`cli.py baseline revoke {doc['id']}`) and have a person approve a new one"]
    if malware_only:
        return []
    checked = entry.get("checked_at_epoch")
    current = now if now is not None else time.time()
    if not isinstance(checked, (int, float)) or current - checked > AUDIT_CACHE_SECONDS:
        return [f"the baseline audit for {doc['id']} is older than a day; run `cli.py audit`"]
    return []


def find_match(root, app_dir, now=None, tree=None, malware_only=False):
    """(baseline document, []) when an approved, usable baseline matches the app at
    `app_dir`; else (None, [reasons]). `reasons` are about the closest baseline,
    which is the one for the same directory name."""
    docs, load_problems = load_approved(root)
    tree = tree if tree is not None else FsTree(app_dir)
    digests, problems = discover_manifests(tree)
    if problems:
        return None, problems
    recorded_by = {}
    for doc in docs:
        recorded_by[doc["id"]] = {m["path"]: m["sha256"] for m in doc["manifests"]}
    reasons = []
    for doc in docs:
        if recorded_by[doc["id"]] == digests:
            bad = usable_problems(root, doc, now, malware_only=malware_only)
            if bad:
                reasons.append(f"{doc['id']} matches but {'; '.join(bad)}")
                continue
            return doc, []
    if not reasons:
        reasons = ["no approved baseline has these manifest digests"]
    return None, reasons + load_problems


# ---------------------------------------------------------------------------
# What a baseline covers
# ---------------------------------------------------------------------------

def covered_identities(doc: dict) -> set:
    """{(ecosystem, name, version)} the document lists. Python names PEP 503
    normalised; a registry sdist counts only when the approval allowed its build."""
    covered = set()
    python = doc["python"]
    for pin in python["pins"]:
        covered.add(("pypi", normalize_py(pin["name"]), pin["version"]))
    allowed = set((doc.get("approval") or {}).get("allowed_builds") or [])
    for entry in python["needs_build"]:
        if "sdist_sha256" in entry and entry.get("version"):
            spec = f"{entry['name']}@{entry['version']}#sha256:{entry['sdist_sha256']}"
            if spec in allowed:
                covered.add(("pypi", normalize_py(entry["name"]), entry["version"]))
    for lock in doc["js"]["locks"]:
        for pkg in lock["packages"]:
            covered.add(("npm", pkg["name"], pkg["version"]))
    return covered


def covers(doc: dict, ecosystem: str, name: str, version: str) -> bool:
    name = normalize_py(name) if ecosystem == "pypi" else name
    return (ecosystem, name, version) in covered_identities(doc)


def git_entries_of(doc: dict, lock_path=None) -> set:
    """{(owner, repo, commit, form)} of the JS locks (one lock when named), and
    ('python', owner, repo, commit, name) for the Python direct references."""
    found = set()
    for lock in doc["js"]["locks"]:
        if lock_path is not None and lock["path"] != lock_path:
            continue
        for git in lock["git"]:
            found.add((git["owner"], git["repo"], git["commit"], git["form"]))
    return found


def lock_app_dirs(doc: dict, lock_dir) -> list:
    """The app directories `lock_dir` could be the `<lock path>` directory of,
    one per lock of `doc` whose directory the path ends with."""
    lock_dir = Path(os.path.abspath(lock_dir))
    found = []
    for lock in doc["js"]["locks"]:
        relative = Path(lock["path"]).parent
        if relative == Path("."):
            found.append((lock["path"], lock_dir))
        elif lock_dir.parts[-len(relative.parts):] == relative.parts:
            found.append((lock["path"], Path(*lock_dir.parts[:-len(relative.parts)])))
    return found


def git_entries_ok(root, lock_dir, entry, now=None) -> str | None:
    """None when the lock entry (a Yarn Classic CODELOAD or GIT entry in the
    yarn.lock of `lock_dir`) is accepted, else why not.

    All of: an approved baseline matches the app by manifest digests; it is
    usable (approved, owner still allowlisted, no malware, audit fresh); the
    owner is allowlisted now; and the exact (owner, repo, commit, form) is listed
    in that baseline's lock.
    """
    form = {"codeload": "codeload", "git": "git"}.get(getattr(entry, "kind", None))
    if form is None or not entry.owner or not entry.commit:
        return "it is not a GitHub codeload or git source"
    try:
        owners, _hosts = load_owners(root)
        docs, _problems = load_approved(root)
    except BaselineError as exc:
        return str(exc)
    if entry.owner not in owners:
        return f"the owner {entry.owner!r} is not in the git-owners allowlist"
    why = "no approved baseline covers this app (run `cli.py baseline plan`)"
    for doc in docs:
        for lock_path, app_dir in lock_app_dirs(doc, lock_dir):
            if (entry.owner, entry.repo, entry.commit, form) not in git_entries_of(doc, lock_path):
                continue
            if not app_dir.is_dir():
                continue
            mismatch = tree_matches(doc, FsTree(app_dir))
            if mismatch:
                why = f"{doc['id']} does not match this app: {mismatch[0]}"
                continue
            bad = usable_problems(root, doc, now, owners)
            if bad:
                why = f"{doc['id']}: {bad[0]}"
                continue
            return None
    return why


_NPM_GIT_SPEC = re.compile(
    r"(?:github:|git\+https://github\.com/|https://github\.com/)?(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)"
    r"(?:\.git)?(?:#(?P<ref>[^\s]+))?\Z")
_PY_GIT_REF = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*git\+https://github\.com/"
    r"(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?@(?P<commit>[0-9a-f]{40})\s*(?:;.*)?\Z")


def manifest_app_dirs(doc: dict, directory, filename) -> list:
    """The app directories `directory` could be the directory of a manifest named
    `filename` of, one per manifest of `doc` with that name whose path `directory` ends with."""
    directory = Path(os.path.abspath(directory))
    found = []
    for manifest in doc["manifests"]:
        path = Path(manifest["path"])
        if path.name != filename:
            continue
        relative = path.parent
        if relative == Path("."):
            found.append(directory)
        elif directory.parts[-len(relative.parts):] == relative.parts:
            found.append(Path(*directory.parts[:-len(relative.parts)]))
    return found


def manifest_git_ok(root, directory, ecosystem, name, spec, now=None) -> str | None:
    """None when a manifest's git spec is accepted, else why not.

    The spec is a package.json value (`github:frappe/air-datepicker`, a git+https
    URL, optionally `#<full commit>`) or a pyproject requirement (`name @
    git+https://github.com/<owner>/<repo>@<full commit>`). It is accepted exactly
    as a lock entry is: the app's manifests match an approved, usable baseline by
    digest, the owner is allowlisted now, and the baseline lists that very source
    (owner, repository and, where the spec names one, the commit) for that
    package. The lock or the pinned reference, not the spec, decides what is
    fetched; a branch, tag or short hash is refused.
    """
    try:
        owners, _hosts = load_owners(root)
        docs, _problems = load_approved(root)
    except BaselineError as exc:
        return str(exc)
    if ecosystem == "pypi":
        match = _PY_GIT_REF.match(spec.strip()) if isinstance(spec, str) else None
        if match is None:
            return "it is not a git reference pinned to a full commit"
        owner, repo, commit, want_name = match.group("owner"), match.group("repo"), match.group("commit"), normalize_py(match.group("name"))
        filename = "pyproject.toml"
    else:
        match = _NPM_GIT_SPEC.match(spec.strip()) if isinstance(spec, str) else None
        if match is None:
            return "it is not a GitHub source"
        owner, repo, commit, want_name = match.group("owner"), match.group("repo"), match.group("ref"), name
        if commit is not None and not _COMMIT.match(commit):
            return "a branch, tag or short hash is not a commit"
        filename = "package.json"
    if owner not in owners:
        return f"the owner {owner!r} is not in the git-owners allowlist"
    why = "no approved baseline covers this app (run `cli.py baseline plan`)"
    for doc in docs:
        if ecosystem == "pypi":
            listed = any(normalize_py(g["name"]) == want_name and (g["owner"], g["repo"], g["commit"]) == (owner, repo, commit)
                         for g in doc["python"]["git"])
        else:
            listed = any(g["name"] == want_name and (g["owner"], g["repo"]) == (owner, repo) and commit in (None, g["commit"])
                         for lock in doc["js"]["locks"] for g in lock["git"])
        if not listed:
            continue
        for app_dir in manifest_app_dirs(doc, directory, filename):
            if not app_dir.is_dir():
                continue
            mismatch = tree_matches(doc, FsTree(app_dir))
            if mismatch:
                why = f"{doc['id']} does not match this app: {mismatch[0]}"
                continue
            bad = usable_problems(root, doc, now, owners)
            if bad:
                why = f"{doc['id']}: {bad[0]}"
                continue
            return None
    return why


# ---------------------------------------------------------------------------
# The audit cache: written by `cli.py audit`, read by the hook
# ---------------------------------------------------------------------------

def _load_audit_cache(root) -> dict:
    """Fails closed: an unreadable cache is an empty one, so nothing is fresh."""
    try:
        data = json.loads(audit_cache_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {"schema_version": SCHEMA_VERSION, "checked": {}}
    if not isinstance(data, dict) or not isinstance(data.get("checked"), dict):
        return {"schema_version": SCHEMA_VERSION, "checked": {}}
    return data


def record_audit(root, baseline_id_, entries, advisories, malware, checked_at=None, epoch=None) -> None:
    """Write the audit result. Malware latches: the id stays revoked, whatever later audits say, until
    `clear_latch` (a person's revoke or re-approval)."""
    if malware:
        latched = _load_latch(root) or {}
        latched[baseline_id_] = sorted(set(latched.get(baseline_id_, [])) | set(malware))
        _write_json(latch_path(root), {"schema_version": SCHEMA_VERSION, "latched": latched})
    cache = _load_audit_cache(root)
    cache["checked"][baseline_id_] = {
        "checked_at": checked_at or store.utcnow(),
        "checked_at_epoch": epoch if epoch is not None else time.time(),
        "entries": entries, "advisories": advisories, "malware": sorted(malware),
    }
    _write_json(audit_cache_path(root), cache)


def audit_entries(doc: dict) -> dict:
    """{ecosystem: [(name, version)]} every identity OSV is asked about for `doc`."""
    out = {"pypi": [], "npm": []}
    seen = set()

    def add(ecosystem, name, version):
        key = (ecosystem, name, version)
        if key not in seen:
            seen.add(key)
            out[ecosystem].append((name, version))

    for pin in doc["python"]["pins"]:
        add("pypi", pin["name"], pin["version"])
    for entry in doc["python"]["needs_build"]:
        if entry.get("version") and "sdist_sha256" in entry:
            add("pypi", entry["name"], entry["version"])
    for lock in doc["js"]["locks"]:
        for pkg in lock["packages"]:
            add("npm", pkg["name"], pkg["version"])
    return out


def audit_baselines(root, osv_batch, batch_size, now=None) -> dict:
    """Ask OSV about every approved baseline, in as many batches as it takes, and
    write the cache. {id: {"malware": [...], "advisories": n}}; ProviderError
    propagates and nothing is written for a baseline whose check did not finish.

    One batch call carries at most `batch_size` queries of one ecosystem and may
    mix baselines, so a bench of 2,081 locked packages costs three calls.
    """
    docs, _problems = load_approved(root)
    wanted = {}
    for doc in docs:
        for ecosystem, pairs in audit_entries(doc).items():
            for pair in pairs:
                wanted.setdefault((ecosystem, pair), []).append(doc["id"])
    answers, calls = {}, 0
    for ecosystem in ("npm", "pypi"):
        pairs = sorted(pair for (eco, pair) in wanted if eco == ecosystem)
        for start in range(0, len(pairs), batch_size):
            calls += 1
            for pair, ids in osv_batch(ecosystem, pairs[start:start + batch_size]).items():
                answers[(ecosystem, pair)] = ids
    result = {}
    stamp, epoch = store.utcnow(), (now if now is not None else time.time())
    for doc in docs:
        malware, advisories, entries = [], 0, 0
        for ecosystem, pairs in audit_entries(doc).items():
            for pair in pairs:
                entries += 1
                ids = answers.get((ecosystem, pair)) or []
                advisories += 1 if ids else 0
                malware += [f"{ecosystem}:{pair[0]}@{pair[1]} {i}" for i in ids if i.startswith("MAL-")]
        record_audit(root, doc["id"], entries, advisories, malware, stamp, epoch)
        result[doc["id"]] = {"malware": malware, "advisories": advisories, "entries": entries}
    result["_calls"] = calls
    return result


# ---------------------------------------------------------------------------
# The custom-app check: every declared package is reviewed, always
# ---------------------------------------------------------------------------

_NPM_EXACT = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?\Z")
_PY_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*")
_PY_EXACT = re.compile(r"\s*===?\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*(?:;.*)?\Z")


def _python_requirement(text):
    """(normalized name, exact version or None, direct-reference?) of one requirement."""
    text = text.split(" #", 1)[0].strip()
    match = _PY_NAME.match(text)
    if not match:
        return None, None, False
    name, rest = normalize_py(match.group(1)), text[match.end():]
    if rest.startswith("@") or "://" in text or text.startswith((".", "/", "~")):
        return name, None, True
    exact = _PY_EXACT.match(rest.split(";", 1)[0])
    return name, (exact.group(1) if exact and "," not in rest.split(";", 1)[0] else None), False


_KNOWN_APPS = frozenset(normalize_py(n) for n in FRAPPE_APP_NAMES)
# The build backends whose extra build requirements are all in files the guard reads: flit_core asks for
# none, setuptools for `setup_requires` (setup.cfg, setup.py). Any other backend (hatchling's
# `tool.hatch...dependencies`, a plugin, an in-tree `backend-path`) can ask for packages nobody reviewed.
_READABLE_BACKENDS = ("flit_core.buildapi", "setuptools.build_meta", "setuptools.build_meta:__legacy__")
_READABLE_BACKENDS_TEXT = "flit_core (`flit_core.buildapi`) or setuptools (`setuptools.build_meta`)"
UV_DEFAULT_BUILD_REQUIREMENT = "setuptools>=40.8.0"
_DEFAULT_BUILD_WHERE = "build-system.requires (uv's default: the app declares no [build-system])"
# `[tool.uv]` keys that change where a package comes from, or which versions can be chosen, when uv
# installs the app (`uv pip install -e apps/<app>` reads them): approving a name and a version
# would not cover what is installed.
_UV_SOURCE_KEYS = ("sources", "index", "index-url", "extra-index-url", "find-links", "override-dependencies",
                   "constraint-dependencies", "workspace")


def declared_dependencies(app_dir, local_names=(), specs=None):
    """(declared, refused) for a custom app: every direct dependency it names, as
    (ecosystem, name, exact version or None, where), and the reasons the declared
    set cannot be read at all (dynamic dependencies, an option line, a source that
    is not the registry). Names in `local_names` are the bench's own apps and are
    not packages to review. A list passed as `specs` receives (name, requirement text, where)
    of every Python requirement, so a range can be judged as it was written."""
    app_dir = Path(app_dir)
    local = {normalize_py(n) for n in local_names}
    declared, refused = [], []

    def add_python(where, text):
        name, version, direct = _python_requirement(text)
        if name is None:
            refused.append(f"{where}: {text!r} is not a requirement Package Guard can read")
        elif direct:
            refused.append(f"{where}: {name} is a git, URL or path source; only a baseline of an upstream "
                           "app accepts those, and a custom app has none")
        elif name in local:
            pass
        elif name in _KNOWN_APPS:
            refused.append(f"{where}: {name} is a Frappe app that is not in this bench. An app comes from "
                           "`bench get-app`, which is the user's command, never from PyPI: Package Guard will "
                           "not review it as a package")
        else:
            declared.append(("pypi", name, version, where))
            if specs is not None:
                specs.append((name, text, where))

    def read_text(path):
        try:
            return normalized_bytes(path.read_bytes(), path.name).decode("utf-8")
        except (OSError, UnicodeDecodeError, BaselineError) as exc:
            refused.append(f"{path.name} cannot be read ({exc})")
            return None

    pyproject = app_dir / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(read_text(pyproject) or "")
        except tomllib.TOMLDecodeError as exc:
            refused.append(f"pyproject.toml cannot be read ({exc})")
            data = {}
        project = data.get("project") if isinstance(data.get("project"), dict) else {}
        dynamic = project.get("dynamic") if isinstance(project.get("dynamic"), list) else []
        for field in ("dependencies", "optional-dependencies"):
            if field in dynamic:
                refused.append(f"pyproject.toml declares {field} dynamically; the guard reads no dynamic dependency")
        uv_table = (data.get("tool") or {}).get("uv") if isinstance(data.get("tool"), dict) else None
        for key in _UV_SOURCE_KEYS if isinstance(uv_table, dict) else ():
            if key in uv_table:
                refused.append(f"pyproject.toml tool.uv.{key} changes where a package comes from (or which "
                               "version can be chosen), so approving a name and a version would not cover what "
                               "gets installed; a custom app cannot declare it")
        for text in project.get("dependencies") or []:
            add_python("pyproject.toml dependencies", text)
        # Optional dependencies are installed when an extra is asked for: reviewed per package too.
        optional = project.get("optional-dependencies")
        for group, items in (optional.items() if isinstance(optional, dict) else ()):
            for text in items if isinstance(items, list) else ():
                add_python(f"pyproject.toml optional-dependencies.{group}", text)
        groups = data.get("dependency-groups")
        for group, items in (groups.items() if isinstance(groups, dict) else ()):
            for item in items if isinstance(items, list) else ():
                if isinstance(item, str):
                    add_python(f"pyproject.toml dependency-groups.{group}", item)
        bench = (data.get("tool") or {}).get("bench") if isinstance(data.get("tool"), dict) else None
        dev = bench.get("dev-dependencies") if isinstance(bench, dict) else None
        for name, spec in (dev.items() if isinstance(dev, dict) else ()):
            add_python("pyproject.toml tool.bench.dev-dependencies",
                       f"{name}{spec}" if str(spec)[:1] in "=~<>!" else f"{name}=={spec}")
        build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
        has_build_system = isinstance(data.get("build-system"), dict)
        requires = build.get("requires")
        if has_build_system and not (isinstance(requires, list) and requires
                                     and all(isinstance(text, str) for text in requires)):
            # A [build-system] with no `requires` list leaves the build requirement to the
            # installer's own default, which nothing names or pins.
            refused.append(f"pyproject.toml build-system.requires {requires!r}: [build-system] must list its "
                           "build requirements, for example requires = [\"flit_core>=3.4,<4\"]")
        for text in requires if isinstance(requires, list) else ():
            if isinstance(text, str):
                add_python("pyproject.toml build-system.requires", text)
        backend = build.get("build-backend")
        if has_build_system and backend is not None and not (
                isinstance(backend, str) and backend.strip() in _READABLE_BACKENDS) or "backend-path" in build:
            refused.append(f"pyproject.toml build-backend {backend!r}: a build backend adds build requirements of its "
                           "own (a plugin, a hook, a configured dependency) that Package Guard cannot read, so none "
                           f"is reviewed or pinned. A custom app may use only {_READABLE_BACKENDS_TEXT}")
    else:
        has_build_system = False
    if not has_build_system:
        # No `[build-system]`: uv builds with its default requirement, which nothing names (uv 0.13.5:
        # `setuptools >= 40.8.0`, backend `setuptools.build_meta:__legacy__`); it is pinned like any other.
        add_python(_DEFAULT_BUILD_WHERE, UV_DEFAULT_BUILD_REQUIREMENT)
    requirement_files = set(p.name for p in app_dir.glob("*.txt") if _REQUIREMENTS_NAME.match(p.name))
    cfg = app_dir / "setup.cfg"
    if cfg.is_file():
        text = read_text(cfg)
        if text is not None:
            cfg_lines, cfg_files, cfg_problems = setup_cfg_requirements(text)
            refused += cfg_problems
            for line in cfg_lines:
                add_python("setup.cfg", line)
            requirement_files |= set(cfg_files)
    setup_py = app_dir / "setup.py"
    if setup_py.is_file():
        text = read_text(setup_py)
        if text is not None:
            reads, why = setup_py_problems(text)
            refused += [f"setup.py: {w}" for w in why]
            if reads:
                requirement_files.add("requirements.txt")
                if not (app_dir / "requirements.txt").is_file():
                    refused.append("setup.py reads requirements.txt, which is not there")
    seen, queue = set(), sorted(requirement_files)
    while queue:
        rel = queue.pop(0)
        if rel in seen:
            continue
        seen.add(rel)
        text = read_text(app_dir / rel)
        if text is None:
            continue
        lines, includes, _constraints, options = requirement_parts(text)
        for option in options:
            refused.append(f"{rel}: the option line {option!r} changes where or how packages are fetched")
        for line in lines:
            add_python(rel, line)
        for include in includes:
            target = os.path.normpath(os.path.join(os.path.dirname(rel), include)).replace(os.sep, "/")
            if target.startswith(("../", "/")) or target == "..":
                refused.append(f"{rel} includes {include!r}, outside the app")
            else:
                queue.append(target)
    for package_json in sorted(app_dir.rglob("package.json")):
        relative = package_json.relative_to(app_dir)
        if any(part in _SKIP_DIRS for part in relative.parts):
            continue
        try:
            data = json.loads(read_text(package_json) or "null")
        except (ValueError, RecursionError):
            refused.append(f"{relative.as_posix()} cannot be read")
            continue
        if not isinstance(data, dict) or ("doctype" in data and len(relative.parts) > 1):
            continue
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(field) or {}).items():
                where = f"{relative.as_posix()} {field}"
                if isinstance(spec, str) and _NPM_EXACT.match(spec):
                    declared.append(("npm", name, spec, where))
                elif isinstance(spec, str) and re.match(r"^(?:[~^<>=*]|\d|x\Z|latest\Z|\s*$)", spec) and "/" not in spec and ":" not in spec:
                    declared.append(("npm", name, None, where))
                else:
                    refused.append(f"{where}: {name} is {spec!r}, a source other than the registry; a custom app "
                                   "has no baseline that could accept it")
    return declared, refused


def custom_app_problems(root, app_dir, local_names=()) -> dict:
    """The per-package review of a custom app. {"refused": [...],
    "unreviewed": [(ecosystem, name, version or None, where)]}: a name that is not
    an exact pin, or is not vetted, needs a review; nothing here is ever covered
    by a baseline."""
    specs = []
    declared, refused = declared_dependencies(app_dir, local_names, specs)
    unreviewed, seen = [], set()
    for ecosystem, name, version, where in declared:
        key = (ecosystem, name, version)
        if key in seen:
            continue
        seen.add(key)
        if version is None:
            # A range is reviewed at one release: the newest approved one every declaration of the name
            # admits is what `config_input` pins, so it needs no review of another.
            if ecosystem == "pypi" and vetted_range_pick(root, name, _installed_texts(specs, name)):
                continue
            unreviewed.append((ecosystem, name, None, where))
            continue
        registry = "https://registry.npmjs.org" if ecosystem == "npm" else "https://pypi.org"
        identity = {"ecosystem": ecosystem, "name": name, "version": version, "registry": registry}
        if not store.is_vetted(root, identity):
            unreviewed.append((ecosystem, name, version, where))
    return {"refused": refused, "unreviewed": unreviewed}


def app_origin_owner(app_dir) -> str | None:
    """The owner of the app repository's `upstream` or `origin` remote, read from
    .git/config without running git; None when there is none or it is not GitHub."""
    config = Path(app_dir) / ".git" / "config"
    try:
        text = config.read_text(encoding="utf-8")
    except OSError:
        return None
    for remote in ("upstream", "origin"):
        match = re.search(r'\[remote "%s"\][^\[]*?url\s*=\s*(\S+)' % remote, text)
        if match:
            parts = repo_parts(match.group(1))
            if parts:
                return parts[0]
    return None


def covering(root, app_dir, local_names=(), now=None) -> dict:
    """What covers the app at `app_dir`.

    {"kind": "baseline", "baseline": doc}: an approved, usable baseline matches by
    digest. Otherwise {"kind": "upstream-uncovered", "reasons": [...]} when the
    app's remote is an allowlisted owner's (the answer is a plan), or {"kind":
    "custom", "refused": [...], "unreviewed": [...]}: the per-package review. The
    label only chooses the denial text; coverage is the digest match alone.
    """
    doc, reasons = find_match(root, app_dir, now)
    if doc is not None:
        return {"kind": "baseline", "baseline": doc}
    try:
        owners = load_owners(root)[0]
    except BaselineError:
        owners = ()
    if app_origin_owner(app_dir) in owners:
        return {"kind": "upstream-uncovered", "reasons": reasons}
    result = custom_app_problems(root, app_dir, local_names)
    result["kind"] = "custom"
    return result


# ---------------------------------------------------------------------------
# The approval prompt and the summary
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def worst_advisories(items, limit=5) -> list:
    """The `limit` worst of {ecosystem, name, version, id, severity} by severity, then id."""
    return sorted(items, key=lambda i: (_SEVERITY_RANK.get(str(i.get("severity") or "").upper(), 9),
                                        str(i.get("id"))))[:limit]


def registry_builds(doc: dict) -> list:
    """The needs_build entries that are registry sdists, as
    <name>@<version>#sha256:<hex>."""
    return sorted(f"{e['name']}@{e['version']}#sha256:{e['sdist_sha256']}"
                  for e in doc["python"]["needs_build"] if "sdist_sha256" in e)


def git_builds(doc: dict) -> list:
    """The needs_build entries that are git sources, as <name>@<commit>."""
    return sorted(f"{e['name']}@{e['commit']}" for e in doc["python"]["needs_build"] if "commit" in e)


def build_lines(doc: dict) -> list:
    """The needs_build list in plain words, one line each: what a person confirms."""
    entries = sorted(doc["python"]["needs_build"], key=lambda e: (e["name"], e.get("version") or "", e.get("commit") or ""))
    if not entries:
        return ["Source builds that run at install: none"]
    lines = [f"These {len(entries)} packages will be built from source on your machine when the bench installs "
             "(their setup code runs):"]
    for entry in entries:
        if "sdist_sha256" in entry:
            lines.append(f"  {entry['name']} {entry['version']}: source archive from the registry, sha256 {entry['sdist_sha256']}")
        else:
            lines.append(f"  {entry['name']}: git commit {entry['commit']}")
    lines.append("Approving, in your own terminal, approves exactly this list and nothing else.")
    return lines


def dev_problem(doc: dict, app_dir=None) -> str:
    """Why `bench` installing this app's development dependencies (it does when `developer_mode` is on) is not
    covered by the baseline: a plain sentence, or "" when it is covered.

    A baseline planned by this release records it (`python.dev`). One planned before has pins of section "dev"
    when the app had development dependencies (v1.12.1 pinned them), so those are covered; one with none
    covers the app only if the app declares none, which the app's own files (their digests are the
    baseline's) say. A file that cannot be read counts as not covered."""
    python = doc["python"]
    record = python.get("dev")
    if isinstance(record, dict):
        return "" if record.get("pinned") is True else (record.get("reason") or "no reason was recorded")
    if any(p["section"] == "dev" for p in python["pins"]):
        return ""
    if app_dir is None:
        return "the baseline does not say whether the development dependencies are pinned"
    app_dir = Path(app_dir)
    try:
        data = tomllib.loads((app_dir / "pyproject.toml").read_text(encoding="utf-8")) \
            if (app_dir / "pyproject.toml").is_file() else {}
        tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
        bench = tool.get("bench") if isinstance(tool.get("bench"), dict) else {}
        declared = bool(bench.get("dev-dependencies")) or (app_dir / "dev-requirements.txt").is_file()
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return "the app's development dependencies cannot be read"
    return ("the baseline was planned before development dependencies were pinned, and the app declares some"
            if declared else "")


def _joint_lines(python: dict) -> list:
    lines = []
    for mate in python["compile"].get("joint_with") or []:
        text = (f"  resolved together with the requirements of {mate['git_url']} at {mate['commit']}"
                " (its packages are not in this list unless this app needs them too)")
        if "release" in mate:
            names = ", ".join(mate["names"]) or "none declared"
            text += f"\n    that app: version {mate['version'] or 'unknown'}; distribution name(s) {names} (left out as local code); "
            if mate["release"] == "none":
                text += ("WARNING: that commit is neither on the release branch for its version nor a release tag. "
                         "Its requirements shaped these pins; check the commit before approving.")
            else:
                text += f"that commit is on its release ({mate['release']})."
        lines.append(text)
    return lines


def prompt_text(doc: dict, owners=None) -> str:
    """The approval prompt, in the order a person needs to decide."""
    app = doc["app"]
    parts = repo_parts(app["git_url"]) or ("?", "?")
    near, distance = nearest_owner(parts[0], owners or GIT_OWNERS_DEFAULT)
    python = doc["python"]
    sections = {}
    for pin in python["pins"]:
        sections[pin["section"]] = sections.get(pin["section"], 0) + 1
    js_count = sum(len(lock["packages"]) for lock in doc["js"]["locks"])
    js_git = [g for lock in doc["js"]["locks"] for g in lock["git"]]
    evidence = doc.get("evidence", {}).get("osv", {})
    lines = [
        f"Package Guard: trust this upstream app's dependency set as one unit ({doc['id']}).",
        f"App: {app['name']} ({app['dir_name']}), {app['git_url']}",
        f"Owner: {parts[0]} (edit distance {distance} from the allowlisted name {near!r})",
        f"Commit: {app['commit']}, dated {app['commit_date']}",
        "Python pins: " + (", ".join(f"{n} {s}" for s, n in sorted(sections.items())) or "none")
        + f"; locked JS packages: {js_count}; git entries: {len(python['git']) + len(js_git)}",
    ]
    lines += _joint_lines(python)
    if python["excluded_local_names"]:
        lines.append("Left out of the resolution as local apps (never installed from a registry): "
                     + ", ".join(python["excluded_local_names"]))
    dev = python.get("dev")
    dev_count = sections.get("dev", 0)
    if not isinstance(dev, dict) and not dev_count:
        pass    # a baseline planned before the record existed: nothing to say
    elif isinstance(dev, dict) and not dev["names"]:
        lines.append("Development dependencies (installed when developer_mode is on): the app declares none")
    elif dev_problem(doc) == "":
        lines.append("Development dependencies (installed when developer_mode is on): pinned, "
                     f"{dev_count} pins, part of this baseline")
    else:
        lines.append("Development dependencies (installed when developer_mode is on): NOT pinned by this baseline: "
                     + dev_problem(doc) + " While developer_mode is on, Package Guard refuses the bench commands "
                     "that install apps; turn developer_mode off for the install. These packages also cannot be installed "
                     "into this bench at all: bench-config writes a constraint no release satisfies for each.")
    for git in python["git"]:
        lines.append(f"  git (Python): {git['name']} from {git['owner']}/{git['repo']} at {git['commit']}")
    for git in js_git:
        lines.append(f"  git (JS): {git['name']} from {git['owner']}/{git['repo']} at {git['commit']} ({git['form']})")
    lines += build_lines(doc)
    scripts = sorted({f"{s['name']}@{s['version']}" for lock in doc["js"]["locks"] for s in lock["scripts"]})
    lines.append("Install scripts stay off for every locked JS package"
                 + (f"; {len(scripts)} carry one: {', '.join(scripts[:8])}"
                    + (f" and {len(scripts) - 8} more" if len(scripts) > 8 else "")
                    if scripts else "")
                 + ". A script that is needed is a separate step for the person.")
    lines += legacy.node_sass_lines(doc)
    if doc["legacy"].get("python_below_3_10") or doc["legacy"].get("reasons"):
        lines.append("Old toolchain: " + "; ".join(doc["legacy"].get("reasons") or ["Python below 3.10"]))
    overrides = python["compile"].get("dependency_metadata_override") or []
    if overrides:
        lines.append(f"dependency-metadata override applied: {', '.join(overrides)}")
    lines.append(f"Advisories (information, they do not block): {evidence.get('advisory_count', 0)} "
                 f"as of {evidence.get('checked_at', 'unknown')}"
                 + ("; worst: " + ", ".join(f"{w['id']} ({w['name']} {w['version']}"
                                            + (f", {w['severity']}" if w.get("severity") else "") + ")"
                                            for w in (evidence.get("worst") or [])[:5])
                    if evidence.get("worst") else ""))
    lines.append("OSV is asked again after you approve, and nothing is written if it lists malware.")
    lines.append("Package Guard pins and checks this set; it does not prevent a package outside it from installing.")
    return "\n".join(lines)


def summary_text(doc: dict, owners=None) -> str:
    """`baseline show`: the prompt, then every pin and lock count."""
    lines = [prompt_text(doc, owners), "", f"Python requires: {doc['python']['requires_python']}; "
             f"compiled with uv {doc['python']['compile']['uv']} for Python "
             f"{doc['python']['compile']['python_version']}, exclude-newer {doc['python']['compile']['exclude_newer']}"]
    if doc["base"]:
        lines.append(f"Compiled with the constraints of: {', '.join(doc['base'])}")
    lines.append(f"Manifests ({len(doc['manifests'])}):")
    lines += [f"  {m['sha256'][:12]}  {m['path']}" for m in doc["manifests"]]
    for lock in doc["js"]["locks"]:
        lines.append(f"Lock {lock['path']}: {lock['entries']} entries, {lock['dangling']} dangling specs, "
                     f"{len(lock['packages'])} registry packages, {len(lock['git'])} git")
    lines.append("Python pins:")
    for pin in sorted(doc["python"]["pins"], key=lambda p: (p["section"], p["name"], p["version"])):
        lines.append(f"  [{pin['section']}] {pin['name']}=={pin['version']}"
                     + (f" ; {pin['markers']}" if pin.get("markers") else ""))
    for entry in doc["python"]["needs_build"]:
        lines.append(f"  [build at install] {entry['name']} {entry.get('version') or entry.get('commit')}: {entry['reason']}")
    if doc["python"]["excluded_local_names"]:
        lines.append("Local app names left out: " + ", ".join(doc["python"]["excluded_local_names"]))
    approval = doc.get("approval")
    lines.append(f"Approved: {approval['approved_at']}, builds confirmed: {len(approval.get('allowed_builds') or [])}"
                 if approval else "Not approved.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# What the guard writes for the installers: the ConfigInput
# ---------------------------------------------------------------------------

_VERSION_LITERAL = re.compile(r"[0-9][A-Za-z0-9.!+_-]*\Z")


def top_level_string(text: str, name: str) -> tuple:
    """(value, None) or (None, why): the plain string literal a module assigns to `name` in its first
    top-level `name = "..."` statement, read from the TOKENS and never parsed as Python. An app's
    source is written for the bench's interpreter (Frappe v16 uses `type X = ...`, 3.12+), which the
    guard's own may be older than, so a parse of the whole file would refuse a value that is plainly
    there. `why` is "absent" when no top-level statement starts `name =`, else the reason that
    statement is not one plain string (a call, an f-string, a concatenation, an annotation...), or
    that the tokens could not be read before it was reached. Exactly three tokens count: NAME, `=`,
    one STRING with no f/b prefix."""
    import ast
    import io
    import tokenize
    line, depth = [], 0
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            kind = token.type
            if kind in (tokenize.COMMENT, tokenize.NL, tokenize.ENCODING):
                continue
            if kind == tokenize.INDENT:
                depth += 1
                continue
            if kind == tokenize.DEDENT:
                depth -= 1
                continue
            if kind in (tokenize.NEWLINE, tokenize.ENDMARKER):
                if line and line[0][1] == name and len(line) > 1 and line[1][1] == "=":
                    if (len(line) == 3 and line[2][0] == tokenize.STRING
                            and not set(line[2][1].partition(line[2][1][-1])[0].lower()) & {"f", "b"}):
                        try:
                            value = ast.literal_eval(line[2][1])
                        except (ValueError, SyntaxError):
                            return None, "the literal cannot be read"
                        return (value, None) if isinstance(value, str) else (None, "not a string")
                    return None, "not a single string literal"
                line = []
                continue
            if not line and depth:
                line = [(None, None)]  # an indented statement is nobody's top level
            if line and line[0] == (None, None):
                continue
            line.append((kind, token.string))
    except (tokenize.TokenError, IndentationError, SyntaxError) as exc:
        return None, f"the tokens before it could not be read ({exc})"
    return None, "absent"


def local_app_version(app_dir) -> tuple:
    """(version, None) or (None, why): the version an app installs as, read
    WITHOUT running anything. A `[project].version` string; or, when the
    version is dynamic (flit, setuptools-from-module: every Frappe app), the
    string literal assigned to `__version__` in the package's `__init__.py`,
    read as syntax. A version computed by a call, an f-string, an import or an
    environment is not static and is refused: a constraint `<dist>==<version>`
    that guessed would let an index answer for the app."""
    app_dir = Path(app_dir)
    try:
        data = tomllib.loads(normalized_bytes((app_dir / "pyproject.toml").read_bytes()).decode("utf-8")) \
            if (app_dir / "pyproject.toml").is_file() else {}
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, BaselineError) as exc:
        return None, f"pyproject.toml cannot be read ({exc})"
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    name = project.get("name") if isinstance(project.get("name"), str) else app_dir.name
    declared = project.get("version")
    dynamic = project.get("dynamic") if isinstance(project.get("dynamic"), list) else []
    if isinstance(declared, str) and "version" not in dynamic:
        return (declared, None) if _VERSION_LITERAL.match(declared) else (None, f"version {declared!r} is not a plain version")
    flit = ((data.get("tool") or {}).get("flit") or {}).get("module") if isinstance(data.get("tool"), dict) else None
    module = (flit.get("name") if isinstance(flit, dict) else None) or normalize_py(name).replace("-", "_")
    candidates = [app_dir / module / "__init__.py"]
    if not (app_dir / "pyproject.toml").is_file() or app_dir.name != module:
        candidates.append(app_dir / app_dir.name / "__init__.py")
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = normalized_bytes(path.read_bytes(), path.name).decode("utf-8")
        except (OSError, UnicodeDecodeError, BaselineError, ValueError) as exc:
            return None, f"{path.relative_to(app_dir)} cannot be read ({exc})"
        value, why = top_level_string(text, "__version__")
        if value is not None and _VERSION_LITERAL.match(value):
            return value, None
        if why == "absent":
            return None, f"{path.relative_to(app_dir)} has no `__version__ = \"...\"` literal, so the version is not static"
        if why is None:
            why = "not a plain version"
        return None, (f"{path.relative_to(app_dir)} sets __version__ by something other than a plain "
                      f"string, so the version is not static ({why})")
    return None, "the app declares no static version (no [project].version and no __version__ literal)"


def baselines_for_bench(root, bench, now=None, malware_only=False) -> tuple:
    """({app directory name: baseline document}, {app directory name: [reasons]}):
    which apps of the bench an approved, usable baseline covers by digest, and
    why each other one is not covered. A custom app is simply uncovered."""
    covered, uncovered = {}, {}
    for app in bench_config.bench_apps(bench):
        doc, reasons = find_match(root, app, now, malware_only=malware_only)
        if doc is not None:
            covered[app.name] = doc
        else:
            uncovered[app.name] = reasons
    return covered, uncovered


def _spec_name(spec: str) -> str:
    return normalize_py(spec.split("@", 1)[0])


def vetted_range_pick(root, name, requirements):
    """The newest release of the PyPI package `name` that a person approved for this project and that
    every one of `requirements` admits; None when there is none or a requirement cannot be judged."""
    import vetting
    try:
        versions = store.vetted_versions(root, "pypi", name, "https://pypi.org", normalize_py)
    except store.StoreError as exc:
        raise BaselineError(f"vetted.json cannot be read ({exc})") from exc
    return vetting.newest_admitted(versions, requirements)


_BUILD_WHERE = "pyproject.toml build-system.requires"
# Declarations that `uv pip install -e apps/<app>` (and a build of it) never installs: an extra, a
# dependency group. They cannot choose the pinned release, but a pin they contradict is refused.
_NOT_INSTALLED = ("pyproject.toml optional-dependencies", "pyproject.toml dependency-groups")


def _installed_texts(specs, name):
    """The requirement texts of `name` that uv installs; its other declarations when it has none."""
    installed = [t for n, t, w in specs if n == name and not w.startswith(_NOT_INSTALLED)]
    return installed or [t for n, t, _w in specs if n == name]


def vetted_range_pick_of(versions, requirements):
    """The newest of `versions` that every one of `requirements` admits, or None."""
    import vetting
    return vetting.newest_admitted(versions, requirements)


def custom_range_pins(root, apps, local_names, runtime, build):
    """([runtime Pin], [build Pin], [(app, name, section, why)] unpinned, {every Python name the custom
    `apps` declare}) for the version ranges the custom `apps` declare.

    `uv pip install` resolves a range to the newest release there is, so the release a person
    approved is not what it installs unless a constraint names it. Each range requirement gets the
    newest approved release that every declaration uv installs admits (in any custom app, exact ones
    included): into the runtime constraint, and for `build-system.requires` into the build
    constraint too (a `setup.cfg` requirement may be either, so both). A declaration uv does not
    install (an extra, a dependency group) does not choose the release, but one that the chosen
    release contradicts makes the name `unpinned` with the pin kept, and so does a range no approved
    release satisfies: the bench verb refuses until the declarations agree. A name that `runtime` /
    `build` (the baselines, the toolchain, the local apps) already pin without a marker has its line;
    no second is written."""
    import bench_config as bc
    wanted = {"runtime": {}, "build": {}}  # section -> {name: [(app, text, installed?)]}
    ranges, names = set(), set()           # ranges: (section, name) with an installed declaration without ==
    for app in apps:
        specs = []
        declared, _refused = declared_dependencies(app, local_names, specs)
        names |= {name for ecosystem, name, _v, _w in declared if ecosystem == "pypi"}
        open_names = {name for _e, name, version, where in declared
                      if version is None and not where.startswith(_NOT_INSTALLED)}
        for name, text, where in specs:
            installed = not where.startswith(_NOT_INSTALLED)
            sections = ("build",) if where in (_BUILD_WHERE, _DEFAULT_BUILD_WHERE) else ("runtime", "build") if where == "setup.cfg" else ("runtime",)
            for section in sections:
                wanted[section].setdefault(name, []).append((Path(app).name, text, installed))
                if name in open_names:
                    ranges.add((section, name))
    pinned = {"runtime": {normalize_py(p.name) for p in runtime if not p.marker},
              "build": {normalize_py(p.name) for p in build if not p.marker}}
    picked, unpinned = {"runtime": [], "build": []}, []
    for section, name in sorted(ranges):
        if name in pinned[section]:
            continue
        found = wanted[section][name]
        version = vetted_range_pick(root, name, [text for _a, text, installed in found if installed])
        apps_of = sorted({a for a, _t, _i in found})
        if not version:
            unpinned.extend((app, name, section, "no approved release satisfies it") for app in apps_of)
            continue
        picked[section].append(bc.Pin(name, version, "", "a custom app"))
        others = [text for _a, text, installed in found if not installed]
        if others and vetted_range_pick_of([version], others) != version:
            unpinned.extend((app, name, section, f"an extra or dependency group of it excludes the approved "
                             f"release {version}") for app in apps_of)
    return picked["runtime"], picked["build"], unpinned, names


def config_input(root, bench, toolchain=(), no_symlinks=False, now=None):
    """The `bench_config.ConfigInput` for `bench`, built from the approved
    baselines of its apps: the union of their pins (run and dev into the runtime constraint, build into the
    build constraint, markers kept), the
    names whose build from source a person allowed, the local app pins and the
    local names that are not present.

    Fails closed, and never writes a partial set: an app whose version is not
    static, an upstream app (its remote is an allowlisted owner's) that no
    baseline covers, or two baselines pinning one name differently, raises
    (BaselineError, bench_config.PinConflict). A custom app is not baselined and
    contributes nothing: its packages are reviewed one by one. The union is built
    from approved, digest-matching baselines of allowlisted owners that the audit
    has not found malware in; a stale audit is its own check and does not change
    the pins. `toolchain` is the pins the person chose (pip, wheel, setuptools).
    """
    import bench_config as bc
    covered, uncovered = baselines_for_bench(root, bench, now, malware_only=True)
    try:
        owners = load_owners(root)[0]
    except BaselineError:
        owners = ()
    for app in bench_config.bench_apps(bench):
        if app.name in uncovered and app_origin_owner(app) in owners:
            raise BaselineError(f"apps/{app.name} is an upstream app no approved baseline covers "
                                f"({'; '.join(uncovered[app.name][:2])}); plan one: `cli.py baseline plan --app apps/{app.name}`")
    runtime, build, allowed, other = [], [], set(), set(normalize_py(n) for n in FRAPPE_APP_NAMES)
    dev_blocked = set()
    for _name, doc in sorted(covered.items()):
        record = doc["python"].get("dev")
        if isinstance(record, dict) and record.get("pinned") is False:
            dev_blocked |= {normalize_py(n) for n in record["names"]}
        for pin in doc["python"]["pins"]:
            item = bc.Pin(normalize_py(pin["name"]), pin["version"], pin.get("markers") or "", doc["id"])
            (build if pin["section"] == "build" else runtime).append(item)
        for spec in (doc.get("approval") or {}).get("allowed_builds") or []:
            allowed.add(_spec_name(spec))
        other |= {normalize_py(n) for n in doc["python"]["excluded_local_names"]}
    local = []
    for app in bench_config.bench_apps(bench):
        version, why = local_app_version(app)
        if version is None:
            raise BaselineError(f"apps/{app.name}: {why}; Package Guard will not pin an app it cannot read a "
                                "version of, because an index could then answer for it")
        try:
            data = tomllib.loads((app / "pyproject.toml").read_text(encoding="utf-8")) if (app / "pyproject.toml").is_file() else {}
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            data = {}
        dist = (data.get("project") or {}).get("name") if isinstance(data.get("project"), dict) else None
        local.append((normalize_py(dist if isinstance(dist, str) else app.name), version))
    present = {name for name, _v in local}
    toolchain = tuple(bc.Pin(normalize_py(t[0]), t[1], "", "toolchain") if not isinstance(t, bc.Pin) else t
                      for t in toolchain)
    custom = [app for app in bench_config.bench_apps(bench) if app.name not in covered]
    names = present | {normalize_py(app.name) for app in custom}
    extra_runtime, extra_build, unpinned, declared_names = custom_range_pins(
        root, custom, names, [*runtime, *toolchain, *(bc.Pin(n, v) for n, v in local)], [*build, *toolchain])
    runtime, build = [*runtime, *extra_runtime], [*build, *extra_build]
    try:  # a package a person approved is a requirement of the bench, whichever package asked for it
        approved = {normalize_py(n) for n in store.vetted_names(root, "pypi")}
    except store.StoreError as exc:
        raise BaselineError(f"vetted.json cannot be read ({exc})") from exc
    config = bc.ConfigInput(
        runtime=tuple(runtime), build=tuple(build), unpinned=tuple(unpinned),
        requirement_names=tuple(sorted({normalize_py(p.name) for p in (*runtime, *build, *toolchain)}
                                       | declared_names | allowed | approved | dev_blocked)),
        toolchain=toolchain, dev_blocked=tuple(sorted(dev_blocked)),
        allowed_builds=tuple(sorted(allowed)), local_apps=tuple(sorted(local)),
        other_local_names=tuple(sorted(other - present)), no_symlinks=no_symlinks)
    try:
        bc.constraint_lines(config)  # two baselines that disagree about a name refuse here, not at write time
    except bc.PinConflict as exc:
        raise BaselineError(_clash_message(str(exc), covered)) from exc
    return config


def _clash_message(text, covered) -> str:
    """Plain words for two approved baselines of one bench that pin a package differently: which two,
    which one to plan again (the later approved), and how."""
    ids = list(dict.fromkeys(re.findall(r"bl-[0-9a-f]{12}", text)))
    by_id = {doc["id"]: (name, doc) for name, doc in covered.items()}
    if len(ids) == 1 and len(re.findall(r"bl-[0-9a-f]{12}", text)) > 1 and ids[0] in by_id:
        # one baseline against itself: planning it again with the same release gives the same id; only a
        # plan from a release that resolves an app as one set gives another
        return (text.split(": the constraint files")[0] + f". {ids[0]} (apps/{by_id[ids[0]][0]}) contradicts itself: "
                "it was planned by an earlier release of Package Guard. Ask the user to plan the app again with "
                f"this release (`cli.py baseline plan --app apps/{by_id[ids[0]][0]}`) and approve the new proposal; "
                f"it resolves the app as one set, and the old baseline can then be revoked "
                f"(`cli.py baseline revoke {ids[0]}`).")
    known = [i for i in ids if i in by_id]
    later = max(known, key=lambda i: (by_id[i][1].get("approval") or {}).get("approved_at") or "") if known else None
    advice = ""
    if later:
        advice = (f" Plan the later one again, apps/{by_id[later][0]} ({later}): ask the user to revoke it "
                  f"(`cli.py baseline revoke {later}`), then `cli.py baseline plan --app apps/{by_id[later][0]}`, "
                  "which resolves it together with the other approved baselines of the bench, or says which "
                  "packages cannot be shared; then the user approves it.")
    return (text.split(": the constraint files")[0] + ". A bench is one Python environment, so its approved "
            "baselines must agree on every package they share." + advice)
