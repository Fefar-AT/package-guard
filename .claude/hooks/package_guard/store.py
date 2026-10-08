"""Vetted-package store and immutable review reports.

All writes are atomic (temp file + os.replace in the same directory).
Malformed state fails closed via StoreError.

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
_REVIEW_ID = re.compile(r"[0-9a-f]{32}")
_VERDICTS = ("review_required", "hard_deny")
_IDENTITY_KEYS = ("ecosystem", "name", "version", "registry")


class StoreError(Exception):
    pass


def project_root(script_file: str | None = None) -> Path:
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return Path(env)
    if script_file is not None:
        # <root>/.claude/hooks/package_guard/<script>
        return Path(script_file).resolve().parents[3]
    raise StoreError("CLAUDE_PROJECT_DIR is not set")


def guard_dir(root: Path) -> Path:
    return Path(root) / ".claude" / "package-guard"


def vetted_path(root: Path) -> Path:
    return guard_dir(root) / "vetted.json"


def reports_dir(root: Path) -> Path:
    return guard_dir(root) / "reports"


def declined_path(root: Path) -> Path:
    return guard_dir(root) / "declined.json"


# The guard's own CLI. Every message that tells the agent to run it must use the
# absolute form: a relative path cannot resolve once the agent has cd-ed into a
# workspace, and the natural repair (`cd <root> && ...`) is compound syntax the
# hook refuses. Both hooks import this module, so the path lives here.
CLI_SUFFIX = ".claude/hooks/package_guard/cli.py"

# The reconciliation layer speaks from three entry points -- the PreToolUse
# gate, the PostToolUse scan and the Stop hook -- with one body. The code lives
# here for the same reason CLI_SUFFIX does: every hook imports this module, and
# a message vocabulary duplicated per entry point drifts apart.
MESSAGE_UNREVIEWED_ON_DISK = "PACKAGE_GUARD_UNREVIEWED_ON_DISK"
MESSAGE_PIN_APPROVED = "PACKAGE_GUARD_PIN_APPROVED"


def cli_path(root) -> str:
    """Absolute path to the guard CLI, so callers never need a `cd` prefix."""
    return str(Path(root) / CLI_SUFFIX)


def cli_command(root, subcommand: str, ids: str) -> str:
    return (
        "uv run --no-project --no-config --no-python-downloads "
        f"{cli_path(root)} {subcommand} {ids}"
    )


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_review_id() -> str:
    return uuid.uuid4().hex


def _default_file_mode() -> int:
    """The mode a normal file would get here, honouring umask.

    Read once at import, while the process is still single-threaded: os.umask is
    process-global and the only way to read it is to set it, which would race
    hook.py's review thread pool if done per write.
    """
    current = os.umask(0)
    os.umask(current)
    return 0o666 & ~current


_DEFAULT_FILE_MODE = _default_file_mode()


def _atomic_write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp always creates at 0600 and os.replace keeps the TEMP file's mode,
    # so without this every write silently narrowed the target -- including
    # vetted.json, which is committed project state. On a shared checkout the
    # second user's load_vetted() then raised StoreError and every package
    # operation denied, with no repair route the agent is permitted to take.
    # Preserve an existing file's mode; create new ones at the umask default.
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = _DEFAULT_FILE_MODE
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Vetted store
# ---------------------------------------------------------------------------

def load_vetted(root: Path) -> dict:
    path = vetted_path(root)
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "packages": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise StoreError(f"vetted.json is unreadable or not valid JSON: {exc}")
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("packages"), list)
    ):
        raise StoreError("vetted.json has an unexpected shape")
    return data


def _identity_key(entry: dict):
    return tuple(entry[k] for k in _IDENTITY_KEYS)


def remove_vetted(root: Path, identity: dict) -> bool:
    """Drop every approval record for one exact identity.

    Returns False when nothing matched. The only writer is `cli.py revoke`,
    behind the same human prompt as `approve`. Nothing is declined by this;
    the identity simply needs a new review before it installs again.
    """
    if not _valid_entry(identity):
        raise StoreError("refusing to revoke an incomplete package identity")
    data = load_vetted(root)
    key = _identity_key(identity)
    kept = [e for e in data["packages"] if not (_valid_entry(e) and _identity_key(e) == key)]
    if len(kept) == len(data["packages"]):
        return False
    data["packages"] = kept
    _atomic_write_json(vetted_path(root), data)
    return True


def _later_approval(root: Path, opened: str, matches) -> dict | None:
    """The first vetted entry satisfying `matches` that was approved after `opened`.

    Second resolution: an approval stamped in the same second as the review is
    still the later decision.
    """
    for entry in load_vetted(root)["packages"]:
        if not _valid_entry(entry) or not matches(entry):
            continue
        approved = entry.get("approved_at")
        if isinstance(approved, str) and approved >= opened:
            return entry
    return None


def superseded_by(root: Path, report: dict, alternative: str | None = None) -> dict | None:
    """The later approval that answered this review.

    Two shapes, one meaning -- *the user moved on, and this review was never a
    decision about this package*:

    - another VERSION of the same package (X@A open, X@B approved after it);
    - the ALTERNATIVE the vetter named for this review, approved after it,
      passed in as `ecosystem:name` from the vetter's machine block.

    Nothing is written; the report stays open on disk and is simply not
    pending. `None` when no such approval exists or the report has no usable
    timestamp.

    The alternative shape exists so such a review closes without a decline. A
    decline says "never install this here" -- a claim nobody made about a
    package that was merely not chosen today.
    """
    identity = report.get("resolved_identity") or {}
    opened = report.get("created_at")
    if not _valid_entry(identity) or not isinstance(opened, str):
        return None
    same_package = _later_approval(root, opened, lambda e: (
        (e["ecosystem"], e["name"], e["registry"])
        == (identity["ecosystem"], identity["name"], identity["registry"])
        and e["version"] != identity["version"]
    ))
    if same_package is not None:
        return same_package
    if not isinstance(alternative, str) or ":" not in alternative:
        return None
    ecosystem, _, name = alternative.partition(":")
    if ecosystem not in ("npm", "pypi") or not name:
        return None
    return _later_approval(root, opened, lambda e: (
        e["ecosystem"] == ecosystem and e["name"] == name
    ))


def vetted_review_id(root: Path, identity: dict) -> str | None:
    """The review id recorded when this exact identity was approved, if any."""
    data = load_vetted(root)
    key = _identity_key(identity)
    for entry in data["packages"]:
        if _valid_entry(entry) and _identity_key(entry) == key:
            rid = entry.get("review_id")
            return rid if isinstance(rid, str) and _REVIEW_ID.fullmatch(rid) else None
    return None


def _valid_entry(entry) -> bool:
    return isinstance(entry, dict) and all(
        isinstance(entry.get(k), str) and entry.get(k) for k in _IDENTITY_KEYS
    )


def vetted_artifacts(root: Path, identity: dict):
    """The approved digests for an identity, or None when none were recorded
    (an approval made before digests were recorded, or an evidence gap)."""
    key = _identity_key(identity)
    for entry in load_vetted(root)["packages"]:
        if _valid_entry(entry) and _identity_key(entry) == key:
            artifacts = entry.get("artifacts")
            if isinstance(artifacts, list) and artifacts and all(isinstance(a, str) for a in artifacts):
                return set(artifacts)
            return None
    return None


def is_vetted(root: Path, identity: dict) -> bool:
    data = load_vetted(root)
    key = _identity_key(identity)
    return any(_valid_entry(e) and _identity_key(e) == key for e in data["packages"])


def add_vetted(root: Path, identity: dict, review_id: str, artifacts=None) -> bool:
    """Append one exact identity. Returns False if it was already vetted.

    `artifacts`: the digests the review saw -- npm's SRI integrity, or
    the sha256 of every PyPI file. An install whose lock names a file outside
    this set is refused (`sources.artifact_problems`)."""
    if not _valid_entry(identity):
        raise StoreError("refusing to vet an incomplete package identity")
    data = load_vetted(root)
    key = _identity_key(identity)
    if any(_valid_entry(e) and _identity_key(e) == key for e in data["packages"]):
        return False
    data["packages"].append(
        {
            "ecosystem": identity["ecosystem"],
            "name": identity["name"],
            "version": identity["version"],
            "registry": identity["registry"],
            "review_id": review_id,
            "approved_at": utcnow(),
            "approved_by": "human",
            **({"artifacts": sorted(set(artifacts))} if artifacts else {}),
        }
    )
    _atomic_write_json(vetted_path(root), data)
    return True


# ---------------------------------------------------------------------------
# Declined store (user rejected a specific reviewed identity)
# ---------------------------------------------------------------------------

def load_declined(root: Path) -> dict:
    path = declined_path(root)
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "reviews": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise StoreError(f"declined.json is unreadable or not valid JSON: {exc}")
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("reviews"), list)
    ):
        raise StoreError("declined.json has an unexpected shape")
    return data


def is_declined(root: Path, identity: dict) -> bool:
    data = load_declined(root)
    key = _identity_key(identity)
    return any(_valid_entry(e) and _identity_key(e) == key for e in data["reviews"])


def declined_review_id(root: Path, identity: dict) -> str | None:
    """The review id recorded when this exact identity was declined, if any."""
    data = load_declined(root)
    key = _identity_key(identity)
    for entry in data["reviews"]:
        if _valid_entry(entry) and _identity_key(entry) == key:
            rid = entry.get("review_id")
            return rid if isinstance(rid, str) and _REVIEW_ID.fullmatch(rid) else None
    return None


def is_review_declined(root: Path, review_id: str) -> bool:
    data = load_declined(root)
    return any(isinstance(e, dict) and e.get("review_id") == review_id for e in data["reviews"])


def remove_declined(root: Path, identity: dict) -> bool:
    """Drop every declined record for one exact identity.

    Returns False when nothing matched. The only writer is `cli.py undecline`,
    behind the same human prompt as `decline`.
    """
    if not _valid_entry(identity):
        raise StoreError("refusing to undecline an incomplete package identity")
    data = load_declined(root)
    key = _identity_key(identity)
    kept = [e for e in data["reviews"] if not (_valid_entry(e) and _identity_key(e) == key)]
    if len(kept) == len(data["reviews"]):
        return False
    data["reviews"] = kept
    _atomic_write_json(declined_path(root), data)
    return True


def add_declined(root: Path, identity: dict, review_id: str) -> bool:
    """Record that the user declined one exact identity. Returns False if already declined."""
    if not _valid_entry(identity):
        raise StoreError("refusing to decline an incomplete package identity")
    data = load_declined(root)
    key = _identity_key(identity)
    if any(_valid_entry(e) and _identity_key(e) == key for e in data["reviews"]):
        return False
    data["reviews"].append(
        {
            "ecosystem": identity["ecosystem"],
            "name": identity["name"],
            "version": identity["version"],
            "registry": identity["registry"],
            "review_id": review_id,
            "declined_at": utcnow(),
            "declined_by": "human",
        }
    )
    _atomic_write_json(declined_path(root), data)
    return True


# ---------------------------------------------------------------------------
# Transitive-check state: one OSV batch result per lockfile digest
# ---------------------------------------------------------------------------

def transitive_state_path(root: Path) -> Path:
    return guard_dir(root) / ".transitive-state.json"


def load_transitive_check(root: Path, digest: str) -> dict | None:
    """The cached batch result for one lockfile digest, or None.

    Fails SOFT: an unreadable cache means "query again", never "clean".
    """
    path = transitive_state_path(root)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    checks = data.get("checks") if isinstance(data, dict) else None
    entry = checks.get(digest) if isinstance(checks, dict) else None
    return entry if isinstance(entry, dict) else None


def vetted_digest(root: Path) -> str | None:
    """The sha256 of vetted.json, the audit's cache key, or None.

    The same cache file keys lockfile digests and this one; a vetted set and a
    lockfile never have identical bytes, so one namespace is enough.
    """
    import hashlib
    try:
        return hashlib.sha256(vetted_path(root).read_bytes()).hexdigest()
    except OSError:
        return None


def record_transitive_check(root: Path, digest: str, entry: dict) -> None:
    path = transitive_state_path(root)
    data = {"schema_version": SCHEMA_VERSION, "checks": {}}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("checks"), dict):
                data = loaded
        except (OSError, ValueError, RecursionError):
            pass
    data["checks"][digest] = entry
    # Keep the file bounded: a lockfile that changes often leaves old digests.
    if len(data["checks"]) > 50:
        oldest = sorted(data["checks"], key=lambda k: data["checks"][k].get("checked_at", ""))
        for key in oldest[: len(data["checks"]) - 50]:
            del data["checks"][key]
    _atomic_write_json(path, data)


# ---------------------------------------------------------------------------
# Stop-hook state (how many times we have refused to let a session end)
# ---------------------------------------------------------------------------

def stop_state_path(root: Path) -> Path:
    return guard_dir(root) / ".stop-state.json"


def _load_stop_state(root: Path) -> dict:
    path = stop_state_path(root)
    if not path.exists():
        return {"sessions": {}}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict) and isinstance(loaded.get("sessions"), dict):
            return loaded
    except (OSError, ValueError, RecursionError):
        pass
    return {"sessions": {}}


def load_stop_nags(root: Path, session_id: str, fingerprint: str) -> int:
    """Consecutive refusals for this session against the SAME pending set.

    A different fingerprint means the agent made progress since the last
    refusal, so the count restarts at 0.
    """
    entry = _load_stop_state(root)["sessions"].get(session_id)
    if not isinstance(entry, dict) or entry.get("fingerprint") != fingerprint:
        return 0
    value = entry.get("count", 0)
    return int(value) if isinstance(value, int) else 0


def record_stop_nag(root: Path, session_id: str, fingerprint: str) -> int:
    data = _load_stop_state(root)
    count = load_stop_nags(root, session_id, fingerprint) + 1
    data["sessions"][session_id] = {"fingerprint": fingerprint, "count": count}
    _atomic_write_json(stop_state_path(root), data)
    return count


# ---------------------------------------------------------------------------
# Reconciliation state
#
# Two files, and the split in failure policy is deliberate:
#
#   .disk-state.json     the watermark. FAILS SOFT, like .stop-state.json. A
#                        malformed watermark that failed closed would deny every
#                        package operation with no repair route the agent is
#                        allowed to take (CLAUDE.md forbids it editing guard
#                        state). Reading as empty re-seeds, which at worst asks
#                        the operator about packages they already have.
#
#   .disk-findings.json  the record that something unreviewed is installed.
#                        FAILS CLOSED, like vetted.json: an unreadable copy of
#                        that record must not read as "nothing is wrong".
# ---------------------------------------------------------------------------

def disk_state_path(root: Path) -> Path:
    return guard_dir(root) / ".disk-state.json"


def disk_findings_path(root: Path) -> Path:
    return guard_dir(root) / ".disk-findings.json"


def new_finding_id() -> str:
    return uuid.uuid4().hex


def load_disk_state(root: Path) -> dict:
    """The watermark. Fails soft: anything unreadable reads as unseeded."""
    path = disk_state_path(root)
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "seeded_at": None, "entries": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        data = None
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("entries"), dict)
        or not isinstance(data.get("seeded_at"), str)
    ):
        return {"schema_version": SCHEMA_VERSION, "seeded_at": None, "entries": {}}
    entries = {k: v for k, v in data["entries"].items() if isinstance(v, int)}
    return {"schema_version": SCHEMA_VERSION, "seeded_at": data["seeded_at"], "entries": entries}


def save_disk_state(root: Path, seeded_at: str, entries: dict) -> None:
    _atomic_write_json(
        disk_state_path(root),
        {
            "schema_version": SCHEMA_VERSION,
            "seeded_at": seeded_at,
            "entries": {key: int(value) for key, value in sorted(entries.items())},
        },
    )


# .environments.json: Python environments outside the project tree that an
# allowed command installed into (a literal UV_PROJECT_ENVIRONMENT, or
# VIRTUAL_ENV with `uv --active` / `uv pip`), keyed by the directory the
# command ran in. The PreToolUse hook writes it when it allows such a command;
# every reconciliation reads it, because disk_guard never looks at a command
# and the next command may not repeat the variable. FAILS SOFT, like the
# watermark: unreadable reads as empty, and `<dir>/.venv` is still read.
#
# At most MAX_RECORDED_ENVIRONMENTS per directory, and a full record is never
# evicted from: forgetting an environment would stop reconciliation reading
# it, so eight harmless commands could hide a real one. A command that would
# record one more is refused instead: `record_environments` returns the reason.

MAX_RECORDED_ENVIRONMENTS = 8


def environments_path(root: Path) -> Path:
    return guard_dir(root) / ".environments.json"


def _directory_key(directory) -> str:
    return os.path.realpath(str(directory))


def load_environments(root: Path) -> dict:
    """{directory: [environment path, ...]}, newest first. Fails soft."""
    try:
        data = json.loads(environments_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        return {}
    table = data.get("environments")
    if not isinstance(table, dict):
        return {}
    return {key: [p for p in value if isinstance(p, str) and p]
            for key, value in table.items() if isinstance(key, str) and isinstance(value, list)}


def recorded_environments(root: Path, directory) -> list:
    """The environments recorded for commands run in `directory`."""
    return load_environments(root).get(_directory_key(directory), [])


def _merged_environments(root: Path, directory, paths):
    """(table, key, current, merged): the record with `paths` added, newest first."""
    paths = [p for p in paths if isinstance(p, str) and p]
    table = load_environments(root)
    key = _directory_key(directory)
    current = table.get(key, [])
    return table, key, current, list(dict.fromkeys(paths + current))


def environments_refusal(root: Path, directory, paths) -> str | None:
    """Why a command naming `paths` must be refused, or None. Reads only.

    Not None exactly when recording `paths` for `directory` would take the
    record past MAX_RECORDED_ENVIRONMENTS, which is never done by evicting an
    older entry. The hook prints it after `PACKAGE_GUARD_UNSUPPORTED: `.
    """
    _table, _key, current, merged = _merged_environments(root, directory, paths)
    if len(merged) <= MAX_RECORDED_ENVIRONMENTS:
        return None
    new = [p for p in merged if p not in current]
    return (
        f"Package Guard already reads {len(current)} Python environments outside the project "
        f"for {_directory_key(directory)}, the most it records, and this command names "
        f"another ({', '.join(new)}). It does not forget one to make room: an install there "
        "would no longer be reconciled. Install into one of the recorded environments "
        f"({', '.join(current)}) or the project's .venv instead. Only the user can remove an "
        f"entry, from {environments_path(root)}."
    )


def record_environments(root: Path, directory, paths):
    """Remember `paths` for `directory`.

    True when the file changed, False when it already held them. When the
    record is full it records nothing, never evicting an older entry, and
    returns the refusal reason (`environments_refusal`), a string the hook
    denies the command with."""
    refusal = environments_refusal(root, directory, paths)
    if refusal:
        return refusal
    table, key, current, merged = _merged_environments(root, directory, paths)
    if merged == current:
        return False
    table[key] = merged
    _atomic_write_json(environments_path(root),
                       {"schema_version": SCHEMA_VERSION, "environments": table})
    return True


def load_disk_findings(root: Path) -> dict:
    """Open findings. Fails closed on malformed content."""
    path = disk_findings_path(root)
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "findings": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise StoreError(f".disk-findings.json is unreadable or not valid JSON: {exc}")
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != SCHEMA_VERSION
        or not isinstance(data.get("findings"), list)
    ):
        raise StoreError(".disk-findings.json has an unexpected shape")
    return data


def save_disk_findings(root: Path, findings) -> None:
    """Replace the open finding set.

    Closing is deletion: an approved or removed finding is dropped
    from the list, and nothing is appended to declined.json for it. There is no
    archive, so this file is the current state and never a history.
    """
    _atomic_write_json(
        disk_findings_path(root),
        {"schema_version": SCHEMA_VERSION, "findings": list(findings)},
    )


# ---------------------------------------------------------------------------
# Review reports
# ---------------------------------------------------------------------------

def write_report(root: Path, report: dict) -> Path:
    review_id = report.get("review_id", "")
    if not isinstance(review_id, str) or not _REVIEW_ID.fullmatch(review_id):
        raise StoreError("report has an invalid review_id")
    path = reports_dir(root) / f"{review_id}.json"
    _atomic_write_json(path, report)
    return path


def load_report(root: Path, review_id: str) -> dict:
    if not isinstance(review_id, str) or not _REVIEW_ID.fullmatch(review_id):
        raise StoreError("invalid review id")
    path = reports_dir(root) / f"{review_id}.json"
    if not path.exists():
        raise StoreError(f"review report {review_id} not found")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise StoreError(f"review report {review_id} is unreadable: {exc}")
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != SCHEMA_VERSION
        or report.get("review_id") != review_id
        or report.get("verdict") not in _VERDICTS
        or not _valid_entry(report.get("resolved_identity"))
    ):
        raise StoreError(f"review report {review_id} is malformed or inconsistent")
    return report


def iter_reports(root: Path):
    """Yield every well-formed report on disk; skip unreadable ones."""
    directory = reports_dir(root)
    if not directory.exists():
        return
    for path in sorted(directory.glob("*.json")):
        try:
            yield load_report(root, path.stem)
        except StoreError:
            continue


def discard_report(root: Path, review_id: str) -> None:
    """Remove a report that duplicates an already-open review."""
    if not isinstance(review_id, str) or not _REVIEW_ID.fullmatch(review_id):
        raise StoreError("invalid review id")
    try:
        (reports_dir(root) / f"{review_id}.json").unlink()
    except FileNotFoundError:
        pass


def find_open_review(root: Path, session_id: str, identity: dict, exclude: str | None = None,
                     any_version: bool = False):
    """An existing review_required report for this identity in this session.

    Lets a retried install reuse the same review id instead of minting a new
    report (and hitting the network) every time.

    `exclude` drops one review id from the search. Callers that have just
    written a report must pass it: iter_reports() yields in filename order and
    filenames are random hex ids, so without it the freshly minted report wins
    the scan roughly half the time and the retry mints a new id instead of
    reusing the open one.

    `any_version` matches on ecosystem, name and registry only, skipping
    reports whose identity has since been vetted or declined. An unpinned
    request cannot name a version without a registry round trip, and if this
    session already put a version of that package in front of the user, that
    review is the one to keep pointing at -- stable ids across retries, even
    when `latest` has moved since.
    """
    if not session_id:
        return None
    if any_version:
        wanted = tuple(identity.get(k) for k in ("ecosystem", "name", "registry"))
        if not all(isinstance(v, str) and v for v in wanted):
            return None
    elif _valid_entry(identity):
        key = _identity_key(identity)
    else:
        return None
    for report in iter_reports(root):
        if exclude is not None and report["review_id"] == exclude:
            continue
        if report.get("session_id") != session_id or report["verdict"] != "review_required":
            continue
        found = report["resolved_identity"]
        if any_version:
            if tuple(found.get(k) for k in ("ecosystem", "name", "registry")) != wanted:
                continue
            if is_vetted(root, found) or is_declined(root, found):
                continue
            return report
        if _identity_key(found) == key:
            return report
    return None
