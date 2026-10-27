"""Package Guard's mode: enforce, warn or off.

    enforce  the default: acquisition is gated, as it always has been
    warn     the gate's refusals become warnings; the command runs
    off      acquisition is not gated at all

Four layers, highest first:

    policy   a machine policy file an administrator owns (POLICY_PATHS). With
             `"locked": true` its mode is final and nothing below is read.
    local    .claude/package-guard/.mode.local.json -- this person, this
             project, this machine. Gitignored.
    project  .claude/package-guard/mode.json -- the team default. Committed,
             so turning it off is visible in review.
    default  an unlocked policy's mode, else enforce.

What a mode never changes: the guard's self-protection. Refusals of writes to
guard state, guard source and settings, of a malformed guard CLI call and of
PowerShell stay on in every mode, because the mode is applied only where
acquisition is decided (hook.evaluate). And the reconciliation layer keeps
recording what reaches disk in every mode, so whatever was installed while the
guard was off is an open finding -- reviewed or removed -- once it is back on.

Fail closed: a mode file that is unreadable, malformed or from a future schema
reads as enforce, with the problem named in the banner. An expired setting is
ignored; `settle()` removes it and says so once.

Only the guard CLI writes these files (`cli.py mode`), and the hook lets Claude
run only `mode` and `mode enforce`; `warn` and `off` are the human's, typed
in their own terminal behind a confirmation the CLI reads from a TTY.

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import store  # noqa: E402

MODES = ("enforce", "warn", "off")
SCOPES = ("local", "project")
SCHEMA_VERSION = 1

PROJECT_FILE = "mode.json"
LOCAL_FILE = ".mode.local.json"
LOG_FILE = ".mode-log.jsonl"
SEEN_FILE = ".mode-seen.json"

# A setting without --permanent lasts this long. A forgotten "off" is the
# long-term risk; an expiry turns it into a short one.
DEFAULT_DURATION = timedelta(hours=24)
MAX_DURATION = timedelta(days=365)

# Meant to be root- or admin-owned, so a process running as the user -- Claude
# included -- cannot write it without elevation. Not every default holds that:
# ordinary users may create folders under C:\ProgramData. So a policy file the
# current user could write is honoured only when it says `enforce` (see
# `policy`), and a planted `{"mode": "off", "locked": true}` turns nothing off.
# On Windows os.access reads only the read-only attribute, not the ACL, so
# there every policy counts as writable and can only enforce.
POLICY_PATHS = {
    "darwin": Path("/Library/Application Support/PackageGuard/policy.json"),
    "linux": Path("/etc/package-guard/policy.json"),
    "win32": Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "PackageGuard" / "policy.json",
}

# The banner is shown once per session per project; the record is bounded.
_MAX_SEEN = 64
_DURATION = re.compile(r"(\d+)([mhd])\Z")


class Mode(NamedTuple):
    mode: str
    scope: str                  # policy | local | project | default
    reason: str | None = None
    set_at: str | None = None
    set_by: str | None = None
    expires_at: str | None = None
    locked: bool = False
    problem: str | None = None  # a layer that could not be read, and was skipped


def policy_path() -> Path | None:
    key = "linux" if sys.platform.startswith("linux") else sys.platform
    return POLICY_PATHS.get(key)


def local_path(root) -> Path:
    return store.guard_dir(Path(root)) / LOCAL_FILE


def project_path(root) -> Path:
    return store.guard_dir(Path(root)) / PROJECT_FILE


def log_path(root) -> Path:
    return store.guard_dir(Path(root)) / LOG_FILE


def _seen_path(root) -> Path:
    return store.guard_dir(Path(root)) / SEEN_FILE


def _parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now(now=None) -> datetime:
    return now or datetime.now(timezone.utc)


def parse_duration(text: str) -> timedelta:
    """`90m`, `24h`, `7d`. Raises ValueError for anything else or past a year."""
    match = _DURATION.match(text or "")
    if not match or int(match.group(1)) == 0:
        raise ValueError(f"{text!r} is not a duration like 90m, 24h or 7d")
    amount, unit = int(match.group(1)), match.group(2)
    span = {"m": timedelta(minutes=amount), "h": timedelta(hours=amount),
            "d": timedelta(days=amount)}[unit]
    if span > MAX_DURATION:
        raise ValueError(f"{text!r} is longer than a year; use --permanent")
    return span


def _read(path: Path):
    """(data, problem): data None when absent; problem set when unusable."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"{path.name} is unreadable ({exc.__class__.__name__})"
    try:
        data = json.loads(text)
    except ValueError:
        return None, f"{path.name} is not valid JSON"
    if not isinstance(data, dict):
        return None, f"{path.name} is not a JSON object"
    return data, None


def _setting(data: dict, scope: str, name: str, now: datetime):
    """(Mode or None, expired, problem) for one layer's file contents."""
    if data.get("schema_version") != SCHEMA_VERSION:
        return None, False, f"{name} has schema_version {data.get('schema_version')!r}"
    mode = data.get("mode")
    if mode not in MODES:
        return None, False, f"{name} names an unknown mode {mode!r}"
    expires = data.get("expires_at")
    if expires is not None:
        moment = _parse_time(expires)
        if moment is None:
            return None, False, f"{name} has an unreadable expires_at {expires!r}"
        if moment <= now:
            return None, True, None
    reason = data.get("reason") if isinstance(data.get("reason"), str) else None
    return Mode(mode, scope, reason, data.get("set_at"), data.get("set_by"), expires,
                bool(data.get("locked")) if scope == "policy" else False), False, None


def _user_writable(path: Path) -> bool:
    """The current user could change or replace this file. Always true for
    root, which only errs towards enforce."""
    return os.access(path, os.W_OK) or os.access(path.parent, os.W_OK)


def policy(now=None) -> tuple[Mode | None, str | None]:
    """The machine policy, or None, and a problem. A policy that cannot be read
    is read as `enforce, locked`: an administrator's file that is broken must
    not hand control back to the layers below it. A policy the current user
    could write is honoured only when it says `enforce`; any other mode is a
    problem and the policy is skipped."""
    path = policy_path()
    if path is None:
        return None, None
    data, problem = _read(path)
    if problem:
        return Mode("enforce", "policy", locked=True, problem=f"policy {problem}"), problem
    if data is None:
        return None, None
    data = {"schema_version": SCHEMA_VERSION, **data}
    found, _expired, problem = _setting(data, "policy", "policy.json", _now(now))
    if problem or found is None:
        return Mode("enforce", "policy", locked=True, problem=f"policy {problem or 'expired'}"), problem
    if found.mode != "enforce" and _user_writable(path):
        return None, (f"policy.json says {found.mode!r} but is writable without administrator "
                      "rights, so it is ignored")
    return found, None


def effective(root, now=None) -> Mode:
    """The mode in force for this project now. Never raises."""
    moment = _now(now)
    try:
        ruling, policy_problem = policy(moment)
    except Exception as exc:  # noqa: BLE001 - fail closed, never crash the gate
        return Mode("enforce", "policy", locked=True, problem=f"policy check failed ({exc})")
    if ruling is not None and ruling.locked:
        return ruling
    # A policy that was skipped counts as a broken layer above the others.
    problems = [policy_problem] if policy_problem else []
    try:
        for scope, path in (("local", local_path(root)), ("project", project_path(root))):
            data, problem = _read(path)
            if problem:
                problems.append(problem)
                continue
            if data is None:
                continue
            found, _expired, problem = _setting(data, scope, path.name, moment)
            if problem:
                problems.append(problem)
                continue
            if found is not None:
                if problems:
                    # A broken higher layer is skipped, and skipping it must never
                    # make the guard LESS strict than that layer could have been.
                    return Mode("enforce", "default", problem="; ".join(problems))
                return found
    except Exception as exc:  # noqa: BLE001 - fail closed, never crash the gate
        problems.append(f"mode check failed ({exc})")
    if problems:
        return Mode("enforce", "default", problem="; ".join(problems))
    if ruling is not None:
        return Mode(ruling.mode, "policy", ruling.reason)
    return Mode("enforce", "default")


def settle(root, now=None) -> list[str]:
    """Remove expired settings, log each, and return one line per removal."""
    moment = _now(now)
    lines = []
    for scope, path in (("local", local_path(root)), ("project", project_path(root))):
        data, problem = _read(path)
        if problem or data is None:
            continue
        _found, expired, problem = _setting(data, scope, path.name, moment)
        if not expired or problem:
            continue
        try:
            path.unlink()
        except OSError:
            continue
        label = "personal" if scope == "local" else "project"
        lines.append(f"the {label} '{data.get('mode')}' setting expired at {data.get('expires_at')}")
        append_log(root, {"event": "expired", "scope": scope, "mode": data.get("mode"),
                          "expires_at": data.get("expires_at")}, moment)
    return lines


def _who() -> str:
    for key in ("USER", "USERNAME", "LOGNAME"):
        if os.environ.get(key):
            return os.environ[key]
    return "unknown"


def set_mode(root, mode: str, scope: str, reason: str | None = None,
             duration: timedelta | None = DEFAULT_DURATION, now=None) -> Mode:
    """Write (or, for enforce, clear) one layer. The CLI is the only caller."""
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}")
    if scope not in SCOPES:
        raise ValueError(f"unknown scope {scope!r}")
    moment = _now(now)
    path = local_path(root) if scope == "local" else project_path(root)
    entry = {"event": "set", "scope": scope, "mode": mode, "reason": reason, "by": _who()}
    if mode == "enforce":
        if path.exists():
            path.unlink()
        append_log(root, entry, moment)
        return effective(root, moment)
    if not reason or not reason.strip():
        raise ValueError("a reason is required for warn and off")
    expires = _stamp(moment + duration) if duration is not None else None
    store._atomic_write_json(path, {
        "schema_version": SCHEMA_VERSION,
        "mode": mode,
        "reason": reason.strip(),
        "set_at": _stamp(moment),
        "set_by": _who(),
        "expires_at": expires,
    })
    entry["expires_at"] = expires
    append_log(root, entry, moment)
    return effective(root, moment)


def append_log(root, entry: dict, now=None) -> None:
    """One JSON line per mode change, expiry and warn-mode pass. Local only:
    nothing is sent anywhere. Best effort -- a log that cannot be written must
    never block a command."""
    record = {"at": _stamp(_now(now)), **entry}
    try:
        path = log_path(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        pass


def read_log(root, limit: int = 20) -> list[dict]:
    try:
        lines = log_path(root).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def describe(current: Mode) -> str:
    """One line for a banner or the CLI."""
    if current.scope == "policy" and current.locked:
        where = "by this machine's Package Guard policy (locked)"
    else:
        where = {"local": "for you in this project", "project": "for this project (committed)",
                 "policy": "by this machine's Package Guard policy",
                 "default": "by default"}[current.scope]
    text = f"Package Guard is {current.mode.upper()} {where}"
    if current.expires_at:
        text += f", until {current.expires_at}"
    elif current.mode != "enforce" and current.scope in SCOPES:
        text += ", with no expiry"
    if current.reason:
        text += f" -- reason: {current.reason}"
    if current.problem:
        text += f" [{current.problem}; enforcing]"
    return text + "."


def _summary(found: Mode) -> str:
    text = found.mode
    if found.locked:
        text += ", locked"
    if found.expires_at:
        text += f" until {found.expires_at}"
    elif found.mode != "enforce" and found.scope in SCOPES:
        text += ", no expiry"
    if found.reason:
        text += f" -- reason: {found.reason}"
    if isinstance(found.set_by, str) and isinstance(found.set_at, str):
        text += f" (set by {found.set_by} at {found.set_at})"
    return text


def layers(root, now=None) -> list[tuple[str, Path | None, str]]:
    """(layer, file, what it holds) for every layer, highest first, for
    `cli.py mode`. Reads only; an expired file is reported, not removed."""
    moment = _now(now)
    ruling, problem = policy(moment)
    if problem:
        state = f"unusable: {problem}" + ("; enforcing, locked" if ruling is not None else "")
    elif ruling is None:
        state = "not set"
    else:
        state = _summary(ruling) + ("" if ruling.locked else " (the default only)")
    rows = [("policy", policy_path(), state)]
    for scope, label, path in (("local", "personal", local_path(root)),
                               ("project", "project", project_path(root))):
        data, problem = _read(path)
        if problem:
            state = f"unusable: {problem}"
        elif data is None:
            state = "not set"
        else:
            found, expired, problem = _setting(data, scope, path.name, moment)
            if problem:
                state = f"unusable: {problem}"
            elif expired:
                state = f"expired at {data.get('expires_at')}"
            else:
                state = _summary(found)
        rows.append((label, path, state))
    return rows


def first_in_session(root, session_id, now=None) -> bool:
    """True the first time this is asked for a session, then False. Best effort:
    an unwritable record shows the banner again rather than never."""
    if not isinstance(session_id, str) or not session_id:
        return False
    path = _seen_path(root)
    data, problem = _read(path)
    seen = data.get("sessions") if isinstance(data, dict) else None
    if problem or not isinstance(seen, list):
        seen = []
    if session_id in seen:
        return False
    seen = (seen + [session_id])[-_MAX_SEEN:]
    try:
        store._atomic_write_json(path, {"schema_version": SCHEMA_VERSION, "sessions": seen})
    except OSError:
        pass
    return True
