#!/usr/bin/env python3
# /// script
# requires-python = "==3.11.*"
# ///
"""Package Guard — Claude Code PostToolUse hook for Bash commands.

Runs after a Bash command and reconciles the filesystem against what the
project declares and what a human approved. Unlike the PreToolUse hook it reads
no command text to decide anything: the command is recorded only so a finding
can say what was running when it appeared.

This is where indirection the command text hides is caught. `npm run serve`
is an npm verb the recognizer does not gate; `uv sync 2>&1 | tail` is a pipe with no acquisition
hint. Both put packages on disk, and both are visible here the instant they do,
because the input is `node_modules` and `site-packages` rather than a string.

**Blocking does not undo the tool.** The command has already run. `decision:
block` feeds the reason back to the model as the next thing to act on, which is
the right shape: the remedy is a review or a removal, never an undo.

**Failure policy: fail OPEN, loudly** — the opposite of hook.py and for the same
reason stop_hook.py does. Failing closed belongs to the enforcement path, and
PreToolUse is that path. A PostToolUse hook that failed closed would block the
agent after a command that already ran, with no way to tell a real finding
from a broken interpreter.

Standard library only, and no network call ever — which is the
structural reason this layer cannot reintroduce the PreToolUse timeout
fail-open.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# The floor, checked before the siblings are imported (see hook.py). Exit 0:
# this layer is not the gate and the command has already run.
if sys.version_info < (3, 11):
    print(
        "Package Guard post hook: needs Python 3.11 or newer; this interpreter is "
        f"{sys.version_info.major}.{sys.version_info.minor}. Allowing.",
        file=sys.stderr,
    )
    sys.exit(0)

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Module-level imports run before main(), so main()'s handler cannot see them.
# An unguarded ImportError means a traceback, exit 1, and a hook that is
# absent while appearing installed. This one fails OPEN (exit 0)
# because it is not the gate -- see the module docstring.
try:
    import bench_config  # noqa: E402
    import bench_gate  # noqa: E402
    import disk_guard  # noqa: E402
    import mode as pg_mode  # noqa: E402
    import parser as pg_parser  # noqa: E402
    import store  # noqa: E402
    import transcript  # noqa: E402
except Exception as _exc:  # pragma: no cover - exercised by test_import_guard
    print(
        f"Package Guard post hook: modules failed to load ({_exc.__class__.__name__}: {_exc}); "
        "allowing. Package Guard requires Python 3.11+.",
        file=sys.stderr,
    )
    sys.exit(0)


def _decision(reason: str) -> dict:
    """The PostToolUse decision shape.

    There is NO `permissionDecision` here. Copying hook._decision would emit a
    PreToolUse payload under a PostToolUse event name, which the harness
    ignores -- a hook that silently does nothing while appearing installed.
    """
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
    }


def _bench_follow_up(root, event, result) -> str | None:
    """What a command left wrong in a Frappe bench, as text, or None.

    After a command the hook allowed under the bench gate, each app it was covered by is compared
    with the manifests ITS BASELINE recorded (never with what the pre-hook read: an earlier segment
    may have swapped a lock before the gate looked, and a frozen install leaves a swapped lock alone);
    the installer files are read again; and every bench env is checked to be readable in full. What is
    found is recorded, and the next bench command is refused until `cli.py reconcile` finds it gone.
    While the Frappe switch is off (`disk_guard.BENCH_ENV_DISK`) this does nothing."""
    if not disk_guard.BENCH_ENV_DISK:
        return None
    allowed = bench_gate.take_allowed(root, event)
    if not bench_gate.allowed_matches(allowed, event):
        allowed = None
    benches = {Path(s.directory) for s in result.scopes if s.kind == "bench-env"}
    if allowed and allowed.get("bench"):
        benches.add(Path(allowed["bench"]))
    found = []
    for bench in sorted(benches):
        mine = allowed if allowed and str(bench) == allowed.get("bench") else None
        found += bench_gate.after_problems(root, bench, mine)
    if not found:
        return None
    bench_gate.add_problems(root, found, store.utcnow(), ((event.get("tool_input") or {}).get("command")))
    lines = ["That command left a Frappe bench in a state Package Guard cannot vouch for:"]
    lines += [f"- {text}" for _kind, text, _check in found[:10]]
    if len(found) > 10:
        lines.append(f"- ... and {len(found) - 10} more")
    lines.append("Bench commands are refused until this is resolved. Tell the user; the fix is theirs "
                 "(restore the files or re-run bench-config apply), then `cli.py reconcile` confirms it.")
    return "PACKAGE_GUARD_BENCH_CONFIG: " + "\n".join(lines)


_DRIFT_FILE = "config-drift.json"


def _drift_report(root, mode) -> str:
    """The files the CLI wrote for an installer (`env/pip.conf`, `uv.toml`, a `.yarnrc`) that no
    longer match their recorded digest, as a message; "" when none changed or the same
    set was already reported. A copy, an archive or git rewrote a file the pre-write lock
    could not see through, and only the digest shows it. Reported once per set of changed
    files, not after every later command; the set is forgotten when the files are right."""
    if not pg_parser.FRAPPE_ENABLED or mode == "off":
        return ""
    changed = [f"{path} {why}" for path, why in bench_config.drift(root)]
    state = Path(root) / ".claude" / "package-guard" / _DRIFT_FILE
    try:
        reported = json.loads(state.read_text(encoding="utf-8")).get("reported", [])
    except (OSError, ValueError, AttributeError):
        reported = []
    if changed == reported:
        return ""
    try:
        if changed:
            state.write_text(json.dumps({"reported": changed}, indent=2) + "\n", encoding="utf-8")
        elif state.exists():
            state.unlink()
    except OSError:
        pass
    if not changed:
        return ""
    return ("A file Package Guard wrote for an installer changed after that command ran, so the "
            "installer no longer reads the configuration the guard checked:\n  "
            + "\n  ".join(changed)
            + "\nThe command has already run. Do not edit the file back by hand: tell the user, "
              "who re-applies the bench configuration.")


def evaluate(event: dict, root) -> dict | None:
    """Return a block decision, or None to say nothing."""
    if event.get("tool_name") != "Bash":
        return None
    command = ((event.get("tool_input") or {}).get("command")) or None
    current = pg_mode.effective(root).mode
    # A project's `off` can arrive with the command that just ran (a pull), so
    # this hook follows the mode too: snapshot while down, catch up once back.
    try:
        caught = disk_guard.follow_mode(root, current, event.get("session_id"))
    except Exception as exc:  # noqa: BLE001 - fails open, see the module docstring
        print(f"Package Guard post hook: could not follow the mode "
              f"({exc.__class__.__name__}: {exc}).", file=sys.stderr)
        caught = []
    if caught:
        pg_mode.append_log(root, {"event": "caught-up", "count": len(caught)})
    result = disk_guard.reconcile(
        root,
        project_root=root,
        detected_by="PostToolUse",
        session_id=event.get("session_id"),
        command=command,
        session_started=transcript.session_started(event.get("transcript_path")),
    )
    try:
        bench_text = _bench_follow_up(root, event, result)
    except Exception as exc:  # noqa: BLE001 - fails open, see the module docstring
        print(f"Package Guard post hook: the bench check failed ({exc.__class__.__name__}: {exc}).",
              file=sys.stderr)
        bench_text = None
    drift = _drift_report(root, current)
    # Both reports are kept: the bench follow-up (not in `off`) and the installer-file drift.
    notes = "\n\n".join(t for t in ((bench_text if current != "off" else None), drift) if t)
    if not result.new_findings and not caught:
        # Findings that were already open are the PreToolUse gate's job and the
        # Stop hook's. Re-reporting them after every command is noise, and an
        # alert nobody reads is not an alert.
        if not notes:
            return None
        if current == "warn":
            return {"hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "Package Guard is in warn mode, so this is not a block; "
                                     "tell the user.\n" + notes}}
        return _decision(notes)
    # Recorded in every mode, so whatever lands while the guard is down is an
    # open finding once it is back on. Only the reporting follows the mode.
    if current == "off":
        return None
    count = len(result.new_findings)
    header = (
        f"That command put {count} unreviewed direct dependenc"
        f"{'y' if count == 1 else 'ies'} on disk. Package Guard found "
        f"{'it' if count == 1 else 'them'} by comparing the filesystem against what this "
        "project declares and what you approved — not by reading the command, which is "
        "why wrapping or indirection does not hide it. The command has already run; this "
        "cannot be undone by the guard."
    ) if count else ""
    if caught:
        header = (header + " " if header else "") + (
            f"Package Guard is enforcing again, and {len(caught)} package(s) installed while it "
            "was down (warn or off) are accounted for by no manifest or lockfile.")
    body = disk_guard.render_block(
        list(result.new_findings) + list(caught),
        root,
        header=header,
        declined_check=lambda identity: store.is_declined(root, identity),
    )
    if notes:
        body += "\n\n" + notes
    if current == "warn":
        return {"hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "Package Guard is in warn mode, so this is not a block; tell "
                                 "the user. It stays an open finding for when the guard is "
                                 "back on.\n" + body,
        }}
    return _decision(body)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        print("Package Guard post hook: malformed JSON input; allowing.", file=sys.stderr)
        return 0
    if not isinstance(event, dict):
        return 0
    try:
        root = store.project_root(__file__)
        decision = evaluate(event, root)
    except Exception as exc:
        print(
            f"Package Guard post hook: internal failure ({exc.__class__.__name__}: {exc}); "
            "allowing. The PreToolUse gate and the Stop hook still enforce.",
            file=sys.stderr,
        )
        return 0
    if decision is not None:
        json.dump(decision, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
