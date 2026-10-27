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
    import disk_guard  # noqa: E402
    import mode as pg_mode  # noqa: E402
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
    if not result.new_findings and not caught:
        # Findings that were already open are the PreToolUse gate's job and the
        # Stop hook's. Re-reporting them after every command is noise, and an
        # alert nobody reads is not an alert.
        return None
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
