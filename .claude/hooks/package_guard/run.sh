#!/bin/sh
# Package Guard runner.
#
#   run.sh <entry-script> <exit-code-when-no-runner> [args...]
#
# Why this exists. Registering `uv run ... hook.py` directly
# means that when `uv` is not on PATH the command exits 127 before Python ever
# starts. Claude Code treats a non-2 exit as a NON-BLOCKING error, so the install
# proceeds: the guard is absent while appearing installed. `uv` installs to
# ~/.local/bin and a Claude Code launched from the macOS dock gets a truncated
# PATH, so this is common rather than exotic. ~/.local/bin is therefore searched
# too, last, so a uv earlier on PATH still wins (provision.sh does the same, so
# it never reports a 3.11 this runner cannot reach).
#
# The second argument is the exit code to use when no runner can be found, and it
# must match the entry point's own failure direction:
#
#   hook.py       2   fail closed -- it is the gate
#   post_hook.py  0   fail open by design; the command already ran
#   stop_hook.py  0   fail open; a Stop hook must never trap a session
#
# Runner order is uv first, deliberately. `uv run --no-project` ignores whatever
# virtualenv and `.python-version` the guarded repository has, and the explicit
# --python beats a UV_PYTHON in the environment (the script's requires-python
# alone does not: uv only warns), so the repo being guarded does not get to
# choose the interpreter that runs the guard. Bare python3.11 is
# the fallback for machines without uv -- worse isolation, but a working gate
# beats no gate.
#
# The interpreter is pinned to CPython 3.11 (any 3.11.x), so every machine runs
# the guard on the same Python. install.sh puts a uv-managed 3.11 in place; the
# hooks never download one (--no-python-downloads).
#
# uv is probed for 3.11 BEFORE the exec. When the requested Python is missing,
# `uv run` prints "No interpreter found" and exits 2 -- and exec hands that 2
# straight to Claude Code. For stop_hook.py that blocks stopping, so the error
# is fed back after every turn: a loop. The probe turns a missing 3.11 into
# $no_runner_exit like any other missing runner.
#
# POSIX sh. macOS and Linux; on native Windows it needs the sh from Git for Windows.

set -u

PG_PYTHON="3.11"
# Keep in step with UV_VERSION in install.sh.
PG_UV_VERSION="0.12.5"

if [ "$#" -lt 2 ]; then
    echo "Package Guard: run.sh needs <script> <exit-code>; got $#." >&2
    exit 2
fi

script="$1"
no_runner_exit="$2"
shift 2

if [ ! -f "$script" ]; then
    echo "Package Guard: $script is missing; failing with $no_runner_exit." >&2
    exit "$no_runner_exit"
fi

if [ -n "${HOME:-}" ]; then
    case ":${PATH:-}:" in
        *":$HOME/.local/bin:"*) ;;
        *) PATH="${PATH:+$PATH:}$HOME/.local/bin"; export PATH ;;
    esac
fi

have_uv=0
if command -v uv >/dev/null 2>&1; then
    have_uv=1
    if uv python find --no-config --no-python-downloads "$PG_PYTHON" </dev/null >/dev/null 2>&1; then
        exec uv run --no-project --no-config --no-python-downloads --python "$PG_PYTHON" "$script" "$@"
    fi
fi

# No uv, or a uv that sees no 3.11. Find a python3 that is exactly 3.11.
for candidate in python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)' \
           </dev/null >/dev/null 2>&1; then
        exec "$candidate" "$script" "$@"
    fi
done

if [ "$have_uv" = 1 ]; then
    echo "Package Guard: no runner found. uv is on PATH but finds no Python $PG_PYTHON, and the hooks never download one." >&2
    echo "Package Guard: nothing was checked. Run once: uv python install $PG_PYTHON   then restart Claude Code." >&2
else
    echo "Package Guard: no runner found. Needs uv on PATH (or a python3.11), and the hooks never install either." >&2
    echo "Package Guard: nothing was checked. Install uv once, then restart Claude Code (the plugin then installs Python $PG_PYTHON itself):" >&2
    echo "Package Guard:   macOS or Linux:  curl -LsSf https://astral.sh/uv/$PG_UV_VERSION/install.sh | sh" >&2
    echo "Package Guard:   Windows:  powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/$PG_UV_VERSION/install.ps1 | iex\"" >&2
fi
exit "$no_runner_exit"
