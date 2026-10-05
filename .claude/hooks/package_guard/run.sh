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
# PATH, so this is common rather than exotic.
#
# The second argument is the exit code to use when no runner can be found, and it
# must match the entry point's own failure direction:
#
#   hook.py       2   fail closed -- it is the gate
#   post_hook.py  0   fail open by design; the command already ran
#   stop_hook.py  0   fail open; a Stop hook must never trap a session
#
# Runner order is uv first, deliberately. `uv run --no-project` ignores whatever
# virtualenv the guarded repository activates, so the repo being guarded does not
# get to choose the interpreter that runs the guard. Bare python3 is the fallback
# for machines without uv -- worse isolation, but a working gate beats no gate.
#
# POSIX sh. macOS and Linux only; Windows is out of scope.

set -u

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

if command -v uv >/dev/null 2>&1; then
    exec uv run --no-project --no-config --no-python-downloads "$script" "$@"
fi

# No uv. Find any python3 that satisfies the floor (3.11, for tomllib).
for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
           </dev/null >/dev/null 2>&1; then
        exec "$candidate" "$script" "$@"
    fi
done

echo "Package Guard: no runner found. Needs \`uv\` on PATH, or a python3 of 3.11 or newer." >&2
echo "Package Guard: nothing was checked. Install uv (https://docs.astral.sh/uv/getting-started/installation/)" >&2
echo "Package Guard: or make a suitable python3 available, then retry." >&2
exit "$no_runner_exit"
