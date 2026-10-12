#!/bin/sh
# Package Guard provisioning, run by the plugin at session start.
#
# The guard runs on exactly Python 3.11 (see run.sh), and the gate itself never
# downloads anything. This script is the one place the plugin sets that up:
#
#   - 3.11 already present        -> exit quietly
#   - uv present, 3.11 missing    -> `uv python install 3.11`, report the result
#   - no uv                       -> tell the user to install uv once, then restart
#
# It never installs uv itself and always exits 0: a SessionStart hook must not
# stop a session from starting. The message goes out as JSON `systemMessage`,
# which Claude Code shows to the user; plain stdout would reach only Claude.
#
# POSIX sh.

set -u

PG_PYTHON="3.11"
# Keep in step with UV_VERSION in install.sh.
UV_VERSION="0.12.5"

# Where uv's installer puts uv; searched last, exactly as run.sh does, so this
# script never reports a 3.11 the runner cannot reach.
if [ -n "${HOME:-}" ]; then
    case ":${PATH:-}:" in
        *":$HOME/.local/bin:"*) ;;
        *) PATH="${PATH:+$PATH:}$HOME/.local/bin"; export PATH ;;
    esac
fi

emit() {
    # $1 is the message. JSON-escape backslashes and quotes, join lines with \n.
    escaped=$(printf '%s\n' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | awk 'NR>1{printf "\\n"} {printf "%s", $0}')
    printf '{"systemMessage": "%s"}\n' "$escaped"
}

have_python() {
    command -v uv >/dev/null 2>&1 &&
        uv python find --no-config --no-python-downloads "$PG_PYTHON" </dev/null >/dev/null 2>&1
}

if have_python; then
    exit 0
fi

if command -v uv >/dev/null 2>&1; then
    if output=$(uv python install "$PG_PYTHON" </dev/null 2>&1) && have_python; then
        emit "Package Guard: installed Python $PG_PYTHON with uv; the guard is ready."
    else
        emit "Package Guard: could not install Python $PG_PYTHON, so the guard cannot run and every Bash command and file edit will be blocked.
Run \`uv python install $PG_PYTHON\` yourself, then restart Claude Code.
uv said: $(printf '%s' "$output" | tail -n 3)"
    fi
    exit 0
fi

emit "Package Guard needs uv, installed once. Until then every Bash command and file edit will be blocked.
Install uv $UV_VERSION, then restart Claude Code (the guard then installs Python $PG_PYTHON by itself):
  macOS or Linux:  curl -LsSf https://astral.sh/uv/$UV_VERSION/install.sh | sh
  Windows (needs Git for Windows too):  powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/$UV_VERSION/install.ps1 | iex\""
exit 0
