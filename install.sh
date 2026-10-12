#!/bin/sh
# Package Guard bootstrap -- one command on a developer machine.
#
#   sh install.sh [<project>]       guards <project> (default: the current directory)
#   sh install.sh <new-dir>         creates <new-dir>, git init, guards it
#
# Run it from a copy of the repository: a clone, or an unzipped download. The
# repository is private, so the old `curl ... raw.githubusercontent.com | sh`
# one-liner does not work; GitHub answers it with "404: Not Found". With no
# local copy, install.sh clones PG_REPO itself, which needs a GitHub login
# (see the message printed when that fails).
#
# A target that does not exist yet is a fresh project: the directory is created
# and `git init` runs in it before the guard goes in, so the printed `git add`
# works as-is. An existing directory is never git-initialised.
#
# macOS and Ubuntu/Debian (any Linux with git, curl and /bin/sh); on Windows,
# WSL2 only (native Windows uses the plugin, which needs Git for Windows). POSIX
# sh: no bashisms, because /bin/sh is dash on Ubuntu.
#
# What it does, and nothing else:
#   1. checks for git and curl;
#   2. makes sure the runner exists: `uv`, pinned to UV_VERSION. A missing or
#      too-old uv is installed into ~/.local/bin with uv's official installer.
#      Then makes sure uv can see a CPython 3.11, the one interpreter the guard
#      runs on; if not, installs a uv-managed CPython 3.11 under
#      ~/.local/share/uv. The hooks never download a Python, so this is the
#      one place it can happen.
#      PG_NO_UV_INSTALL=1 refuses both installs; the run then falls back to a
#      python3.11 on PATH if one exists, otherwise stops with a message;
#   3. clones the Package Guard repository (PG_REPO at PG_REF) into PG_HOME;
#   4. runs install.py from that clone against the project, which copies the
#      guard in, merges .claude/settings.json, appends CLAUDE.md, seeds the
#      state directory and .gitignore. Re-running is the upgrade path.
#
# Nothing is written outside ~/.local/bin (uv), ~/.local/share/uv (a managed
# Python, only if needed), PG_HOME (the clone) and the project. The guard itself installs no packages: it is standard library only.
#
# Settings, all overridable from the environment:
#   PG_REPO   git URL of the Package Guard repository
#   PG_REF    branch or tag to install (default: main)
#   PG_HOME   where the clone lives (default: ~/.cache/package-guard)
#   PG_UV_VERSION      uv version to install when needed (default: pinned below)
#   PG_NO_UV_INSTALL   1 = never install uv or a Python; use a python3.11 or stop
#   PG_SANDBOX         1 = also turn on the strict Claude Code sandbox (install.py --sandbox)

set -eu

PG_REPO="${PG_REPO:-https://github.com/Fefar-AT/package-guard.git}"
PG_REF="${PG_REF:-main}"
PG_HOME="${PG_HOME:-${XDG_CACHE_HOME:-$HOME/.cache}/package-guard}"
# Pinned so every machine runs the same runner. Bump deliberately, with a run
# of the install matrix; PG_UV_VERSION overrides for a one-off.
UV_VERSION="${PG_UV_VERSION:-0.12.5}"
UV_INSTALLER="https://astral.sh/uv/$UV_VERSION/install.sh"
# The guard's interpreter, and the one installed when uv cannot see it. Not
# overridable: it must equal PG_PYTHON in run.sh and the entry points'
# requires-python ("==3.11.*"), or the hooks find no runner.
PY_VERSION="3.11"

say()  { printf 'package-guard: %s\n' "$*"; }
fail() { printf 'package-guard: %s\n' "$*" >&2; exit 2; }

python_ok() {
    # $1 is a python3 candidate; true when it is 3.11 (run.sh accepts no other).
    command -v "$1" >/dev/null 2>&1 &&
        "$1" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)' \
            </dev/null >/dev/null 2>&1
}

find_python() {
    for candidate in python3.11 python3; do
        if python_ok "$candidate"; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

# --- 0. platform and tools ------------------------------------------------------

case "$(uname -s)" in
    Darwin|Linux) ;;
    *) fail "$(uname -s) is not supported; Package Guard runs on macOS and Linux." ;;
esac

command -v git  >/dev/null 2>&1 || fail "git is required. macOS: xcode-select --install; Ubuntu: sudo apt install git"
command -v curl >/dev/null 2>&1 || fail "curl is required. Ubuntu: sudo apt install curl"

# With PG_SANDBOX=1 the project's settings turn on the Claude Code
# sandbox with failIfUnavailable, so on Linux Claude Code will not start there
# without these. A warning, not a failure: the machine that installs is not
# always the machine that runs Claude Code.
sandbox_flag=""
[ "${PG_SANDBOX:-}" = "1" ] && sandbox_flag="--sandbox"
if [ -n "$sandbox_flag" ] && [ "$(uname -s)" = Linux ]; then
    for tool in bwrap socat; do
        command -v "$tool" >/dev/null 2>&1 \
            || say "warning: $tool not found; the guarded project's sandbox needs it (sudo apt-get install bubblewrap socat)"
    done
fi

# --- 1. target -----------------------------------------------------------------

# Checked after the tools so a refusal leaves no half-made directory behind.
target="${1:-$PWD}"
fresh=0
if [ ! -e "$target" ]; then
    mkdir -p "$target" || fail "cannot create $target"
    fresh=1
elif [ ! -d "$target" ]; then
    fail "$target is not a directory."
fi
target=$(cd "$target" && pwd)

if [ "$fresh" = 1 ]; then
    git -C "$target" init --quiet || fail "git init failed in $target"
    say "fresh project: created $target and ran git init"
fi

# --- 2. runner -----------------------------------------------------------------

# uv installs to ~/.local/bin, which a fresh shell may not have on PATH yet.
PATH="$HOME/.local/bin:$PATH"; export PATH

uv_ok() {
    # An existing uv must accept the flags run.sh passes. An older uv rejects
    # one of them and the gate then fails closed on every command. --help does
    # not need the Python to exist; the 3.11 check is step 2's own.
    command -v uv >/dev/null 2>&1 &&
        uv run --no-project --no-config --no-python-downloads --python "$PY_VERSION" --help >/dev/null 2>&1
}

install_uv() {
    say "installing uv $UV_VERSION into ~/.local/bin ($UV_INSTALLER)"
    curl -LsSf "$UV_INSTALLER" | sh -s -- --no-modify-path >/dev/null \
        || fail "uv installer failed"
    uv_ok || fail "uv installed but does not run; add ~/.local/bin to PATH and re-run."
    say "runner: uv ($(uv --version)) -- add ~/.local/bin to your PATH for future shells"
}

# uv is THE runner: every machine gets the same one, pinned. python3 is only a
# fallback for a machine where installing uv is refused (PG_NO_UV_INSTALL=1).
if uv_ok; then
    say "runner: uv ($(uv --version), $(command -v uv))"
elif [ "${PG_NO_UV_INSTALL:-}" = "1" ]; then
    if command -v uv >/dev/null 2>&1; then
        say "warning: $(command -v uv) is too old for run.sh and PG_NO_UV_INSTALL=1 forbids replacing it"
    fi
    if python=$(find_python); then
        say "runner: $python (fallback; uv is the supported runner)"
    else
        fail "no runner: needs uv on PATH or a python3.11, and PG_NO_UV_INSTALL=1 forbids installing uv."
    fi
else
    if command -v uv >/dev/null 2>&1; then
        say "$(command -v uv) is too old for run.sh; replacing it in ~/.local/bin"
    fi
    install_uv
fi

# uv needs the guard's interpreter, CPython 3.11. The hooks run with
# --no-python-downloads (the gate never fetches a Python), so the interpreter
# has to exist BEFORE the first hook fires. A uv-managed Python under
# ~/.local/share/uv is found by that flag; only downloading is refused. A 3.12
# or newer does not count: run.sh asks uv for 3.11 and nothing else.
if uv_ok; then
    if uv python find --no-config --no-python-downloads "$PY_VERSION" >/dev/null 2>&1; then
        say "python: $(uv python find --no-config --no-python-downloads "$PY_VERSION")"
    elif [ "${PG_NO_UV_INSTALL:-}" = "1" ]; then
        fail "no Python $PY_VERSION for uv to run the guard with, and PG_NO_UV_INSTALL=1 forbids installing one."
    else
        say "no Python $PY_VERSION found; installing a uv-managed CPython $PY_VERSION"
        uv python install --no-config "$PY_VERSION" >/dev/null 2>&1 \
            || fail "uv python install $PY_VERSION failed"
        say "python: $(uv python find --no-config --no-python-downloads "$PY_VERSION")"
    fi
fi

# --- 3. source -----------------------------------------------------------------

# From a clone, use it; the bootstrap is then just the runner check plus install.py.
# Piped through `sh`, $0 is "sh" and names no file, so this branch is skipped.
here=""
if [ -f "$0" ]; then
    here=$(cd "$(dirname "$0")" && pwd)
fi
if [ -n "$here" ] && [ -f "$here/install.py" ] && [ -f "$here/.claude/hooks/package_guard/run.sh" ]; then
    src="$here"
    say "source: $src (local clone)"
else
    rm -rf "$PG_HOME"
    mkdir -p "$(dirname "$PG_HOME")"
    say "source: $PG_REPO @ $PG_REF -> $PG_HOME"
    git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$PG_REF" "$PG_REPO" "$PG_HOME" \
        || fail "clone failed: $PG_REPO @ $PG_REF
The Package Guard repository is private. Git needs a GitHub account that has
been given read access, and a saved login. GitHub does not accept your account
password for git. Pick one way to log in, in a terminal, then run this again:
  1. gh auth login   (choose GitHub.com, HTTPS, then 'Login with a web browser')
  2. Git Credential Manager (signs in through the browser; included with Git
     for Windows; on macOS: brew install --cask git-credential-manager)
  3. A personal access token, pasted when git asks for the password
Other ways:
  - SSH: PG_REPO=git@github.com:Fefar-AT/package-guard.git sh install.sh ...
  - A ZIP: download it from GitHub in the browser (or get it from the
    maintainer), unzip it, then run: sh <folder>/install.sh <your-project>
If this run has no terminal (for example Claude started it), git cannot ask for
a login. Log in in a terminal first, then run the command there."
    src="$PG_HOME"
fi

[ -f "$src/.claude/hooks/package_guard/run.sh" ] \
    || fail "$src has no run.sh: that ref predates the runner. Use PG_REF=main."

# --- 4. install ----------------------------------------------------------------

if uv_ok; then
    uv run --no-project --no-config --no-python-downloads --python "$PY_VERSION" "$src/install.py" "$target" $sandbox_flag
else
    "$python" "$src/install.py" "$target" $sandbox_flag
fi
