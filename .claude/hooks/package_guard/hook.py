#!/usr/bin/env python3
# /// script
# requires-python = "==3.11.*"
# ///
"""Package Guard — Claude Code PreToolUse hook for Bash package commands.

Reads the hook event JSON on stdin and prints a PreToolUse permission
decision. Unrelated commands produce no output (normal permission flow).

Failure policy: internal errors while evaluating a package operation fail
closed (deny / exit 2). Standard library only.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import textwrap
import time
from concurrent import futures
from pathlib import Path
from typing import NamedTuple

# The floor, checked before the siblings are imported so an old interpreter gets
# a sentence naming the cause instead of an ImportError about a module nobody has
# heard of. Runner-agnostic on purpose: this fires under uv, under bare python3,
# and on a machine the installer never ran on. Exit 2, because this is the gate.
if sys.version_info < (3, 11):
    print(
        "Package Guard: needs Python 3.11 or newer (manifest parsing uses tomllib); "
        f"this interpreter is {sys.version_info.major}.{sys.version_info.minor}. "
        "Failing closed -- nothing was installed.",
        file=sys.stderr,
    )
    sys.exit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Module-level imports run before main(), so main()'s fail-closed handler cannot
# see them. An ImportError here would exit 1 with a traceback, and Claude Code
# treats a non-2 exit as a non-blocking error -- the command proceeds and the
# guard is absent while appearing installed. tomllib (manifest.py) needs 3.11+;
# the same hole opens for any syntax error or missing file in these four modules.
try:
    import tomllib  # noqa: E402
    import baseline  # noqa: E402
    import bench_config  # noqa: E402
    import bench_gate  # noqa: E402
    import legacy  # noqa: E402
    import bun_lock  # noqa: E402,F401
    import disk_guard  # noqa: E402
    import lock_errors  # noqa: E402,F401
    import manifest as pg_manifest  # noqa: E402
    import mode as pg_mode  # noqa: E402
    import pm_config  # noqa: E402
    import pnpm_lock  # noqa: E402,F401
    import parser as pg_parser  # noqa: E402
    import sources  # noqa: E402
    import store  # noqa: E402
    import transcript  # noqa: E402
    import vetting  # noqa: E402
    import yarn_lock  # noqa: E402,F401
except Exception as _exc:  # pragma: no cover - exercised by test_import_guard
    print(
        f"Package Guard: hook modules failed to load ({_exc.__class__.__name__}: {_exc}); "
        "failing closed. Package Guard requires Python 3.11+.",
        file=sys.stderr,
    )
    sys.exit(2)

_REQUIRED_CLI_FLAGS = {"--no-project", "--no-config", "--no-python-downloads"}

# A state-changing call to Package Guard's own CLI. If this appears in a command
# that _guard_cli_call() could not recognise as a clean, standalone invocation
# (compound syntax, a wrapper, unbalanced quotes), the human approval gate would
# be skipped silently — so fail closed instead. Deliberately narrow: 'show' and
# ordinary reads of the source file (cat/grep) are unaffected. `reconcile` and
# `audit` are here because an installed project's sandbox excludes them: a
# wrapped or prefixed form would run outside it. `mode` is here because only
# its exact standalone form is told apart from turning the guard down; it is
# matched only as a word of its own, so `cli.py mode.py` (two file names) is not.
_GUARD_CLI_HINT = re.compile(
    r"package_guard/cli\.py\s+(?:(?:approve|decline|undecline|revoke|reconcile|audit)\b"
    r"|(?:mode|baseline|git-owners|bench-config)(?![\w.\-]))")
# A plugin's guard lives wherever the plugin is installed, so any cli.py named
# with one of those verbs counts.
_PLUGIN_CLI_HINT = re.compile(
    r"cli\.py\s+(?:(?:approve|decline|undecline|revoke|reconcile|audit)\b"
    r"|(?:mode|baseline|git-owners|bench-config)(?![\w.\-]))")
# The guard's CLI reached some other way: the people's launcher `pg` given any
# argument, or run.sh handed cli.py. Neither is a form the checks above can
# read, so Claude is refused both and pointed at the one it may use. A plain
# read (`cat …/pg`) names no argument after it and still runs.
_LAUNCHER_HINT = re.compile(r"package_guard/pg(?![\w.\-])\s+\S|run\.sh\s+\S*cli\.py")
# The shell removes quotes and backslashes before it runs anything, so
# `'…/cli.py' approve`, `cli.py \mode` and `cli.py m''ode` are the same calls.
_SHELL_QUOTING = re.compile(r"[\"'\\]")


def _names_cli_verb(command: str, plugin: bool) -> bool:
    """The command text names a state-changing guard CLI verb, read as written
    and again with the shell's quoting removed. Text only: a verb built from a
    variable is out of reach, as for every hint here."""
    hint = _PLUGIN_CLI_HINT if plugin else _GUARD_CLI_HINT
    return bool(hint.search(command) or hint.search(_SHELL_QUOTING.sub("", command)))

# Guard state -- vetted.json, declined.json, the reports, the identity
# catalogs -- is written only by the guard CLI behind its prompts. In a project
# whose settings carry the installer's lock rules, the guard's own files (hook
# source, vetter, skill, both settings files) are written only by the human,
# outside Claude.
#
# Two layers. The coarse match -- a protected name together with a write-shaped
# verb, a redirect into it, or an inline interpreter carrying a write token --
# is the default, and it never needs to understand the command. The precise
# pass splits plain commands, follows `cd`, and resolves each written path; it
# may ALLOW only a command it fully understands (copying the catalog out is a
# read), and it may DENY on its own (relative and no-slash forms of a write).
# Neither is a shell parser: a script file or an interpreter the text does not
# show is out of reach; the sandbox closes that gap.
_GUARD_STATE_SEGMENT = ".claude/package-guard/"
_GUARD_LOCK_RULE = "Edit(.claude/hooks/package_guard/**)"
_STATE_MARKERS = (".claude/package-guard", ".config/package-guard", "trusted-packages.json")
# `.claude` covers a write to a directory containing the locked files when the
# command is not understood (`rm -rf "$PWD/.claude"`).
_SOURCE_MARKERS = ("package_guard", "package-vetter", "skills/package-guard",
                   "settings.json", "settings.local.json", ".claude")
_STATE_PATHS = (".claude/package-guard", ".claude/hooks/package_guard/trusted-packages.json")
_SOURCE_PATHS = (".claude/hooks/package_guard", ".claude/agents/package-vetter.md",
                 ".claude/skills/package-guard", ".claude/settings.json",
                 ".claude/settings.local.json")
_GUARD_STATE_WRITERS = re.compile(
    r"(?:^|[\s;&|(`'\"{,])"
    r"(?:tee|cp|mv|rm|rmdir|truncate|touch|ln|chmod|chown|dd|sponge|install|unlink|shred|"
    r"sed|perl|sort|uniq|tree|awk|gawk|find|curl|wget|rsync|scp|tar|unzip|patch|"
    r"git\s+(?:\S+\s+)*?(?:checkout|restore|rm|mv|apply|stash|reset|clean|am|switch|pull|merge|"
    r"rebase|cherry-pick|revert|read-tree|checkout-index)"
    r"|git\s.*--output\S*)"
    r"(?=[\s'\",};&|)]|$)"
)
# An inline interpreter is a writer only when its code says so: reading the
# JSON with `python3 -c` is the ordinary way to inspect guard state.
_GUARD_STATE_INLINE = re.compile(
    r"(?:^|[\s;&|(`])(?:python3?\s+-c(?=\s)|node\s+-e(?=\s)|(?:python3?|node)\s*(?:-\s*)?<<)")
_GUARD_STATE_INLINE_WRITE = re.compile(
    r"[\"'][wax]b?\+?[\"']|\.write\(|\.dump\(|os\.replace|os\.rename|unlink|\bremove\(|"
    r"rename\(|writeFile|truncate|rmSync|renameSync|shutil\."
)
# The guard's installer, run by Claude in a locked project, would take the lock
# off in one command that names no protected path.
_GUARD_INSTALLER = re.compile(r"install\.(?:py|sh)\b")

# Commands the precise pass understands. Anything else hands the decision back
# to the coarse match.
_READERS = {"cat", "ls", "grep", "egrep", "fgrep", "rg", "head", "tail", "jq", "wc", "diff",
            "echo", "printf", "less", "more", "stat", "file", "test", "[", "true", "false",
            "pwd", "cut", "tr", "find", "du", "realpath",
            "basename", "dirname", "shasum", "sha256sum", "md5", "mkdir", "which", "type"}
_GIT_READS = {"status", "diff", "log", "show", "blame", "grep", "ls-files", "rev-parse", "add",
              "commit", "branch", "tag", "fetch", "describe", "shortlog", "reflog", "push",
              "ls-tree", "cat-file", "merge-base", "rev-list", "show-ref", "remote"}
# Git subcommands that can rewrite the work tree. In a repository that tracks
# guard files the hook asks git itself whether they would change (_git_write).
_GIT_TREE = {"checkout", "switch", "restore", "reset", "stash", "apply", "am", "rm", "mv",
             "clean", "merge", "pull", "rebase", "cherry-pick", "revert", "read-tree",
             "checkout-index", "filter-branch", "filter-repo"}
_ALL_OPERANDS = {"tee", "rm", "rmdir", "touch", "truncate", "chmod", "chown", "unlink", "shred",
                 "sponge"}
_COPIERS = {"cp", "ln", "install"}
_TAKES_VALUE = {"truncate": {"-s", "--size", "-r", "--reference"}, "install": {"-m", "-o", "-g"}}
# Commands that run another command, or a script, from their arguments or
# stdin. Their segment is never judged on its own text.
_EXECUTORS = {"xargs", "sudo", "doas", "su", "env", "command", "builtin", "exec", "eval", "source",
              ".", "nohup", "nice", "ionice", "timeout", "time", "stdbuf", "watch", "parallel",
              "flock", "chroot", "unshare", "taskset", "caffeinate", "script", "sh", "bash",
              "zsh", "dash", "ksh", "fish", "csh", "tcsh"}
_SHELL_PREFIX = {"if", "then", "else", "elif", "do", "while", "until", "!"}
_SHELL_END = {"fi", "done", "esac"}
_SHELL_UNREAD = {"for", "case", "select", "function", "coproc", "trap", "alias"}


def _guard_locked(root) -> bool:
    """The installer's lock rules are in this project's settings.

    A plugin cannot ship deny rules; the guard's own Edit hook is its lock, so a
    plugin project is always locked."""
    if store.plugin_mode():
        return True
    path = Path(root) / ".claude" / "settings.json"
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return True
    deny = (settings.get("permissions") or {}).get("deny") if isinstance(settings, dict) else None
    return isinstance(deny, list) and _GUARD_LOCK_RULE in deny


# A heredoc fed to `cat` is data (a commit message); where cat's output goes is
# outside the body and still matched.
_CAT_HEREDOC = re.compile(r"(\bcat\s+<<-?\s*['\"]?(\w+)['\"]?[^\n]*\n).*?\n\s*\2\b", re.DOTALL)


def _coarse_guard_write(command: str, locked: bool):
    command = _CAT_HEREDOC.sub(lambda m: m.group(1) + m.group(2), command)
    markers = _STATE_MARKERS + (_SOURCE_MARKERS if locked else ())
    named = [m for m in markers if m in command]
    if not named:
        return None
    kind = "state" if any(m in _STATE_MARKERS for m in named) else "source"
    alternatives = "|".join(re.escape(m) for m in named)
    if re.search(r">>?\|?\s*[\"']?\S*(?:%s)" % alternatives, command):
        return kind
    if _GUARD_STATE_WRITERS.search(command):
        return kind
    if _GUARD_STATE_INLINE.search(command) and _GUARD_STATE_INLINE_WRITE.search(command):
        return kind
    return None


class _NotUnderstood(Exception):
    pass


# A heredoc body is stdin data. It is cut out and replaced by an input
# redirect, so a commit message that mentions `reset` and `settings.json` is
# not read as a command; a command that would EXECUTE stdin (an interpreter,
# a shell) is not understood and goes back to the coarse match.
_HEREDOC = re.compile(r"(?<!<)<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")
_HEREDOC_DATA = "__package_guard_heredoc__"
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_BRACE_EXPANSION = re.compile(r"\{[^{}]*(?:,|\.\.)[^{}]*\}")


def _strip_heredocs(command: str) -> str:
    while True:
        match = _HEREDOC.search(command)
        if not match:
            return command
        line_end = command.find("\n", match.end())
        if line_end < 0:
            raise _NotUnderstood
        word, dash, pos = match.group(3), match.group(1), line_end + 1
        while True:
            nxt = command.find("\n", pos)
            line = command[pos:nxt if nxt >= 0 else len(command)]
            if (line.lstrip("\t") if dash else line) == word:
                end = nxt if nxt >= 0 else len(command)
                break
            if nxt < 0:
                raise _NotUnderstood
            pos = nxt + 1
        command = (command[:match.start()] + "< " + _HEREDOC_DATA
                   + command[match.end():line_end] + command[end:])


def _segments(command: str):
    """[("seg", words, out-redirects, in-redirects, piped) | ("push",) | ("pop",)].

    `{ ...; }` groups are read through; `( ... )` subshells scope a `cd`."""
    command = _strip_heredocs(command)
    if any(s in command for s in ("$(", "${", "`", "<(", ">(")):
        raise _NotUnderstood
    lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        raise _NotUnderstood
    items = []
    state = {"words": [], "out": [], "in": [], "piped": False}

    def flush(next_piped):
        if state["words"] or state["out"] or state["in"]:
            items.append(("seg", state["words"], state["out"], state["in"], state["piped"]))
        state.update(words=[], out=[], piped=next_piped)
        state["in"] = []

    expect = None
    for token in tokens:
        punct = bool(token) and set(token) <= set("<>&|;()")  # '' is a quoted empty word
        if expect:
            if punct:
                raise _NotUnderstood
            state[expect].append(token)
            expect = None
        elif punct and ">" in token:
            if state["words"] and state["words"][-1].isdigit():
                state["words"].pop()
            expect = "out"
        elif punct and "<" in token:
            if set(token) != {"<"} or len(token) == 2:
                raise _NotUnderstood
            if state["words"] and state["words"][-1].isdigit():
                state["words"].pop()
            expect = "in"
        elif token in ("(", ")"):
            flush(False)
            items.append(("push",) if token == "(" else ("pop",))
        elif punct:
            if "(" in token or ")" in token:
                raise _NotUnderstood
            flush(token in ("|", "|&"))
        elif token in ("{", "}") and not state["words"]:
            continue
        else:
            state["words"].append(token)
    if expect:
        raise _NotUnderstood
    flush(False)
    return items


def _glob_matches(pattern: str, path: str, ancestors: bool) -> bool:
    """The glob can name `path`, something inside it, or (with `ancestors`)
    a directory containing it."""
    import fnmatch
    pat, parts = pattern.split("/"), path.split("/")
    if len(pat) < len(parts) and not ancestors:
        return False
    depth = min(len(pat), len(parts))
    for p, part in zip(pat[:depth], parts[:depth]):
        if part.startswith(".") and not p.startswith("."):
            return False
        if not fnmatch.fnmatchcase(part, p):
            return False
    return True


def _hits(target: str, protected, ancestors: bool) -> bool:
    """target and protected are absolute, normalised. A glob target matches by pattern."""
    for path in protected:
        if any(c in target for c in "*?["):
            if _glob_matches(target, path, ancestors):
                return True
            continue
        if target == path or target.startswith(path + "/"):
            return True
        if ancestors and path.startswith(target.rstrip("/") + "/"):
            return True
    return False


def _git(args, cwd):
    """(returncode, stdout) of a read-only git query; None when git cannot run."""
    try:
        done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=10,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.returncode, done.stdout.decode("utf-8", "replace")


# `git -c` keys that change only output or identity, never which tree is
# written. Any other key makes the command opaque.
_GIT_INERT_CONFIG = ("color.", "advice.", "user.", "core.quotepath", "commit.gpgsign",
                     "init.defaultbranch", "pager.", "column.")


_GIT_VALUE_FLAGS = {
    "checkout": {"-b", "-B", "--orphan", "--conflict"},
    "switch": {"-c", "-C", "--orphan", "--conflict"},
    "restore": {"-s", "--source", "--conflict"},
    "merge": {"-m", "-s", "-X", "-F", "--strategy", "--strategy-option", "--file",
              "--into-name"},
    "rebase": {"-s", "-X", "--strategy", "--strategy-option", "--onto", "-x", "--exec"},
    "cherry-pick": {"-m", "--mainline", "-X", "--strategy", "--strategy-option"},
    "revert": {"-m", "--mainline", "-X", "--strategy", "--strategy-option"},
    "stash": {"-m", "--message"},
    "clean": {"-e", "--exclude"},
}


def _git_write(sub, args, here, protected, inside, opaque=False, config=()) -> bool:
    """Would this git command change a tracked or untracked guard file? `inside(word)` resolves a pathspec and tells whether
    it is in (True), above ("above") or outside (False) the guard files.
    Anything git cannot answer counts as a write; so does any tree-changing
    command run with GIT_* variables the hook cannot see through (`opaque`).
    `config` is the command's `-c safe.directory=...` options, passed to every
    query so a mount git distrusts is seen as git will see it. Any other
    config is never forwarded (core.fsmonitor and friends run commands);
    the caller marks it opaque instead."""
    if sub in ("rm", "mv") and not opaque:
        return any(inside(a) for a in args if not a.startswith("-"))
    # A pathspec inside the guard files is a write whatever git would make of it.
    if any(inside(a) is True for a in args if not a.startswith("-")):
        return True
    found = _git([*config, "rev-parse", "--show-toplevel"], here)
    if found is None:
        return True
    if found[0] != 0:
        # Not a repository here: git refuses and writes nothing, unless
        # GIT_* variables the hook cannot see point it at one.
        return opaque
    top = os.path.realpath(found[1].strip())
    real = [os.path.realpath(p) for p in protected]
    guard = [os.path.relpath(p, top) for p in real if p == top or p.startswith(top + "/")]
    if not guard:
        return False
    if opaque:
        return True

    # The directories that hold the guard files. A tree that tracks one of them as a file (or
    # a link, or a submodule) replaces the directory, and the file in it goes with it, which
    # a diff of the guard files' own paths does not show.
    ancestors = sorted({Path(*Path(g).parts[:i]).as_posix() for g in guard
                        for i in range(1, len(Path(g).parts))})

    def replaces(*revs) -> bool:
        if not ancestors:
            return False
        for rev in revs or (None,):
            if rev is not None and ".." in rev:
                rev = rev.rsplit("..", 1)[1].lstrip(".") or "HEAD"
            # One query for each directory: a pathspec that is a directory is listed by what
            # is inside it, and the entry for the directory itself is what is wanted.
            for ancestor in ancestors:
                if rev is None:
                    listed = _git([*config, "ls-files", "-s", "-z", "--", ancestor], top)
                else:
                    listed = _git([*config, "ls-tree", "-z", rev, "--", ancestor], top)
                if listed is None or listed[0] != 0:
                    return True
                for entry in filter(None, listed[1].split("\0")):
                    meta, _, path = entry.partition("\t")
                    if path != ancestor:
                        continue  # (the index lists the files under a directory, not it)
                    if rev is None or not meta.startswith("040000"):
                        return True  # a file, a link or a submodule where the directory is
        return False

    def differs(*revs) -> bool:
        result = _git([*config, "diff", "--quiet", *revs, "--", *guard], top)
        return result is None or result[0] != 0 or replaces(*revs)

    def untracked(*extra) -> bool:
        result = _git([*config, "ls-files", "--others", *extra, "--", *guard], top)
        return result is None or result[0] != 0 or bool(result[1].strip())

    def commit(rev) -> bool:
        result = _git([*config, "rev-parse", "--verify", "--quiet", rev + "^{commit}"], top)
        return result is not None and result[0] == 0

    def remote(name) -> str | None:
        """The remote branch `git checkout/switch <name>` would create from."""
        listed = _git([*config, "for-each-ref", "--format=%(refname)", "refs/remotes/*/" + name], top)
        refs = listed[1].split() if listed and listed[0] == 0 else []
        return refs[0] if len(refs) == 1 else None

    flags = [a for a in args if a.startswith("-")]
    values = _GIT_VALUE_FLAGS.get(sub, set())
    operands, paths, skip = [], [], False
    for i, a in enumerate(args):
        if skip:
            skip = False
        elif a == "--":
            paths = args[i + 1:]
            break
        elif a in values:
            skip = True
        elif not a.startswith("-"):
            operands.append(a)
    if sub in ("checkout", "switch", "restore"):
        source = None
        for i, a in enumerate(args):
            if a in ("-s", "--source") and i + 1 < len(args):
                source = args[i + 1]
            elif a.startswith("--source="):
                source = a.split("=", 1)[1]
        if sub == "checkout":
            if "--" in args:
                source = operands[0] if operands else None
            elif operands and commit(operands[0]):
                source, paths = operands[0], operands[1:]
            elif (len(operands) == 1 and not os.path.lexists(os.path.join(here, operands[0]))
                  and remote(operands[0])):
                source = remote(operands[0])
            else:
                paths = operands
        elif sub == "switch":
            if "--orphan" in flags:
                tracked = _git([*config, "ls-files", "--", *guard], top)
                return tracked is None or tracked[0] != 0 or bool(tracked[1].strip())
            source = operands[0] if operands else None
            if source and not commit(source):
                source = remote(source) or source
        else:
            paths = paths or operands
            if "--staged" in flags and "--worktree" not in flags and "-W" not in flags:
                return False
        if paths:
            where = [inside(p) for p in paths]
            if True in where:
                return True
            if "above" not in where:
                return False
            return differs(source) if source else differs()
        if not source:
            return False
        forced = any(f in ("-f", "--force", "--discard-changes", "-m", "--merge") for f in flags)
        return differs("HEAD", source) or (forced and differs("HEAD"))
    if sub == "reset":
        if not any(f in ("--hard", "--merge", "--keep") for f in flags):
            return False
        return differs(operands[0] if operands else "HEAD")
    if sub == "stash":
        verb = operands[0] if operands else "push"
        if verb in ("list", "show", "drop", "clear", "create", "store"):
            return False
        if verb in ("push", "save"):
            if differs("HEAD"):
                return True
            if any(f in ("-a", "--all") for f in flags):
                return untracked()
            if any(f in ("-u", "--include-untracked") for f in flags):
                return untracked("--exclude-standard")
            return False
        ref = operands[1] if len(operands) > 1 else "stash@{0}"
        if verb in ("pop", "apply", "branch"):
            if verb == "branch":
                ref = operands[2] if len(operands) > 2 else "stash@{0}"
            if differs(ref + "^1", ref):
                return True
            third = _git([*config, "ls-tree", "-r", "--name-only", ref + "^3", "--", *guard], top)
            return third is not None and third[0] == 0 and bool(third[1].strip())
        return True
    if sub == "clean":
        if any(f in ("-n", "--dry-run") or (not f.startswith("--") and "n" in f) for f in flags):
            return False
        if any(f == "-x" or (not f.startswith("--") and "x" in f) for f in flags):
            return untracked()
        if any(f == "-X" or (not f.startswith("--") and "X" in f) for f in flags):
            return untracked("--ignored", "--exclude-standard")
        return untracked("--exclude-standard")
    if sub in ("merge", "rebase"):
        if any(f in ("--continue", "--edit-todo", "--show-current-patch") for f in flags):
            return False
        if any(f in ("--abort", "--quit", "--skip") for f in flags):
            return differs("ORIG_HEAD") or differs("HEAD")
        if sub == "rebase":
            # --exec runs commands between picks; --root rewrites everything.
            if "--root" in flags or any(f in ("-x", "--exec") or f.startswith("--exec=")
                                        for f in flags):
                return True
            onto = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "--onto"]
            onto += [a.split("=", 1)[1] for a in args if a.startswith("--onto=")]
            bases = onto + operands[:1] or ["@{upstream}"]
        else:
            bases = operands or ["@{upstream}"]
        return any(differs("HEAD..." + base) if commit(base) else True for base in bases)
    if sub in ("cherry-pick", "revert"):
        if "--continue" in flags:
            return False
        if any(f in ("--abort", "--quit", "--skip") for f in flags):
            return differs("HEAD")
        if not operands:
            return True
        for rev in operands:
            pair = rev.split("..", 1) if ".." in rev and "..." not in rev else (rev + "^", rev)
            if not all(commit(r) for r in pair) or differs(*pair):
                return True
        return False
    if sub == "apply" and not any(f in ("--index", "--3way", "-3", "--apply") for f in flags) \
            and any(f in ("--check", "--stat", "--numstat", "--summary", "--cached")
                    for f in flags):
        return False
    if sub in ("apply", "am"):
        if any(f in ("--abort", "--quit", "--skip") for f in flags):
            return differs("HEAD")
        if "--continue" in flags or "--resolved" in flags:
            return False
        if not operands or any(f.startswith(("-p", "--directory", "--include", "--exclude"))
                               for f in flags):
            return True
        listed = _git([*config, "apply", "--numstat", "-z", *[os.path.join(here, o) for o in operands]],
                      top)
        if listed is None or listed[0] != 0:
            return True
        touched = []
        for field in listed[1].split("\0"):
            touched.append(field.split("\t")[-1])
        return any(t and (inside(os.path.join(top, t)) or inside(t)) for t in touched)
    return True


_ARCHIVE_EXTRACTORS = {"tar", "bsdtar", "gtar", "gnutar", "unzip", "7z", "7za", "7zr", "7zz",
                       "cpio", "pax"}


def _short_flags(args) -> str:
    """The letters of the short-option clusters in `args` (`-xzf` gives `xzf`), before `--`."""
    letters = ""
    for a in args:
        if a == "--":
            break
        if a.startswith("-") and not a.startswith("--"):
            letters += a[1:]
    return letters


def _tree_copy_writes(sources, directory, resolve, tree_overwrites, delete=False) -> bool:
    """Whether a recursive copy of `sources` into `directory` (the destination operand)
    can overwrite a recorded installer file. Each source is copied to `directory/<name>`
    when `directory` is a directory that is there, to `directory` itself when it is not,
    and as its contents into `directory` when it ends in `/.` (and, for BSD cp and rsync,
    in `/`: both are tried). A source a remote host holds is not known."""
    target = resolve(directory)
    is_dir = os.path.isdir(target)
    for source in sources:
        if re.match(r"^[^/]*:", source) and not source.startswith(("/", ".", "~")):
            return tree_overwrites(os.devnull, target, True)  # `host:path`: contents unknown
        contents = source.endswith("/.")
        folded = source[:-2] if contents else source
        trailing = folded.endswith("/") and not contents
        src = resolve(folded.rstrip("/") or "/")
        roots = [target]
        if not contents and (is_dir or len(sources) > 1):
            roots = [os.path.join(target, os.path.basename(src))] + ([target] if trailing else [])
        if any(tree_overwrites(src, root, delete) for root in roots):
            return True
    return False


def _tree_command_writes(name, args, here, resolve, extraction_covers, tree_overwrites) -> bool:
    """True when this archive extraction, `ditto` or `rsync` can write a recorded installer
    file. An archive's members are not read, so extracting into a directory that holds one
    counts, whatever the archive is; a tree copy is judged by the source that is on disk."""
    letters = _short_flags(args)
    operands = [a for a in args if not a.startswith("-")]
    if name in ("tar", "bsdtar", "gtar", "gnutar"):
        # `tar xf a.tar` (no dash) is an option bundle too
        old_style = bool(operands) and not args[0].startswith("-") and "x" in operands[0]
        if not ("x" in letters or old_style
                or any(a in ("--extract", "--get") or a.startswith("--extract") for a in args)):
            return False
        dirs = [a[2:] for a in args if a.startswith("-C") and len(a) > 2]
        dirs += [b for a, b in zip(args, args[1:]) if a in ("-C", "--directory")]
        dirs += [a.split("=", 1)[1] for a in args if a.startswith("--directory=")]
        return any(extraction_covers(d) for d in (dirs or [here]))
    if name == "unzip":
        # unzip's mode flags, as whole option words (`-dDIR` is a directory, not flags)
        if any(re.fullmatch(r"-[lvtpZcnoqjLUCa]+", a) and set(a[1:]) & set("lvtpZc") for a in args):
            return False
        dirs = [b for a, b in zip(args, args[1:]) if a == "-d"] + [
            a[2:] for a in args if a.startswith("-d") and len(a) > 2]
        return any(extraction_covers(d) for d in (dirs or [here]))
    if name.startswith("7z"):
        verb = operands[0] if operands else ""
        if verb not in ("x", "e"):
            return False
        dirs = [a[2:] for a in args if a.startswith("-o") and len(a) > 2]
        return any(extraction_covers(d) for d in (dirs or [here]))
    if name == "cpio":
        if "i" not in letters and "p" not in letters:
            return False
        dirs = [b for a, b in zip(args, args[1:]) if a in ("-D", "--directory")]
        if "p" in letters and operands:
            dirs = dirs or [operands[-1]]
        return any(extraction_covers(d) for d in (dirs or [here]))
    if name == "pax":
        if "r" not in letters or "w" in letters:
            return False
        return extraction_covers(operands[-1] if operands and "p" in letters else here)
    if name == "ditto":
        if "c" in letters and "x" not in letters:
            return False
        if len(operands) < 2:
            return False
        if "x" in letters:
            return extraction_covers(operands[-1])
        # ditto merges each source directory's contents into the destination
        return _tree_copy_writes([s.rstrip("/") + "/." for s in operands[:-1]], operands[-1],
                                 resolve, tree_overwrites)
    if name == "rsync":
        if len(operands) < 2:
            return False
        recursive = any(a in ("--recursive", "--archive", "--dirs") for a in args) or bool(
            set(letters) & set("rad"))
        if not recursive:
            return False
        delete = any(a.startswith(("--delete", "--remove")) for a in args)
        destination = operands[-1]
        if re.match(r"^[^/]*:", destination) and not destination.startswith(("/", ".", "~")):
            return False  # the destination is a remote host
        return _tree_copy_writes(operands[:-1], destination, resolve, tree_overwrites, delete)
    return False


def _precise_guard_write(command: str, root, cwd, locked: bool):
    """Return (understood, kind-or-None)."""
    home = str(Path.home())
    root = os.path.normpath(str(root))
    state = [os.path.join(root, p) for p in _STATE_PATHS] + [os.path.join(home, ".config/package-guard")]
    source = [os.path.join(root, p) for p in _SOURCE_PATHS] if locked else []
    if locked and store.plugin_root():
        source.append(store.plugin_root())
    real_state = [os.path.realpath(p) for p in state]
    real_source = [os.path.realpath(p) for p in source]
    # The installer files the CLI wrote for a bench (pip.conf, uv.toml, .yarnrc): folded as
    # NTFS compares names, and only once the CLI has recorded any.
    installer_files = bench_config.config_paths(root) if pg_parser.FRAPPE_ENABLED else []
    installer_paths = ([os.path.normpath(str(p)) for p in bench_config.recorded_paths(root)]
                       if installer_files else [])
    here = os.path.normpath(str(cwd or root))
    stack, moved = [], False

    def resolve(word: str, base=None) -> str:
        # `stash@{0}` is a word; `{a,b}` and `{1..3}` are shell expansions.
        if "$" in word or "\\" in word or _BRACE_EXPANSION.search(word):
            raise _NotUnderstood
        if word == "~" or word.startswith("~/"):
            word = home + word[1:]
        elif word.startswith("~"):
            raise _NotUnderstood
        return os.path.normpath(os.path.join(base or here, word))

    def kind_of(target: str, ancestors: bool):
        # An existing symlink is followed too: an alias made before the lock
        # is the same file.
        real = None if any(c in target for c in "*?[") else os.path.realpath(target)
        if _hits(target, source, ancestors) or (real and _hits(real, real_source, ancestors)):
            return "source"
        if _hits(target, state, ancestors) or (real and _hits(real, real_state, ancestors)):
            return "state"
        if installer_files and (
                _hits(bench_config.fold_path(target), installer_files, ancestors)
                or (real and _hits(bench_config.fold_path(real), installer_files, ancestors))):
            return "config"
        return None

    def check(words, ancestors=True, base=None):
        for word in words:
            if not word:
                continue
            found = kind_of(resolve(word, base), ancestors)
            if found:
                return found
        return None

    def inside(word):
        target = resolve(word)
        if kind_of(target, False):
            return True
        return "above" if kind_of(target, True) else False

    def recorded_under(root_path):
        """[(recorded file, its path below `root_path` as parts)] for each recorded installer
        file at or below `root_path`, which a copy onto `root_path` can overwrite."""
        found = []
        for recorded in installer_paths:
            for candidate, base in ((recorded, root_path),
                                    (os.path.realpath(recorded), os.path.realpath(root_path))):
                at, under = bench_config.fold_path(candidate), bench_config.fold_path(base)
                if at == under or at.startswith(under.rstrip(os.sep) + os.sep):
                    found.append((recorded, Path(candidate).parts[len(Path(base).parts):]))
                    break
        return found

    def tree_overwrites(source, root_path, delete=False):
        """Would copying the tree at `source` onto `root_path` overwrite, or (`delete`: an
        rsync that removes what the source lacks) remove, a recorded file? True unless the
        source is a directory on disk that has no such member: what a source that is not
        there yet holds is not known."""
        hits = recorded_under(root_path)
        if not hits:
            return False
        if delete or not os.path.isdir(source):
            return True
        return any(not parts or os.path.lexists(os.path.join(source, *parts)) for _p, parts in hits)

    def extraction_covers(directory):
        """An archive's members are not read: extracting into a directory that holds a
        recorded file may overwrite it."""
        return bool(recorded_under(resolve(directory)))

    try:
        for item in _segments(command):
            if item[0] == "push":
                stack.append(here)
                continue
            if item[0] == "pop":
                if not stack:
                    raise _NotUnderstood
                here = stack.pop()
                continue
            _, words, redirects, inputs, piped = item
            found = check(redirects)
            if found:
                return True, found
            while words and words[0] in _SHELL_PREFIX:
                words = words[1:]
            if not words:
                continue
            if words[0] in _SHELL_END:
                if len(words) > 1:
                    raise _NotUnderstood
                continue
            assigned = []
            while words and _ASSIGNMENT.match(words[0]):
                assigned.append(words[0].split("=", 1)[0])
                words = words[1:]
            if not words:
                continue
            if (words[0] in _SHELL_UNREAD or words[0].startswith("-")
                    or "=" in words[0] or "$" in words[0] or "\\" in words[0]):
                raise _NotUnderstood
            name = os.path.basename(words[0])
            args = words[1:]
            operands = [a for a in args if not a.startswith("-")]
            if installer_paths and (name in _ARCHIVE_EXTRACTORS or name in ("ditto", "rsync")) and (
                    _tree_command_writes(name, args, here, resolve, extraction_covers,
                                         tree_overwrites)):
                return True, "config"
            if name in ("cd", "pushd"):
                if len(operands) != 1 or len(args) != 1:
                    raise _NotUnderstood
                here, moved = resolve(operands[0]), True
                continue
            if name == "git":
                at, config, opaque_config = here, [], False
                while args and args[0].startswith("-"):
                    if args[0] == "-C" and len(args) > 1:
                        at, args = resolve(args[1]), args[2:]
                    elif args[0] == "-c" and len(args) > 1:
                        key = args[1].split("=", 1)[0].lower()
                        if key == "safe.directory":
                            config += args[:2]
                        elif not key.startswith(_GIT_INERT_CONFIG):
                            opaque_config = True
                        args = args[2:]
                    elif args[0] in ("--no-pager", "-P", "--paginate", "--no-optional-locks",
                                     "--literal-pathspecs", "--no-replace-objects"):
                        args = args[1:]
                    else:
                        raise _NotUnderstood
                if not args or any(a.startswith(("--output", "-o")) for a in args[1:]):
                    raise _NotUnderstood
                if args[0] in _GIT_READS:
                    continue
                if args[0] not in _GIT_TREE:
                    raise _NotUnderstood
                saved, here = here, at
                opaque = opaque_config or any(n.startswith("GIT_") for n in assigned)
                wrote = _git_write(args[0], args[1:], here, source + state + installer_paths,
                                   inside, opaque, config)
                here = saved
                if wrote:
                    return True, "git"
                continue
            if name == "sed":
                if not any(a.startswith("-i") or a.startswith("--in-place") or
                           (a.startswith("-") and not a.startswith("--") and "i" in a)
                           for a in args):
                    # A sed script can write with its own `w` command.
                    if any(re.search(r"(?:^|[;{}\s/])[wW]\s*\S", a) for a in args):
                        raise _NotUnderstood
                    continue
                found = check(operands)
            elif _venv_creation(name, args) is not None:
                # `uv venv`, `python -m venv`, `virtualenv`: with `--clear` (or over an existing env) they
                # remove the guard's `env/pip.conf`, and `--seed` fetches pip and setuptools unreviewed.
                # A target the shell builds (`$PWD/env`, `` `pwd`/env ``) may be the env: a guard write.
                targets = _venv_creation(name, args)
                found = ("config" if any(re.search(r"[$`{\\]", t) or (t.startswith("~") and t != "~"
                                                                      and not t.startswith("~/"))
                                         for t in targets)
                         else check(targets or [".venv"]))
            elif name in _READERS:
                if name == "find":
                    for i, a in enumerate(args):
                        if a == "-delete" or a.startswith(("-fprint", "-fls")):
                            raise _NotUnderstood
                        if a in ("-exec", "-execdir", "-ok", "-okdir"):
                            run = os.path.basename(args[i + 1]) if i + 1 < len(args) else ""
                            if run not in _READERS or run in ("find", "mkdir"):
                                raise _NotUnderstood
                continue
            elif name in _ALL_OPERANDS:
                skip = _TAKES_VALUE.get(name, set())
                kept, drop = [], False
                for a in args:
                    if drop:
                        drop = False
                    elif a in skip:
                        drop = True
                    elif not a.startswith("-"):
                        kept.append(a)
                found = check(kept)
            elif name == "mv":
                found = check(operands)
            elif name in _COPIERS:
                skip = _TAKES_VALUE.get(name, set())
                kept, drop, directory = [], False, None
                for a in args:
                    if drop is True:
                        drop = False
                    elif drop == "t":
                        directory, drop = a, False
                    elif a in ("-t", "--target-directory"):
                        drop = "t"
                    elif a.startswith("--target-directory="):
                        directory = a.split("=", 1)[1]
                    elif a in skip:
                        drop = True
                    elif not a.startswith("-"):
                        kept.append(a)
                if directory is None:
                    if len(kept) < 2:
                        raise _NotUnderstood
                    directory, kept = kept[-1], kept[:-1]
                written = [directory] + [os.path.join(directory, os.path.basename(k.rstrip("/")))
                                         for k in kept]
                found = check(written, ancestors=False)
                if not found and name == "cp" and installer_paths and any(
                        a in ("--recursive", "--archive")
                        or (a.startswith("-") and not a.startswith("--") and set(a[1:]) & set("rRa"))
                        for a in args):
                    found = "config" if _tree_copy_writes(kept, directory, resolve, tree_overwrites) else None
                # A link is an alias: one made TO a guard file or directory
                # lets a later write reach it under an unprotected name.
                linking = name == "ln" or (name == "cp" and any(
                    a in ("--link", "--symbolic-link") or
                    (a.startswith("-") and not a.startswith("--") and ("l" in a or "s" in a))
                    for a in args))
                if not found and linking:
                    found = check(kept)
                    target_dir = resolve(directory)
                    if not found and not os.path.isdir(target_dir):
                        target_dir = os.path.dirname(target_dir)
                    if not found:
                        found = check(kept, base=target_dir)
            elif name == "dd":
                found = check([a[3:] for a in args if a.startswith("of=")])
            elif name in ("sort", "tree"):
                # Readers with an output-file option.
                targets = [a.split("=", 1)[1] for a in args if a.startswith("--output=")]
                targets += [b for a, b in zip(args, args[1:]) if a in ("-o", "--output")]
                targets += [a[2:] for a in args if a.startswith("-o") and len(a) > 2]
                found = check(targets)
            elif name == "uniq":
                found = check(operands[1:2])
            else:
                # A command the pass does not model. Judged on its own text
                # when nothing else can steer it: not fed by a pipe or stdin,
                # not after a `cd`, not a command that runs other commands.
                if piped or inputs or moved or name in _EXECUTORS:
                    raise _NotUnderstood
                found = (_coarse_guard_write(shlex.join(words), locked)
                         or _coarse_config_write(shlex.join(words), root))
            if found:
                return True, found
    except _NotUnderstood:
        return False, None
    return True, None


_PYTHON_NAME = re.compile(r"(?:python|pypy)[0-9.]*\Z")
_VENV_VALUE_OPTIONS = {"--python", "-p", "--prompt", "--python-preference", "--index-url", "--index",
                       "--default-index", "--extra-index-url", "-i", "--find-links", "-f", "--cache-dir",
                       "--directory", "--project", "--config-file", "--exclude-newer", "--link-mode",
                       "--python-fetch", "--app-data", "--prompt", "--creator", "--seeder",
                       "--activators", "--extra-search-dir", "--pip", "--setuptools", "--wheel",
                       "--try-first-with", "--system-site-packages-dir"}


def _python_module_args(args):
    """(module, the arguments after it) of the `-m <module>` a python command line runs, read as CPython
    reads its options (`-mvenv`, `-Imvenv`, `-X dev -m venv`; `-c`, `--` and the first operand end
    them); None when it runs no module."""
    i = 0
    while i < len(args):
        text = args[i]
        if text in ("-", "--") or not text.startswith("-"):
            return None
        if text.startswith("--"):
            i += 2 if text in pg_parser._PYTHON_VALUE_LONG else 1
            continue
        for j, flag in enumerate(text[1:], 1):
            if flag == "c":
                return None
            if flag == "m":
                attached = text[j + 1:]
                if not attached:
                    i += 1
                    if i >= len(args):
                        return None
                    attached = args[i]
                return attached.casefold(), list(args[i + 1:])
            if flag in pg_parser._PYTHON_VALUE_FLAGS:
                if j == len(text) - 1:
                    i += 1
                break
        i += 1
    return None


def _venv_creation(name, args):
    """The operands that name the directory of a virtual environment `uv venv`, `python -m venv` or
    `virtualenv` would create (every operand: one that is not the target is only checked, it is not
    mistaken for it), [] when it names none (the tool's default directory), None when this is not one."""
    if name == "virtualenv":
        rest = list(args)
    elif name == "uv":
        words = [a for a in args if not a.startswith("-")]
        if not words or words[0] != "venv":
            return None
        rest = args[args.index("venv") + 1:]
    elif _PYTHON_NAME.match(name):
        module = _python_module_args(args)
        if module is None or module[0].split(".")[0] not in ("venv", "virtualenv"):
            return None
        rest = module[1]
    else:
        return None
    targets, skip = [], False
    for word in rest:
        if skip:
            skip = False
        elif word in _VENV_VALUE_OPTIONS:
            skip = True
        elif not word.startswith("-"):
            targets.append(word)
    return targets


_VENV_CREATION_TEXT = re.compile(r"(?<![\w-])(?:virtualenv|uv\s+venv)(?![\w-])|\s-[a-z]*m\s*(?:venv|virtualenv)\b")


def _coarse_config_write(command: str, root):
    """'config' when a command that this pass cannot read names a file the CLI wrote for an
    installer and has a writer in it, as `_coarse_guard_write` does for guard state."""
    if not pg_parser.FRAPPE_ENABLED:
        return None
    names = {Path(p).name.casefold() for p in bench_config.recorded_paths(root)}
    lowered = command.casefold()
    # A virtual environment created by a command this pass cannot read (`` `pwd`/env ``, `${PWD}/env`) may
    # be the bench's env, whose `pip.conf` it removes: refused like any other write.
    if names and _VENV_CREATION_TEXT.search(lowered):
        return "config"
    named = [n for n in names if n in lowered]
    if not named:
        return None
    alternatives = "|".join(re.escape(n) for n in named)
    if (re.search(r">>?\|?\s*[\"']?\S*(?:%s)" % alternatives, lowered)
            or _GUARD_STATE_WRITERS.search(command)
            or (_GUARD_STATE_INLINE.search(command) and _GUARD_STATE_INLINE_WRITE.search(command))):
        return "config"
    return None


def _guard_write(command: str, root, cwd=None, locked: bool | None = None):
    """'state', 'source', 'git', 'config', or None: what guard file a Bash command writes."""
    if locked is None:
        locked = _guard_locked(root)
    # argparse accepts any unambiguous prefix of --uninstall.
    uninstall = any(len(t) >= 3 and "--uninstall".startswith(t.split("=")[0])
                    for t in command.split())
    if locked and _GUARD_INSTALLER.search(command) and (
            uninstall or "package-guard" in command or "package_guard" in command):
        return "source"
    understood, found = _precise_guard_write(command, root, cwd, locked)
    if understood:
        return found
    return _coarse_guard_write(command, locked) or _coarse_config_write(command, root)


def _writes_guard_state(command: str, root=None, cwd=None) -> bool:
    return _guard_write(command, root or Path.cwd(), cwd, locked=False) in ("state", "git")


def _decision(value: str, reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": value,
            "permissionDecisionReason": reason,
        }
    }


# ---------------------------------------------------------------------------
# Package Guard's own CLI (show / approve)
# ---------------------------------------------------------------------------

def _guard_cli_call(tokens):
    """Return (subcommand, [review ids]) when tokens are the Package Guard CLI."""
    if len(tokens) < 4 or tokens[0] != "uv" or tokens[1] != "run":
        return None
    flags = {t for t in tokens[2:] if t.startswith("--")}
    positional = [t for t in tokens[2:] if not t.startswith("--")]
    if not _REQUIRED_CLI_FLAGS <= flags or not positional:
        return None
    script = positional[0].replace("\\", "/")
    if not script.endswith(store.CLI_SUFFIX):
        return None
    subcommand = positional[1] if len(positional) > 1 else None
    arguments = []
    for rid in positional[2:]:
        if rid not in arguments:
            arguments.append(rid)
    return subcommand, arguments


def _clean_project_cli(tokens, root, cwd) -> bool:
    """`uv run` + exactly the three flags + this project's own cli.py.

    An installed project's sandbox lets the CLI's writing verbs run outside it,
    matched on command text. Another option can swap the interpreter or add a
    dependency (`--python=`, `--with=`), and a cli.py elsewhere is not the
    guard, so either would run unsandboxed behind a guard-looking prompt.
    """
    if len(tokens) < 6 or set(tokens[2:5]) != _REQUIRED_CLI_FLAGS:
        return False
    script = Path(tokens[5]).expanduser()
    if not script.is_absolute():
        script = Path(cwd or root) / script
    return os.path.realpath(script) == os.path.realpath(Path(root) / store.CLI_SUFFIX)


_CLI_VERBS = ("show", "approve", "decline", "undecline", "revoke", "reconcile", "audit", "mode",
              "baseline", "git-owners", "bench-config")
# These two take their raw tokens, like `mode`: a parsed argument list drops every `--flag`,
# and nothing a person alone may do is told apart by a flag.
_RAW_TAIL_VERBS = ("mode", "baseline", "git-owners", "bench-config")
_REVIEW_ID_TOKEN = re.compile(r"[0-9a-f]{32}\Z")
# A path token must mean the same to the shell as to this parser.
_UNSAFE_PATH_TOKEN = re.compile(r"[$`*?\[\]{}()<>|&;!\n\x00]")


def _plain_abs_path(token: str) -> bool:
    return os.path.isabs(token) and not _UNSAFE_PATH_TOKEN.search(token)


def _plugin_cli_call(tokens, root):
    """A plugin's guard CLI call: None when these tokens are not one, a refusal
    decision when they look like one but are not exactly the permitted form, else
    (subcommand, [review ids]) -- for `mode`, (mode, [the raw tokens after
    --root X]), which `_mode_cli_decision` reads.

    The form, and nothing else:
      uv run <the three flags> <abs path of THIS guard's cli.py> <verb> --root <abs project root> [ids]
    """
    if len(tokens) < 6 or tokens[0] != "uv" or tokens[1] != "run":
        return None
    own = os.path.realpath(store.own_cli())
    looks = False
    for i, token in enumerate(tokens[2:], start=2):
        slashed = token.replace("\\", "/")
        if slashed.rsplit("/", 1)[-1] != "cli.py":
            continue
        following = tokens[i + 1] if i + 1 < len(tokens) else None
        if following in _CLI_VERBS or "package_guard" in slashed or (
                _plain_abs_path(token) and os.path.realpath(token) == own):
            looks = True
            break
    if not looks:
        return None
    verb = tokens[6] if len(tokens) > 6 else None
    form = store.cli_command(root, verb if verb in _CLI_VERBS else "<approve|decline>",
                             "" if verb in ("reconcile", "audit") + _RAW_TAIL_VERBS else "<review-id> ...")

    def refuse(why):
        return _decision(
            "deny",
            f"PACKAGE_GUARD_CLI_REFUSED: {why}. Package Guard accepts only its own CLI, "
            f"with no other option, exactly as:\n  {form.rstrip()}")

    flags = tokens[2:5]
    if len(set(flags)) != 3 or set(flags) != _REQUIRED_CLI_FLAGS:
        return refuse("`uv run` takes exactly --no-project --no-config --no-python-downloads")
    if not _plain_abs_path(tokens[5]) or os.path.realpath(tokens[5]) != own:
        return refuse("that is not this Package Guard's own cli.py")
    if verb not in _CLI_VERBS:
        return refuse("the subcommand must come directly after cli.py")
    if len(tokens) < 9 or tokens[7] != "--root":
        return refuse("`--root <project root>` must come directly after the subcommand")
    if not _plain_abs_path(tokens[8]) or os.path.realpath(tokens[8]) != os.path.realpath(str(root)):
        return refuse("`--root` is not this project's root")
    if verb in _RAW_TAIL_VERBS:
        return verb, list(tokens[9:])
    ids = []
    for rid in tokens[9:]:
        if verb in ("reconcile", "audit") or not _REVIEW_ID_TOKEN.match(rid):
            return refuse("only review ids may follow; no other option or shell syntax")
        if rid not in ids:
            ids.append(rid)
    return verb, ids


def _label(identity: dict) -> str:
    return f"{identity['ecosystem']}:{identity['name']}@{identity['version']}"


def _identity_of(report: dict) -> dict:
    return report.get("resolved_identity") or {}


# A manifest can declare a dozen dependencies, and each review costs a registry
# packument plus an OSV lookup. Done one at a time, a stock Vite scaffold takes
# ~90s -- far past the hook timeout, and a timed-out PreToolUse hook lets the
# command through, so the gate would fail open exactly when it has the most to
# catch. Reviews write one file each and share no mutable state, so
# they overlap safely.
_REVIEW_WORKERS = 8

# The hook's timeout in .claude/settings.json (300s) is a security bound: past
# it the install runs unreviewed. Concurrency alone only moves the manifest size
# at which that happens, so the bound is enforced here instead of measured.
#
#   _REVIEW_BATCH          new reviews opened per invocation. A user cannot
#                          split a manifest, so the surplus is deferred, not
#                          refused: reviews already on disk are reused on the
#                          next run (store.find_open_review), so every run makes
#                          progress and a large manifest converges in a few
#                          vet -> approve -> retry cycles.
#   _REVIEW_BUDGET_SECONDS wall-clock ceiling for one batch. Reviews still
#                          running at the deadline are abandoned and counted as
#                          deferred; the ones that finished are kept.
#
# Budget arithmetic, keep it in step with settings.json: a review is at most
# _REVIEW_CALLS HTTPS calls of vetting.TIMEOUT_SECONDS (8s) each -- the
# registry and OSV plus the reputation step's vetting.REPUTATION_CALLS -- and
# the interpreter joins worker threads at exit, so the hook can outlive the
# budget by one in-flight review (~56s). 150 + 56 + 56 leaves ~38s under the
# 300s ceiling. The ceiling is the harness's, so the guard's own share is what
# moves when a review grows more calls.
#
# A mandatory call retries once after a timeout or a reset
# (vetting._mandatory_json), but only when the backoff and a whole second
# request end within _REVIEW_BUDGET_SECONDS of evaluate()'s start, a mark no
# later than any deadline below. Retries therefore spend time inside the
# budget, never after it, and add no term. A review whose npm packument is
# too large to read spends two more registry calls (the dist-tags and the
# version document) and skips the two repository-manifest fetches, so it
# stays within _REVIEW_CALLS.
_REVIEW_BATCH = 20
_REVIEW_BUDGET_SECONDS = 150.0
# A function deadline is not a process deadline: abandoned review threads are
# joined at interpreter exit, so the process could outlive
# the 300s ceiling and the harness would let the command through. The
# watchdog denies and exits at this mark, 20s inside the ceiling; main() also
# exits without joining once its decision is written.
_WATCHDOG_SECONDS = 280
_REVIEW_CALLS = 2 + vetting.REPUTATION_CALLS

# An approved version still inside vetting.FRESH_VERSION_DAYS is
# re-checked against OSV on every install: most malicious versions are pulled
# within days, and a MAL record that lands after the approval must still stop
# the install. One OSV call each, at most this many per invocation; the
# arithmetic above gains _RECHECK_MAX x TIMEOUT_SECONDS (24s at 3).
_RECHECK_MAX = 3

# When a command is about to be allowed, every package the
# lockfile would install -- the transitive tree the direct-dependency gate
# never sees -- is checked against OSV in batch: one POST per
# vetting.OSV_BATCH_SIZE packages, at most this many per invocation. Malware
# denies; advisories are reported on the allow. Results are cached per
# lockfile digest for _TRANSITIVE_CACHE_SECONDS so a retry costs nothing.
# The inequality above gains _TRANSITIVE_BATCH_CALLS x TIMEOUT_SECONDS (16s).
_TRANSITIVE_BATCH_CALLS = 2
_TRANSITIVE_CACHE_SECONDS = 24 * 3600

# vetted.json is committed and travels with the repo, so an approval made in
# March installs in July with no network call at all. A version can gain a
# MAL record in between. Before an allow,
# the whole approved set is re-asked of OSV in batch -- at most _AUDIT_CALLS
# calls PER ECOSYSTEM, because query_osv_batch sends one ecosystem per POST
# and a mixed vetted set would otherwise be refused forever. Cached per
# vetted.json digest for _AUDIT_CACHE_SECONDS, so this costs one call a day.
# The inequality above gains len(_OSV_ECOSYSTEM) x _AUDIT_CALLS x
# TIMEOUT_SECONDS (16s), which is the worst case an npm+PyPI set can spend.
_AUDIT_CALLS = 1
_AUDIT_CACHE_SECONDS = 24 * 3600


# Without --locked / --frozen, `uv sync` and `uv run` first re-resolve
# pyproject.toml and rewrite uv.lock, then install the new resolution -- which
# the gate, reading the lock before the command runs, has never seen.
_UV_UNLOCKED = (
    "PACKAGE_GUARD_UNSUPPORTED: in a uv project, `uv sync` and `uv run` must run with "
    "`--locked` (or `--frozen`). Without it uv re-resolves pyproject.toml and installs "
    "versions Package Guard has not reviewed. Re-run the same command with `--locked` "
    "added, e.g. `uv sync --locked` or `uv run --locked <command>`. If uv then reports "
    "that the lock is out of date, run `uv lock` as its own command first; the next "
    "`--locked` run reviews the new lock. `uv version` with a new version or `--bump` "
    "re-locks and syncs the same way, and the new version changes the lock, so `--locked` "
    "fails there: add "
    "`--no-sync` to it instead (it re-locks without installing), then run "
    "`uv sync --locked`."
)


_SCRIPTS_OFF_HINT = ("or install with scripts off: add `--ignore-scripts` to the same "
                     "command")
# Yarn Berry has no --ignore-scripts (the parser refuses it); its flag is --mode=skip-build.
_SCRIPTS_OFF_FLAG = {"npm": "--ignore-scripts", "pnpm": "--ignore-scripts",
                     "bun": "--ignore-scripts", "yarn": "--mode=skip-build"}


def _scripts_off_hint(manager="npm") -> str:
    if manager == "npm":
        return _SCRIPTS_OFF_HINT
    return ("or install with scripts off: add "
            f"`{_SCRIPTS_OFF_FLAG[manager]}` to the same command")


# A root lifecycle script reaches code through `npm run <x>` (and
# its aliases) in the same package.json, which is followed; through a file
# run by an interpreter, a script piped to a shell, or a path executable,
# which the gate cannot read and so refuses while scripts are on.
_NPM_RUN = {"run", "run-script", "rum", "urn"}
_NPM_RUN_FIXED = {"start": "start", "test": "test", "t": "test", "tst": "test",
                  "stop": "stop", "restart": "restart"}
_SCRIPT_INTERPRETERS = re.compile(
    r"^(?:sh|bash|zsh|dash|ksh|fish|node|nodejs|deno|bun|tsx|ts-node|perl|ruby|php|make|"
    r"python(?:\d+(?:\.\d+)?)?)$")
_INLINE_CODE_FLAGS = {"-e", "-c", "-p", "--eval", "--print", "-r", "--require", "--import"}
_SCRIPT_DEPTH = 8

# What each manager's command word means inside a lifecycle script body: the
# verbs that run a script of the same package.json, and the flags that move the
# command to another package (a body this reader cannot follow).
_RUN_MANAGERS = {"npm": "npm", "pnpm": "pnpm", "yarn": "yarn", "yarnpkg": "yarn", "bun": "bun"}
_RUN_VERBS = {"npm": _NPM_RUN, "pnpm": {"run", "run-script"}, "yarn": {"run"}, "bun": {"run"}}
_RUN_FIXED = {"npm": _NPM_RUN_FIXED, "pnpm": _NPM_RUN_FIXED, "yarn": {}, "bun": {}}
_RUN_MOVES = {
    "npm": {"--prefix", "-C", "--workspace", "-w", "--workspaces", "-ws"},
    "pnpm": {"--dir", "-C", "--filter", "-F", "--filter-prod", "-r", "--recursive", "-w",
             "--workspace-root", "--workspace", "--parallel"},
    "yarn": {"--cwd", "-A", "--all", "-W"},
    "bun": {"--cwd", "--filter", "--workspaces"},
}


def _script_steps(body: str):
    """[(words, piped)] of a script body, or None when it cannot be read."""
    if any(s in body for s in ("$(", "`", "<(", ">(", "<<")):
        return None
    lexer = shlex.shlex(body.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    steps, words, piped, skip = [], [], False, False
    for token in tokens:
        if skip:
            skip = False
        elif token and set(token) <= set("<>&|;()"):
            if "<" in token or ">" in token:
                skip = True
                continue
            if words:
                steps.append((words, piped))
            words, piped = [], token in ("|", "|&")
        else:
            words.append(token)
    if words:
        steps.append((words, piped))
    return steps


def _script_problem(name, body, scripts, root, chain, depth=0):
    """(kind, chain) when a lifecycle body acquires, runs code the gate
    cannot read, or delegates to a script that cannot be resolved."""
    chain = chain + [(name, body)]
    inner = pg_parser.parse_command(body)
    unvetted = [r for r in inner.requests if not (r.exact_version and store.is_vetted(root, {
        "ecosystem": r.ecosystem, "name": r.name, "version": r.exact_version,
        "registry": r.registry}))]
    if inner.kind != "ignore" and (inner.kind == "unsupported" or unvetted or inner.manifests):
        return "acquires", chain
    steps = _script_steps(body)
    if steps is None:
        return "unreadable", chain
    for words, piped in steps:
        while words and (_ASSIGNMENT.match(words[0]) or words[0] in ("env", "cross-env")):
            words = words[1:]
        if not words:
            continue
        command = os.path.basename(words[0])
        args = words[1:]
        manager = _RUN_MANAGERS.get(command)
        bun_run = False
        if manager == "bun":
            # `bun run <script>` follows the script. Anything else Bun takes (a file,
            # `bun test`, `bun x.ts`) runs code from a file and stays "runs-file".
            names = [a for a in args if not a.startswith("-")]
            bun_run = (len(names) >= 2 and names[0] == "run" and not piped
                       and not pg_parser._is_bun_file(names[1])
                       and not any(a.split("=", 1)[0] in _INLINE_CODE_FLAGS for a in args))
        if piped and _SCRIPT_INTERPRETERS.match(command):
            return "runs-file", chain
        if not bun_run and _SCRIPT_INTERPRETERS.match(command) and (
                command == "make" or any(not a.startswith("-") for a in args)
                or any(a.split("=", 1)[0] in _INLINE_CODE_FLAGS for a in args)):
            return "runs-file", chain
        if "/" in words[0] and not words[0].startswith("node_modules/.bin/"):
            return "runs-file", chain
        if manager is None:
            continue
        if any(a.split("=", 1)[0] in _RUN_MOVES[manager] for a in args):
            return "unresolved", chain
        verbs = [a for a in args if not a.startswith("-")]
        if not verbs:
            continue
        verb = verbs[0]
        if verb in _RUN_VERBS[manager]:
            if len(verbs) < 2:
                continue  # `npm run` alone lists the scripts
            targets = [verbs[1]]
        elif verb in _RUN_FIXED[manager]:
            targets = [_RUN_FIXED[manager][verb]]
            if targets == ["restart"] and "restart" not in scripts:
                targets = ["stop", "start"]
        elif manager == "yarn" and verb in ("workspace", "workspaces"):
            return "unresolved", chain
        else:
            continue
        for target in targets:
            if target not in scripts:
                if "--if-present" in args or target == "stop":
                    continue
                # A missing `start` runs `node server.js`.
                return ("runs-file" if target == "start" else "unresolved"), \
                    chain + [(target, None)]
            if depth >= _SCRIPT_DEPTH or any(target == seen for seen, _ in chain):
                return "unresolved", chain + [(target, scripts[target])]
            for hop in ("pre" + target, target, "post" + target):
                if isinstance(scripts.get(hop), str):
                    found = _script_problem(hop, scripts[hop], scripts, root, chain, depth + 1)
                    if found:
                        return found
    return None


def _root_scripts(directory) -> dict:
    try:
        data = json.loads(pg_manifest.manifest_path(directory).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    return {k: v for k, v in scripts.items() if isinstance(v, str)} \
        if isinstance(scripts, dict) else {}


def _render_script_problem(kind, chain, manager="npm") -> str:
    (first, body), path = chain[0], " -> ".join(
        f"`scripts.{n}`" + (f" (`{b}`)" if b is not None else " (missing)") for n, b in chain[1:])
    via = f", which leads to {path}" if path else ""
    head = f"PACKAGE_GUARD_UNSUPPORTED: package.json `scripts.{first}` runs `{body}`{via}"
    flag = _SCRIPTS_OFF_FLAG[manager]
    if kind == "acquires":
        return (f"{head}. {manager} executes it during this install and it acquires packages. Run "
                "that acquisition as its own command first so it is reviewed (pin it to an exact "
                f"version in the script), {_scripts_off_hint(manager)}.")
    if kind == "runs-file":
        return (f"{head}. {manager} executes it during this install, and it runs code from a file, an "
                "inline interpreter or a pipe into a shell, which Package Guard cannot read, so "
                "it cannot tell what that code acquires. Install with scripts off: add "
                f"`{flag}` to the same command. Then tell the user that this script did "
                "not run; whether to run it is theirs to decide.")
    return (f"{head}. {manager} executes it during this install, and Package Guard cannot resolve that "
            "script in this package.json (missing, a cycle, more than "
            f"{_SCRIPT_DEPTH} levels deep, unreadable, or another directory). Install with "
            f"scripts off: add `{flag}` to the same command, and tell the user.")


def _lifecycle_check(directory, root, kind="npm"):
    """With scripts on, `npm install` / `npm ci` run code the
    gate would otherwise never see: the root package.json's own lifecycle
    scripts, the sibling scripts they reach through `npm run`, and install
    scripts of locked packages. A root script that acquires packages must
    acquire only exact vetted versions; one that runs a file the gate cannot
    read is refused; a locked package that runs an install script must itself
    be vetted. pnpm, Bun and Yarn follow the same rules for the root; which
    dependencies may build is each manager's own allow-list (design 6)."""
    if kind == "yarn" and pm_config.yarn_scripts_disabled(directory, sources.HOME):
        return None  # `enableScripts: false` stops the root's and every dependency's scripts
    lifecycle = pg_manifest.npm_root_lifecycle_scripts(directory, kind)
    scripts = _root_scripts(directory) if lifecycle else {}
    for name, body in lifecycle:
        found = _script_problem(name, body, scripts, root, [])
        if found:
            return _decision("deny", _render_script_problem(*found, manager=kind))
    if kind != "npm":
        return _dependency_builds_check(directory, root, kind)
    unreviewed = []
    for name, version in pg_manifest.npm_install_script_packages(directory):
        identity = {"ecosystem": "npm", "name": name, "version": version,
                    "registry": pg_parser.NPM_REGISTRY}
        if not store.is_vetted(root, identity):
            unreviewed.append(f"{name}@{version}")
    if unreviewed:
        listed = ", ".join(unreviewed[:10]) + (" ..." if len(unreviewed) > 10 else "")
        return _decision("deny", (
            "PACKAGE_GUARD_UNSUPPORTED: these locked packages run install scripts during "
            f"this install and were never reviewed: {listed}. Review each by naming it, e.g. "
            f"`npm install --no-save {unreviewed[0]}` (it goes through the normal review), "
            f"{_SCRIPTS_OFF_HINT}."))
    return None


_ADD_VERB = {"pnpm": "pnpm add", "bun": "bun add", "yarn": "yarn add"}


def _build_denial(kind, text, remedy) -> dict:
    return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: {text} {remedy}")


def _dependency_builds_check(directory, root, kind, removing=False):
    """The dependency build scripts a pnpm, Bun or Yarn install would run.

    None of the three locks says reliably which locked package has an install
    script, so the rule never depends on that flag. Each manager has an explicit
    allow-list; the install is allowed when scripts are off, or when the
    allow-list exists (so the manager's default, which Package Guard cannot
    enumerate, does not apply) and every locked package on it is a reviewed exact
    version. Fail closed: an entry or setting that cannot be read denies."""
    off = _scripts_off_hint(kind)
    if removing and kind != "yarn":
        # `remove` has no scripts-off flag to offer: pnpm rejects `--ignore-scripts` on it and
        # Bun's is unverified, so the way out is the human's.
        off = ("or ask the user to remove the package themselves outside this session: this "
               "command has no flag that turns dependency scripts off")
    home = sources.HOME
    try:
        tree = pg_manifest.pm_locked_tree(directory, kind)
        if kind == "pnpm":
            settings = pm_config.pnpm_build_settings(directory, home)
            if settings.bad:
                return _build_denial(kind, "pnpm's build settings cannot be read: "
                                     + "; ".join(settings.bad[:5]) + ".", off + ".")
            if settings.danger:
                return _build_denial(
                    kind, "`dangerouslyAllowAllBuilds` lets every dependency run its install "
                    "scripts and Package Guard cannot review them.",
                    "The human removes it, or " + off + ".")
            if settings.never:
                return _build_denial(
                    kind, "`neverBuiltDependencies` is set; pnpm then runs every dependency's "
                    "build script that it does not name.",
                    "The human replaces it with an `onlyBuiltDependencies` allow-list, or "
                    + off + ".")
            if settings.allow is None:
                return _build_denial(
                    kind, "no explicit build allow-list: pnpm 9 runs every dependency's install "
                    "scripts by default, and Package Guard cannot tell what pnpm 10 would skip. "
                    "Declare `onlyBuiltDependencies` (even empty) in pnpm-workspace.yaml (the "
                    "human's to do),", off + ".")
            listed = settings.allow
        elif kind == "bun":
            package_list = pm_config.trusted_dependencies(directory)
            if package_list is None:
                return _build_denial(
                    kind, "package.json has no `trustedDependencies`, so Bun runs the install "
                    "scripts of its built-in default list (about 367 packages) and Package "
                    "Guard cannot review them. The human declares `trustedDependencies` "
                    "(even `[]`),", "or " + off + ".")
            lock_list = bun_lock.trusted_dependencies(pg_manifest.pm_lock_path(directory, "bun"))
            extra = sorted(set(lock_list) - set(package_list))
            if extra:
                return _build_denial(
                    kind, "bun.lock trusts packages that package.json `trustedDependencies` does "
                    f"not ({', '.join(extra[:5])}): the lock is out of date or was edited.",
                    "Tell the user, or " + off + ".")
            listed = {n.lower() for n in package_list}
        else:
            listed = _yarn_built_names(directory)
            names = {n.lower() for n, _v in tree}
            unlocked = sorted(listed - names)
            if unlocked:
                return _build_denial(
                    kind, "`dependenciesMeta` allows builds for packages the lock does not "
                    f"contain ({', '.join(unlocked[:5])}): a stale entry would run scripts of "
                    "whatever gets installed under that name later.", "Tell the user, or "
                    + off + ".")
    except (pg_manifest.ManifestError, lock_errors.LockReadError, pm_config.ConfigError) as exc:
        return _decision("deny", f"PACKAGE_GUARD_ERROR: the build-script settings for {kind} could "
                                 f"not be read ({exc}). Nothing was installed; tell the user.")
    unreviewed = []
    for name, version in tree:
        if name.lower() in listed:
            identity = {"ecosystem": "npm", "name": name, "version": version,
                        "registry": pg_parser.NPM_REGISTRY}
            if not store.is_vetted(root, identity):
                unreviewed.append(f"{name}@{version}")
    if unreviewed:
        shown = ", ".join(unreviewed[:10]) + (" ..." if len(unreviewed) > 10 else "")
        return _build_denial(
            kind, "these packages are allowed to run install scripts during this install and "
            f"were never reviewed: {shown}. Package Guard reviews only what a command names, and "
            f"{kind} has no way to name one without adding it to package.json and the lock, so "
            "do not add them as dependencies to get a review. Tell the user which packages "
            "these are; they decide whether to remove them from the build allow-list or to "
            "have them reviewed outside this session,", off + ".")
    return None


def _yarn_built_names(directory):
    """Lower-cased package names `dependenciesMeta.<pkg>.built: true` allows (package.json
    and the lock's root entry)."""
    names = set()
    for key in yarn_lock.built_allowlist(Path(directory) / "package.json"):
        match = pm_config._BUILD_NAME.match(key)
        if match is None:
            raise pm_config.ConfigError(f"package.json: dependenciesMeta key {key!r} is not a "
                                        "plain package name")
        names.add(match.group("name").lower())
    lock = yarn_lock.read_yarn_lock(pg_manifest.pm_lock_path(directory, "yarn"))
    for key, meta in lock.root.dependencies_meta.items():
        if isinstance(meta, dict) and meta.get("built") in (True, "true"):
            match = pm_config._BUILD_NAME.match(key)
            if match is None:
                raise pm_config.ConfigError(f"yarn.lock: dependenciesMeta key {key!r} is not a "
                                            "plain package name")
            names.add(match.group("name").lower())
    return names


def _git_allowed(root):
    """The acceptance of a git source in a lock (inside an approved baseline), for `sources.problems_for`:
    None while the Frappe switch is off, so every such source stays refused."""
    if not pg_parser.FRAPPE_ENABLED:
        return None
    return lambda directory, entry: baseline.git_entries_ok(root, directory, entry)


def _git_spec_allowed(root):
    """The acceptance of a git spec in a manifest; None while the switch is off."""
    if not pg_parser.FRAPPE_ENABLED:
        return None
    return lambda directory, ecosystem, name, spec: baseline.manifest_git_ok(root, directory, ecosystem, name, spec)


def _source_problems(parsed, targets, directory, root, **kwargs) -> list:
    """`sources.problems_for` for the shell's directory, as always, and again
    for every project directory an installer reads instead (`targets`): the
    manifest, lock and project configuration it finds there. npm also reads
    that project's .npmrc for the packages a command names."""
    kwargs.setdefault("git_allowed", _git_allowed(root))
    kwargs.setdefault("git_spec_allowed", _git_spec_allowed(root))
    problems = list(sources.problems_for(parsed, directory, **kwargs))
    here = os.path.realpath(directory)
    groups = {}
    for scope, path in targets:
        if os.path.realpath(path) != here:
            groups.setdefault(os.path.realpath(path), (path, [], []))[2].append(scope)
    named = [r for r in parsed.requests if r.ecosystem == "npm"]
    if named:
        home = _npm_project(directory, root)
        if os.path.realpath(home) != here:
            groups.setdefault(os.path.realpath(home), (home, [], []))[1].extend(named)
    for path, requests, scopes in groups.values():
        subset = dataclasses.replace(parsed, requests=tuple(requests), manifests=tuple(scopes))
        problems += sources.problems_for(subset, path, **kwargs)
    return list(dict.fromkeys(problems))


def _render_alternate_source(problems) -> str:
    lines = ["PACKAGE_GUARD_UNSUPPORTED: this install would fetch from somewhere other than "
             "the registry its review vets (alternate registries, indexes and direct "
             "Git/URL/path sources are not supported):"]
    lines += [f"- {p}" for p in problems[:10]]
    if len(problems) > 10:
        lines.append(f"- ... and {len(problems) - 10} more")
    lines.append("Tell the user which file or setting this is. Do not edit it yourself to "
                 "make the install pass; the user decides whether that source is acceptable.")
    return "\n".join(lines)


class _BuildRequirement(NamedTuple):
    """An unpinned `[build-system] requires` entry, with the project it is in.

    No resolver pins these and no lock records them, so the denial's remedy
    differs from a manifest's: pin the line in that project's pyproject.toml.
    `default_backend` marks a project with no `[build-system]` at all, which is
    built with setuptools' default backend."""
    requirement: str
    reason: str
    project: Path
    default_backend: bool


def _build_requires(directory):
    resolved, unresolved = pg_manifest.build_requires(directory)
    return resolved, [_BuildRequirement(spec, reason, Path(directory),
                                        (spec, reason) == pg_manifest._DEFAULT_BACKEND)
                      for spec, reason in unresolved]


# ---------------------------------------------------------------------------
# Which project a command installs
#
# npm and uv do not install the manifest of the shell's directory: they walk
# up from it to the project they find, and install that. Run from `src/`,
# `npm ci` installs the parent's package-lock.json and `uv sync --locked` the
# parent's uv.lock. The gate reads the project each installer finds. When
# nothing inside the guard root stops the walk, the installers keep climbing
# past it, and so does the gate (`_beyond`); a project found out there is not
# one the guard protects, and the command is refused (`_outside_project`).
# ---------------------------------------------------------------------------

def _upward(directory, root) -> list:
    """`directory` and each parent up to the guard root, nearest first.

    Walked on real paths, as the installers walk from the process's working
    directory, then spelled under `root` as given. A directory outside the
    guard root yields only itself.
    """
    start = Path(directory)
    try:
        relative = Path(os.path.realpath(start)).relative_to(os.path.realpath(root))
    except ValueError:
        return [start]
    parts = relative.parts
    chain = [Path(root).joinpath(*parts[:depth]) for depth in range(len(parts), -1, -1)]
    chain[0] = start
    return chain


def _within(path, root) -> bool:
    """True when `path` is the guard root or lies under it, on real paths."""
    try:
        Path(os.path.realpath(path)).relative_to(os.path.realpath(root))
    except ValueError:
        return False
    return True


def _beyond(directory, root) -> list:
    """The directories above the guard root, nearest first, on real paths:
    where npm and uv go on looking when nothing inside the guarded project
    stopped them. Empty for a `directory` outside the guard root, which is
    read alone, as before."""
    if not _within(directory, root):
        return []
    return list(Path(os.path.realpath(root)).parents)


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


def _read_toml(path):
    try:
        with open(path, "rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def _npm_stops(candidate: Path) -> bool:
    return (candidate / "package.json").is_file() or (candidate / "node_modules").is_dir()


def _npm_workspace_takes(project: Path, workspace_root: Path, data) -> bool:
    """Whether the package.json `data` of `workspace_root` declares workspaces
    that could take `project`. npm matches each `workspaces` glob (the array,
    or its `packages` array) against the member's path; here `*` also
    crosses `/` and a `!` exclusion is not subtracted, so a doubtful match
    reads as a member. A workspaces value of any other shape counts as one."""
    if not isinstance(data, dict) or not data.get("workspaces"):
        return False
    declared = data["workspaces"]
    patterns = declared.get("packages") if isinstance(declared, dict) else declared
    if not isinstance(patterns, list):
        return True
    try:
        relative = Path(os.path.realpath(project)).relative_to(
            os.path.realpath(workspace_root)).as_posix()
    except ValueError:
        return False
    for pattern in patterns:
        if not isinstance(pattern, str):
            return True
        if pattern.startswith("!"):
            continue
        compiled = _uv_glob(pattern)
        if compiled is None or compiled.match(relative):
            return True
    return False


def _npm_project(directory, root) -> Path:
    """The directory npm acts on for a command run in `directory`.

    npm's own rule: the nearest directory at or above it holding a
    package.json or a node_modules directory. From there npm keeps climbing
    for a workspace root that lists it, and installs from that root. Inside
    the guard root, any ancestor package.json declaring workspaces is taken as
    that root, which the source check then refuses (workspaces are not
    supported). npm does not stop at the guard root, and neither does this
    walk (`_beyond`): above it, a workspace root whose globs take the project,
    or the nearest directory npm stops at when nothing inside did, is returned
    though it lies outside, and `_outside_project` refuses it. `directory`
    itself when nothing is found, where npm would create the manifest.
    """
    chain = _upward(directory, root)
    beyond = _beyond(directory, root)
    for index, candidate in enumerate(chain):
        if _npm_stops(candidate):
            for outer in chain[index + 1:]:
                data = _read_json(outer / "package.json")
                if isinstance(data, dict) and data.get("workspaces"):
                    return outer
            for outer in beyond:
                if (outer / "package.json").is_file() and _npm_workspace_takes(
                        candidate, outer, _read_json(outer / "package.json")):
                    return outer
            return candidate
    for candidate in beyond:
        if _npm_stops(candidate):
            return candidate
    return Path(directory)


def _uv_workspace(directory):
    """The `[tool.uv.workspace]` table of `directory`'s pyproject.toml, or None."""
    data = _read_toml(Path(directory) / "pyproject.toml")
    tool = data.get("tool") if isinstance(data, dict) else None
    uv = tool.get("uv") if isinstance(tool, dict) else None
    workspace = uv.get("workspace") if isinstance(uv, dict) else None
    return workspace if isinstance(workspace, dict) else None


def _uv_glob(pattern: str):
    """A compiled regex matching what uv's workspace glob matches: the glob is
    matched against the whole path, `*` and `?` crossing `/`, and a `**`
    component standing for any number of directories, none included."""
    parts = [p for p in pattern.strip().replace("\\", "/").split("/") if p not in ("", ".")]
    out = []
    for index, part in enumerate(parts):
        last = index == len(parts) - 1
        if part == "**":
            out.append(".*" if last else "(?:.*/)?")
            continue
        piece, i = "", 0
        while i < len(part):
            char = part[i]
            if char == "*":
                piece += ".*"
            elif char == "?":
                piece += "."
            elif char == "[" and "]" in part[i + 2:]:
                end = part.index("]", i + 2)
                body = part[i + 1:end]
                piece += "[" + ("^" + body[1:] if body.startswith("!") else body).replace("\\", "\\\\") + "]"
                i = end
            else:
                piece += re.escape(char)
            i += 1
        out.append(piece + ("" if last else "/"))
    try:
        return re.compile("".join(out) + r"\Z", re.DOTALL)
    except re.error:
        return None


def _uv_member(project: Path, workspace_root: Path, workspace: dict) -> bool:
    """uv's membership test: a `members` glob takes the project and no
    `exclude` glob does."""
    try:
        relative = Path(os.path.realpath(project)).relative_to(
            os.path.realpath(workspace_root)).as_posix()
    except ValueError:
        return False

    def matched(key):
        globs = workspace.get(key)
        for glob in globs if isinstance(globs, list) else []:
            compiled = _uv_glob(glob) if isinstance(glob, str) else None
            if compiled is not None and compiled.match(relative):
                return True
        return False

    return matched("members") and not matched("exclude")


def _uv_nearest(directory, root):
    """The nearest directory at or above `directory` holding a pyproject.toml,
    as uv finds its project, or None. uv does not stop at the guard root, and
    neither does this walk (`_beyond`)."""
    walk = _upward(directory, root) + _beyond(directory, root)
    return next((d for d in walk if (d / "pyproject.toml").is_file()), None)


def _uv_projects(directory, root) -> list:
    """The directories whose uv.lock a uv project command run in `directory`
    installs from, primary first; empty when uv finds no pyproject.toml.

    uv takes the nearest pyproject.toml as the project. Unless that file
    declares a workspace itself, the first pyproject.toml above it decides:
    when it declares `[tool.uv.workspace]` whose globs take the project, the
    project is a member and uv installs from the workspace root's uv.lock.
    Both searches go on past the guard root, as uv's do (`_beyond`); a
    project or workspace root found there is returned though it lies outside,
    and `_outside_project` refuses it. Inside the guard root, a lock of the
    project's own next to a workspace is read as well, so a misjudged
    membership never leaves the lock uv uses unread.
    """
    chain = _upward(directory, root)
    walk = chain + _beyond(directory, root)
    project = next((d for d in walk if (d / "pyproject.toml").is_file()), None)
    if project is None:
        return []
    if _uv_workspace(project) is not None:
        return [project]
    above = walk[walk.index(project) + 1:]
    first = next((d for d in above if (d / "pyproject.toml").is_file()), None)
    workspace = _uv_workspace(first) if first is not None else None
    if workspace is not None and _uv_member(project, first, workspace):
        own = (project / "uv.lock").is_file()
        return [first, project] if own else [first]
    if (project / "uv.lock").is_file() and project in chain:
        outer = next((d for d in chain[chain.index(project) + 1:] if _uv_workspace(d) is not None), None)
        if outer is not None:
            return [project, outer]
    return [project]


def _python_project(parsed, directory, root) -> Path:
    """Where the Python environments a command names are recorded and read:
    the uv project it acts on (`_uv_projects`) when it carries one, else the
    shell's directory. `uv pip` and pip look for no project, and a
    requirements file is reconciled from its own directory."""
    if any(scope.kind == "uv-project" for scope in parsed.manifests):
        found = _uv_projects(directory, root)
        # A project outside the guard root is refused (`_outside_project`)
        # and keys nothing.
        if found and (_within(found[0], root) or not _within(directory, root)):
            return found[0]
    return Path(directory)


def _scope_directories(scope, directory, root) -> list:
    """Every directory the installer reads `scope` from, for a command run
    in `directory`. A requirements file is named relative to the shell's
    directory. A local build is pip's `.` or uv's discovered project, so both
    are read."""
    if scope.kind in pg_parser.NPM_FAMILY_KINDS:
        return [_npm_project(directory, root)]
    if scope.kind == "uv-project":
        return _uv_projects(directory, root) or [Path(directory)]
    if scope.kind == "build-requires":
        nearest = _uv_nearest(directory, root)
        same = nearest is None or os.path.realpath(nearest) == os.path.realpath(directory)
        return [Path(directory)] if same else [Path(directory), nearest]
    return [Path(directory)]


# What each installer looks for on its way up, named in the refusal, and the
# command that gives the guarded project its own manifest so the walk stops
# inside it. Both commands acquire nothing.
_OWN_MANIFEST = {
    "npm": ("npm walks up to the nearest package.json or node_modules", "npm init -y"),
    "uv-project": ("uv walks up to the nearest pyproject.toml", "uv init --no-workspace"),
    "build-requires": ("a local build takes the nearest pyproject.toml at or above this directory",
                       "uv init --no-workspace"),
}


def _outside_project(targets, directory, root) -> dict | None:
    """A denial when an installer, run in `directory` inside the guard root,
    would act on a project outside it.

    npm and uv climb past the guard root when nothing inside it stops them,
    and a workspace above it takes a member inside it (`_npm_project`,
    `_uv_projects`). That project's manifest, lock and configuration are
    nobody's to review here, and what it installs lands where no scan of this
    project reads. A command run from outside the guard root is read where it
    runs, as before, and is not refused here."""
    if not _within(directory, root):
        return None
    for scope, path in targets:
        if _within(path, root):
            continue
        outside = os.path.realpath(path)
        guarded = os.path.realpath(root)
        lines = [f"PACKAGE_GUARD_UNSUPPORTED: this install would use {outside}, outside the "
                 f"project Package Guard protects ({guarded}); run it from inside the project, "
                 f"or install the guard at {outside}."]
        chain = _upward(directory, root)
        npm_like = scope.kind in pg_parser.NPM_FAMILY_KINDS
        stopped = (any(_npm_stops(d) for d in chain) if npm_like
                   else any((d / "pyproject.toml").is_file() for d in chain))
        walk, create = _OWN_MANIFEST.get("npm" if npm_like else scope.kind, (None, None))
        if walk and not stopped:
            lines.append(f"{walk}, and the project has none of its own, so it climbs out. To make "
                         f"this directory the project, create its manifest first, as its own "
                         f"command: `{create}`.")
        else:
            lines.append(f"{outside} is a workspace root that takes this project as a member, "
                         "so the installer works from there.")
        lines.append("Do not edit or move files outside the project to make the install pass; "
                     "tell the user which project the install would use.")
        return _decision("deny", "\n".join(lines))
    return None


_BENCH_ENV_MESSAGE = (
    "PACKAGE_GUARD_UNSUPPORTED: this installs into a Frappe bench's Python env, but {why}. "
    "`uv pip ... --python <bench>/env/bin/python` and `bench pip install` are supported "
    "only inside the bench they name: run the command from that bench's root or from "
    "`apps/<app>`, or install with `<bench>/env/bin/pip install name==version`.")


_BENCH_PIP_DIRECTORY_MESSAGE = (
    "PACKAGE_GUARD_UNSUPPORTED: `bench pip` changes to the bench root ({root}) before it runs "
    "pip, so a relative requirements file or a local project (`.`, `-e .`) is read there, "
    "not in this directory. Run it from the bench root, or name the requirements file by its "
    "absolute path.")


_BENCH_REDIRECT_MESSAGE = (
    "PACKAGE_GUARD_UNSUPPORTED: `bench pip` is not supported here: {why}. Remove that file, "
    "or install with `<bench>/env/bin/pip install name==version` from inside the bench.")


_BENCH_SOURCE_BUILD_MESSAGE = (
    "PACKAGE_GUARD_UNSUPPORTED: {flags} names packages to build from source, and inside a Frappe "
    "bench uv builds nothing from source except the packages a person allowed (`no-build = true` "
    "in the bench's uv.toml): uv lets a package named there through. Drop the flag; to allow a "
    "build, tell the user.")


_BENCH_DYNAMIC_MESSAGE = (
    "PACKAGE_GUARD_UNSUPPORTED: `{path}` runs pip or python from a path the shell expands "
    "when the command runs (a variable, a substitution, a glob), and inside a Frappe bench "
    "Package Guard cannot tell which env that installs into. Write the literal path: "
    "`env/bin/pip install name==version`, or `~/frappe-bench/env/bin/pip ...`.")


def _bench_env_problem(parsed, cwd) -> dict | None:
    """Deny an install that names a bench env (`--python <bench>/env/bin/python`,
    `bench pip`, `<bench>/env/bin/pip`) unless it is the env of the bench the shell's
    directory is in. The parser read only the shape of the path; this is where it
    meets the disk."""
    if (pg_parser.FRAPPE_ENABLED and parsed.source_build_flags
            and bench_config.bench_root(cwd) is not None):
        return _decision("deny", _BENCH_SOURCE_BUILD_MESSAGE.format(
            flags=", ".join(parsed.source_build_flags)))
    for path in parsed.executables:
        if bench_config.executable_is_dynamic(path) and bench_config.bench_root(cwd) is not None:
            return _decision("deny", _BENCH_DYNAMIC_MESSAGE.format(path=path))
        why = bench_config.executable_problem(path, cwd)
        if why:
            return _decision("deny", _BENCH_ENV_MESSAGE.format(why=why))
    for value in parsed.bench_pythons:
        if value:
            why = bench_config.python_in_env_problem(value, cwd)
        else:
            redirect = bench_config.redirect_problem()
            if redirect:
                return _decision("deny", _BENCH_REDIRECT_MESSAGE.format(why=redirect))
            root, why = bench_config.env_problem(cwd)
            if root is not None and os.path.realpath(root) != os.path.realpath(cwd) and any(
                    (scope.kind == "requirements" and not os.path.isabs(scope.path))
                    or scope.kind == "build-requires" for scope in parsed.manifests):
                # `bench` moves to the bench root before it runs pip, so a relative
                # requirements file or `.` is read there, not where the hook looks.
                return _decision("deny", _BENCH_PIP_DIRECTORY_MESSAGE.format(root=root))
        if why:
            return _decision("deny", _BENCH_ENV_MESSAGE.format(why=why))
    return None


def _bench_app_lines(parsed, targets, cwd) -> list:
    """[(where, name, bench root)] for every PyPI requirement this command would
    install, wherever it is written: named on the command line, listed in a
    requirements file, or declared in the pyproject.toml it installs. `where` is
    the file and line, or the command."""
    found = []
    here = bench_config.bench_root(cwd)
    for request in parsed.requests:
        if request.ecosystem == "pypi":
            found.append(("the command line", request.name, request.display_name, here))
    for scope, directory in targets:
        if pg_parser.scope_ecosystem(scope.kind) != "pypi":
            continue
        if scope.kind == "requirements":
            path = Path(scope.path)
            if not path.is_absolute():
                path = Path(directory) / path
            benches = {bench_config.bench_root(directory), bench_config.bench_root(path.parent)}
            for number, name, line in bench_config.requirements_file_names(path):
                for bench in benches:
                    found.append((f"{path}, line {number}", name, line, bench))
        else:
            bench = bench_config.bench_root(directory)
            path = Path(directory) / "pyproject.toml"
            # A local build with its dependencies off installs only its build requirements.
            # The other scopes read every list, selected or not (5A and 5C of Codex's P3
            # review: an extra nobody asked for, a marker that is false here): rare, and
            # a refusal is the safe error.
            for where, name in bench_config.pyproject_names(
                    path, build_only=scope.kind == "build-requires"):
                found.append((f"{path} ({where})", name, name, bench))
            if scope.kind == "uv-project":
                found.extend(_uv_lock_lines(scope, directory, bench))
    return found


def _uv_lock_lines(scope, directory, bench) -> list:
    """What a uv sync installs beyond the directory's own pyproject.toml: the uv.lock it
    installs as it stands (a frozen lock is not updated from pyproject.toml, so a stale
    entry for a bench app is installed), and the manifests of the workspace members and
    local packages it builds. An unreadable lock is the install gate's to report."""
    found = []
    try:
        for where, name in pg_manifest.uv_lock_names(directory, scope.extras):
            found.append((where, name, name, bench))
        for member in pg_manifest.uv_member_directories(directory):
            path = member / "pyproject.toml"
            for where, name in bench_config.pyproject_names(path):
                found.append((f"{path} ({where})", name, name, bench))
    except pg_manifest.ManifestError:
        pass
    return found


def _bench_app_name_problem(parsed, targets, cwd) -> dict | None:
    """A requirement that names an app of the bench is local code, and an index
    answers it with someone else's package (`frappe` is a placeholder on PyPI):
    deny, whatever is vetted, before any review."""
    apps = {}
    hits = []
    for where, name, shown, bench in _bench_app_lines(parsed, targets, cwd):
        if bench is None:
            continue
        if bench not in apps:
            apps[bench] = bench_config.app_names(bench)
            if pg_parser.FRAPPE_ENABLED:
                # The known Frappe app names are local in every bench, present or not: PyPI answers
                # several of them with someone else's package.
                for known in baseline.FRAPPE_APP_NAMES:
                    apps[bench].setdefault(bench_config._normalize(known), "a known Frappe app name")
        if name in apps[bench]:
            hits.append(f"- {where}: `{shown}` is a local bench app ({apps[bench][name]})")
    if not hits:
        return None
    hits = list(dict.fromkeys(hits))
    lines = ["PACKAGE_GUARD_UNSUPPORTED: a requirement names a local bench app, and a bench app is "
             "never installed from PyPI; an index answers its name with an unrelated package "
             "(PyPI's `frappe` is a placeholder, `frappe==0.0.1`):"]
    lines += hits[:10]
    if len(hits) > 10:
        lines.append(f"- ... and {len(hits) - 10} more")
    lines.append("Tell the user which requirement this is. Do not edit the file to make the "
                 "install pass: a bench app is installed from its own directory, by the user "
                 "or by bench.")
    return _decision("deny", "\n".join(lines))


def _read_manifest(scope, directory):
    """(resolved, unresolved, where) for one ManifestScope."""
    if scope.kind == "npm":
        resolved, unresolved = pg_manifest.direct_dependencies(directory)
        return resolved, unresolved, pg_manifest.manifest_path(directory)
    if scope.kind in pg_parser.PM_KINDS:
        resolved, unresolved = pg_manifest.pm_direct_dependencies(directory, scope.kind)
        return resolved, unresolved, pg_manifest.manifest_path(directory)
    if scope.kind == "requirements":
        path = Path(scope.path)
        if not path.is_absolute():
            path = Path(directory) / path
        resolved, unresolved = pg_manifest.requirements_dependencies(path)
        return resolved, unresolved, path
    if scope.kind == "uv-project":
        resolved, unresolved = pg_manifest.uv_project_dependencies(directory, scope.extras)
        for built in pg_manifest.uv_built_directories(directory):
            # Syncing builds the packaged root and every editable or
            # path member, each fetching its own backend.
            more, missing = _build_requires(built)
            resolved, unresolved = resolved + more, unresolved + missing
        return resolved, unresolved, Path(directory) / "uv.lock"
    if scope.kind == "build-requires":
        resolved, unresolved = _build_requires(directory)
        return resolved, unresolved, Path(directory) / "pyproject.toml"
    raise pg_manifest.ManifestError(f"unknown manifest kind {scope.kind!r}")


def _create_reviews(requests, root, session_id, deadline=None, project=None, environments=(),
                    uv_project=False):
    """(reports, abandoned) for PackageRequests, in the given order.

    `deadline` is a time.monotonic() value shared by every call in one hook
    invocation (None starts a fresh budget). `abandoned` counts requests whose
    review did not finish in time. Their reports are not returned; a review
    that was mid-flight may still land on disk afterwards, and the next run
    picks it up unchanged. `project` is the directory the command runs in,
    whose Python a wheel is judged against, `environments` the Python
    environments outside the tree the command names, and `uv_project` true
    for the dependencies of a uv project the command syncs, whose Python uv
    chooses when the project names none.
    """
    if not requests:
        return [], 0
    if deadline is None:
        deadline = time.monotonic() + _REVIEW_BUDGET_SECONDS
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return [], len(requests)
    extra = {"uv_project": True} if uv_project else {}

    def build(request):
        if project is None:
            return vetting.create_review(request, root, session_id=session_id, **extra)
        if environments:
            return vetting.create_review(request, root, session_id=session_id, project=project,
                                         environments=tuple(environments), **extra)
        return vetting.create_review(request, root, session_id=session_id, project=project, **extra)

    workers = min(_REVIEW_WORKERS, len(requests))
    pool = futures.ThreadPoolExecutor(max_workers=workers)
    submitted = [pool.submit(build, request) for request in requests]
    done, not_done = futures.wait(submitted, timeout=remaining)
    # Do not wait for stragglers: past the budget every extra second is a step
    # toward the harness timeout, which fails open.
    pool.shutdown(wait=False, cancel_futures=True)
    return [future.result() for future in submitted if future in done], len(not_done)


# Per manifest kind: how to let the real resolver pin the versions. The guard
# never resolves ranges itself -- a resolver that disagreed with the ecosystem's
# own would vet a different version than the one installed.
_PIN_HELP = {
    "npm": (
        "Let npm resolve them, which writes package-lock.json without installing "
        "anything and, with scripts off, runs no code:",
        "  npm install --package-lock-only --ignore-scripts",
        "Pinning the specs in package.json to exact versions works too.",
    ),
    "pnpm": (
        "Let pnpm resolve them, which writes pnpm-lock.yaml without installing anything and, "
        "with scripts off, runs no code:",
        "  pnpm install --lockfile-only --ignore-scripts",
        "The lock must record each dependency for exactly the spec package.json declares.",
    ),
    "bun": (
        "Let Bun resolve them, which writes bun.lock without installing anything and, "
        "with scripts off, runs no code:",
        "  bun install --lockfile-only --ignore-scripts",
        "The lock must record each dependency for exactly the spec package.json declares.",
    ),
    "yarn": (
        "Let Yarn resolve them, which writes yarn.lock without linking or building anything:",
        "  yarn install --mode=update-lockfile",
        "The lock must record each dependency for exactly the spec package.json declares.",
    ),
    "yarn-classic": (
        "Yarn Classic cannot write yarn.lock without also installing, and an install resolves "
        "versions nobody reviewed. Each of these goes to review by name and exact version "
        "first. Once it is approved, remove its line from package.json (a revert, not an "
        "addition) and add it in the app's own folder, which writes package.json and yarn.lock:",
        "  yarn add <name>@<exact version> --ignore-scripts",
        "The lock must have an entry for each dependency under exactly the spec package.json "
        "declares (`name@spec`).",
    ),
    "requirements": (
        "Let a resolver pin them into a fully-pinned requirements file, which "
        "installs nothing:",
        "  uv pip compile <input>.in -o <this-file>",
        "Editing every line to a bare name==version pin works too.",
    ),
    # A [build-system] requirement has no resolver to pin it: the denial names
    # the exact version to write (`_render_build_unpinned`), and for a local
    # build this is the other way out.
    "build-requires": (
        "Or build without isolation, which fetches nothing:",
        "  pip install --no-deps --no-build-isolation .   (or: uv build --no-build-isolation)",
        "",
    ),
    "uv-project": (
        "Let uv resolve the project, which writes uv.lock without installing "
        "anything into the environment:",
        "  uv lock",
        "",
    ),
}

# Unpinned build requirements whose exact version the denial looks up, one
# PyPI call each, never retried, and only while the review deadline leaves
# room for the call: they end before the deadline, so the budget arithmetic
# is unchanged.
_BUILD_PIN_LOOKUPS = 3


def _build_pins(unresolved, deadline=None) -> dict:
    """requirement -> (name, version) or None, for the unpinned build
    requirements in `unresolved` (`vetting.suggest_build_pin`)."""
    pins = {}
    for entry in unresolved:
        if not isinstance(entry, _BuildRequirement) or entry.requirement in pins:
            continue
        if len(pins) >= _BUILD_PIN_LOOKUPS or (
                deadline is not None and time.monotonic() + vetting.TIMEOUT_SECONDS > deadline):
            break
        pins[entry.requirement] = vetting.suggest_build_pin(entry.requirement, pg_parser.PYPI_REGISTRY)
    return pins


def _render_build_unpinned(entries, pins, kind) -> list:
    """The remedy for unpinned `[build-system] requires`: the exact line to
    write, said to be allowed, and the project shape that needs none."""
    lines = [
        "",
        "Building this project runs the build backend its pyproject.toml names under "
        "[build-system] requires, fetched from PyPI. Package Guard reviews exact versions "
        "only, and these are not pinned:",
    ]
    for entry in entries:
        pyproject = entry.project / "pyproject.toml"
        pin = pins.get(entry.requirement)
        exact = f"{pin[0]}=={pin[1]}" if pin else None
        if entry.default_backend:
            lines += [
                f"  {entry.project}: no [build-system], so the build uses setuptools' default "
                "backend, fetched unpinned.",
                f"    fix: declare that backend, pinned, in {pyproject}:",
                "      [build-system]",
                f"      requires = [\"{exact or 'setuptools==<version>'}\"]",
                "      build-backend = \"setuptools.build_meta:__legacy__\"",
            ]
        else:
            lines.append(f"  {pyproject}: {entry.requirement}")
            lines.append(f"    fix: change `{entry.requirement}` to `{exact}`" if exact else
                         f"    fix: change `{entry.requirement}` to one exact `name==version` pin "
                         "(Package Guard could not look the version up)")
    if any(pins.get(e.requirement) for e in entries):
        lines.append("The version shown is the newest release the range allows, held back to "
                     "the newest one at least a week old when the latest is newer.")
    lines += [
        "This edit is allowed: it pins a build requirement the project already uses and adds "
        "no dependency, so the rule against hand-editing pyproject.toml to add a dependency "
        "does not apply. Change only that requirement, then re-run the same command. The pinned "
        "version is reviewed and approved like any other package.",
        "An application needs no build backend: `uv init --app --no-package` creates a project "
        "without [build-system], so this does not come up.",
    ]
    if kind == "build-requires":
        intro, fix, _extra = _PIN_HELP["build-requires"]
        lines += [intro, fix]
    return lines


def _render_unpinned(unresolved, where, kind, pins=None) -> str:
    """The manifest declares versions Package Guard cannot pin to an exact release."""
    build = [e for e in unresolved if isinstance(e, _BuildRequirement)]
    rest = [e for e in unresolved if not isinstance(e, _BuildRequirement)]
    if build and not rest:
        where = build[0].project / "pyproject.toml"
    lines = ["PACKAGE_GUARD_MANIFEST_UNPINNED", f"manifest: {where}"]
    if rest:
        lines += [
            "",
            "This command installs everything the manifest lists, so these dependencies "
            "would land without ever being named on the command line. Package Guard "
            "cannot vet them because they are not pinned to exact versions:",
        ]
        lines += [f"  {name}: {spec}" for name, spec in rest]
        intro, fix, extra = _PIN_HELP.get(kind, _PIN_HELP["npm"])
        lines += ["", intro, fix]
        directory = Path(where).parent
        lines.append(f"Run it with {directory} as the working directory, so it resolves the "
                     "manifest above and not another one: change directory in its own command "
                     "first, then run the pinning command bare -- no `cd ... &&`, no pipe, no `;`.")
        lines += ["", "Then re-run the install. The exact pinned versions become the reviews."]
        if extra:
            lines.append(extra)
    if build:
        lines += _render_build_unpinned(build, pins or {}, kind)
    return "\n".join(lines)


# The approval prompt is read in a yellow box by a human deciding in seconds.
# Every line is at most this wide, wrapped at spaces only, so a URL or a package
# name is never split; a wrapped line counts against the prompt's line budget.
_PROMPT_WIDTH = 100
_DETAIL = "    "
_DETAIL_MORE = "      "
_OFFICIAL_REGISTRIES = {"npm": pg_parser.NPM_REGISTRY, "pypi": pg_parser.PYPI_REGISTRY}

# One approve is one prompt, and Claude Code cuts a long hook reason with "…":
# a package past the cut would be approved unseen. An approve names at most
# this many review ids; every message that hands the agent an approve command
# splits a longer list into commands of this size.
_APPROVE_BATCH_MAX = 12


def _lookalike_of(report: dict):
    """The far more downloaded name the hook found one edit away, or None."""
    reputation = (report.get("optional_checks") or {}).get("reputation")
    name = reputation.get("lookalike_of") if isinstance(reputation, dict) else None
    return name if isinstance(name, str) and name else None


def _alone_flags(report: dict, verdict: dict | None) -> list:
    """Why an id may only be approved on its own: a DO_NOT_RECOMMEND verdict,
    a TYPO_SQUAT red flag, or the hook's own lookalike signal. Such a package's
    prompt must never ride on the approval of others."""
    flags = []
    if verdict and verdict.get("verdict") == "DO_NOT_RECOMMEND":
        flags.append("DO_NOT_RECOMMEND")
    if "TYPO_SQUAT" in ((verdict or {}).get("red_flags") or []):
        flags.append("TYPO_SQUAT")
    lookalike = _lookalike_of(report)
    if lookalike:
        flags.append(f"one edit from '{lookalike}'")
    return flags


def _approval_kind(report: dict, verdict: dict | None) -> str:
    """Which prompt an id belongs on.

    `flagged`: approved alone (`_alone_flags`). `decision`: a
    NEEDS_HUMAN_REVIEW verdict, the human's call. `recommended`: a RECOMMEND
    verdict, or no verdict and the established tier. A verdict outranks the
    tier, and an id that has neither is a decision: nothing recommends it."""
    if _alone_flags(report, verdict):
        return "flagged"
    said = (verdict or {}).get("verdict")
    if said == "RECOMMEND" or (said is None and vetting.is_established(report)):
        return "recommended"
    return "decision"


_KIND_RANK = {"flagged": 0, "decision": 1, "recommended": 2}


def _approve_commands(root, ids) -> list:
    """The approve command(s) for `ids`, at most _APPROVE_BATCH_MAX ids each."""
    ids = list(dict.fromkeys(ids))
    return [store.cli_command(root, "approve", " ".join(ids[i:i + _APPROVE_BATCH_MAX]))
            for i in range(0, len(ids), _APPROVE_BATCH_MAX)]


def _ids_by_kind(reports, verdicts) -> dict:
    """kind -> review ids in the agent's order, for ids that are not flagged."""
    groups = {"recommended": [], "decision": []}
    for report in reports:
        kind = _approval_kind(report, verdicts.get(report["review_id"]))
        if kind in groups:
            groups[kind].append(report["review_id"])
    return groups


def _approve_in_order(root, reports, verdicts) -> list:
    """The approve commands for the ids that are not flagged: every recommended
    id first, then every decision id, never both kinds in one command."""
    groups = _ids_by_kind(reports, verdicts)
    return _approve_commands(root, groups["recommended"]) + _approve_commands(root, groups["decision"])


def _command_lines(commands) -> str:
    """Several commands, one per line, to run one after another."""
    return "\n".join(f"  {command}" for command in commands)


def _wrap(text: str, indent: str = "", more: str = "  ") -> list:
    return textwrap.wrap(str(text), width=_PROMPT_WIDTH, initial_indent=indent,
                         subsequent_indent=more, break_long_words=False,
                         break_on_hyphens=False) or [indent.rstrip()]


_VERSION_TEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}")


def _same_package(ecosystem: str, one: str, other) -> bool:
    if ecosystem == "pypi":
        return vetting._pypi_normalise(one) == vetting._pypi_normalise(str(other or ""))
    return one == other


def _pinned_alternative(alternative: str, report: dict | None) -> str:
    """The alternative as the human should read it.

    A vetter's verdict line loses the alternative's version, so an earlier
    release of the package itself arrives as its bare name. That release is
    the hook's own settled one: the newest at least a week old."""
    identity = (report or {}).get("resolved_identity") or {}
    ecosystem, _, name = alternative.partition(":")
    if "@" in name[1:] or ecosystem != identity.get("ecosystem") \
            or not _same_package(ecosystem, name, identity.get("name")):
        return alternative
    settled = ((report or {}).get("evidence") or {}).get("settled_release")
    if isinstance(settled, str) and _VERSION_TEXT.fullmatch(settled) and settled != identity.get("version"):
        return f"{alternative}@{settled}"
    return f"an earlier version of {alternative}"


def _render_verdict(verdict: dict, report: dict | None = None) -> list:
    """The suggestion line under a package that needs the human's decision.

    Built only from the sanitised fields transcript.vetter_verdicts kept: the
    alternative is rendered only when it is still one `npm:` or `pypi:`
    package reference, so free text from the vetter never reaches the prompt.
    The verdict itself is the prompt's kind, and its red flags and evidence
    status are reasons (`_plain_reasons`)."""
    alternative = verdict.get("alternative")
    if isinstance(alternative, str) and transcript._PACKAGE_REF.fullmatch(alternative):
        line = f"Claude suggests: use {_pinned_alternative(alternative, report)} instead"
    else:
        line = ("Claude suggests: approve only if you need this exact package; "
                "the vetter found no alternative")
    return _wrap(line, _DETAIL, _DETAIL_MORE)


# The hook's own unmet strings, cut to what a human needs on one line, for a
# criterion that has no plain phrase below. The full text stays in the report
# and in `cli.py show`. An unknown string keeps its words and loses only a
# trailing parenthesis.
_UNMET_SHORT = (
    (re.compile(r"package age unknown day\(s\), under \d+"), "package age unknown"),
    (re.compile(r"unknown release\(s\), under \d+"), "release count unknown"),
    (re.compile(r"version age unknown day\(s\), under \d+"), "version age unknown"),
    (re.compile(r"repository manifest does not name this package"),
     "repository manifest names a different package"),
    (re.compile(r"(one edit from '[^']*'),.*"), r"\1"),
    (re.compile(r"no wheel for this version\b.*"), "no wheel"),
)


def _short_unmet(reason) -> str:
    text = " ".join(str(reason).split())
    for pattern, short in _UNMET_SHORT:
        match = pattern.fullmatch(text)
        if match:
            return match.expand(short)
    return re.sub(r"\s*\([^()]*\)$", "", text) or text


# The approval prompt is read by people who are not package experts. Each
# reason under a package is one fixed plain phrase, keyed here from the three
# places a reason comes from: the hook's risk signals, the unmet criteria of a
# package outside the established tier, and the vetter's red-flag codes. The
# numbers in a phrase come from the report. A string or code with no key is
# shown as the hook or the vetter wrote it, so nothing is dropped, and two
# sources with the same key make one line.
_SIGNAL_KEYS = (
    (re.compile(r"version published \d+ day\(s\) ago(, no provenance attestation)?"), "fresh"),
    (re.compile(r"package declares npm lifecycle/install scripts"), "install"),
    (re.compile(r"deprecated on the registry\b.*"), "deprecated"),
    (re.compile(r"package first published \d+ day\(s\) ago"), "young"),
    (re.compile(r"only \d+ release\(s\) on the registry"), "young"),
    (re.compile(r"last publish \d+ year\(s\) ago"), "stale"),
    (re.compile(r"\d+ known OSV vulnerability record\(s\) for this exact version"), "vulns"),
    (re.compile(r"cool-down unavailable \(.*"), "partial"),
    (re.compile(r"registry history too large to read\b.*"), "history"),
    (re.compile(r"name is one edit from '[^']*', which has .*\(possible lookalike\)"), "lookalike"),
    (re.compile(r"sdist only: setup\.py may execute on install"), "sdist"),
    (re.compile(r"no wheel for this platform\b.*"), "sdist"),
    (re.compile(r"the sdist's build backend .*unreviewed"), "build"),
)
_UNMET_KEYS = (
    (re.compile(r"version age \d+ day\(s\), under \d+"), "fresh"),
    (re.compile(r"declares install scripts"), "install"),
    (re.compile(r"deprecated on the registry"), "deprecated"),
    (re.compile(r"repository manifest (could not be read|not checked)\b.*"), "repo"),
    (re.compile(r"weekly downloads \d+ under \d+"), "few"),
    (re.compile(r"not in the top-[\d,]+ list\b.*"), "few"),
    (re.compile(r"package age \d+ day\(s\), under \d+"), "young"),
    (re.compile(r"\d+ release\(s\), under \d+"), "young"),
    (re.compile(r"\d+ OSV record\(s\) for this version"), "vulns"),
    (re.compile(r"(no weekly download count from|weekly downloads unavailable|near-name check "
                r"unavailable|reputation evidence was malformed)\b.*"), "partial"),
    (re.compile(r"registry history too large to read\b.*"), "history"),
    (re.compile(r"one edit from '[^']*', which has .*"), "lookalike"),
    (re.compile(r"no wheel for this version\b.*"), "sdist"),
    # Unknown because the history could not be read: the history line says so.
    (re.compile(r"(package age|version age) unknown day\(s\).*|unknown release\(s\).*"), "unknown"),
)
_CODE_KEYS = {
    "FRESH_PUBLISH": "fresh", "INSTALL_SCRIPT": "install", "DEPRECATED": "deprecated",
    "NO_REPOSITORY": "repo", "REPO_REDIRECTED": "repo", "LOW_ADOPTION": "adoption",
    "STALE": "stale", "ADVISORY": "vulns", "ADVISORY_UNFIXED": "vulns",
    "PROVIDER_UNREACHABLE": "partial", "REPORT_NOT_FOUND": "partial",
    "PURPOSE_UNCONFIRMED": "purpose", "TYPO_SQUAT": "lookalike", "SDIST_ONLY": "sdist",
    "RELEASE_DIFF": "diff",
}
_FIXED_PHRASES = {
    "install": "runs code while installing (install script)",
    "deprecated": "marked deprecated by its maintainers",
    "repo": "its source repository could not be confirmed",
    "partial": "some checks could not be completed",
    "history": "release history too large to read: age unknown",
    "purpose": "may not do what the task needs",
    "sdist": "installing builds it from source, which runs the package's own code",
    "build": "its build tool is downloaded and run while installing, unreviewed",
    "diff": "this release changed in ways worth checking against the previous one",
}


def _key_of(table, text: str):
    return next((key for pattern, key in table if pattern.fullmatch(text)), None)


def _ago(days: int) -> str:
    if days >= 730:
        return f"{days // 365} years ago"
    if days >= 365:
        return "over a year ago"
    if days >= 60:
        return f"{days // 30} months ago"
    return "today" if days == 0 else "1 day ago" if days == 1 else f"{days} days ago"


def _plural(count: int, word: str) -> str:
    return f"{count:,} {word}{'' if count == 1 else 's'}"


def _first_number(texts, pattern: str):
    for text in texts:
        match = re.fullmatch(pattern, text)
        if match:
            return int(match.group(1))
    return None


class _Phrases:
    """The plain phrase for each key, read from one package's report."""

    def __init__(self, report: dict, signals: list, unmet: list):
        self.evidence = report.get("evidence") or {}
        optional = report.get("optional_checks") or {}
        reputation = optional.get("reputation")
        self.reputation = reputation if isinstance(reputation, dict) else {}
        self.signals, self.unmet = signals, unmet
        provenance = optional.get("provenance")
        # Only the hook's own evidence says "not signed": npm reports whether
        # a version is attested; PyPI's attestations are never fetched, so
        # there it is unknown, and a vetter code alone cannot tell absent
        # from not fetched.
        self.unsigned = (isinstance(provenance, dict) and provenance.get("attested") is False) or any(
            s.endswith(", no provenance attestation") for s in signals)
        mandatory = report.get("mandatory_checks") or {}
        ids = [i for i in ((mandatory.get("osv") or {}).get("ids") or []) if not str(i).startswith("MAL-")]
        known = self.evidence.get("known_vulnerabilities")
        self.vulns = len(ids) or (len(known) if isinstance(known, list) else 0) or _first_number(
            signals, r"(\d+) known OSV vulnerability record\(s\) for this exact version")

    def fresh(self):
        age = self.evidence.get("version_age_days")
        if not _is_count(age):
            age = _first_number(self.signals, r"version published (\d+) day\(s\) ago.*") or \
                _first_number(self.unmet, r"version age (\d+) day\(s\), under \d+")
        text = (f"published {_ago(age)}" if _is_count(age)
                else f"published less than {vetting.FRESH_VERSION_DAYS} days ago")
        return text + (" and not signed" if self.unsigned else "")

    def young(self):
        releases, age = self.evidence.get("release_count"), self.evidence.get("package_age_days")
        parts = []
        if _is_count(releases):
            parts.append(_plural(releases, "release"))
        if _is_count(age):
            parts.append(f"first published {_ago(age)}")
        if not parts:
            return None
        # Few releases over more than a year is not a new package.
        old = _is_count(age) and age >= vetting.ESTABLISHED_MIN_AGE_DAYS
        return ("only " if old else "new package: ") + ", ".join(parts)

    def few(self):
        downloads = self.reputation.get("weekly_downloads")
        if not _is_count(downloads):
            downloads = _first_number(self.unmet, r"weekly downloads (\d+) under \d+")
        if _is_count(downloads):
            return f"few users ({downloads:,} downloads a week)"
        for reason in self.unmet:
            match = re.fullmatch(r"not in the top-([\d,]+) list\b.*", reason)
            if match:
                return f"few users (not in PyPI's top {match.group(1)} by downloads)"
        return "few users"

    def adoption(self):
        """LOW_ADOPTION is the vetter's code for few downloads or for a young
        package; the report's own count says which one it can be."""
        downloads = self.reputation.get("weekly_downloads")
        if _is_count(downloads) and downloads >= vetting.ESTABLISHED_MIN_WEEKLY_DOWNLOADS:
            return self.young()
        return self.few()

    def stale(self):
        years = _first_number(self.signals, r"last publish (\d+) year\(s\) ago")
        if years is None:
            return f"not updated in over {vetting.STALE_PUBLISH_DAYS // 365} years"
        return f"not updated in {_plural(years, 'year')}"

    def vulns_phrase(self):
        if self.vulns:
            return f"{_plural(self.vulns, 'known vulnerability report')} for this version"
        return "known vulnerability reports for this version"

    def lookalike(self):
        name = self.reputation.get("lookalike_of")
        if not isinstance(name, str) or not name:
            for text in self.signals + self.unmet:
                match = re.search(r"one edit from '([^']+)'", text)
                if match:
                    name = match.group(1)
                    break
        if isinstance(name, str) and re.fullmatch(r"[@A-Za-z0-9._/-]{1,214}", name or ""):
            return f"name is one letter away from '{name}', a far more popular package (possible typosquat)"
        return "name looks like a far more popular package (possible typosquat)"

    def phrase(self, key):
        if key in _FIXED_PHRASES:
            return _FIXED_PHRASES[key]
        return {"fresh": self.fresh, "young": self.young, "few": self.few,
                "adoption": self.adoption, "stale": self.stale,
                "vulns": self.vulns_phrase, "lookalike": self.lookalike}[key]()


def _plain_reasons(report: dict, verdict: dict | None = None, skip_fresh: bool = False) -> list:
    """One plain phrase per reason this package needs the human's eye, in
    order: risk signals, unmet criteria, the vetter's red flags and evidence
    status, an assumed-interpreter wheel, a license that is not permissive.

    A package with none of these gets no lines, and the summary line speaks
    for it. `skip_fresh` drops the fresh-release phrase when the package line
    already says it in its continuity suffix."""
    evidence = report.get("evidence") or {}
    reputation = (report.get("optional_checks") or {}).get("reputation")
    signals = [" ".join(str(s).split()) for s in report.get("risk_signals") or [] if str(s).strip()]
    established = vetting.is_established(report)
    unmet = [] if established else [
        " ".join(str(u).split()) for u in (reputation or {}).get("unmet") or [] if u] \
        if isinstance(reputation, dict) else []
    phrases = _Phrases(report, signals, unmet)
    entries = [("signal", _key_of(_SIGNAL_KEYS, s), s) for s in signals]
    entries += [("unmet", _key_of(_UNMET_KEYS, u), u) for u in unmet]
    if not established and not unmet:
        entries.append(("unmet", None, "no reason recorded" if isinstance(reputation, dict)
                        else "reputation not checked"))
    if verdict:
        entries += [("code", _CODE_KEYS.get(code), code) for code in verdict.get("red_flags") or []]
        if verdict.get("evidence_status") in ("partial", "unavailable"):
            entries.append(("code", "partial", verdict["evidence_status"]))
    pypi = (report.get("resolved_identity") or {}).get("ecosystem") == "pypi"
    assumed = vetting.assumed_wheel(evidence) if pypi else None
    if assumed:
        entries.append(("signal", None, assumed))
    license_class = evidence.get("license_class")
    if isinstance(license_class, str) and license_class and license_class != "permissive":
        entries.append(("signal", None, f"license: {evidence.get('license') or 'none declared'} "
                                        f"({license_class} — check it fits your project)"))
    history = any(key == "history" for _source, key, _text in entries)
    out = []
    for source, key, text in entries:
        if (key == "fresh" and skip_fresh) or (key == "unknown" and history):
            continue
        phrase = phrases.phrase(key) if key not in (None, "unknown") else None
        if phrase is None:
            phrase = _short_unmet(text) if source == "unmet" else text
            # An unmet criterion a signal above already states in full.
            if source == "unmet" and any(phrase in line for line in out):
                continue
        if phrase not in out:
            out.append(phrase)
    return out


def _continuity_suffix(report: dict) -> str:
    """A fresh release of an established package, on its own package line.

    The facts the hook compared against the newest release at least a week
    old, in plain words: when this version was published, whether it is
    signed, and whether the same publisher released both."""
    continuity = (report.get("optional_checks") or {}).get("release_continuity")
    if not isinstance(continuity, dict) or not vetting.is_established(report):
        return ""
    parts = []
    age = (report.get("evidence") or {}).get("version_age_days")
    if _is_count(age):
        parts.append(f"published {_ago(age)}")
    attested, same = continuity.get("attested"), continuity.get("same_publisher")
    baseline = continuity.get("baseline")
    baseline = baseline if isinstance(baseline, str) and baseline else None
    publisher = None
    if baseline and same is True:
        publisher = f"the same publisher as {baseline}"
    elif baseline and same is False:
        publisher = f"a different publisher than {baseline}"
    if attested is True:
        parts.append(f"signed by {publisher}" if publisher else "signed")
    else:
        if attested is False:
            parts.append("not signed")
        if publisher:
            parts.append(f"from {publisher}")
    for key, label in (("new_install_scripts", "new install script"),
                       ("new_dependencies", "new dependency")):
        added = continuity.get(key)
        if isinstance(added, list) and added:
            parts.append(f"{label}: {', '.join(str(a) for a in added)}")
    return f"  ({', '.join(parts)})" if parts else ""


def _refresh_reports(reports, deadline=None) -> dict:
    """review_id -> vetting.gather() result, or None when abandoned.

    The prompt is the moment of decision, so it renders evidence fetched now,
    not the report written at review time: a malware record, an unpublish, a
    deprecation or a changed publisher since then all reach the human.
    Concurrent, under the same budget as review creation.
    """
    if not reports:
        return {}
    if deadline is None:
        deadline = time.monotonic() + _REVIEW_BUDGET_SECONDS
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {r["review_id"]: None for r in reports}

    def refresh(report):
        identity = report["resolved_identity"]
        request = pg_manifest.as_request(
            identity["name"], identity["version"], "(approve-time refresh)", identity["ecosystem"])
        if identity["ecosystem"] != "pypi":
            return vetting.gather(request)
        # The interpreter the review judged the wheels against, and where it
        # came from, so the prompt does not re-derive it from another
        # directory and still says when it was assumed.
        source = vetting.reviewed_python_source(report)
        if source:
            return vetting.gather(request, python=vetting.reviewed_python(report), python_source=source)
        return vetting.gather(request, python=vetting.reviewed_python(report))

    pool = futures.ThreadPoolExecutor(max_workers=min(_REVIEW_WORKERS, len(reports)))
    submitted = {report["review_id"]: pool.submit(refresh, report) for report in reports}
    done, _not_done = futures.wait(list(submitted.values()), timeout=remaining)
    pool.shutdown(wait=False, cancel_futures=True)
    return {rid: (future.result() if future in done else None) for rid, future in submitted.items()}


def _refreshed_view(report: dict, found: dict) -> dict:
    """The stored report with its evidence replaced by a fresh gather()."""
    view = dict(report)
    view["mandatory_checks"] = found["mandatory"]
    view["evidence"] = found["evidence"]
    view["optional_checks"] = dict(
        report.get("optional_checks") or {},
        provenance=found["provenance"],
        reputation=found.get("reputation"),
    )
    if "release_continuity" in found:
        view["optional_checks"]["release_continuity"] = found["release_continuity"]
    view["risk_signals"] = found["risk_signals"]
    view["refreshed_at"] = store.utcnow()
    return view


def _shows_fresh_suffix(report: dict) -> bool:
    """The package line's continuity suffix already says when it was published."""
    return bool(_continuity_suffix(report)) and _is_count(
        (report.get("evidence") or {}).get("version_age_days"))


def _package_details(report: dict, verdict: dict | None = None) -> list:
    """The reason lines under one package, wrapped: only what needs the
    human's eye (`_plain_reasons`). A package with none gets no lines, and the
    summary line speaks for it."""
    lines = []
    for reason in _plain_reasons(report, verdict, skip_fresh=_shows_fresh_suffix(report)):
        lines += _wrap(reason, _DETAIL, _DETAIL_MORE)
    return lines


def _render_package_block(report: dict, verdict: dict | None = None) -> list:
    """`ecosystem:name@version` alone on its line -- the column a human scans
    for a lookalike -- then the package's reason lines, if any, and, for a
    package that needs the human's decision, Claude's suggestion."""
    line = f"{_label(report['resolved_identity'])}{_continuity_suffix(report)}"
    lines = _wrap(line, "  ", _DETAIL_MORE) + _package_details(report, verdict)
    if verdict and _approval_kind(report, verdict) != "recommended":
        lines += _render_verdict(verdict, report)
    return lines


def _is_count(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _summary_facts(report: dict, verdicts: dict) -> dict:
    """Each fixed phrase, true only when this package's own fields show it.

    A missing field is a fact not shown, never a fact assumed: an old report,
    a catalog identity that skipped the download count, or a manifest that
    could not be read all leave the phrase out of the summary."""
    identity = report.get("resolved_identity") or {}
    ecosystem = identity.get("ecosystem")
    mandatory = report.get("mandatory_checks") or {}
    registry = mandatory.get("registry") or {}
    osv = mandatory.get("osv") or {}
    evidence = report.get("evidence") or {}
    reputation = (report.get("optional_checks") or {}).get("reputation")
    reputation = reputation if isinstance(reputation, dict) else {}
    manifest = reputation.get("manifest") if isinstance(reputation.get("manifest"), dict) else {}
    scripts = evidence.get("install_scripts")
    age, downloads = evidence.get("package_age_days"), reputation.get("weekly_downloads")
    return {
        "registry": (registry.get("exists") is True and ecosystem in _OFFICIAL_REGISTRIES
                     and identity.get("registry") == _OFFICIAL_REGISTRIES[ecosystem]),
        "osv": osv.get("ok") is True and osv.get("ids") == [],
        # A wheel judged against an assumed interpreter is not "nothing runs
        # while installing": it holds only if the installer runs that one.
        "wheel": (ecosystem == "pypi" and evidence.get("distribution") == "wheel"
                  and vetting.assumed_wheel(evidence) is None),
        "scripts": ecosystem == "npm" and scripts == [],
        "age": _is_count(age) and age >= 365,
        "downloads": _is_count(downloads) and downloads >= 10_000,
        "manifest": manifest.get("names_package") is True,
    }


_REGISTRY_NAMES = {"npm": "npm", "pypi": "PyPI"}


def _render_summary(clean: list, count: int, verdicts: dict) -> list:
    """The "Why" line for every package shown with nothing under it, computed
    for this batch: a phrase appears only when it held for each of them."""
    if not clean:
        return []
    facts = [_summary_facts(report, verdicts) for report in clean]

    def held(key):
        return all(f[key] for f in facts)

    ecosystems = {(r.get("resolved_identity") or {}).get("ecosystem") for r in clean}
    phrases = []
    if held("registry"):
        phrases.append(f"from the official {_REGISTRY_NAMES[next(iter(ecosystems))]} registry"
                       if len(ecosystems) == 1 else "from the official registries")
    if held("age"):
        phrases.append("first published over a year ago")
    if held("downloads"):
        phrases.append("widely used (10,000+ downloads a week)")
    if held("osv"):
        phrases.append("no known vulnerabilities or malware reports for "
                       f"{'this version' if len(clean) == 1 else 'these versions'} (checked today)")
    if all(f["wheel"] or f["scripts"] for f in facts):
        phrases.append("nothing runs while installing")
    if held("manifest"):
        phrases.append("published from its own source repository")
    if len(clean) == count:
        lead = "Why: "
    else:
        lead = ("Why, for the one without notes: " if len(clean) == 1
                else f"Why, for the {len(clean)} without notes: ")
    line = lead + (", ".join(phrases) + "." if phrases else "Package Guard's own checks passed.")
    return _wrap(line, "", "")


def _noun(count: int) -> str:
    return f"{count} package{'' if count == 1 else 's'}"


def _render_header(kinds: list) -> str:
    """One header per kind of prompt. The hook never mixes kinds on one
    approve (`_flagged_in_batch`, `_mixed_in_batch`); a mixed list, rendered
    directly, still says what each package is."""
    count = len(kinds)
    if set(kinds) == {"recommended"}:
        return (f"Package Guard — approve {count} recommended package{'' if count == 1 else 's'} "
                "for this project")
    if set(kinds) == {"decision"}:
        return f"Package Guard — {_noun(count)} need{'s' if count == 1 else ''} your decision"
    if set(kinds) == {"flagged"}:
        return f"Package Guard — {_noun(count)} NOT recommended"
    parts = []
    for kind, words in (("flagged", "NOT recommended"), ("decision", None),
                        ("recommended", "recommended")):
        n = kinds.count(kind)
        if n:
            parts.append(f"{n} {words or ('needs your decision' if n == 1 else 'need your decision')}")
    return f"Package Guard — approve {_noun(count)}: {', '.join(parts)}"


def _render_approval(reports, verdicts: dict | None = None) -> str:
    """The permission prompt, in plain words for a reader who is not a
    package expert: a header that says which kind of prompt it is, one line
    per package with reason lines only where something needs the human's eye
    and Claude's suggestion under a package that needs a decision, one "Why"
    line for the recommended packages with nothing under them, and the
    question. Flagged and decision packages come first. No review ids and no
    paths: the human cannot act on them in a modal prompt, and `cli.py show`
    carries every dropped fact."""
    verdicts = verdicts or {}
    kinds = {r["review_id"]: _approval_kind(r, verdicts.get(r["review_id"])) for r in reports}
    details = {r["review_id"]: _package_details(r, verdicts.get(r["review_id"])) for r in reports}
    # A reason too long for the prompt is cut at its end, so the end is where
    # the packages with nothing to weigh go.
    reports = sorted(reports, key=lambda r: (_KIND_RANK[kinds[r["review_id"]]],
                                             0 if details[r["review_id"]] else 1))
    order = [kinds[r["review_id"]] for r in reports]
    count = len(reports)
    lines = _wrap(_render_header(order), "", "  ")
    clean = []
    for report in reports:
        lines += _render_package_block(report, verdicts.get(report["review_id"]))
        if kinds[report["review_id"]] == "recommended" and not details[report["review_id"]]:
            clean.append(report)
    if "recommended" in order:
        lines.append("")
        lines += _render_summary(clean, count, verdicts)
    anyway = "" if set(order) == {"recommended"} else " anyway"
    if count == 1:
        lines.append(f"Approve this exact version{anyway}? Rejecting installs nothing and declines nothing.")
    else:
        lines.append(f"Approve these exact versions{anyway}? To skip one or see details, reject and "
                     "tell Claude.")
    return "\n".join(lines)


def _render_decline(reports) -> str:
    """Decline is permanent and records a human, so a human sees it."""
    lines = [f"Package Guard decline — PERMANENT, {len(reports)} package{'s' if len(reports) != 1 else ''}", ""]
    for report in reports:
        lines.append(f"  {_label(report['resolved_identity'])}  (review {report['review_id']})")
    lines += [
        "",
        "Never install these exact versions in this project? A declined version is refused "
        "on every future attempt. Reversal is `cli.py undecline <review-id>`, which also prompts.",
    ]
    return "\n".join(lines)


def _render_undecline(reports) -> str:
    lines = [f"Package Guard undecline — {len(reports)} package{'s' if len(reports) != 1 else ''}", ""]
    for report in reports:
        lines.append(f"  {_label(report['resolved_identity'])}  (review {report['review_id']})")
    lines += [
        "",
        "Allow these exact versions to be reviewed again? Nothing is approved by this: the next "
        "install goes through the vetter and the approve prompt as usual.",
    ]
    return "\n".join(lines)


def _render_revoke(reports) -> str:
    """Withdrawing an approval is a human act, like granting it."""
    lines = [f"Package Guard revoke — {len(reports)} package{'s' if len(reports) != 1 else ''}", ""]
    for report in reports:
        lines.append(f"  {_label(report['resolved_identity'])}  (review {report['review_id']})")
    lines += [
        "",
        "Withdraw approval for these exact versions? They are not declined: the next install "
        "needs a new review and a new approval. A copy already installed is reported as "
        "unreviewed on disk by the next command, with removal as the way out.",
    ]
    return "\n".join(lines)


def _load_for_cli(root, review_ids):
    """Every report named, or the problems that stop the whole call."""
    reports, problems = [], []
    for rid in review_ids:
        try:
            reports.append(store.load_report(root, rid))
        except store.StoreError as exc:
            problems.append(f"{rid}: {exc}")
    return reports, problems


def _oversized_approve(root, review_ids) -> dict | None:
    """A denial for an approve naming more ids than one prompt may carry."""
    if len(review_ids) <= _APPROVE_BATCH_MAX:
        return None
    return _decision(
        "deny",
        f"PACKAGE_GUARD_UNSUPPORTED: one approve takes at most {_APPROVE_BATCH_MAX} review ids "
        f"and this one names {len(review_ids)}, so its prompt could be cut before the user saw "
        "every package. Nothing was approved. Split it: run these one after another, each as a "
        "simple standalone command (no `cd`, no `&&`):\n"
        + _command_lines(_approve_commands(root, review_ids)),
    )


def _flagged_in_batch(root, reports, verdicts) -> dict | None:
    """A denial when a DO_NOT_RECOMMEND, TYPO_SQUAT or lookalike id shares an
    approve with any other id. The prompt is one accept for every package on
    it, so a flagged package in a batch is approved by the keypress meant for
    the clean ones."""
    if len(reports) < 2:
        return None
    flagged = {r["review_id"]: _alone_flags(r, verdicts.get(r["review_id"])) for r in reports}
    flagged = {rid: flags for rid, flags in flagged.items() if flags}
    if not flagged:
        return None
    labels = " | ".join(
        f"{_label(r['resolved_identity'])} ({', '.join(flagged[r['review_id']])}; "
        f"review {r['review_id']})" for r in reports if r["review_id"] in flagged)
    rest = [r for r in reports if r["review_id"] not in flagged]
    lines = [f"PACKAGE_GUARD_UNSUPPORTED: approve flagged packages alone: {labels}. "
             "Nothing was approved."]
    if rest:
        lines += ["Approve the other ids without the flagged ones, exactly as written, one "
                  "command after another (recommended ids first, then the ones that need the "
                  "user's decision):",
                  _command_lines(_approve_in_order(root, rest, verdicts))]
    lines.append(
        "Tell the user about each flagged package in one short message and offer the "
        "alternative the vetter named. Run a separate approve for one flagged id, alone, only "
        "if the user explicitly asks to approve it anyway: "
        f"{store.cli_command(root, 'approve', '<review-id>')}")
    return _decision("deny", "\n".join(lines))


def _mixed_in_batch(root, reports, verdicts) -> dict | None:
    """A denial when one approve names recommended ids and ids that need the
    user's decision. Each kind has a prompt of its own: the recommended ones
    first, then the decision ones, each package with its reasons and Claude's
    suggestion, so the keypress meant for the recommended packages never
    approves a package the vetter left to the user."""
    groups = _ids_by_kind(reports, verdicts)
    if not groups["recommended"] or not groups["decision"]:
        return None
    by_id = {r["review_id"]: r for r in reports}

    def labels(ids):
        return ", ".join(dict.fromkeys(_label(by_id[rid]["resolved_identity"]) for rid in ids))

    lines = [
        "PACKAGE_GUARD_CLI_REFUSED: cannot approve — this approve mixes recommended packages "
        f"({labels(groups['recommended'])}) with packages that need the user's decision "
        f"({labels(groups['decision'])}). Nothing was approved. Run the recommended ids first, "
        "exactly as written and as a simple standalone command (no `cd`, no `&&`):",
        _command_lines(_approve_commands(root, groups["recommended"])),
        "Then give the user ONE short chat line per package that needs a decision: its red "
        "flags in plain words and the risk they carry first, then your suggestion (use the "
        "alternative the vetter named, or approve only if the user needs this exact package; "
        "never a plain 'approve it'), and run the decision "
        "ids as a separate command, without waiting for a reply: its prompt is the question.",
        _command_lines(_approve_commands(root, groups["decision"])),
    ]
    return _decision("deny", "\n".join(lines))


# What Claude may run of `cli.py mode`: show it, or turn the guard back on.
_MODE_CLAUDE_FORMS = ([], ["enforce"], ["enforce", "--project"])


def _mode_cli_decision(tail, root) -> dict:
    """`tail` is the raw tokens after `mode` (after `--root X` in the plugin
    form), or None when the verb was not directly after cli.py. Never the
    parsed argument list: that drops `--flags`, so `mode --reason enforce off`
    would read as `enforce`."""
    if tail is not None and list(tail) in _MODE_CLAUDE_FORMS:
        return _decision("allow", "Package Guard: showing the mode." if not tail else
                         "Package Guard: turning the guard back on (enforce).")
    if tail and tail[0] in ("warn", "off"):
        # The command handed to the user must be one the CLI accepts.
        asked = shlex.join(tail) + ("" if "--reason" in tail else ' --reason "<why>"')
    else:
        asked = '<warn|off> --reason "<why>" [--for 8h | --permanent] [--project]'
    return _decision(
        "deny",
        "PACKAGE_GUARD_MODE_HUMAN_ONLY: only the user can turn Package Guard down, in their "
        "own terminal -- not through Claude, and not with `!`. Do not look for another way "
        "to do this. Tell the user, and if they want it, give them this command to run "
        f"themselves from the project folder ({root}):\n"
        f"  {store.human_command(root, 'mode', asked)}\n"
        "Claude may run only `mode` (to show it) and `mode enforce [--project]` (to turn it "
        "back on), exactly as:\n  "
        f"{store.cli_command(root, 'mode', '').rstrip()}")

# What Claude may run of `cli.py baseline` and `cli.py git-owners`. Read from the
# raw tokens after the verb, never a parsed list that drops `--flags`.
_BASELINE_ID_TOKEN = re.compile(r"bl-[0-9a-f]{12}\Z")
_BASELINE_READ_VERBS = ("show", "list", "export")


def _baseline_human_only(root, what, tail, verb="baseline") -> dict:
    """PACKAGE_GUARD_BASELINE_HUMAN_ONLY: the exact command for the
    person's own terminal, and that Claude does not retry or reword it."""
    return _decision(
        "deny",
        f"PACKAGE_GUARD_BASELINE_HUMAN_ONLY: only the user can do this, in their own terminal ({what}): "
        f"{store.human_command(root, verb, shlex.join(tail))}. Stop and tell them; do not retry or reword it, "
        "and do not look for another way.")


def _baseline_plan_tokens_problem(tail):
    """Why `baseline plan`'s tokens are not one of its two forms, or None."""
    rest, positional, i = tail[1:], [], 0
    forms = {"--app": 1, "--base": 1, "--python-version": 1}
    seen = set()
    while i < len(rest):
        token = rest[i]
        if token in forms:
            if i + 1 >= len(rest) or rest[i + 1].startswith("-"):
                return f"{token} needs a value"
            if token != "--base" and token in seen:
                return f"{token} is given twice"
            if token == "--base" and not _BASELINE_ID_TOKEN.match(rest[i + 1]):
                return "--base takes a baseline id (bl-<12 hex>)"
            seen.add(token)
            i += 2
        elif token.startswith("-"):
            return f"{token} is not an option of `baseline plan`"
        else:
            positional.append(token)
            i += 1
    if "--app" in seen and not positional:
        return None
    if "--app" not in seen and len(positional) == 2 and positional[0].startswith("https://"):
        return None
    return "name an app (--app apps/<x>) or a GitHub URL and a ref"


def _baseline_cli_decision(verb, tail, root) -> dict:
    """The hook's decision for `cli.py baseline ...` and `cli.py git-owners ...`
   . `tail` is the raw tokens after the verb,
    or None when the verb was not directly after cli.py."""
    def refuse(why):
        return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: {why}. Package Guard accepts only its own CLI, "
                                 f"exactly as: {store.cli_command(root, verb, '<subcommand> ...').rstrip()}")

    if tail is None:
        return refuse("the subcommand must come directly after cli.py")
    tail = list(tail)
    if any(_UNSAFE_PATH_TOKEN.search(token) for token in tail):
        return refuse("a path, ref or id may not carry shell syntax")
    # The human-only acts, first and whatever the switch says, so the agent is never
    # told to try them another way.
    if verb == "git-owners" and tail[:1] in (["add"], ["remove"]):
        return _baseline_human_only(root, "the git-owners allowlist is a person's to edit", tail, verb)
    if not pg_parser.FRAPPE_ENABLED:
        return _decision("deny", "PACKAGE_GUARD_UNSUPPORTED: Frappe baselines are not enabled in this release "
                                 "of Package Guard yet (planned for v1.12.0).")
    if verb == "git-owners":
        if tail == ["list"]:
            return _decision("allow", "Package Guard: showing the git-owners allowlist.")
        return refuse("git-owners takes `list`")
    if not tail:
        return refuse("`baseline` takes plan, show, list, export, import, approve or revoke")
    sub, rest = tail[0], tail[1:]
    if sub == "plan":
        why = _baseline_plan_tokens_problem(tail)
        if why:
            return refuse(why)
        return _decision("allow", "Package Guard: planning a baseline. It fetches the commit from the app's own "
                                  "URL and compiles without building; it writes a proposal and approves nothing.")
    if sub == "list" and not rest:
        return _decision("allow", "Package Guard: listing baselines.")
    if sub in ("show", "export") and len(rest) == 1 and _BASELINE_ID_TOKEN.match(rest[0]):
        return _decision("allow", "Package Guard: read-only baseline display.")
    if sub == "import" and len(rest) == 1 and not rest[0].startswith("-"):
        return _decision("allow", "Package Guard: importing a baseline as a proposal. The plan is run again from "
                                  "its URL and commit; nothing is approved.")
    if sub in ("approve", "revoke") and len(rest) == 1 and _BASELINE_ID_TOKEN.match(rest[0]):
        bid = rest[0]
        if sub == "revoke":
            try:
                doc = baseline.load(root, bid)
            except baseline.BaselineError as exc:
                return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: cannot revoke - {exc}")
            return _decision("ask", f"Package Guard: withdraw the approval of baseline {bid} "
                                    f"({doc['app']['name']} {doc['app']['commit'][:12]}). Nothing is declined; "
                                    "its commands need a new approved baseline.")
        try:
            doc = baseline.load(root, bid, proposal=True)
        except baseline.BaselineError as exc:
            return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: cannot approve - {exc}")
        if doc.get("approvable") is False or doc["evidence"]["osv"]["malware"]:
            return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: cannot approve - OSV lists malware in {bid}: "
                                     + "; ".join(doc["evidence"]["osv"]["malware"][:3]))
        try:
            owners = baseline.load_owners(root)[0]
        except baseline.BaselineError as exc:
            return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: cannot approve - {exc}")
        why = baseline.owner_problem(doc["app"]["git_url"], owners)
        if why:
            return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: cannot approve - {why}")
        builds = baseline.all_builds(doc)
        if builds:
            return _baseline_human_only(
                root, f"{bid} lists {len(builds)} packages that will be built from source on the person's machine, "
                      "and only they confirm that list, once, by typing a word", ["approve", bid])
        return _decision("ask", baseline.prompt_text(doc, owners))
    return refuse("that is not a form of `baseline` Claude may run")



def _bench_config_cli_decision(tail, root) -> dict:
    """The hook's decision for `cli.py bench-config ...`: `check` reads and says whether the installer
    files hold; `apply` writes them, so the person's prompt is the gate. Only the documented options
    pass, read from the raw tokens, and the verb is refused while the Frappe switch is off."""
    def refuse(why):
        return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: {why}. Package Guard accepts only its own CLI, "
                                 f"exactly as: {store.cli_command(root, 'bench-config', '<apply|check>').rstrip()}")

    if tail is None:
        return refuse("the subcommand must come directly after cli.py")
    tail = list(tail)
    if any(_UNSAFE_PATH_TOKEN.search(token) for token in tail):
        return refuse("a path or version may not carry shell syntax")
    if not pg_parser.FRAPPE_ENABLED:
        return _decision("deny", "PACKAGE_GUARD_UNSUPPORTED: Frappe support is not enabled in this release "
                                 "of Package Guard yet.")
    if not tail or tail[0] not in ("apply", "check"):
        return refuse("`bench-config` takes apply or check")
    verb, rest, i, toolchain, new_apps = tail[0], tail[1:], 0, [], []
    while i < len(rest):
        if rest[i] == "--bench" and i + 1 < len(rest) and not rest[i + 1].startswith("-"):
            i += 2
        elif verb == "apply" and rest[i] == "--toolchain" and i + 1 < len(rest) and "==" in rest[i + 1]:
            toolchain.append(rest[i + 1])
            i += 2
        elif verb == "apply" and rest[i] == "--no-symlinks":
            i += 1
        elif (verb == "apply" and rest[i] == "--new-app" and i + 1 < len(rest)
              and bench_config.NEW_APP_NAME.fullmatch(rest[i + 1])):
            new_apps.append(rest[i + 1])
            i += 2
        else:
            return refuse(f"{rest[i]!r} is not an option of `bench-config {verb}`")
    if verb == "check":
        return _decision("allow", "Package Guard: checking the bench's installer files.")
    chosen = (" The toolchain pins you chose: " + ", ".join(toolchain) + ".") if toolchain else ""
    if new_apps:
        chosen += (" It also lets uv build, from source, the app(s) `bench new-app` is about to create: "
                   + ", ".join(new_apps) + ". Allow this only if that is the name of a new app of yours and "
                   "not the name of a package from an index.")
    return _decision("ask", (
        "Package Guard: write this bench's installer files: env/pip.conf, uv.toml, the constraint files "
        "under the guard's state directory and a .yarnrc in each yarn directory. They pin what bench's "
        "installs may fetch to the approved baselines of its upstream apps (a package outside them can "
        "still install; the guard checks the disk afterwards). It also adds the .yarnrc files to each app "
        "repository's .git/info/exclude and, where the bench is a git repository, two lines to its "
        ".gitattributes." + chosen +
        " A file that is there already and was not written by the guard is never overwritten."))


def _handle_cli(call, root, transcript_path=None) -> dict:
    subcommand, review_ids = call
    if subcommand == "mode":
        return _mode_cli_decision(review_ids, root)
    if subcommand == "bench-config":
        return _bench_config_cli_decision(review_ids, root)
    if subcommand in ("baseline", "git-owners"):
        return _baseline_cli_decision(subcommand, review_ids, root)
    if subcommand == "show":
        return _decision("allow", "Package Guard: read-only review display.")
    if subcommand in ("decline", "undecline", "revoke"):
        # Every verb that changes what may install is a human act: decline is
        # permanent and stamps `declined_by: human` (ungated, it would let an
        # agent blacklist canonical packages on its own), and revoke withdraws
        # an approval a human gave.
        if not review_ids:
            return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: '{subcommand}' requires at least one review id.")
        reports, problems = _load_for_cli(root, review_ids)
        for report in reports:
            label = f"{report['review_id']} ({_label(report['resolved_identity'])})"
            if subcommand == "undecline" and not (
                store.is_review_declined(root, report["review_id"])
                or store.is_declined(root, report["resolved_identity"])
            ):
                problems.append(f"{label} is not declined")
            if subcommand == "revoke" and not store.is_vetted(root, report["resolved_identity"]):
                problems.append(f"{label} is not vetted")
        if problems:
            return _decision(
                "deny",
                f"PACKAGE_GUARD_CLI_REFUSED: cannot {subcommand} — " + " | ".join(problems)
                + ". Remove the offending id(s) and re-run with the rest.",
            )
        render = {"decline": _render_decline, "undecline": _render_undecline,
                  "revoke": _render_revoke}[subcommand]
        return _decision("ask", render(reports))
    if subcommand == "reconcile":
        # `reconcile` only OPENS reviews for packages already on disk: it can
        # write review_required reports and can never write to vetted.json, so
        # the ask-gate it feeds is still the only approval. It runs here rather
        # than in a hook because it makes network calls, and the
        # reconciliation hooks stay free of any network deadline.
        return _decision("allow", "Package Guard: opening reviews for unreviewed packages on disk.")
    if subcommand == "audit":
        # A read-only network verb, like `reconcile`:
        # it re-asks OSV about versions a human already approved and writes
        # only the audit cache. It approves nothing, declines nothing and
        # revokes nothing -- a MAL hit prints the revoke command for a human
        # to run, and that command still shows its own prompt. Nothing here
        # needs approval, so `_GUARD_CLI_HINT` does not name it.
        return _decision("allow", "Package Guard: re-checking the approved set against OSV.")
    if subcommand != "approve":
        return _decision("deny", f"PACKAGE_GUARD_CLI_REFUSED: unknown subcommand {subcommand!r}.")
    if not review_ids:
        return _decision("deny", "PACKAGE_GUARD_CLI_REFUSED: 'approve' requires at least one review id.")
    oversized = _oversized_approve(root, review_ids)
    if oversized:
        return oversized
    loaded, problems = _load_for_cli(root, review_ids)
    reports = []
    for report in loaded:
        rid = report["review_id"]
        if report["verdict"] == "hard_deny":
            findings = "; ".join(report.get("hard_findings") or []) or "deterministic hard denial"
            problems.append(f"{rid} ({_label(report['resolved_identity'])}) is hard-denied: {findings}")
        elif store.is_review_declined(root, rid) or store.is_declined(root, report["resolved_identity"]):
            problems.append(
                f"{rid} ({_label(report['resolved_identity'])}) was declined by the user; never retry it"
            )
        else:
            reports.append(report)
    if problems:
        return _decision(
            "deny",
            "PACKAGE_GUARD_CLI_REFUSED: cannot approve — nothing was vetted. "
            + " | ".join(problems)
            + ". Remove the offending id(s) and re-run approve with the rest.",
        )
    # The vetter's report exists only in the conversation, so the transcript is
    # the one copy this hook can read. No block for an id means the human would
    # be shown a prompt with no research behind it. The verdict itself is not
    # enforced: a DO_NOT_RECOMMEND still reaches the prompt, marked -- but only
    # on a prompt of its own (`_flagged_in_batch`), and a NEEDS_HUMAN_REVIEW
    # only on a prompt without recommended packages (`_mixed_in_batch`).
    # A report whose own evidence put it in the established tier needs no
    # vetter: the facts the vetter would have fetched are in the report, and
    # the prompt renders them.
    verdicts = transcript.vetter_verdicts(transcript_path, reports)
    missing = [
        r["review_id"] for r in reports
        if r["review_id"] not in verdicts and not vetting.is_established(r)
    ]
    if missing:
        return _decision(
            "deny",
            "PACKAGE_GUARD_CLI_REFUSED: cannot approve — no package-vetter verdict in this session for "
            + " ".join(missing)
            + ". Wait for the vetter's notification. If its report arrived without a verdict "
            "for ids that vetter was launched with, load the SendMessage tool first (it is "
            "deferred: ToolSearch with query `select:SendMessage`), then ask the same vetter "
            "(SendMessage to its agent id) to resend its full report with the machine blocks; "
            "launch a new vetter only if that fails. A review id never given to a vetter needs a new "
            "package-vetter launch with that id; do not send it to an existing vetter. "
            "Approve only after a verdict has arrived.",
        )
    flagged = _flagged_in_batch(root, reports, verdicts) or _mixed_in_batch(root, reports, verdicts)
    if flagged:
        return flagged
    # Render what is true now, not what was true at review time.
    refreshed = _refresh_reports(reports)
    abandoned = [rid for rid, found in refreshed.items() if found is None]
    if abandoned:
        return _decision(
            "deny",
            "PACKAGE_GUARD_REVIEW_BUDGET: the approve-time evidence refresh did not finish for "
            + " ".join(abandoned) + ". Nothing was approved; re-run the same approve command.",
        )
    failures, malware, lapsed = [], [], []
    for report in reports:
        found = refreshed[report["review_id"]]
        label = f"{report['review_id']} ({_label(report['resolved_identity'])})"
        for finding in found["hard_findings"]:
            (failures if finding.startswith("mandatory provider failure") else malware).append(
                f"{label}: {finding}")
        # The tier must hold NOW as well as at review time. A
        # package that has since lost it (a deprecation, a new advisory, a
        # download endpoint outage) goes back through the vetter.
        if report["review_id"] not in verdicts and not found["hard_findings"]:
            fresh = {"optional_checks": {"reputation": found.get("reputation")}}
            if not vetting.is_established(fresh):
                unmet = ((found.get("reputation") or {}).get("unmet") or ["reputation not checked"])
                lapsed.append(f"{label}: {'; '.join(unmet)}")
    if lapsed and not malware and not failures:
        return _decision(
            "deny",
            "PACKAGE_GUARD_CLI_REFUSED: cannot approve — the established reputation did not hold at approve time for "
            + " | ".join(lapsed)
            + ". Nothing was approved; launch the package-vetter with these review ids and approve "
            "after its report has arrived.",
        )
    if malware:
        return _decision(
            "deny",
            "PACKAGE_GUARD_DENIED\n" + "\n".join(malware)
            + "\nThe evidence changed since the review was opened; this cannot be approved. "
            "Tell the user and propose an alternative.",
        )
    if failures:
        return _decision(
            "deny",
            "PACKAGE_GUARD_ERROR: the approve-time evidence refresh failed — " + " | ".join(failures)
            + ". Nothing was approved; re-run the same approve command.",
        )
    views = [_refreshed_view(report, refreshed[report["review_id"]]) for report in reports]
    # Again on the live view: a lookalike the registry shows only now.
    flagged = _flagged_in_batch(root, views, verdicts) or _mixed_in_batch(root, views, verdicts)
    if flagged:
        return flagged
    return _decision("ask", _render_approval(views, verdicts))


# ---------------------------------------------------------------------------
# Package command evaluation
# ---------------------------------------------------------------------------

def _fresh_recheck(root, identity: dict, state: dict) -> dict | None:
    """A denial when an approved fresh version fails its OSV re-check.

    None means install as approved: the version is a week old or more, the
    approval predates the evidence fields, or OSV is clean. The approved
    lookup itself stays local; only fresh versions cost a call.
    """
    rid = store.vetted_review_id(root, identity)
    if rid is None:
        return None
    if not (store.reports_dir(root) / f"{rid}.json").exists():
        return None  # no report (a fresh clone: reports/ is not committed)
    try:
        report = store.load_report(root, rid)
    except store.StoreError as exc:
        # A report that exists but cannot be read must not switch the
        # fresh-version re-check off.
        return _decision(
            "deny",
            f"PACKAGE_GUARD_ERROR: the approval report for {_label(identity)} is unreadable "
            f"({exc}); its fresh-version re-check cannot run. Tell the user; do not repair "
            ".claude/package-guard/ yourself.")
    if not vetting.is_fresh_version(report):
        return None
    label = _label(identity)
    if state["done"] >= _RECHECK_MAX:
        return _decision(
            "deny",
            f"PACKAGE_GUARD_REVIEW_BUDGET: {label} is approved but under "
            f"{vetting.FRESH_VERSION_DAYS} days old and this run already re-checked "
            f"{_RECHECK_MAX} such versions. Nothing was installed. Install the fresh versions in "
            "a separate command so each is re-checked against OSV.",
        )
    state["done"] += 1
    try:
        malware = vetting.recheck_malware(identity)
    except vetting.ProviderError as exc:
        return _decision(
            "deny",
            f"PACKAGE_GUARD_ERROR: {label} is approved but under {vetting.FRESH_VERSION_DAYS} days "
            f"old, and its OSV re-check failed ({exc}). Nothing was installed; re-run the command.",
        )
    if malware:
        return _decision(
            "deny",
            f"PACKAGE_GUARD_DENIED\npackage: {label} (review {rid})\n"
            f"OSV now lists malware for this exact version: {', '.join(malware)}. It was approved "
            "before that record existed. Nothing was installed. Tell the user; do not retry this "
            f"version. Withdraw the approval with: {store.cli_command(root, 'revoke', rid)}",
        )
    return None


# ---------------------------------------------------------------------------
# pnpm, Bun and Yarn: one manager per project (design section 4)
#
# A lock the invoked manager does not own is a lock it may silently migrate
# (Bun reads yarn.lock, package-lock.json and pnpm-lock.yaml; Berry migrates a
# Classic lock), and a reviewer reading the wrong lock approves the wrong tree.
# Every rule here applies to pnpm, Bun and Yarn invocations only: npm and npx
# behave exactly as they always have, whatever else sits in the directory.
# ---------------------------------------------------------------------------

_LOCK_FAMILIES = {
    "npm": ("package-lock.json", "npm-shrinkwrap.json"),
    "pnpm": ("pnpm-lock.yaml",),
    "bun": ("bun.lock", "bun.lockb"),
    "yarn": ("yarn.lock",),
}
_NO_LOCK_REMEDY = {
    "pnpm": "Create the lock without installing anything, with scripts off, as its own "
            "command: `pnpm install --lockfile-only --ignore-scripts`.",
    "bun": "Create the lock without installing anything, with scripts off, as its own "
           "command: `bun install --lockfile-only --ignore-scripts`.",
    "yarn": "Create the lock without linking or building anything, as its own "
            "command: `yarn install --mode=update-lockfile`.",
}
_NO_LOCK_REMEDY_CLASSIC = (
    "Yarn Classic cannot create a lock without installing, and an install resolves a tree "
    "nobody reviewed. Add each dependency by name and exact version, after it is reviewed and "
    "approved, inside the app's own folder: `yarn add <name>@<exact version> --ignore-scripts` "
    "(it writes package.json and yarn.lock). Remove a dependency's line from package.json "
    "first if you wrote it there; or ask the user to run `yarn install --ignore-scripts` "
    "themselves, outside this session.")
_PM_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?$")
_YARN_PIN = re.compile(r"^4\.(\d+)\.\d+$")
_YARN_CLASSIC_PIN = re.compile(r"^1\.\d+\.\d+$")
_PM_FIELD = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9._-]*)@(?P<version>[^+\s]+)"
                       r"(?:\+(?P<hash>(?:sha1|sha224|sha256|sha384|sha512)\.[0-9A-Fa-f]+))?$")


def _lock_files(directory) -> dict:
    """family -> the lock files of that family present in `directory`."""
    return {family: [n for n in names if (Path(directory) / n).exists()]
            for family, names in _LOCK_FAMILIES.items()
            if any((Path(directory) / n).exists() for n in names)}


def _declares_dependencies(directory, kind=None) -> bool:
    try:
        return pg_manifest.pm_declares_dependencies(directory, kind)
    except pg_manifest.ManifestError:
        return True


def _declared_package_managers(directory) -> list:
    """[(where, name, version or None)] from package.json's `packageManager` and
    `devEngines.packageManager`. Raises ValueError for any shape not understood."""
    path = Path(directory) / "package.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError(f"package.json cannot be read ({exc})") from None
    if not isinstance(data, dict):
        raise ValueError("package.json is not a JSON object")
    found = []
    field = data.get("packageManager")
    if field is not None:
        match = _PM_FIELD.match(field) if isinstance(field, str) else None
        if match is None:
            raise ValueError(f"packageManager {field!r} is not name@exact-version")
        found.append(("packageManager", match.group("name"), match.group("version")))
    dev = data.get("devEngines")
    if dev is not None:
        if not isinstance(dev, dict):
            raise ValueError("devEngines is not an object")
        entries = dev.get("packageManager")
        if isinstance(entries, dict):
            entries = [entries]
        if entries is not None:
            if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
                raise ValueError("devEngines.packageManager is not an object or a list of objects")
            for entry in entries:
                name, version = entry.get("name"), entry.get("version")
                if not isinstance(name, str) or not name or not (
                        version is None or isinstance(version, str)):
                    raise ValueError("devEngines.packageManager needs a text name and version")
                found.append(("devEngines.packageManager", name, version))
    return found


def _manager_pin(directory, kind, pin_required=True):
    """(problem or None, (npm package, exact version) or None): what package.json
    says about the manager being run (Q15, D7). pnpm and Yarn are downloaded and
    switched to the pinned release, so that release is an acquisition and goes
    through review as an npm package; Bun does not act on the field."""
    try:
        declared = _declared_package_managers(directory)
    except ValueError as exc:
        return f"{exc}; a package manager pin that cannot be read cannot be reviewed", None
    classic = False
    if kind == "yarn":
        flavour = pm_config.yarn_flavour(directory)
        if flavour.conflict:
            return f"{flavour.conflict}", None
        classic = flavour.kind == pm_config.CLASSIC
    pins = set()
    for where, name, version in declared:
        if name != kind:
            return (f"{where} names {name}@{version or '*'} but this command runs {kind}; "
                    "another manager would be fetched or the project is mixed. One manager "
                    "per project."), None
        if kind == "bun":
            continue  # informational
        if version is None or not _PM_VERSION.match(version):
            return (f"{where} {kind}@{version or '(no version)'} is not an exact version; "
                    "a range, tag or URL names no release Package Guard can review"), None
        if kind == "yarn" and classic:
            if _YARN_CLASSIC_PIN.match(version) is None:
                return (f"{where} yarn@{version}: this project is Yarn Classic (1.x); the pin "
                        "must be an exact 1.X.Y"), None
            pins.add(("yarn", version))  # Corepack downloads npm's `yarn` package
        elif kind == "yarn":
            match = _YARN_PIN.match(version)
            if match is None or int(match.group(1)) < 14:
                return (f"{where} yarn@{version}: only Yarn Berry 4.14 or newer, or Yarn Classic "
                        "1.x, is supported (Berry 2.x, 3.x and older 4.x run dependency scripts "
                        "by default)"), None
            pins.add(("@yarnpkg/cli-dist", version))
        else:
            pins.add(("pnpm", version))
    if len(pins) > 1:
        return ("packageManager and devEngines.packageManager name different versions: "
                + ", ".join(sorted(v for _n, v in pins))), None
    if kind == "yarn" and not pins and pin_required and not classic:
        return ("package.json must pin Yarn with packageManager: \"yarn@4.X.Y\" (X >= 14) for "
                "Yarn Berry, or have a v1 yarn.lock (Yarn Classic); without evidence of which, "
                "Corepack or a Yarn on PATH decides which release runs"), None
    return None, (next(iter(pins)) if pins else None)


def _npm_project_problem(directory):
    """A denial when npm would install into a project another manager owns: its lock or
    its package.json pin names pnpm, Bun or Yarn. npm would write package-lock.json
    beside that lock and install a tree resolved from the manifest, which nobody reviewed.
    The reverse (pnpm, Bun or Yarn beside package-lock.json) is `_pm_project_problem`."""
    present = {k: v for k, v in _lock_files(directory).items() if k != "npm"}
    owner = None
    if present:
        kind, files = next(iter(sorted(present.items())))
        owner = f"{kind} ({files[0]})"
    else:
        try:
            declared = _declared_package_managers(directory)
        except ValueError:
            return None  # an unreadable package.json is the manifest gate's PACKAGE_GUARD_ERROR
        for where, name, version in declared:
            if name != "npm":
                owner = f"{name} ({where} {name}@{version or '*'})"
                break
    if owner is None:
        return None
    return _decision(
        "deny",
        f"PACKAGE_GUARD_UNSUPPORTED: {directory} belongs to {owner}. npm would write "
        "package-lock.json beside it and install a tree nobody reviewed. One manager per "
        "project: use the project's own manager, or ask the user to convert the project "
        "outside this session.")


def _pm_project_problem(scope, directory):
    """(denial or None, pin or None, note or None) for one pnpm, Bun or Yarn target.

    Runs before any review is opened: a command refused for its shape must not
    cost the human an approval prompt. Reads the lock completely, so a Classic,
    malformed or unreadable one denies here and never reads as an empty tree."""
    kind = scope.kind
    classic = False
    if kind == "yarn":
        flavour = pm_config.yarn_flavour(directory)
        if flavour.conflict:
            return _decision(
                "deny", f"PACKAGE_GUARD_UNSUPPORTED: {flavour.conflict}. One Yarn per project: "
                "Package Guard will not guess which one runs. Tell the user."), None, None
        classic = flavour.kind == pm_config.CLASSIC
    present = _lock_files(directory)
    if len(present) > 1:
        names = ", ".join(sorted(n for files in present.values() for n in files))
        return _decision(
            "deny",
            f"PACKAGE_GUARD_UNSUPPORTED: one manager per project: {directory} has {names}. "
            "Which lock is authoritative is the manager's choice, and a reviewer who reads "
            "the wrong one approves the wrong tree. Tell the user; do not delete a lock "
            "yourself."), None, None
    try:
        lockless = not present and pg_manifest.no_lock_needed(directory)
    except pg_manifest.ManifestError as exc:
        return _decision(
            "deny",
            f"PACKAGE_GUARD_ERROR: package.json in {directory} could not be read ({exc}). "
            "Nothing was installed."), None, None
    if lockless:
        # B2: a project that declares nothing and has no lock has an empty tree, and no
        # lock can exist for it, so a first `add` must not wait on one.
        problem, pin = _manager_pin(directory, kind)
        if problem:
            return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: {problem}."), None, None
        return None, pin, None
    if kind not in present:
        if present:
            other = next(iter(present.values()))[0]
            return _decision(
                "deny",
                f"PACKAGE_GUARD_UNSUPPORTED: {kind} has no lock in {directory} but {other} is "
                f"there. {kind} may migrate it into a new lock and resolve versions nobody "
                "reviewed. Use the manager the project's lock belongs to, or ask the user to "
                "convert the project outside this session."), None, None
        return _decision(
            "deny",
            f"PACKAGE_GUARD_UNSUPPORTED: {directory} has no {pg_manifest.PM_LOCKFILES[kind]}, so "
            f"the tree this {kind} install would put on disk is not known and cannot be checked. "
            + (_NO_LOCK_REMEDY_CLASSIC if classic else _NO_LOCK_REMEDY[kind])), None, None
    note = None
    if kind == "bun":
        if "bun.lock" not in present["bun"]:
            return _decision(
                "deny",
                "PACKAGE_GUARD_UNSUPPORTED: this project has only bun.lockb, Bun's binary lock, "
                "which Package Guard cannot read. Stop and ask the user to migrate it outside "
                "this session (`bun install --save-text-lockfile --frozen-lockfile "
                "--lockfile-only`, then delete bun.lockb), then re-run the command."), None, None
        if "bun.lockb" in present["bun"]:
            note = "bun.lockb is present beside bun.lock and is ignored"
    try:
        pg_manifest.pm_locked_tree(directory, kind)  # parse and validate it all, now
    except pg_manifest.ManifestError as exc:
        return _decision(
            "deny",
            f"PACKAGE_GUARD_ERROR: the lock for {kind} in {directory} could not be read ({exc}). "
            "Nothing was installed; do not edit the lock yourself, tell the user."), None, None
    problem, pin = _manager_pin(directory, kind)
    if problem:
        return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: {problem}."), None, None
    if classic:
        # A Classic lock need not be closed (HRMS's root one is not): a spec the install would
        # reach and the lock has no entry for is resolved by Yarn itself, from the registry, as
        # whatever is newest in range. Nobody reviewed that.
        try:
            unlocked = pg_manifest.classic_unlocked_specs(directory)
        except pg_manifest.ManifestError as exc:
            return _decision(
                "deny",
                f"PACKAGE_GUARD_ERROR: the lock for yarn in {directory} could not be read ({exc}). "
                "Nothing was installed; do not edit the lock yourself, tell the user."), None, None
        if unlocked:
            shown = "; ".join(f"{spec} (needed by {parent})" for parent, spec in unlocked[:5])
            more = f" and {len(unlocked) - 5} more" if len(unlocked) > 5 else ""
            return _decision(
                "deny",
                f"PACKAGE_GUARD_UNSUPPORTED: yarn.lock in {directory} has no entry for "
                f"{len(unlocked)} dependency specs this install would reach: {shown}{more}. Yarn "
                "would resolve them itself, to versions nobody reviewed. The lock is stale; do "
                "not edit it yourself, tell the user."), None, None
    if kind == "pnpm":
        problem = _pnpm_env_lock_problem(directory, pin)
        if problem:
            return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: {problem}."), None, None
    return None, pin, note


def _pnpm_env_lock_problem(directory, pin, strict=True) -> str | None:
    """pnpm's lock may open with an environment document naming the packages pnpm itself
    fetches before it resolves anything: `packageManagerDependencies` (the pnpm release) and
    `configDependencies` (config packages that run code). Neither is a dependency of the
    project, so no manifest reader lists them and no review saw them (A10): the pnpm
    release, when it is listed at all, must be exactly the reviewed pin, and config dependencies are refused (P3)."""
    path = pg_manifest.pm_lock_path(directory, "pnpm")
    try:
        found = pnpm_lock.env_dependency_sections(path)
    except lock_errors.LockReadError as exc:
        # An install and a `remove` read the whole lock anyway; a run or a read-only verb does
        # not need it, so a lock this reader does not understand is not a reason to refuse it.
        return f"pnpm-lock.yaml cannot be read ({exc})" if strict else None
    config = found.get("configDependencies") or []
    if config:
        names = ", ".join(f"{name}@{version}" for name, version in config[:5])
        return ("pnpm-lock.yaml lists configDependencies, which pnpm downloads and runs before "
                f"resolving anything and no review covers: {names}")
    manager = found.get("packageManagerDependencies") or []
    wanted = [("pnpm", pin[1])] if pin else []
    if manager and sorted(manager) != sorted(wanted):
        listed = ", ".join(f"{name}@{version}" for name, version in manager[:5])
        expected = f"{wanted[0][0]}@{wanted[0][1]}" if wanted else "nothing (package.json pins no pnpm)"
        return ("pnpm-lock.yaml's packageManagerDependencies "
                f"({listed}) is not the reviewed packageManager pin; it must be {expected}")
    return None


def _locked_tree(scope, directory):
    """(ecosystem, [(name, version)], lockfile path) for a gated manifest, or None.

    pnpm, Bun and Yarn read their own lock and nothing else; a lock that is
    missing or unreadable raises ManifestError, never an empty tree."""
    if scope.kind == "npm":
        return "npm", pg_manifest.npm_locked_tree(directory), Path(directory) / "package-lock.json"
    if scope.kind == "uv-project":
        return "pypi", pg_manifest.uv_locked_tree(directory), Path(directory) / "uv.lock"
    if scope.kind in pg_parser.PM_KINDS:
        return (pg_parser.scope_ecosystem(scope.kind),
                pg_manifest.pm_locked_tree(directory, scope.kind),
                pg_manifest.pm_lock_path(directory, scope.kind))
    return None  # a requirements file is already flattened: every line is direct


def _check_transitives(targets, root) -> tuple:
    """(denial or None, notes) for the trees the command installs.

    `targets` pairs each gated scope with a directory it is read from
    (`_scope_directories`). Runs only on the allow path: direct dependencies
    are all vetted, so what lands now is the tree. Vetted and declined
    identities are skipped (they were judged individually); a MAL record on
    anything else denies; other advisories become notes on the allow. Cached
    per lockfile digest.
    """
    import hashlib
    notes = []
    calls = 0
    for scope, directory in targets:
        try:
            tree = _locked_tree(scope, directory)
        except (pg_manifest.ManifestError, lock_errors.LockReadError) as exc:
            return _decision("deny", f"PACKAGE_GUARD_ERROR: the lock for {scope.kind} could not be "
                                     f"read ({exc}). Nothing was installed."), notes
        if tree is None:
            continue
        ecosystem, pairs, lock = tree
        if not pairs:
            if scope.kind in pg_parser.PM_KINDS and _declares_dependencies(directory, scope.kind):
                # The manifest declares dependencies and its lock lists none:
                # the install would resolve a tree nobody reviewed.
                return _decision(
                    "deny",
                    f"PACKAGE_GUARD_ERROR: {lock.name} lists no packages although package.json "
                    f"declares dependencies. Nothing was installed; the lock is stale or empty."), notes
            continue
        registry = "https://registry.npmjs.org" if ecosystem == "npm" else "https://pypi.org"
        candidates = [
            (name, version) for name, version in pairs
            if not store.is_vetted(root, {"ecosystem": ecosystem, "name": name,
                                          "version": version, "registry": registry})
        ]
        if not candidates:
            continue
        try:
            digest = hashlib.sha256(lock.read_bytes()).hexdigest()
        except OSError:
            digest = None
        cached = store.load_transitive_check(root, digest) if digest else None
        if cached and (time.time() - cached.get("checked_at_epoch", 0)) < _TRANSITIVE_CACHE_SECONDS:
            result = cached
        else:
            chunks = [candidates[i:i + vetting.OSV_BATCH_SIZE]
                      for i in range(0, len(candidates), vetting.OSV_BATCH_SIZE)]
            if calls + len(chunks) > _TRANSITIVE_BATCH_CALLS:
                return _decision(
                    "deny",
                    f"PACKAGE_GUARD_REVIEW_BUDGET: {lock.name} lists {len(candidates)} unvetted "
                    f"packages, more than the {_TRANSITIVE_BATCH_CALLS * vetting.OSV_BATCH_SIZE} one "
                    "run can check against OSV. Nothing was installed.",
                ), notes
            advisories = {}
            try:
                for chunk in chunks:
                    calls += 1
                    for pair, ids in vetting.query_osv_batch(ecosystem, chunk).items():
                        if ids:
                            advisories[f"{pair[0]}@{pair[1]}"] = ids
            except vetting.ProviderError as exc:
                return _decision(
                    "deny",
                    f"PACKAGE_GUARD_ERROR: the OSV check of {lock.name}'s {len(candidates)} "
                    f"transitive packages failed ({exc}). Nothing was installed; re-run the command.",
                ), notes
            result = {"checked_at": store.utcnow(), "checked_at_epoch": time.time(),
                      "packages": len(candidates), "advisories": advisories}
            if digest:
                store.record_transitive_check(root, digest, result)
        malware = {pkg: [i for i in ids if i.startswith("MAL-")]
                   for pkg, ids in (result.get("advisories") or {}).items()}
        malware = {pkg: ids for pkg, ids in malware.items() if ids}
        if malware:
            lines = [f"  {pkg}: {', '.join(ids)}" for pkg, ids in sorted(malware.items())]
            return _decision(
                "deny",
                f"PACKAGE_GUARD_DENIED\n{lock.name} would install a package with an OSV malware "
                "record:\n" + "\n".join(lines)
                + "\nNothing was installed. This is a transitive dependency: tell the user, and "
                "find which direct dependency pulls it in before changing anything.",
            ), notes
        others = {pkg: ids for pkg, ids in (result.get("advisories") or {}).items()
                  if any(not i.startswith("MAL-") for i in ids)}
        note = (f"{lock.name}: {result.get('packages', len(candidates))} transitive packages checked "
                f"against OSV ({'cached' if result is cached else 'live'})")
        if others:
            note += "; advisories on " + ", ".join(
                f"{pkg} ({', '.join(ids)})" for pkg, ids in sorted(others.items())[:10])
            if len(others) > 10:
                note += f" and {len(others) - 10} more"
        notes.append(note)
    return None, notes


def _label_key(label: str):
    """`npm:@scope/x@1.0.0` -> ("npm", "@scope/x")."""
    ecosystem, _, rest = label.partition(":")
    name = rest[0] + rest[1:].rpartition("@")[0] if "@" in rest[1:] else rest
    return ecosystem, name


def _audit_vetted(root, relevant=None) -> tuple:
    """(denial or None, notes) for the approved set itself.

    Runs on the allow path, beside _check_transitives. The approved lookup
    stays local; this sits AFTER it and asks a different
    question: has anything a human already approved since become malware. A
    MAL record denies and names the revoke command; other advisories become a
    note on the allow. Cached per vetted.json digest, so the cost is one batch
    call a day, not one per install.
    """
    try:
        entries = store.load_vetted(root)["packages"]
    except store.StoreError as exc:
        return _decision(
            "deny",
            f"PACKAGE_GUARD_ERROR: the approved set could not be read for its OSV audit ({exc}). "
            "Nothing was installed.",
        ), []
    plan = vetting.audit_batches(entries)
    if not plan:
        return None, []
    checked = sum(len(chunk) for _ecosystem, chunk in plan)
    digest = store.vetted_digest(root)
    cached = store.load_transitive_check(root, digest) if digest else None
    if cached and (time.time() - cached.get("checked_at_epoch", 0)) < _AUDIT_CACHE_SECONDS:
        result = cached
    else:
        per_ecosystem = {}
        for ecosystem, _chunk in plan:
            per_ecosystem[ecosystem] = per_ecosystem.get(ecosystem, 0) + 1
        if max(per_ecosystem.values()) > _AUDIT_CALLS:
            return _decision(
                "deny",
                f"PACKAGE_GUARD_REVIEW_BUDGET: the approved set holds {checked} versions, more "
                f"than the {_AUDIT_CALLS * vetting.OSV_BATCH_SIZE} per ecosystem one run can "
                "re-check against OSV. Nothing was installed. Audit it in its own command: "
                f"{store.cli_command(root, 'audit', '')}".rstrip(),
            ), []
        try:
            advisories, _calls = vetting.audit_vetted(entries)
        except vetting.ProviderError as exc:
            return _decision(
                "deny",
                f"PACKAGE_GUARD_ERROR: the OSV audit of the {checked} approved versions failed "
                f"({exc}). Nothing was installed; re-run the command.",
            ), []
        result = {"checked_at": store.utcnow(), "checked_at_epoch": time.time(),
                  "packages": checked, "advisories": advisories}
        if digest:
            store.record_transitive_check(root, digest, result)
    found = result.get("advisories") or {}
    malware = {label: [i for i in ids if i.startswith("MAL-")] for label, ids in found.items()}
    malware = {label: ids for label, ids in malware.items() if ids}
    if malware:
        # The review id comes from the vetted entry itself, not from a rebuilt
        # identity: the entry carries the registry it was approved against and
        # guessing one would silently miss a private registry.
        by_label = {
            f"{e.get('ecosystem')}:{e.get('name')}@{e.get('version')}": e
            for e in entries if isinstance(e, dict)
        }
        lines, fixes = [], []
        for label, ids in sorted(malware.items()):
            entry = by_label.get(label) or {}
            identity = {k: entry.get(k) for k in
                        ("ecosystem", "name", "version", "registry")}
            rid = store.vetted_review_id(root, identity)
            lines.append(f"  {label} (review {rid or 'not recorded'}): {', '.join(ids)}")
            fixes.append(
                f"  {store.cli_command(root, 'revoke', rid)}" if rid else
                f"  no review id is recorded for {label} in vetted.json; ask the user to "
                "remove the approval"
            )
        return _decision(
            "deny",
            "PACKAGE_GUARD_DENIED\nOSV now lists malware for a version this project has already "
            "approved:\n" + "\n".join(lines)
            + "\nIt was approved before that record existed. Nothing was installed. Tell the user, "
            "and withdraw the approval with:\n" + "\n".join(fixes),
        ), []
    others = {label: ids for label, ids in found.items()
              if any(not i.startswith("MAL-") for i in ids)}
    count = result.get("packages", checked)
    note = (f"vetted set audited ({'cached' if result is cached else 'live'}): "
            f"{count} entr{'y' if count == 1 else 'ies'}")
    # Advisories on approved packages this command does not touch, relayed on
    # every allow, would teach the reader to skip the line that matters. They
    # become a count and a command; malware above still denies regardless.
    unrelated = {}
    if relevant is not None:
        unrelated = {label: ids for label, ids in others.items()
                     if _label_key(label) not in relevant}
        others = {label: ids for label, ids in others.items() if label not in unrelated}
    if unrelated:
        note += (f"; {len(unrelated)} other approved package{'s' if len(unrelated) != 1 else ''} "
                 "this command does not install have known advisories (list them with "
                 f"{store.cli_command(root, 'audit', '')})".rstrip())
    if others:
        note += "; advisories on " + ", ".join(
            f"{label} ({', '.join(ids)})" for label, ids in sorted(others.items())[:10])
        if len(others) > 10:
            note += f" and {len(others) - 10} more"
    return None, [note]


def _deferred_note(deferred: int) -> str:
    return (
        f"{deferred} more package{' was' if deferred == 1 else 's were'} not reviewed in this run "
        f"(at most {_REVIEW_BATCH} new reviews per run, named or from a manifest, within a "
        f"{int(_REVIEW_BUDGET_SECONDS)}s budget). Nothing was installed. Reviews already opened are "
        "reused without network, so re-running the same install after approval reviews the rest."
    )


def _render_review_required(reports, root, deferred: int = 0) -> str:
    """One block per package, then the next action.

    The next action depends on the tier: an
    established id goes straight to the approve prompt, an unresolved id goes
    to the vetter first. Both paths are spelled out so the agent never has to
    infer one from the other.
    """
    blocks = ["PACKAGE_GUARD_REVIEW_REQUIRED"]
    established, unresolved = [], []
    for report in reports:
        identity = report["resolved_identity"]
        tier = "established" if vetting.is_established(report) else "unresolved"
        (established if tier == "established" else unresolved).append(report)
        blocks += [
            f"review_id: {report['review_id']}",
            f"package: {_label(identity)}",
            "reason: Exact version is not vetted for this project.",
            *_cooldown_note(report),
            f"reputation: {tier}",
        ]
        if (report.get("request") or {}).get("operation") == "manager-pin":
            blocks.append(
                "note: this is the project's pinned package manager (package.json "
                "`packageManager`); it is downloaded and run before anything else. Approving "
                "it does not install it anywhere in the project.")
        if report.get("retry_command"):
            blocks.append(f"retry: {report['retry_command']}")
    unresolved_ids = " ".join(r["review_id"] for r in unresolved)
    established_ids = " ".join(r["review_id"] for r in established)
    blocks += [
        "",
        "STOP. Do not run any other install, npx, pip, or uv package command.",
    ]
    split = (f"At most {_APPROVE_BATCH_MAX} ids fit one approve, so run these one after another, "
             "each exactly as written and as a simple standalone command (no `cd`, no `&&`)")
    if established:
        commands = _approve_commands(root, [r["review_id"] for r in established])
        intro = (
            f"ESTABLISHED ids [{established_ids}]: recommended, and approved first. The hook's own "
            "checks hold (age, releases, weekly "
            "downloads, repository manifest, no near-name giant, no install script, no advisory, "
            "not fresh unless an attested release continues its publisher). No vetter is needed. "
            "State in one line per package whether "
            "it is the mainstream choice for its purpose and name a successor if you know one, then ")
        blocks += ([intro + "run ONE approve command with these ids, exactly as written and as a "
                    f"simple standalone command (no `cd`, no `&&`): {commands[0]}"]
                   if len(commands) == 1 else
                   [intro + f"approve them. {split}:", _command_lines(commands)])
    if unresolved:
        # The hook's own near-name signal is known now; the vetter's verdicts
        # are not. A lookalike id is kept out of the batch command, because
        # approve refuses it next to any other id.
        alone = [r["review_id"] for r in unresolved if _lookalike_of(r)]
        batch = [r["review_id"] for r in unresolved if not _lookalike_of(r)]
        blocks += [
            ("NEXT ACTION (mandatory)" if not established else "UNRESOLVED ids, in parallel")
            + ": Agent tool -> subagent_type: package-vetter, ONCE, passing all "
            f"review ids [{unresolved_ids}], the intended purpose of each package, and the requirement.",
            # The vetter inherits the session's working directory, which is a
            # subdirectory as soon as the agent cd-s into the app. A relative reports
            # path would resolve under that subdirectory and the vetter would report
            # "report not found" on a package it never read: hand over the
            # absolute path rather than one the reader must rebuild.
            f"Tell it each report is at {store.reports_dir(root)}/<review-id>.json -- pass that "
            "absolute path; it must not rebuild it from its own working directory.",
        ]
        if batch:
            # The verdicts are not known yet, so the order is given, not the ids.
            blocks += [
                "THEN approve in this order, never both kinds in one approve, each exactly as "
                "written with the ids filled in and as a simple standalone command (no `cd`, no "
                f"`&&`), at most {_APPROVE_BATCH_MAX} ids per approve:",
                "  1. the RECOMMEND ids, together: "
                + store.cli_command(root, "approve", "<RECOMMEND ids>"),
                "  2. then the NEEDS_HUMAN_REVIEW ids, together: "
                + store.cli_command(root, "approve", "<NEEDS_HUMAN_REVIEW ids>"),
                "Before step 2, give the user ONE short chat line per NEEDS_HUMAN_REVIEW package: "
                "its red flags in plain words and the risk they carry first, then your suggestion "
                "(use the alternative the vetter named, or approve only if the user needs this "
                "exact package; never a plain 'approve it'), then "
                "run it without waiting for a reply: its prompt shows each reason in plain words "
                "and your suggestion, and the prompt is the question. A DO_NOT_RECOMMEND or "
                "TYPO_SQUAT id gets no approve command.",
            ]
        if alone:
            blocks.append(
                f"LOOKALIKE ids [{' '.join(alone)}]: the hook found each name one edit from a package "
                "with far more downloads, so none goes in an approve command above.")
        blocks.append(
            "Approve is refused for an unresolved id until the vetter's notification has arrived, "
            "and for recommended and NEEDS_HUMAN_REVIEW ids together. For DO_NOT_RECOMMEND, a "
            "TYPO_SQUAT red flag or a LOOKALIKE id, tell the user in one short message and offer "
            "the alternative the vetter named; run a separate approve for that id only if the user "
            "explicitly asks to approve it anyway. Approve refuses such an id together with any "
            "other id.")
    blocks.append("Retry the install only after approval, using the exact 'retry' versions above.")
    if deferred:
        blocks += ["", _deferred_note(deferred)]
    return "\n".join(blocks)


def _render_deferred_only(deferred: int) -> str:
    """Every review this run attempted was abandoned; nothing to approve yet."""
    return "\n".join([
        "PACKAGE_GUARD_REVIEW_BUDGET",
        _deferred_note(deferred),
        "Re-run the same install command now. If this repeats, the registry or OSV is slow: "
        "wait and retry rather than working around the guard.",
    ])


def _render_declined(reports, root) -> str:
    lines = ["PACKAGE_GUARD_DECLINED"]
    for report in reports:
        lines.append(f"package: {_label(report['resolved_identity'])} (review {report['review_id']})")
    ids = " ".join(r["review_id"] for r in reports)
    lines.append(
        "The user already declined this exact version. Never retry it. "
        "Propose an alternative package or ask the user how to proceed. Only the user can "
        f"reverse a decline, and only through the prompt shown by: {store.cli_command(root, 'undecline', ids)}"
    )
    return "\n".join(lines)


def _render_hard_deny(reports) -> str:
    lines = ["PACKAGE_GUARD_DENIED"]
    for report in reports:
        identity = report["resolved_identity"]
        lines.append(f"package: {identity['ecosystem']}:{identity['name']}@{identity['version']}")
        for finding in report.get("hard_findings") or []:
            lines.append(f"finding: {finding}")
    lines.append("This denial is deterministic and cannot be approved through Package Guard.")
    return "\n".join(lines)


def _advance_watermark(event: dict, root, environments=None) -> None:
    """Decide on everything already installed, before this command runs.

    After this, whatever the command puts on disk is attributable
    to *that* command rather than to the accumulated past, which is what makes
    the PostToolUse report readable. `environments` maps the command's
    directory to the Python environments it names (`_command_environments`).

    Fails SOFT, and that is structural rather than a judgement call: the
    PostToolUse scan re-derives the same set from the same filesystem
    afterwards, so a failed advance costs attribution quality and never
    detection. Failing closed here would deny every Bash command in the
    project -- including the removal commands and the guard's own CLI -- and
    the guard must never make its own fix unreachable.
    """
    try:
        return disk_guard.reconcile(
            root,
            project_root=root,
            detected_by="PreToolUse",
            session_id=event.get("session_id"),
            command=(event.get("tool_input") or {}).get("command") or None,
            session_started=transcript.session_started(event.get("transcript_path")),
            environments=environments,
        )
    except Exception as exc:  # noqa: BLE001 - see the docstring
        print(
            f"Package Guard: disk reconciliation could not advance "
            f"({exc.__class__.__name__}: {exc}); the PostToolUse scan still runs.",
            file=sys.stderr,
        )
        # No disk view. Every caller must read this as "unknown", never as
        # "nothing is installed".
        return None


def _command_environments(parsed, event: dict, root) -> dict | None:
    """{project directory: [environment, ...]} for the Python environments a
    command names (a literal UV_PROJECT_ENVIRONMENT, or VIRTUAL_ENV used by
    `uv --active` / `uv pip`), or None. Keyed by the uv project the command
    acts on (`_python_project`), which is the scope reconciliation reads."""
    if parsed is None or parsed.kind != "package" or not parsed.environments:
        return None
    return {str(_python_project(parsed, event.get("cwd") or root, root)): list(parsed.environments)}


def _inside_guard_dir(root, path) -> bool:
    """True when `path` resolves into the project's `.claude/`: through any
    symlink, in any letter case, or by any other spelling of the same
    directory.

    A case-insensitive volume (APFS, NTFS) opens `.CLAUDE` as `.claude`, and
    realpath keeps the case it was given, so the paths are compared
    case-folded. Then by device and inode along every ancestor of the target
    that exists, which no spelling can get past."""
    guard = os.path.realpath(Path(root) / ".claude")
    target = os.path.realpath(path)
    folded_guard = os.path.normcase(guard).casefold()
    folded = os.path.normcase(target).casefold()
    if folded == folded_guard or folded.startswith(folded_guard + os.sep):
        return True
    try:
        guard_stat = os.stat(guard)
    except OSError:
        return False
    for candidate in (Path(target), *Path(target).parents):
        try:
            if os.path.samestat(os.stat(candidate), guard_stat):
                return True
        except OSError:
            continue
    return False


def _record_environments(parsed, directory, root) -> str | None:
    """Remember the environments an allowed command installs into, under the
    project directory it acts on, so every later scan of that project reads
    them even when the next command does not name them.

    Returns the store's reason when it refuses the record (a string from
    `store.record_environments`): the command is then denied, because an
    environment no scan will read is an install nobody reconciles. Any other
    failure is soft: the project's own `.venv` is read regardless."""
    if not parsed.environments:
        return None
    try:
        result = store.record_environments(root, directory, list(parsed.environments))
    except Exception as exc:  # noqa: BLE001 - a lost record costs scan coverage, not the gate
        print(f"Package Guard: could not record the environment "
              f"({exc.__class__.__name__}: {exc}).", file=sys.stderr)
        return None
    return result if isinstance(result, str) and result else None


def _render_pin_approved(approved, heading: bool) -> str:
    """Name the approved version and the pinned command; no approve."""
    if not approved:
        return ""
    lines = ([store.MESSAGE_PIN_APPROVED + ": already approved for this project at the version "
              "this name resolves to. Nothing needs approving; run the install pinned, "
              "exactly as written:"] if heading
             else ["", "Already approved, no review needed; pin them in the retry:"])
    for report in approved:
        lines.append(f"- {_label(report['resolved_identity'])}  retry: {report['retry_command']}")
    return "\n".join(lines)


def _cooldown_note(report) -> list:
    """Say which release was passed over, and how to ask for it."""
    cooldown = (report.get("evidence") or {}).get("cooldown")
    if not isinstance(cooldown, dict):
        return []
    identity = report["resolved_identity"]
    return [
        f"note: {identity['name']} {cooldown['latest']} is the latest release but is "
        f"{cooldown['latest_age_days']} day(s) old with no provenance attestation, so this review "
        f"is for {cooldown['chosen']}, the newest release at least {cooldown['min_age_days']} days "
        f"old. Install {cooldown['chosen']} unless the user needs {cooldown['latest']}; to review "
        f"{cooldown['latest']} instead, name that exact version.",
    ]


def _unspent_approvals(root, installed, parsed, session_id, covered=()) -> list:
    """Identities THIS session approved and never put on disk.

    The mirror image of reconciliation. That layer asks "is anything installed
    that no human approved"; this one asks "did an approval the human gave go
    unspent". Both are read-only, and only this one is advisory: the guard must
    never deny over a package the human already said yes to.

    Session-scoped on purpose. An older project's approvals are a legitimate
    steady state -- a package removed, a tool used through `npx` and evicted
    from the cache -- and naming them on every allow would be a backlog nobody
    asked for. The case that matters is narrower: an approval given minutes
    ago, in this turn, that the pinned retry never spent.

    `installed is None` means the watermark advance failed, so there is no disk
    view; that reads as unknown and names nothing. `covered` carries the
    (ecosystem, name) pairs a gated manifest declares, so the command that is
    about to install them does not report them as unspent.
    """
    if installed is None or not session_id:
        return []
    on_disk = {(p.ecosystem, p.name, p.version) for p in installed}
    touched = {(r.ecosystem, r.name) for r in parsed.requests} | set(covered)
    labels = []
    for entry in store.load_vetted(root)["packages"]:
        identity = (entry["ecosystem"], entry["name"], entry["version"])
        if identity in on_disk or identity[:2] in touched:
            continue
        # Read the report only for the few that survived the cheap filters: the
        # steady state is zero, and this runs on every allowed package command.
        try:
            report = store.load_report(root, entry.get("review_id") or "")
        except store.StoreError:
            continue
        if report.get("session_id") == session_id:
            labels.append("%s:%s@%s" % identity)
    return sorted(labels)


def _unreviewed_on_disk(findings, root) -> dict:
    """A package op is refused while findings stand."""
    count = len(findings)
    header = (
        f"{count} direct dependenc{'y is' if count == 1 else 'ies are'} installed in this "
        "project that no human approved, so package operations are blocked until "
        f"{'it is' if count == 1 else 'they are'} resolved. Package Guard found "
        f"{'it' if count == 1 else 'them'} on disk rather than in a command."
    )
    return _decision(
        "deny",
        disk_guard.render_block(
            findings, root, header=header,
            declined_check=lambda identity: store.is_declined(root, identity),
        ),
    )


_EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")


def _powershell_refusal() -> dict:
    return _decision(
        "deny",
        "PACKAGE_GUARD_UNSUPPORTED: Package Guard cannot inspect PowerShell commands, so it "
        "cannot tell whether this one installs a package. Run the command through the Bash "
        "tool (Git Bash) instead. To make Claude Code use Bash and not PowerShell, set "
        "CLAUDE_CODE_USE_POWERSHELL_TOOL=0.")


def _edit_protected(root) -> list:
    """Absolute paths a plugin-mode guard keeps the agent's file tools out of."""
    home = str(Path.home())
    roots = {os.path.normpath(str(root)), os.path.realpath(str(root))}
    paths = [os.path.join(home, ".config", "package-guard")]
    for base in roots:
        paths += [os.path.join(base, ".claude", "package-guard"),
                  os.path.join(base, ".claude", "settings.json"),
                  os.path.join(base, ".claude", "settings.local.json")]
        paths += [os.path.join(base, p) for p in _SOURCE_PATHS]
    if store.plugin_root():
        paths.append(store.plugin_root())
        paths.append(os.path.normpath(os.environ["CLAUDE_PLUGIN_ROOT"]))
    if pg_parser.FRAPPE_ENABLED:
        paths += [str(p) for p in bench_config.recorded_paths(root)]
    return paths


def _edit_hits(candidate: str, protected: list) -> bool:
    # Lexical and resolved forms, compared case-insensitively: macOS and
    # Windows volumes are, and `.Claude/Package-Guard` is the same directory.
    forms = {os.path.normpath(candidate).casefold(), os.path.realpath(candidate).casefold()}
    for path in protected:
        for prot in {os.path.normpath(path).casefold(), os.path.realpath(path).casefold()}:
            if any(f == prot or f.startswith(prot.rstrip(os.sep) + os.sep) for f in forms):
                return True
    # The same file under another name: a bind mount, a hard link, or a case
    # spelling the volume treats as equal that casefolding missed.
    probe = os.path.realpath(candidate)
    try:
        info = os.stat(probe)
    except OSError:
        info = None
    if info is not None and os.path.isfile(probe) and info.st_nlink > 1:
        seen = 0
        for path in protected:
            for here, _dirs, files in os.walk(path):
                for name in files:
                    seen += 1
                    try:
                        if seen > 20000 or os.path.samestat(info, os.stat(os.path.join(here, name))):
                            return True
                    except OSError:
                        continue
    while True:
        for path in protected:
            try:
                if os.path.exists(probe) and os.path.exists(path) and os.path.samefile(probe, path):
                    return True
            except OSError:
                continue
        parent = os.path.dirname(probe)
        if parent == probe:
            return False
        probe = parent


def _edit_decision(event: dict, root) -> dict | None:
    """Plugin mode's lock: the file tools may not touch the guard's own files or
    the approval state, which a plugin cannot protect with permission rules."""
    tool_input = event.get("tool_input")
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    named = [tool_input[k] for k in ("file_path", "notebook_path") if k in tool_input]
    refusal = _decision(
        "deny",
        "PACKAGE_GUARD_UNSUPPORTED: this file is part of Package Guard (its approval state under "
        ".claude/package-guard/, the user's trust catalog, .claude/settings*.json or the guard "
        "and plugin files themselves). Only the human changes it, outside Claude. Do not look for "
        "another way: stop and tell the user what you were asked and that this is theirs to do.")
    if not named or not all(isinstance(n, str) and n for n in named):
        return refusal  # a path the hook cannot read is not one it can clear
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) and event.get("cwd") else str(root)
    try:
        protected = _edit_protected(root)
        for raw in named:
            candidates = [os.path.join(cwd, raw)]
            if raw == "~" or raw.startswith(("~/", "~\\")):
                candidates.append(os.path.expanduser(raw))
            if any(_edit_hits(c, protected) for c in candidates):
                return refusal
    except (OSError, ValueError):
        return refusal
    return None


def _resolve_only_denial(parsed, event, root):
    """A command that only resolves and writes a lock acquires nothing, so it is
    `ignore`. npm's (`--package-lock-only`, `--dry-run`) is only refused in a
    project another manager owns. A pnpm, Bun or Yarn one still runs where the
    manager's configuration says: a Yarn `yarnPath` or plugin, a `.pnpmfile.cjs`,
    a registry redirect. The same source checks run,
    on the project as it stands; the lock does not exist yet, so none is
    required. Berry has no `--ignore-scripts`: a root `preinstall`/`install`/
    `postinstall`/`prepare` script is refused for `--mode=update-lockfile`."""
    cwd = event.get("cwd") or root
    problems, scripts = [], []
    for kind in parsed.resolve_only:
        scope = pg_parser.ManifestScope(kind, scripts=False)
        if kind == "npm":
            # `npm install --package-lock-only --ignore-scripts` / `--dry-run`: the
            # hatch for an unpinned manifest, so it stays allowed in an npm project
            # and is not source-checked (npm reads no code-running configuration).
            # Only one-manager-per-project applies: in a project pnpm, Bun or Yarn
            # owns it would write package-lock.json beside that lock.
            for directory in _scope_directories(scope, cwd, root):
                denial = _npm_project_problem(directory)
                if denial:
                    return denial
            continue
        targets = [(scope, directory) for directory in _scope_directories(scope, cwd, root)]
        outside = _outside_project(targets, cwd, root)
        if outside:
            return outside
        for _scope, directory in targets:
            # One manager per project: a lock-writing command beside another
            # manager's lock may migrate it (Bun reads yarn.lock, Berry a Classic
            # lock). A directory with no lock at all is the case this form is for.
            present = _lock_files(directory)
            if present and set(present) != {kind}:
                denial, _pin, _note = _pm_project_problem(scope, directory)
                if denial:
                    return denial
            if kind == "yarn" and pm_config.yarn_flavour(directory).kind == pm_config.CLASSIC:
                return _decision(
                    "deny", f"PACKAGE_GUARD_UNSUPPORTED: `yarn install --mode=update-lockfile` is "
                    f"a Yarn Berry command and {directory} is a Yarn Classic project, which has no "
                    "way to write a lock without installing. Ask the user to refresh yarn.lock "
                    "themselves, outside this session.")
            if kind == "yarn":
                scripts += [f"{Path(directory) / 'package.json'}: `{name}`"
                            for name, _body in pg_manifest.npm_root_lifecycle_scripts(directory)]
        synthetic = dataclasses.replace(parsed, kind="package", manifests=(scope,))
        problems += _source_problems(synthetic, targets, cwd, root)
    if scripts:
        return _decision("deny", (
            "PACKAGE_GUARD_UNSUPPORTED: `yarn install --mode=update-lockfile` may run the root "
            "project's own install-time scripts, and Yarn has no --ignore-scripts to turn them "
            f"off: {', '.join(scripts)}. Ask the user to create or refresh yarn.lock outside this "
            "session, or to remove those scripts."))
    problems = list(dict.fromkeys(problems))
    if problems:
        return _decision("deny", _render_alternate_source(problems))
    return None


def _bun_autoinstall_problem(cwd, directory, root) -> str | None:
    """Why `bun run` / `bun test` / `bun <file>` could install packages unreviewed,
    or None. With no node_modules in the shell's directory or an ancestor inside
    the guard root, Bun resolves what the code imports from the registry at run
    time, `latest` when unpinned. A node_modules outside the guard root does not
    count: it is not one this guard reviewed. Bun reads `bunfig.toml` from the
    directory it runs in, so `[install] auto = "disable"` counts only there."""
    if pm_config.bun_auto_install_disabled(cwd, sources.HOME):
        return None
    if any((candidate / "node_modules").is_dir() for candidate in _upward(cwd, root)):
        return None
    return ("with no node_modules here Bun installs the packages this code imports at run "
            "time, unpinned and unreviewed. Run `bun install` first, as its own reviewed "
            "command (put `--no-install` BEFORE the script or file name to run only what is "
            "already installed: after it the flag belongs to the script), or have the user "
            "set `[install] auto = \"disable\"` in bunfig.toml")


def _yarn_install_state_problem(directory) -> str | None:
    """The install state of the project's Yarn: Berry's `yarn run` checks it and refuses to
    run when stale, and does not install by itself (UNVERIFIED), so a project without one has
    nothing installed that was reviewed. Classic writes `node_modules/.yarn-integrity`."""
    base = Path(directory)
    if pm_config.yarn_flavour(directory).kind == pm_config.CLASSIC:
        marker = ".yarn-integrity"
    else:
        marker = ".yarn-state.yml"
    if (base / "node_modules").is_dir() and (base / "node_modules" / marker).is_file():
        return None
    return (f"there is no installed state here (node_modules/{marker}): run `yarn install` "
            "first, as its own reviewed command")


# Yarn Berry and Yarn Classic share the `yarn` head and differ in which words are builtins. A word
# that is not a builtin of the project's Yarn runs a package.json script of that name instead,
# which the gate does not read.
_YARN_CLASSIC_WORDS = frozenset({
    "", "install", "add", "upgrade", "remove", "run", "why", "info", "bin", "help", "config",
    "list", "ls", "outdated", "licenses", "check", "audit", "versions", "cache", "print"})
_YARN_CLASSIC_ONLY = frozenset({"upgrade", "list", "ls", "outdated", "licenses", "check", "audit",
                                "versions", "cache"})
_CLASSIC_ALLOWED_FLAGS = None  # built lazily from the parser's tables


def _classic_allowed_flags():
    global _CLASSIC_ALLOWED_FLAGS
    if _CLASSIC_ALLOWED_FLAGS is None:
        _CLASSIC_ALLOWED_FLAGS = (pg_parser.YARN_CLASSIC_FLAGS | pg_parser._YARN_SAVE_FLAGS) \
            - {"--mode"}
    return _CLASSIC_ALLOWED_FLAGS


def _yarn_word_denial(flavour, word, flags, directory) -> dict | None:
    """A denial when the verb word or a flag is not one the project's Yarn knows. `flavour` is
    `pm_config.yarn_flavour(directory)`. Berry's own rules are unchanged; a Classic-only word or
    flag on Berry, and a Berry-only one on Classic, are refused rather than guessed at."""
    if flavour.kind == pm_config.CLASSIC:
        if word and word not in _YARN_CLASSIC_WORDS:
            return _decision("deny", (
                f"PACKAGE_GUARD_UNSUPPORTED: `yarn {word}` is not a Yarn Classic command ({directory} "
                "is a Yarn Classic project): Classic would run a package.json script of that name "
                "instead, which Package Guard does not read. Use `yarn run <script>`."))
        bad = [f for f in flags if f not in _classic_allowed_flags()]
        if bad:
            return _decision("deny", (
                f"PACKAGE_GUARD_UNSUPPORTED: {', '.join(bad)} is not a Yarn Classic flag "
                f"({directory} is a Yarn Classic project)."))
    elif flavour.kind == pm_config.BERRY or flavour.kind is None:
        if word in _YARN_CLASSIC_ONLY:
            return _decision("deny", (
                f"PACKAGE_GUARD_UNSUPPORTED: `yarn {word}` is a Yarn Classic command, and {directory} "
                "is not a Yarn Classic project (no v1 yarn.lock, no yarn@1 pin): Yarn would run a "
                "package.json script of that name instead. Use `yarn run <script>`."))
        bad = [f for f in flags if f in pg_parser.YARN_CLASSIC_FLAGS - pg_parser.YARN_BERRY_FLAGS]
        if bad:
            hint = (" (Yarn Berry has no --ignore-scripts; use --mode=skip-build)"
                    if "--ignore-scripts" in bad else "")
            return _decision("deny", (
                f"PACKAGE_GUARD_UNSUPPORTED: {', '.join(bad)} is a Yarn Classic flag and {directory} "
                f"is not a Yarn Classic project{hint}."))
    return None


def _yarn_classic_config(scope, directory, cwd, command):
    """(ClassicConfig, denial) for a Classic command: the effective configuration, computed with
    what the shell gives the command (an inline YARN_IGNORE_SCRIPTS=true, the PATH it sets) and
    with the rc files counted only when the `yarn` that will run is shown to be Yarn Classic. A
    Classic lock does not prove the executable is Classic: a Berry binary on PATH migrates the
    lock and runs the root scripts, ignoring every Classic rc key. The executable is found, never
    run (`pm_config.yarn_executable`). A known Berry denies; one that cannot be established leaves
    only `--frozen-lockfile` and `--ignore-scripts` on the command, which Berry rejects."""
    facts = dict(scope.env)
    environ = dict(os.environ)
    if facts.get("YARN_IGNORE_SCRIPTS") == "true":
        environ["YARN_IGNORE_SCRIPTS"] = "true"
    path_value = facts["PATH"] if "PATH" in facts else os.environ.get("PATH", "")
    pin = None
    try:
        pin = next((v for _w, n, v in _declared_package_managers(directory) if n == "yarn" and v), None)
    except ValueError:
        pass
    exe = pm_config.yarn_executable(facts.get("head", "yarn"), path_value, cwd, pin)
    if exe.major is not None and exe.major != 1:
        return None, _decision("deny", (
            f"PACKAGE_GUARD_UNSUPPORTED: {directory} is a Yarn Classic project, but the `yarn` that "
            f"would run is Yarn {exe.version} ({exe.why}). It would migrate yarn.lock and install "
            "versions nobody reviewed. Use the project's Yarn Classic, or ask the user."))
    config = pm_config.yarn_classic_config(cwd, sources.HOME, environ, command, scope.flags,
                                           trust_rc=exe.major == 1, untrusted_why=
                                           f"the `yarn` that would run is not shown to be Yarn Classic ({exe.why})")
    return config, None


def _yarn_install_denial(scope, directory, cwd) -> dict | None:
    """The checks a Yarn install, add or upgrade needs beyond the lock and the pin, once the
    project's Yarn is known.

    Berry: a Classic-only verb or flag is refused. Classic (v1): the verb is a Classic one, every
    flag is Classic's, scripts are PROVEN off for this command and the lock is PROVEN frozen for
    a bare install, from the command line and the `.yarnrc` files and environment Yarn reads in
    its own order. Cross-flavour proofs never count: Berry's `--mode=skip-build` and
    `enableScripts: false` mean nothing to Yarn Classic. `add` and `upgrade` rewrite the lock by
    design, so `--frozen-lockfile` would fail them: it is required of `install` only."""
    flavour = pm_config.yarn_flavour(directory)
    denial = _yarn_word_denial(flavour, scope.verb, scope.flags, directory)
    if denial or flavour.kind != pm_config.CLASSIC or flavour.conflict:
        return denial
    command = scope.verb or "install"
    config, denial = _yarn_classic_config(scope, directory, cwd, command)
    if denial:
        return denial
    if not config.scripts_off:
        unread = (f" A .yarnrc that Package Guard cannot read the way Yarn does is not counted: "
                  f"{config.problems[0]}." if config.problems else "")
        return _decision("deny", (
            f"PACKAGE_GUARD_UNSUPPORTED: `yarn {scope.verb}`".rstrip() + " would run lifecycle scripts "
            f"(dependency install scripts and the root's own): {config.scripts_reason}.{unread} Add "
            "`--ignore-scripts` to the same command. Do not edit .yarnrc or the environment to "
            "get around this. A package whose script is needed (node-sass on Frappe v11 to v13 downloads "
            "native code with no checksum) is for the user to build, once, in their own terminal, after "
            f"the install: {legacy.node_sass_command(directory)} . That is scoped to node-sass; "
            "`YARN_IGNORE_SCRIPTS=false yarn install` would run every locked package's script and is not "
            "offered. Claude does not run it."))
    if command == "install" and not config.frozen:
        return _decision("deny", (
            "PACKAGE_GUARD_UNSUPPORTED: `yarn install` without a frozen lockfile may resolve "
            f"versions nobody reviewed: {config.frozen_reason}. Add `--frozen-lockfile` to the "
            "same command (`--pure-lockfile` does not stop resolution)."))
    return None


def _yarn_run_denial(run, directory, cwd) -> dict | None:
    """The same word and flag judgement for a Yarn command that acquires nothing (a runner,
    `remove`, a read-only verb)."""
    flavour = pm_config.yarn_flavour(directory)
    word = run.word or (run.verb if run.verb not in ("manager", "print", "remove") else "")
    if run.verb == "print":
        word = "print"
    return _yarn_word_denial(flavour, word, run.flags, directory)


def _manager_pin_denial(kind, directory, root, event, pin_required=True):
    """A denial when the manager `kind` would run a pinned release nobody reviewed, or
    when the pin cannot be read; None when it is fine (or there is no pin to review).

    pnpm and Yarn are downloaded and switched to the release `package.json` pins, so that
    release is an acquisition and goes through review as an npm package (Q15, D7), for
    EVERY command that executes the manager, not only an install. An unvetted pin opens
    (or reuses) a review of that package here, so a project that cannot install yet (it
    has no lock) or a command that must stay reachable (`remove`, with a finding open)
    never waits on an install that is itself denied. Its retry is the original command."""
    problem, pin = _manager_pin(directory, kind, pin_required)
    if problem:
        return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: {problem}.")
    if kind == "pnpm" and pg_manifest.pm_lock_path(directory, "pnpm").is_file():
        # A10 on every pnpm execution: the lock's environment document names what pnpm itself
        # fetches before it runs anything.
        problem = _pnpm_env_lock_problem(directory, pin, strict=False)
        if problem:
            return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: {problem}.")
    if not pin:
        return None
    identity = {"ecosystem": "npm", "name": pin[0], "version": pin[1],
                "registry": pg_parser.NPM_REGISTRY}
    try:
        if store.is_vetted(root, identity):
            return _fresh_recheck(root, identity, {"done": 0})
        if store.is_declined(root, identity):
            return _decision("deny", _render_declined([{
                "resolved_identity": identity,
                "review_id": store.declined_review_id(root, identity) or "(declined earlier)"}],
                root))
        session_id = event.get("session_id")
        report = store.find_open_review(root, session_id, identity)
        if report is None:
            command = ((event.get("tool_input") or {}).get("command") or "")
            request = dataclasses.replace(
                pg_manifest.as_request(pin[0], pin[1], command, "npm"), operation="manager-pin")
            reports, abandoned = _create_reviews([request], root, session_id)
            if abandoned or not reports:
                return _decision("deny", _render_deferred_only(max(abandoned, 1)))
            report = reports[0]
    except store.StoreError as exc:
        return _decision("deny", f"PACKAGE_GUARD_ERROR: Package Guard state is unavailable ({exc}). "
                                 "Package operations are blocked until it is repaired.")
    if report["verdict"] == "hard_deny":
        return _decision("deny", _render_hard_deny([report]))
    # An open review is reused across commands, and its stored retry names the command that
    # opened it: the one to retry is this one.
    command = ((event.get("tool_input") or {}).get("command") or "")
    return _decision("deny", _render_review_required([dict(report, retry_command=command)], root))


def _remove_denial(run, directory, root, cwd=None) -> dict | None:
    """The checks a `pnpm|bun|yarn remove` needs beyond the configuration and pin checks
    every run gets (v1.10.0 hardening, A4). `remove` rewrites package.json and the lock,
    relinks node_modules and runs the root project's lifecycle scripts, and it is the
    printed remedy for an unreviewed package, so it stays an `ignore` the gate lets by
    while a finding is open; the checks run here instead:

      - one manager per project, the lock read in full, no unreadable lock;
      - the manifest and the lock agree (a dependency the lock does not record would be
        resolved and installed by the relink), the names being removed excepted;
      - no root install-lifecycle script runs unless the command turns scripts off, and
        every dependency allowed to build is a reviewed version."""
    kind = run.kind
    scope = pg_parser.ManifestScope(kind, scripts=run.scripts)
    denial, _pin, _note = _pm_project_problem(scope, directory)
    if denial:
        return denial
    try:
        _resolved, unresolved, where = _read_manifest(scope, directory)
    except (pg_manifest.ManifestError, lock_errors.LockReadError) as exc:
        return _decision("deny", f"PACKAGE_GUARD_ERROR: the manifest for {kind} could not be read "
                                 f"({exc}). Nothing was changed; tell the user.")
    removed = set(run.names)
    stale = [(name, spec) for name, spec in unresolved if name not in removed]
    if stale:
        listed = "; ".join(f"{name}: {spec}" for name, spec in stale[:5])
        return _decision("deny", (
            f"PACKAGE_GUARD_UNSUPPORTED: `{kind} remove` would re-resolve the project, and "
            f"{where.name} and the lock disagree, so it would install something nobody "
            f"reviewed ({listed}). Tell the user; do not edit the lock yourself."))
    if kind == "yarn" and pm_config.yarn_flavour(directory).kind == pm_config.CLASSIC:
        # Classic: scripts are off only by Classic's own proofs; Berry's `--mode=skip-build` and
        # `enableScripts: false` mean nothing to it. `remove` is not frozen (it rewrites the lock).
        config, denial = _yarn_classic_config(run, directory, cwd or directory, "remove")
        if denial:
            return denial
        if config.scripts_off:
            return None
        return _decision("deny", (
            "PACKAGE_GUARD_UNSUPPORTED: `yarn remove` re-runs the install, with dependency and "
            f"root lifecycle scripts: {config.scripts_reason}. Add `--ignore-scripts` to the same "
            "command. Do not edit package.json, .yarnrc or the lock to get around this."))
    if not run.scripts or (kind == "yarn" and pm_config.yarn_scripts_disabled(directory, sources.HOME)):
        return None
    try:
        lifecycle = pg_manifest.npm_root_lifecycle_scripts(directory, kind)
    except pg_manifest.ManifestError as exc:
        return _decision("deny", f"PACKAGE_GUARD_ERROR: the manifest for {kind} could not be "
                                 f"read ({exc}). Nothing was changed; tell the user.")
    if lifecycle:
        names = ", ".join(f"`{name}`" for name, _body in lifecycle)
        return _decision("deny", (
            f"PACKAGE_GUARD_UNSUPPORTED: `{kind} remove` runs the root project's own "
            f"install-time scripts ({names} in {where.name}). "
            + ("Add `--mode=skip-build` to turn them off." if kind == "yarn" else
               "Add `--ignore-scripts` to turn them off." if kind == "bun" else
               "This command has no flag Package Guard can rely on to turn them off. Tell the "
               "user: they remove those scripts, or remove the package themselves outside this "
               "session.")
            + " Do not edit package.json or the lock to get around this."))
    return _dependency_builds_check(directory, root, kind, removing=True)


def _run_denial(parsed, event, root):
    """A pnpm, Bun or Yarn command that RUNS project code or only executes the manager
    (`parsed.runs`). It acquires nothing, like `npm run`, and the script's own text is not
    read; but the manager's configuration applies to it (a pnpmfile, a Yarn plugin, a Bun
    preload) wherever the shell is and wherever the project is, the pinned manager is
    downloaded when it differs, Bun installs what it cannot find, and Yarn needs an
    install state. Design 7; `manager` and `remove` runs are v1.10.0 hardening (A2, A4)."""
    cwd = event.get("cwd") or root
    for run in parsed.runs:
        scope = pg_parser.ManifestScope(run.kind, scripts=False)
        targets = [(scope, directory) for directory in _scope_directories(scope, cwd, root)]
        outside = _outside_project(targets, cwd, root)
        if outside:
            return outside
        synthetic = pg_parser.ParseResult(kind="ignore", runs=(run,))
        # Where the shell is AND where the project is: Bun reads the bunfig of the
        # directory it runs in, Yarn and pnpm walk up from it (A6).
        here = {os.path.realpath(d): d for d in [cwd] + [d for _s, d in targets]}
        problems = []
        for directory in here.values():
            problems += sources.problems_for(synthetic, directory)
        problems = list(dict.fromkeys(problems))
        if problems:
            return _decision("deny", _render_alternate_source(problems))
        for _scope, directory in targets:
            if run.kind == "yarn":
                denial = _yarn_run_denial(run, directory, cwd)
                if denial:
                    return denial
            if run.kind in ("pnpm", "yarn"):
                denial = _manager_pin_denial(run.kind, directory, root, event,
                                             pin_required=run.verb != "print")
                if denial:
                    return denial
            if run.verb == "remove":
                denial = _remove_denial(run, directory, root, cwd)
                if denial:
                    return denial
            reason = None
            if run.kind == "bun" and run.autoinstall:
                reason = _bun_autoinstall_problem(cwd, directory, root)
            elif run.kind == "yarn" and run.verb not in ("manager", "print", "remove"):
                reason = _yarn_install_state_problem(directory)
            if reason:
                return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: `{run.kind} {run.verb}`: {reason}.")
    return None


def _pm_not_yet_readable(parsed) -> str | None:
    """THE SAFETY SWITCH for pnpm, Bun and Yarn (`parser.PNPM_BUN_YARN_ENABLED`).

    Their scopes, and the requests `pnpm dlx`, `bunx` and `yarn dlx` make, are
    recognised, but nothing reads their manifests, locks or configuration yet. Until
    every stage does, any command that reaches them is denied here, so no
    intermediate state lets one through unreviewed."""
    if pg_parser.PNPM_BUN_YARN_ENABLED or not pg_parser.uses_pnpm_bun_yarn(parsed):
        return None
    names = [m.kind for m in parsed.manifests if m.kind in pg_parser.PM_KINDS]
    names += [r.manager.split()[0] for r in parsed.requests
              if r.manager and r.manager.split()[0] in pg_parser.PM_MANAGERS]
    return (f"PACKAGE_GUARD_UNSUPPORTED: manifest not yet readable for {names[0]} "
            "(support lands in v1.10.0)")


def evaluate(event: dict, root) -> dict | None:
    tool = event.get("tool_name")
    if isinstance(tool, str) and tool.lower() == "powershell":
        return _powershell_refusal()
    if tool in _EDIT_TOOLS:
        return _edit_decision(event, root) if store.plugin_mode() else None
    if tool != "Bash":
        return None
    # The review and refresh deadlines this invocation sets are at least
    # _REVIEW_BUDGET_SECONDS from here, so a retry that ends by this mark
    # spends no time past the budget (see the budget arithmetic above).
    vetting.set_retry_deadline(time.monotonic() + _REVIEW_BUDGET_SECONDS)
    tool_input = event.get("tool_input")
    command = (tool_input or {}).get("command") or ""

    # Parsing is pure, so it runs once, here: a Python environment the command
    # names is then part of the scan before the command runs. A parser failure
    # is retried below, where it fails closed as it always has.
    try:
        early = pg_parser.parse_command(command)
    except Exception:  # noqa: BLE001 - see the comment
        early = None
    advanced = _advance_watermark(event, root, _command_environments(early, event, root))

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = None
    plugin = store.plugin_mode()
    if tokens and plugin:
        outcome = _plugin_cli_call(tokens, root)
        if isinstance(outcome, dict):
            return outcome
        if outcome:
            return _handle_cli(outcome, root, event.get("transcript_path"))
    elif tokens:
        call = _guard_cli_call(tokens)
        if call:
            if not _clean_project_cli(tokens, root, event.get("cwd")):
                ids = "" if call[0] in _RAW_TAIL_VERBS else " ".join(call[1]) or "<review-id> ..."
                return _decision(
                    "deny",
                    "PACKAGE_GUARD_UNSUPPORTED: run this project's own Package Guard CLI, "
                    "with no other `uv` option, exactly as:\n  "
                    f"{store.cli_command(root, call[0] or '<subcommand>', ids).rstrip()}",
                )
            if call[0] in _RAW_TAIL_VERBS:
                # The raw tokens after the verb; None when the verb is not
                # directly after cli.py (the parsed call skips `--flags`).
                call = (call[0], tokens[7:] if tokens[6] == call[0] else None)
            return _handle_cli(call, root, event.get("transcript_path"))

    # The command names a guard CLI verb but was not recognised as a clean
    # standalone invocation above. Falling through would hand it to the normal
    # permission flow, where an auto-accept mode runs it with no human prompt —
    # silently defeating the approval gate. Fail closed.
    if _names_cli_verb(command, plugin):
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: a Package Guard CLI call (approve, decline, mode, ...) "
            "must be a simple standalone command — not wrapped in a `cd`, `&&`, `;`, subshell, "
            "or any other compound or dynamic shell syntax. Re-run it on its own, using this "
            "absolute path so no directory change is needed:\n  "
            f"{store.cli_command(root, '<approve|decline>', '<review-id> ...')}",
        )
    if _LAUNCHER_HINT.search(command) or _LAUNCHER_HINT.search(_SHELL_QUOTING.sub("", command)):
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: `pg` and `run.sh … cli.py` are how the user runs "
            "Package Guard in their own terminal; Claude does not run them. Use the CLI "
            "exactly as:\n  "
            f"{store.cli_command(root, '<subcommand>', '...')}",
        )

    written = _guard_write(command, root, event.get("cwd"))
    if written == "git":
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: this git command would change Package Guard's files "
            "(its state under .claude/package-guard/, or, where locked, its hook, the "
            "package-vetter agent, the package-guard skill and .claude/settings*.json). Git "
            "operations that rewrite those files -- a checkout, switch, reset, merge, pull, "
            "rebase, stash, clean or apply that reaches them -- are the human's to run. Do not "
            "look for another way: stop and tell the user the exact command you wanted to run.",
        )
    if written == "source":
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: Package Guard's own files -- its hook, the package-vetter "
            "agent, the package-guard skill and .claude/settings*.json -- are locked in this "
            "project. Only the human changes or removes them, outside Claude. Do not look for "
            "another way to do this: stop and tell the user what you were asked and that this "
            "is theirs to do.",
        )
    if written == "config":
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: this writes a file Package Guard wrote for an installer "
            "(a bench's pip.conf or uv.toml, a .yarnrc, a constraint file). They pin what bench "
            "may install and only Package Guard changes them, from an approved baseline. Do not "
            "look for another way: stop and tell the user what you wanted to change.")
    if written == "state":
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: Package Guard state under .claude/package-guard/ is written "
            "only by the guard CLI, behind a permission prompt. Read it freely (cat, ls, grep); "
            "change it only through: "
            f"{store.cli_command(root, '<approve|decline|undecline|revoke>', '<review-id> ...')}",
        )

    return _with_mode(event, root, command, early, advanced)


def _join_output(decision: dict | None, message: str, context: str) -> dict:
    """Add a line for the user (systemMessage) and one for Claude
    (additionalContext) to a PreToolUse reply, keeping what it already says.
    A reply with no permissionDecision leaves the command to the normal
    permission flow."""
    decision = decision if decision is not None else {
        "hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    out = decision["hookSpecificOutput"]
    out["additionalContext"] = "\n\n".join(
        part for part in (context, out.get("additionalContext")) if part)
    decision["systemMessage"] = "\n".join(
        part for part in (message, decision.get("systemMessage")) if part)
    return decision


def _warned(decision: dict, root, command: str) -> dict:
    """warn mode: the refusal becomes context, with NO permission decision.
    Never `allow`: that would skip the user's own permission prompt."""
    reason = decision["hookSpecificOutput"].get("permissionDecisionReason") or ""
    code = reason.split(":", 1)[0].split("\n", 1)[0]
    pg_mode.append_log(root, {"event": "warned", "code": code, "command": command[:200]})
    return _join_output(
        None,
        f"Package Guard (warn mode) would have refused this command: {code}.",
        "Package Guard is in warn mode, so it did not block this command; it goes to the "
        "user's normal permission prompt. Tell the user what the guard would have refused, "
        "and do not try to change the mode. Enforcing, the guard would have said:\n" + reason)


def _record_while_down(event: dict, root, command: str, early) -> None:
    """warn and off: record the Python environments a command names, as an
    allow does, so the scans that catch up afterwards read them. Without it, an
    install into an outside environment while the guard was down would never be
    seen. Best effort; it decides nothing."""
    try:
        parsed = early if early is not None else pg_parser.parse_command(command)
        if parsed.kind != "package" or not parsed.environments:
            return
        if any(_inside_guard_dir(root, e) for e in parsed.environments):
            return
        _record_environments(parsed, _python_project(parsed, event.get("cwd") or root, root), root)
    except Exception as exc:  # noqa: BLE001 - a lost record costs scan coverage, not the gate
        print(f"Package Guard: could not record the environment "
              f"({exc.__class__.__name__}: {exc}).", file=sys.stderr)


def _follow_mode(root, mode: str, session_id) -> list:
    """`disk_guard.follow_mode`, failing soft: a snapshot or catch-up that
    fails stays for the next command, and the gate still reads the findings
    record (and fails closed on it) itself."""
    try:
        caught = disk_guard.follow_mode(root, mode, session_id)
    except Exception as exc:  # noqa: BLE001 - see the docstring
        print(f"Package Guard: could not follow the mode ({exc.__class__.__name__}: {exc}).",
              file=sys.stderr)
        return []
    if caught:
        pg_mode.append_log(root, {"event": "caught-up", "count": len(caught)})
    return caught


def _with_mode(event: dict, root, command: str, early, advanced) -> dict | None:
    """Apply the mode to acquisition, and nowhere else. Everything evaluate()
    decided before this -- PowerShell, the guard CLI, writes to guard files --
    holds in every mode."""
    global _WARN_RUNNING
    expired = pg_mode.settle(root)
    current = pg_mode.effective(root)
    # Before the gate, so the first package command after the guard is back
    # is refused while what arrived in the meantime waits for review.
    caught = _follow_mode(root, current.mode, event.get("session_id"))
    if current.mode == "off":
        decision = None
        _record_while_down(event, root, command, early)
    elif current.mode == "warn":
        _WARN_RUNNING = True
        try:
            decision = _acquisition(event, root, command, early, advanced)
        except Exception as exc:  # noqa: BLE001 - the user asked not to be blocked
            # warn is the way out the internal-failure message names, so a
            # crash in acquisition must not block here.
            decision = _decision("deny", f"PACKAGE_GUARD_ERROR: internal failure "
                                         f"({exc.__class__.__name__}: {exc}).")
        finally:
            _WARN_RUNNING = False
        out = (decision or {}).get("hookSpecificOutput") or {}
        if out.get("permissionDecision") == "deny":
            decision = _warned(decision, root, command)
            _record_while_down(event, root, command, early)
    else:
        decision = _acquisition(event, root, command, early, advanced)
    down = current.mode != "enforce" or current.problem
    if expired or caught or (down and pg_mode.first_in_session(root, event.get("session_id"))):
        lines = [f"Package Guard: {line}." for line in expired]
        lines.append(pg_mode.describe(current))
        if caught:
            lines.append(f"{len(caught)} package(s) installed while it was down wait for review: "
                         + ", ".join(disk_guard._label(f) for f in caught) + ".")
        banner = " ".join(lines)
        decision = _join_output(
            decision, banner,
            banner + " Only the user changes the mode; do not try to change it.")
    return decision


# ---------------------------------------------------------------------------
# The bench gate (Frappe, behind `parser.FRAPPE_ENABLED`)
#
# A `bench` verb that installs packages or runs project code, and an install into a bench's env,
# run only when every app they touch is covered by an approved baseline (an upstream app) or a
# fully reviewed manifest (a custom app), the guard's installer files are what they should be and
# nothing overrides them, the bench itself is a release that was looked at, and no earlier part of
# the command could have changed what the gate read. Local reads and one recomputation: the one
# network step, the baseline audit, runs in the CLI (`cli.py audit`) and the hook reads its cache.
# ---------------------------------------------------------------------------

def _bench_deny(code: str, text: str) -> dict:
    return _decision("deny", f"{code}: {text}")


def _bench_plan_command(root, app_name) -> str:
    return store.cli_command(root, "baseline", f"plan --app apps/{app_name}").rstrip()


def _bench_apply_command(root) -> str:
    return store.cli_command(root, "bench-config", "apply").rstrip()


def _bench_problem_lines(problems, limit=6) -> str:
    lines = [f"- {p}" for p in problems[:limit]]
    if len(problems) > limit:
        lines.append(f"- ... and {len(problems) - limit} more")
    return "\n".join(lines)


def _exclusive_denial(parsed, event, classic=False) -> dict | None:
    """A bench verb, an env install or a Yarn Classic install must be the only writer of its
    command and must run in the foreground: an earlier segment that is not a known reader may have
    changed the manifests after the gate compared them, and a background install is reconciled
    before it ends."""
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    if tool_input.get("run_in_background"):
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: this install would run in the background, so the disk is "
            "reconciled before it ends and what it installs is not checked. Run it in the "
            "foreground, as its own command.")
    if not parsed.exclusive:
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: this install follows another command of the same line "
            "that is not a plain reader, or runs in the background (`&`, `nohup`): the manifests "
            "could change after the gate compared them, or the install may still be running when "
            "the disk is read. Run the install as its own command, with nothing before it that "
            "writes.")
    return None


def _bench_requests(unreviewed, command, app=None):
    """PackageRequests for the declared dependencies of a custom app that are not exact vetted
    pins, so the ordinary review path asks for each one. A Python requirement with a range
    (`flit_core >=3.4,<4`) is reviewed at the newest release the range admits, never at the newest
    release there is."""
    requests = []
    for ecosystem, name, version, _where in unreviewed:
        spec = f"=={version}" if (version and ecosystem == "pypi") else version
        if ecosystem == "pypi" and version is None and app is not None:
            text = bench_config.pyproject_requirement_text(Path(app) / "pyproject.toml", name)
            pick = vetting.suggest_build_pin(text.split(";", 1)[0]) if text else None
            if pick:
                version, spec = pick[1], f"=={pick[1]}"
        requests.append(pg_parser.PackageRequest(
            manager="bench", operation="install", ecosystem=ecosystem,
            name=name, display_name=name, requested_spec=spec, exact_version=version,
            registry=pg_parser.NPM_REGISTRY if ecosystem == "npm" else pg_parser.PYPI_REGISTRY,
            original_command=command))
    return requests


def _unapproved(root, request) -> bool:
    """True when `request` names a release no person approved for this project (or none at all)."""
    if not request.exact_version:
        return True
    try:
        return not store.is_vetted(root, {"ecosystem": request.ecosystem, "name": request.name,
                                          "version": request.exact_version, "registry": request.registry})
    except store.StoreError:
        return True


def _bench_scope_check(scope, parsed, event, root, cwd, command, yarn_targets=None, notes=None):
    """(denial or None, [PackageRequest] still to review, [{"app", "baseline"}] covered).

    The order of design section 6, with coverage before the files: the files are recomputed from
    the baselines of the covered apps, so they cannot be judged until those are known.

    `yarn_targets` (a list, filled in) receives (ManifestScope, directory) for each yarn directory of
    a CUSTOM app that this verb installs in, so the caller runs on them exactly what a direct
    `yarn install` there would get: the source check on the lock, the review of every direct
    dependency, the OSV check of the whole tree, the `.npmrc` chain. An upstream app's lock is the
    baseline's (its manifest digests are checked above), and gets the same executable and `.npmrc`
    checks."""
    env_install = scope.verb == "env-install"
    runner = scope.verb in ("build", "update-run")

    def deny(code, text):
        return _bench_deny(code, text), [], []

    problems = bench_gate.read_problems(root)
    if problems:
        return deny("PACKAGE_GUARD_BENCH_CONFIG", "a bench command left something wrong that nobody has resolved yet:\n"
                    + _bench_problem_lines([p.get("text", "?") for p in problems])
                    + "\nTell the user. After they fix it, `" + store.cli_command(root, "reconcile", "").rstrip()
                    + "` re-checks it and clears what is gone.")
    why = bench_config.redirect_problem()
    if why:
        return deny("PACKAGE_GUARD_UNSUPPORTED", why + ".")
    bench = bench_config.bench_root(cwd)
    if bench is None:
        return deny("PACKAGE_GUARD_UNSUPPORTED", f"no Frappe bench (a directory with apps/ and sites/) holds {cwd}; "
                    "run the command from the bench root or from an app inside it.")
    if not _within(bench, root):
        return deny("PACKAGE_GUARD_UNSUPPORTED", f"the bench at {bench} is outside the project Package Guard protects "
                    f"({os.path.realpath(root)}): its baselines and configuration would be somebody else's. "
                    "Install the guard at the bench root.")
    if not env_install:
        try:
            install = bench_gate.read_bench_install(os.environ.get("PATH"), executable=scope.executable,
                                                    cwd=cwd)
        except bench_config.BenchConfigError as exc:
            return deny("PACKAGE_GUARD_UNSUPPORTED", f"{exc}, so the bench release cannot be checked. Tell the user.")
        why = bench_gate.version_problem(install)
        if why:
            return deny("PACKAGE_GUARD_UNSUPPORTED", f"{why}. Tell the user.")
        if scope.verb.startswith("update"):
            try:
                missing = bench_gate.missing_patches(bench, install)
            except bench_config.BenchConfigError as exc:
                return deny("PACKAGE_GUARD_UNSUPPORTED", f"{exc}: `bench update` runs the patches the bench lacks, "
                            "and what they are cannot be read. Tell the user.")
            if missing:
                return deny("PACKAGE_GUARD_UNSUPPORTED", "`bench update` runs the patches of the installed bench that "
                            f"{bench}/patches.txt does not list, and one of them runs `npm install`: "
                            + ", ".join(missing) + ". Tell the user; they can run the update themselves.")
    env = bench / "env"
    if not (env / "pyvenv.cfg").is_file():
        return deny("PACKAGE_GUARD_UNSUPPORTED", f"the bench at {bench} has no Python environment in env/ yet; creating it "
                    "(`bench init`, `bench setup env`) is a step for the user, in their own terminal.")

    apps_all = bench_config.bench_apps(bench)
    if scope.verb in ("build", "update-run"):
        strays = bench_config.apps_txt_strays(bench)
        if strays:
            return deny("PACKAGE_GUARD_UNSUPPORTED", "sites/apps.txt lists " + ", ".join(strays[:3])
                        + ", which is not a folder directly in apps/: Frappe's build changes into it and runs "
                        "yarn there, and no app rule covers it. Tell the user.")
    by_name = {Path(a).name: a for a in apps_all}
    if env_install or runner and not scope.apps:
        involved = list(apps_all)
    else:
        unknown = [n for n in scope.apps if n not in by_name]
        if unknown:
            return deny("PACKAGE_GUARD_UNSUPPORTED", f"{', '.join(unknown)} is not an app of the bench at {bench} (its "
                        "directory in apps/ needs hooks.py, modules.txt and patches.txt, or a line in sites/apps.txt).")
        involved = [by_name[n] for n in scope.apps] if scope.apps else list(apps_all)
    if scope.verb == "build":
        involved = [by_name[n] for n in scope.apps if n in by_name]
    if runner:
        # Frappe v16's build runs `yarn install --frozen-lockfile` in EVERY app of the bench that has a
        # `scripts.build` and no node_modules, whatever `--app` names. Such a run is an install of
        # those apps: coverage, the custom-app review, the recomputed installer files, the lock checks.
        node_apps = [a for a in apps_all if _builds_with_yarn(a)]
        if node_apps:
            runner = False
            involved = list(dict.fromkeys([*involved, *node_apps]))
    if scope.node:
        major = bench_gate.frappe_major(bench)
        if major is None or major < bench_gate.NODE_YARN_FROM:
            return deny("PACKAGE_GUARD_UNSUPPORTED", "`bench setup requirements --node` on a Frappe older than "
                        f"v{bench_gate.NODE_YARN_FROM} (or one whose version is not written down) runs a "
                        "bench-root `npm install` that Package Guard does not read.")

    names = bench_gate.local_names(bench, apps_all)
    try:
        coverings = bench_gate.covering_of(root, apps_all, names)
    except Exception as exc:  # noqa: BLE001 - what cannot be read is not covered
        return deny("PACKAGE_GUARD_BASELINE_REQUIRED", f"the baselines could not be read ({exc.__class__.__name__}: {exc}).")
    extras, covered = [], []
    need_coverage = [] if runner else involved
    if env_install:
        need_coverage = [a for a in apps_all if coverings[Path(a)]["kind"] != "custom"]
    for app in need_coverage:
        covering = coverings[Path(app)]
        label = Path(app).name
        if covering["kind"] == "baseline":
            covered.append({"app": str(app), "baseline": covering["baseline"]["id"]})
        elif covering["kind"] == "upstream-uncovered":
            return deny("PACKAGE_GUARD_BASELINE_REQUIRED", (
                f"apps/{label} is not covered by an approved baseline: "
                + "; ".join(covering["reasons"][:3])
                + f". A baseline approves an app's whole dependency set once. Run, then ask the user to "
                f"approve the proposal it prints (advisories in it are information, not a block): "
                f"{_bench_plan_command(root, label)}. Do not install the app's packages one by one."))
        else:
            if covering["refused"]:
                return deny("PACKAGE_GUARD_UNSUPPORTED", (
                    f"apps/{label} is a custom app and declares dependencies Package Guard cannot "
                    "review: " + "; ".join(str(r) for r in covering["refused"][:5]) + "."))
            extras += _bench_requests(covering["unreviewed"], command, app)
    docs = bench_gate.baseline_docs(coverings)
    absent = bench_gate.absent_excluded_names(docs, names)
    if absent and not runner:
        return deny("PACKAGE_GUARD_UNSUPPORTED", "a baseline's requirements name an app that is not in this bench: "
                    + ", ".join(f"{name} ({bid})" for bid, name in absent[:5])
                    + ". An app comes from `bench get-app`, which is the user's command, never from PyPI, so nothing "
                    "here may install the name. Tell the user.")
    unbuilt = bench_gate.unapproved_builds(docs)
    if unbuilt and not runner:
        return deny("PACKAGE_GUARD_BASELINE_REQUIRED", "a baseline lists packages that build from source at install and "
                    "its approval did not allow them: "
                    + ", ".join(f"{name} ({bid})" for bid, name in unbuilt[:5]) + ". Tell the user.")
    if not runner:
        for doc in docs:
            why = bench_gate.requires_python_problem(doc["python"]["requires_python"], env)
            if why:
                return deny("PACKAGE_GUARD_BASELINE_REQUIRED", f"baseline {doc['id']} ({doc['app']['name']}): {why}.")

    # The installer files, recomputed, and what pip, uv and yarn would really read.
    home = Path.home()
    config_cwd = bench if not env_install else cwd
    config = None
    try:
        if runner:
            problems = bench_config.verify_recorded(bench, root, cwd=config_cwd, home=home, environ=os.environ)
        else:
            config = bench_gate.config_input(root, bench)
            problems = bench_config.verify(bench, root, config, cwd=config_cwd, home=home,
                                           environ=os.environ)
    except bench_config.BenchConfigError as exc:
        return deny("PACKAGE_GUARD_BASELINE_REQUIRED" if getattr(exc, "baseline", False)
                    else "PACKAGE_GUARD_BENCH_CONFIG", f"{exc}. Tell the user.")
    if problems:
        return deny("PACKAGE_GUARD_BENCH_CONFIG", (
            "Package Guard's installer files for this bench are missing, differ from what the "
            "approved baselines call for, or something overrides them:\n"
            + _bench_problem_lines(problems)
            + f"\nRun the command without the override, or ask the user to run `{_bench_apply_command(root)}`. "
            "Do not set it another way or edit the files."))
    if not runner:
        editable = bench_gate.editable_installs(env)
        for app in involved:
            for why in bench_gate.local_name_problems(app, names, apps_all, editable):
                return deny("PACKAGE_GUARD_UNSUPPORTED", why)
    # Yarn: the flavour, the lock read in full, the pin, for every directory a yarn install runs in.
    if not env_install:
        run_dirs = []
        for app in involved:
            for directory in _bench_yarn_run_dirs(bench, app):
                if directory not in [d for _a, d in run_dirs]:
                    run_dirs.append((Path(app), directory))
        for app_root, directory in run_dirs:
            if notes is not None and directory != app_root and not (directory / "node_modules").is_dir() \
                    and (directory / "yarn.lock").is_file():
                notes.append(
                    f"{directory} has no node_modules, and the guard's .yarnrc keeps a script such as "
                    f"`cd {directory.name} && yarn install` from running, so the build of "
                    f"{app_root.name} cannot find its tools. Install it first, as its own command, with "
                    f"{directory} as the working directory: yarn install --frozen-lockfile --ignore-scripts "
                    "(an app an approved baseline covers needs no review for this).")
            route, requests = _classic_route(root, directory, command)
            if route:
                return route, [], []
            if requests:
                extras += requests
                continue
            denial, _pin, _note = _pm_project_problem(pg_parser.ManifestScope("yarn"), directory)
            if denial:
                return denial, [], []
            denial = _bench_yarn_executable_denial(directory)
            if denial:
                return denial, [], []
            custom = any(_within(directory, a) and coverings[Path(a)]["kind"] == "custom" for a in involved)
            if custom and yarn_targets is not None and (
                    (Path(directory) / "yarn.lock").is_file() or _declares_dependencies(directory, "yarn")):
                yarn_targets.append((pg_parser.ManifestScope("yarn", verb=_BENCH_YARN), directory))
            else:
                problems = sources.npm_config_problems(directory) + sources.yarn_npmrc_problems(directory)
                if problems:
                    return _decision("deny", _render_alternate_source(problems)), [], []
    # A version range of a custom app is installed at the release a constraint names, so every range
    # uv will install must have its pin line, and nothing a review can approve changes that: the verb
    # is refused whatever requests are open, except that a request for a release nobody approved is
    # returned as it is (the caller denies it with the review, which is how the release gets approved;
    # the next run is refused until `apply` has written the pin).
    stuck = [] if config is None or env_install else [
        entry for entry in config.unpinned if entry[0] in {Path(a).name for a in involved}]
    if stuck and not any(_unapproved(root, request) for request in extras):
        return deny("PACKAGE_GUARD_UNSUPPORTED", (
            "a custom app declares a version range that is not pinned to a release it can install, so uv would "
            "take the newest release there is, not the one reviewed: "
            + "; ".join(f"apps/{app} {name} ({'build requirement' if section == 'build' else 'requirement'}): {why}"
                        for app, name, section, why in stuck[:5])
            + ". If a release is approved, `" + _bench_apply_command(root) + "` writes the pin (ask the user). "
            "Otherwise ask the user to pin each to one exact version (`name==X.Y.Z`) in the app's own files "
            "and to make its extras and groups agree with it; an exact version is reviewed like any package."))
    return None, extras, covered


_SHELL_DIR = re.compile(
    r"""(?:\bcd|\bpushd)\s+(?P<cd>"[^"]+"|'[^']+'|[^\s&;|()]+)"""
    r"""|--(?:cwd|prefix)(?:=|\s+)(?P<flag>"[^"]+"|'[^']+'|[^\s&;|()]+)""")


def _bench_yarn_run_dirs(bench, app) -> list:
    """The folders of one app that yarn will actually run in when bench (or frappe's build) runs yarn
    there: the app's root (bench runs `yarn install` in each app root, and Frappe's build runs
    `yarn install` and `yarn build` there), and every sub-project a script of an app's package.json
    changes into or points yarn at (`cd banking && yarn install`, `yarn --cwd ui build`), followed
    through the sub-projects' own scripts. A folder with a package.json that no script names (Frappe's
    `ui/`) is not one: bench never runs yarn there. A script this reader cannot follow (a variable,
    a command substitution, `~`, an unreadable package.json) puts every folder of the app that has a
    yarn.lock back in the set, the stricter answer."""
    app = Path(app)
    found, seen, uncertain = [], set(), False

    def visit(folder, depth):
        nonlocal uncertain
        manifest = folder / "package.json"
        if folder in seen or depth > 3 or not manifest.is_file():
            return
        seen.add(folder)
        found.append(folder)
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            uncertain = True
            return
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            return
        for body in scripts.values():
            if not isinstance(body, str):
                continue
            if re.search(r"\b(?:yarn|npm|pnpm|npx)\b", body) and re.search(r"[$`~]|\\", body):
                uncertain = True
                continue
            here = folder
            for match in _SHELL_DIR.finditer(body):
                token = (match.group("cd") or match.group("flag")).strip("\"'")
                target = Path(os.path.normpath(here / token))
                if target != app and app not in target.parents:
                    continue
                if match.group("cd"):
                    here = target
                visit(target, depth + 1)

    visit(app, 0)
    if uncertain:
        for directory in bench_config.yarn_dirs(bench)[1:]:
            directory = Path(directory)
            if (directory == app or app in directory.parents) and directory not in seen:
                found.append(directory)
    return found


def _baseline_vouches(root, directory) -> bool:
    """True when the baseline of the Frappe-bench app that holds `directory` lists THIS folder: its own
    `package.json` and `yarn.lock` are entries of the matching approved baseline, and the files on disk
    still have those digests. Then the baseline, not a review per package, vouches for what the install
    fetches. A folder the baseline's walk skips (inside node_modules, .git, __pycache__, .hg, .svn), a
    folder that is new, or a symbolic link is never vouched for: the full direct-install checks run."""
    if not pg_parser.FRAPPE_ENABLED:
        return False
    try:
        import baseline
        folder = Path(os.path.realpath(directory))
        bench = bench_config.bench_root(directory)
        if bench is None or not (folder / "yarn.lock").is_file() or not (folder / "package.json").is_file():
            return False
        apps = bench_config.bench_apps(bench)
        app = next((Path(os.path.realpath(a)) for a in apps if _within(directory, a)), None)
        if app is None:
            return False
        parts = folder.relative_to(app).parts
        if set(parts) & baseline._SKIP_DIRS:
            return False
        prefix = "/".join(parts) + "/" if parts else ""
        names = bench_gate.local_names(bench, apps)
        covering = bench_gate.covering_of(root, [app], names)[app]
        if covering.get("kind") != "baseline":
            return False
        recorded = {m["path"]: m["sha256"] for m in covering["baseline"]["manifests"]}
        for name in ("package.json", "yarn.lock"):
            path = folder / name
            if path.is_symlink() or (prefix + name) not in recorded:
                return False
            if baseline.sha256_text_file(path.read_bytes(), prefix + name) != recorded[prefix + name]:
                return False
    except Exception:  # noqa: BLE001 - what cannot be read vouches for nothing
        return False
    return True


# The `verb` of the ManifestScope for a yarn directory a bench verb installs in: the lock, the
# dependencies and the tree are judged like a direct install's, the command line's own flags (there are
# none: bench passes them, and the guard's .yarnrc, verified above, stands for them) are not.
_BENCH_YARN = "bench-yarn"


def _builds_with_yarn(app) -> bool:
    """True when running Frappe's build would run `yarn install` in this app: a `build` key in scripts and
    no node_modules. A package.json that cannot be read counts as one that does."""
    app = Path(app)
    if (app / "node_modules").is_dir() or not (app / "package.json").is_file():
        return False
    try:
        data = json.loads((app / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return True
    if not isinstance(data, dict):
        return True
    scripts = data.get("scripts")
    # Frappe's build tests `!scripts?.build`, so any truthy value counts (a list, 1, true, {}); the guard
    # is stricter still: a `build` key with any value at all (false, null, "") is a build.
    return isinstance(scripts, dict) and "build" in scripts


_NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?$")


def _bench_yarn_exe(directory):
    """The `yarn` bench would run, from the hook's PATH (found, never run)."""
    pin = None
    try:
        pin = next((v for _w, n, v in _declared_package_managers(directory) if n == "yarn" and v), None)
    except ValueError:
        pass
    return pm_config.yarn_executable("yarn", os.environ.get("PATH", ""), directory, pin)


def _classic_unlocked_deps(directory):
    """[(name, spec)] that package.json declares and a Yarn Classic install would have to
    resolve itself: there is no yarn.lock, or none of its entries is `name@spec`. None when the
    ordinary lock checks must judge the directory (Berry, a conflict, an unreadable file, or a
    spec that is not a registry name and version range, which they deny by name)."""
    if not pm_config.classic_enabled():
        return None
    flavour = pm_config.yarn_flavour(directory)
    if flavour.conflict or flavour.kind == pm_config.BERRY:
        return None
    try:
        specs = pg_manifest._npm_dep_specs(directory)
        if not specs:
            return None
        if (Path(directory) / "yarn.lock").is_file():
            lock = pg_manifest.yarn_classic_lock.read_yarn_lock(Path(directory) / "yarn.lock")
            listed = {d for entry in lock.entries for d in entry.descriptors}
            specs = [(n, s) for n, s in specs if not isinstance(s, str) or f"{n}@{s}" not in listed]
        elif flavour.kind is None and _bench_yarn_exe(directory).major != 1:
            return None  # no evidence of Classic and no proof the yarn that runs is one
    except (pg_manifest.ManifestError, lock_errors.LockReadError):
        return None
    if any(not isinstance(s, str) or ":" in s or "/" in s or "@" in s for _n, s in specs):
        return None
    return specs


def _classic_route(root, directory, command):
    """(denial or None, [PackageRequest]) for a Yarn Classic directory whose package.json lists
    dependencies the lock lacks. Each goes to review by name and exact version, the way
    `npm install x@1.2.3` does (a range is reviewed at the newest settled release it admits).
    While any is in that state NO verb that runs yarn here is allowed, whatever is vetted: the
    install would resolve it, and everything under it, itself. Once every one is approved the
    denial names the Classic route. (None, []) when the directory has no such dependency."""
    unlocked = _classic_unlocked_deps(directory)
    if not unlocked:
        return None, []
    requests, route = [], []
    for name, spec in unlocked:
        exact = spec if _NPM_EXACT.match(spec) else None
        identity = {"ecosystem": "npm", "name": name, "version": exact, "registry": pg_parser.NPM_REGISTRY}
        if exact and store.is_vetted(root, identity) and not store.is_declined(root, identity):
            route.append(f"yarn add {name}@{exact} --ignore-scripts")
            continue
        requests.append(pg_parser.PackageRequest(
            manager="yarn classic", operation="add", ecosystem="npm", name=name, display_name=name,
            requested_spec=spec, exact_version=exact, registry=pg_parser.NPM_REGISTRY,
            original_command=command))
    if requests:
        return None, requests
    return _decision("deny", (
        f"PACKAGE_GUARD_UNSUPPORTED: {directory}/package.json lists dependencies that yarn.lock does "
        "not have, so a Yarn Classic install would resolve them, and what they bring, by itself. "
        "They are reviewed and approved. Remove their lines from package.json (a revert, not an "
        "addition), then add each one in that app's own folder, as its own command; it writes "
        "package.json and yarn.lock:\n  " + "\n  ".join(route))), []


def _bench_yarn_executable_denial(directory) -> dict | None:
    """The `yarn` bench will run (found on the PATH, never run) must not be a Berry: the Classic
    rc files that stand for frozen locks and scripts off mean nothing to it, and it would migrate
    the lock and run the root scripts before anything is reconciled. The same executable check a
    direct `yarn install` gets (`_yarn_classic_config`)."""
    if pm_config.yarn_flavour(directory).kind == pm_config.BERRY:
        return None  # the ordinary Berry checks judge it
    exe = _bench_yarn_exe(directory)
    if exe.major != 1:
        what = (f"is Yarn {exe.version}" if exe.major else "is not shown to be Yarn Classic")
        return _decision("deny", (
            f"PACKAGE_GUARD_UNSUPPORTED: bench would run `yarn` in {directory}, and the `yarn` the hook "
            f"finds {what} ({exe.why}). A Berry or an unknown yarn would ignore the Classic .yarnrc "
            "bench-config wrote (frozen lock, scripts off), migrate yarn.lock and run every "
            "dependency's install script. The same rule as a direct `yarn install`: the hook has to see "
            "Yarn Classic (1.x) on its own PATH. Start Claude Code from a shell where that `yarn` is "
            "first on the PATH (nvm and volta set it only in the shell), or ask the user."))
    return None


def _bench_executables(parsed, cwd) -> list:
    """The pip or python executables of the command that are a bench env's own."""
    return [p for p in parsed.executables if bench_config.env_bin_bench(p, cwd) is not None]


def _bench_gate(parsed, event, root, command):
    """(denial or None, extra requests, yarn targets) for the `bench` scopes of a parse, and for an
    install into a bench's env."""
    cwd = event.get("cwd") or root
    scopes = list(parsed.bench)
    if parsed.bench_pythons or _bench_executables(parsed, cwd):
        scopes.append(pg_parser.BenchScope("env-install"))
    denial = _exclusive_denial(parsed, event)
    if denial:
        return denial, [], [], []
    extras, covered, bench, yarn_targets, notes = [], [], None, [], []
    for scope in scopes:
        denial, more, found = _bench_scope_check(scope, parsed, event, root, cwd, command, yarn_targets, notes)
        if denial:
            return denial, [], [], []
        extras += more
        covered += found
    if covered:
        bench = bench_config.bench_root(cwd)
    if bench is not None:
        bench_gate.record_allowed(root, bench, covered, event.get("tool_use_id"), command)
    return None, extras, list(dict.fromkeys(yarn_targets)), list(dict.fromkeys(notes))


def _note_guard_yarnrc(root, cwd) -> None:
    """Fill `pm_config.GUARD_YARNRC_DIRS` for the bench the shell is in (see there)."""
    pm_config.GUARD_YARNRC_DIRS.clear()
    if not pg_parser.FRAPPE_ENABLED:
        return
    try:
        if bench_config.bench_root(cwd) is None:
            return
        record = bench_config.read_record(root)
        changed = {Path(p) for p, _why in bench_config.drift(root)}
    except (bench_config.BenchConfigError, OSError):
        return
    for name in record:
        path = Path(os.path.abspath(Path(root) / name))
        if path.name == ".yarnrc" and path not in changed:
            pm_config.GUARD_YARNRC_DIRS.add(os.path.realpath(path.parent))


def _acquisition(event: dict, root, command: str, early, advanced) -> dict | None:
    """The package gate: what the mode turns down."""
    parsed = early if early is not None else pg_parser.parse_command(command)
    _note_guard_yarnrc(root, event.get("cwd") or root)
    if parsed.kind == "ignore":
        if parsed.resolve_only:
            denial = _resolve_only_denial(parsed, event, root)
            if denial:
                return denial
        if parsed.runs:
            return _run_denial(parsed, event, root)
        return None

    # Something unreviewed is already installed. Deny package operations until
    # it is resolved -- and NOTHING else. `npm uninstall`, `uv remove`,
    # `pip uninstall` and `rm -rf` all classify as `ignore` and returned above;
    # they are the route out, and a blanket Bash block would make the fix
    # unreachable. The guard CLI returned even earlier, so
    # `approve`/`decline`/`reconcile` are never gated by this.
    try:
        findings = disk_guard.open_findings(root)
    except store.StoreError as exc:
        # Fail closed: an unreadable record that something unreviewed is
        # installed must not read as "nothing is wrong".
        return _decision(
            "deny",
            f"PACKAGE_GUARD_ERROR: the disk-findings record is unreadable ({exc}). "
            "Package operations are blocked until it is repaired.",
        )
    if findings:
        return _unreviewed_on_disk(findings, root)

    if parsed.kind == "unsupported":
        return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: {parsed.reason}")
    not_yet = _pm_not_yet_readable(parsed)
    if not_yet:
        return _decision("deny", not_yet)
    if parsed.resolve_only:
        # A lock-writing pnpm, Bun or Yarn command beside an acquiring one.
        denial = _resolve_only_denial(parsed, event, root)
        if denial:
            return denial
    if parsed.runs:
        denial = _run_denial(parsed, event, root)
        if denial:
            return denial
    inside = [e for e in parsed.environments if _inside_guard_dir(root, e)]
    if inside:
        # The parser refuses a `.claude` path it can read; this is the one a
        # symlink leads into.
        return _decision(
            "deny",
            f"PACKAGE_GUARD_UNSUPPORTED: the environment {inside[0]!r} resolves inside this "
            "project's .claude/, which holds Package Guard's own files. Use a directory "
            "outside .claude/, written as a literal absolute path.")
    cwd = event.get("cwd") or root
    bench_targets, bench_notes = [], []
    # An install into a bench env is one only for the bench the shell is in.
    denial = _bench_env_problem(parsed, cwd)
    if denial:
        return denial
    if pg_parser.FRAPPE_ENABLED and (parsed.bench or parsed.bench_pythons
                                     or _bench_executables(parsed, cwd)):
        denial, extra, bench_targets, bench_notes = _bench_gate(parsed, event, root, command)
        if denial:
            return denial
        if extra:
            # A custom app's declared dependencies that are not vetted exact pins go through the
            # review every named package goes through.
            parsed = dataclasses.replace(parsed, requests=parsed.requests + tuple(extra))
    if any(r.manager == "yarn" for r in parsed.requests) \
            and pm_config.yarn_flavour(cwd).kind == pm_config.CLASSIC:
        # The retry the review prints for a Classic project names Classic's own flags.
        parsed = dataclasses.replace(parsed, requests=tuple(
            dataclasses.replace(r, manager="yarn classic") if r.manager == "yarn" else r
            for r in parsed.requests))
    # Each manifest where its installer finds it, from the shell's directory
    # up (`_scope_directories`); the Python project the command acts on keys
    # its environments. A project the installer finds outside the guard root
    # is refused before anything reads it or opens a review for it.
    targets = [(scope, directory) for scope in parsed.manifests
               for directory in _scope_directories(scope, cwd, root)]
    targets += [t for t in bench_targets if t not in targets]  # what a bench verb installs, judged as a direct install is
    outside = _outside_project(targets, cwd, root)
    if outside:
        return outside
    denial = _bench_app_name_problem(parsed, targets, cwd)
    if denial:
        return denial
    project = _python_project(parsed, cwd, root)
    # A full record refuses before any review is opened: approving packages
    # for a command that is refused anyway would waste the human's prompt.
    # Recording at the allow asks the store again.
    refusal = parsed.environments and store.environments_refusal(
        root, project, list(parsed.environments))
    if refusal:
        return _decision("deny", f"PACKAGE_GUARD_UNSUPPORTED: {refusal}")
    environments = disk_guard.environments(project, root, parsed.environments)

    # pnpm, Bun and Yarn: one manager per project, the lock read in full, the
    # packageManager pin. Before any review, so a refused shape costs no prompt.
    pm_pins, pm_notes = {}, []
    routed = set()
    for scope, directory in targets:
        if scope.kind == "npm":
            denial = _npm_project_problem(directory)
            if denial:
                return denial
        if scope.kind == "yarn":
            # A Yarn Classic dependency the lock lacks goes to review by name and exact version,
            # then to the Classic route; nothing that runs yarn here is allowed meanwhile.
            denial, requests = _classic_route(root, directory, command)
            if denial:
                return denial
            if requests:
                parsed = dataclasses.replace(parsed, requests=parsed.requests + tuple(requests))
                routed.add((scope.kind, os.path.realpath(directory)))
                continue
        if scope.kind in pg_parser.PM_KINDS:
            denial, pin, note = _pm_project_problem(scope, directory)
            if denial:
                return denial
            if (scope.kind == "yarn" and scope.verb != _BENCH_YARN and pg_parser.FRAPPE_ENABLED
                    and pm_config.yarn_flavour(directory).kind == pm_config.CLASSIC):
                denial = _exclusive_denial(parsed, event)
                if denial:
                    return denial
            if scope.kind == "yarn" and scope.verb != _BENCH_YARN:
                denial = _yarn_install_denial(scope, directory, cwd)
                if denial:
                    return denial
            pm_pins[(scope.kind, os.path.realpath(directory))] = pin
            if note and note not in pm_notes:
                pm_notes.append(note)

    targets = [(scope, directory) for scope, directory in targets
               if (scope.kind, os.path.realpath(directory)) not in routed]
    vouched = {(scope.kind, os.path.realpath(directory)) for scope, directory in targets
               if scope.kind == "yarn" and _baseline_vouches(root, directory)}
    # A review vets registry/name@version; refuse when configuration, a
    # lock entry or a manifest spec would make the installer fetch from
    # anywhere else, so an approval always means what it says.
    def artifacts_of(ecosystem, name, version):
        return store.vetted_artifacts(root, {
            "ecosystem": ecosystem, "name": name, "version": version,
            "registry": pg_parser.NPM_REGISTRY if ecosystem == "npm" else pg_parser.PYPI_REGISTRY})

    try:
        problems = _source_problems(parsed, targets, cwd, root, artifacts_of=artifacts_of,
                                    environments=environments)
    except store.StoreError as exc:
        return _decision("deny", f"PACKAGE_GUARD_ERROR: Package Guard state is unavailable ({exc}). "
                                 "Package operations are blocked until it is repaired.")
    if problems:
        return _decision("deny", _render_alternate_source(problems))

    pending = []
    hard = []
    declined = []
    approved = []  # unpinned requests that resolved to an approved version
    deferred = 0
    # (ecosystem, name) pairs a gated manifest declares, so the unspent-approval
    # note does not report the command that is about to install them.
    covered = set()
    session_id = event.get("session_id")
    # One allowance and one deadline for the whole invocation, whichever path
    # a package arrives by. Two paths with a budget each could add up to more
    # than the harness ceiling.
    recheck = {"done": 0}
    allowance = _REVIEW_BATCH
    deadline = time.monotonic() + _REVIEW_BUDGET_SECONDS

    def file(report):
        if report["verdict"] == "hard_deny":
            hard.append(report)
        elif store.is_declined(root, report["resolved_identity"]):
            declined.append(report)
        elif not any(r["review_id"] == report["review_id"] for r in pending):
            pending.append(report)

    def review(requests, uv_project=False):
        nonlocal allowance, deferred
        batch, surplus = requests[:allowance], requests[allowance:]
        # The project, not the shell's directory: its environments are
        # recorded under it, and its interpreter is the one a wheel must fit.
        # A named request says which installer runs it; a manifest dependency
        # is a uv project's when its scope is (`uv_project`).
        extra = {"uv_project": True} if uv_project else {}
        reports, abandoned = _create_reviews(batch, root, session_id, deadline,
                                             project=str(project) if event.get("cwd") else None,
                                             environments=parsed.environments, **extra)
        allowance -= len(batch)
        deferred += len(surplus) + abandoned
        return reports

    try:
        named = []
        for request in parsed.requests:
            identity = {
                "ecosystem": request.ecosystem,
                "name": request.name,
                "version": request.exact_version,
                "registry": request.registry,
            }
            if request.exact_version:
                if store.is_vetted(root, identity):
                    blocked = _fresh_recheck(root, identity, recheck)
                    if blocked:
                        return blocked
                    continue
                if store.is_declined(root, identity):
                    declined.append({
                        "resolved_identity": identity,
                        "review_id": store.declined_review_id(root, identity) or "(declined earlier)",
                    })
                    continue
            # Local first (no network). A pinned request reuses the open review
            # for its exact version; an unpinned one reuses the open review of
            # its name -- resolving it again would only re-derive the version
            # this session has already put in front of the user.
            existing = store.find_open_review(
                root, session_id, identity, any_version=not request.exact_version
            )
            if existing is not None:
                file(existing)
                continue
            named.append(request)
        # Named packages share the batch and budget with manifest
        # dependencies, so neither path can outrun the deadline.
        for report in review(named):
            if (report["verdict"] == "review_required"
                    and store.is_vetted(root, report["resolved_identity"])):
                # The version this name resolves to is already approved. A new
                # review would put the same package in front of the human
                # again; the unpinned command cannot be allowed either, because
                # the installer may resolve differently from the review.
                store.discard_report(root, report["review_id"])
                approved.append(report)
                continue
            if report["verdict"] == "review_required":
                # Two unpinned requests resolving to one identity in the same
                # batch: keep the first review id, drop the duplicate report.
                existing = store.find_open_review(
                    root, session_id, report["resolved_identity"], exclude=report["review_id"]
                )
                if existing is not None and existing["review_id"] != report["review_id"]:
                    store.discard_report(root, report["review_id"])
                    report = existing
            file(report)
        # Any npm install also reconciles the manifest of the project npm
        # finds from the working directory. Those dependencies land on disk
        # without ever being named on the command line, so they need the
        # same gate. (A yarn folder an approved baseline covers is that baseline's: its direct
        # dependencies and its tree were reviewed and audited as a unit.)
        for scope, directory in [t for t in targets if (t[0].kind, os.path.realpath(t[1])) not in vouched]:
            if (scope.kind == "uv-project" and not scope.locked and not scope.relocks
                    and (Path(directory) / "uv.lock").is_file()):
                return _decision("deny", _UV_UNLOCKED)
            try:
                resolved, unresolved, where = _read_manifest(scope, directory)
            except (pg_manifest.ManifestError, lock_errors.LockReadError) as exc:
                return _decision(
                    "deny",
                    f"PACKAGE_GUARD_ERROR: the manifest for {scope.kind} could not be read ({exc}). "
                    "Package operations are blocked until it is repaired.",
                )
            pin = pm_pins.get((scope.kind, os.path.realpath(directory)))
            if pin:
                # The pinned manager is downloaded and run: it is reviewed like
                # any other npm package (Q15, D7).
                resolved = list(resolved) + [(pin[0], pin[1], "packageManager")]
            if unresolved:
                pin_kind = ("yarn-classic" if scope.kind == "yarn" and
                            pm_config.yarn_flavour(directory).kind == pm_config.CLASSIC
                            else scope.kind)
                return _decision("deny", _render_unpinned(unresolved, where, pin_kind,
                                                          _build_pins(unresolved, deadline)))
            if scope.kind in pg_parser.NPM_FAMILY_KINDS and scope.scripts and not (
                    scope.kind == "yarn"
                    and pm_config.yarn_flavour(directory).kind == pm_config.CLASSIC):
                # (A Yarn Classic install has no build allow-list: `_yarn_install_denial` already
                # proved scripts off for it, or refused.)
                blocked = _lifecycle_check(directory, root, scope.kind)
                if blocked:
                    return blocked
            ecosystem = pg_parser.scope_ecosystem(scope.kind)
            registry = pg_parser.NPM_REGISTRY if ecosystem == "npm" else pg_parser.PYPI_REGISTRY
            # Local checks first (no network), so only genuinely new packages
            # cost a round trip.
            todo = []
            for name, version, source in resolved:
                covered.add((ecosystem, name))
                identity = {
                    "ecosystem": ecosystem,
                    "name": name,
                    "version": version,
                    "registry": registry,
                }
                if store.is_vetted(root, identity):
                    blocked = _fresh_recheck(root, identity, recheck)
                    if blocked:
                        return blocked
                    continue
                if any(_identity_of(r) == identity for r in pending + hard + declined):
                    continue
                if store.is_declined(root, identity):
                    declined.append({
                        "resolved_identity": identity,
                        "review_id": store.declined_review_id(root, identity) or "(declined earlier)",
                    })
                    continue
                existing = store.find_open_review(root, session_id, identity)
                if existing is not None:
                    file(existing)
                    continue
                request = pg_manifest.as_request(name, version, command, ecosystem)
                if source == "packageManager":
                    request = dataclasses.replace(request, operation="manager-pin")
                todo.append(request)
            for report in review(todo, uv_project=scope.kind == "uv-project"):
                file(report)
    except store.StoreError as exc:
        return _decision(
            "deny",
            f"PACKAGE_GUARD_ERROR: Package Guard state is unavailable ({exc}). "
            "Package operations are blocked until it is repaired.",
        )

    if hard:
        return _decision("deny", _render_hard_deny(hard))
    if declined:
        return _decision("deny", _render_declined(declined, root))
    if pending:
        return _decision("deny", _render_review_required(pending, root, deferred)
                         + _render_pin_approved(approved, heading=False))
    if approved:
        return _decision("deny", _render_pin_approved(approved, heading=True))
    if deferred:
        # Every attempted review was abandoned. Allowing here would be the
        # timeout fail-open by another route.
        return _decision("deny", _render_deferred_only(deferred))
    # Everything named or declared is vetted -- but "vetted" is a
    # record of a past decision, and OSV has moved since. Re-ask it about the
    # approved set before trusting it again.
    relevant = set(covered) | {(r.ecosystem, r.name) for r in parsed.requests}
    blocked, audit_notes = _audit_vetted(root, relevant)
    if blocked:
        return blocked
    # Everything named or declared is vetted; what lands now is
    # the tree under it. One batch call answers "is anything in it malware".
    blocked, notes = _check_transitives(
        [t for t in targets if (t[0].kind, os.path.realpath(t[1])) not in vouched], root)
    if blocked:
        return blocked
    # Recorded before the allow, under the project directory: a record the
    # store refuses would leave an environment no scan reads.
    refusal = _record_environments(parsed, project, root)
    if refusal:
        return _decision("deny", refusal if refusal.startswith("PACKAGE_GUARD_")
                         else f"PACKAGE_GUARD_UNSUPPORTED: {refusal}")
    reason = "Package Guard: all direct external packages are exact vetted versions."
    if audit_notes:
        reason += " " + " | ".join(audit_notes) + "."
    if pm_notes:
        reason += " " + " | ".join(pm_notes) + "."
    if notes:
        reason += " Transitive check: " + " | ".join(notes) + "."
    # An allow's reason reaches the debug log, not the model.
    # Anything the agent must act on goes in additionalContext, and a material
    # risk is also shown to the user; a routine allow stays quiet.
    advisories = [n for n in audit_notes + notes if "advisories on" in n]
    context = list(bench_notes)
    if advisories:
        context.append("Package Guard allowed this install, with known advisories: "
                       + " | ".join(advisories) + ". Tell the user about them.")
    unspent = _unspent_approvals(root, advanced.installed if advanced else None,
                                 parsed, session_id, covered)
    if unspent:
        context.append(
            "Approved in this session and not installed: " + ", ".join(unspent)
            + ". Run the pinned install for those, or tell the user you did not — "
            "do not report a package as installed on the strength of its approval."
        )
    decision = _decision("allow", reason + (" " + " ".join(context) if context else ""))
    if context:
        decision["hookSpecificOutput"]["additionalContext"] = " ".join(context)
    if advisories:
        decision["systemMessage"] = "Package Guard: install allowed with known advisories — " + \
            " | ".join(advisories)
    return decision


# Set while acquisition runs in warn mode: the user asked not to be blocked,
# and a slow network is one of the ways a guard is broken.
_WARN_RUNNING = False


def _watchdog(_signum, _frame):
    if _WARN_RUNNING:
        reply = _join_output(
            None, "Package Guard (warn mode) ran out of time before deciding; not blocking.",
            "Package Guard is in warn mode and ran out of time before deciding, so it did not "
            "block this command; it goes to the user's normal permission prompt.")
    else:
        reply = _decision(
            "deny",
            "PACKAGE_GUARD_REVIEW_BUDGET: Package Guard ran out of time before deciding. "
            "Nothing was installed. Re-run the same command; reviews already opened are reused.")
    sys.stdout.write(json.dumps(reply))
    sys.stdout.flush()
    os._exit(0)


def _arm_watchdog():
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _watchdog)
        signal.alarm(_WATCHDOG_SECONDS)


# A project that still has the file install runs both guards once the plugin
# arrives (org sync puts it in every project), and each refuses the other's
# approve command, so no approval can complete. The plugin never stands down for
# a file install it finds -- a cloned repository could ship a fake one -- it says
# how to migrate instead.
_MIGRATE_NOTE = (
    "\n\nNOTE: this project still has the older file-based Package Guard install, so two "
    "guards run and an approval cannot complete (each refuses the other's approve command). "
    "Ask the user to migrate once: run /package-guard:setup (it removes the old hooks and "
    "keeps the approvals), then restart Claude Code.")


def _with_migration_note(decision: dict, root) -> dict:
    if not store.plugin_mode():
        return decision
    if not (Path(root) / ".claude" / "hooks" / "package_guard").is_dir():
        return decision
    out = decision.get("hookSpecificOutput")
    reason = out.get("permissionDecisionReason") if isinstance(out, dict) else None
    if (out.get("permissionDecision") == "deny" and isinstance(reason, str)
            and reason.startswith(("PACKAGE_GUARD_REVIEW_REQUIRED", "PACKAGE_GUARD_CLI_REFUSED"))):
        out["permissionDecisionReason"] = reason + _MIGRATE_NOTE
    return decision


def _way_out() -> str:
    """The guard still fails closed; this names the supported way past a
    broken one."""
    try:
        command = store.human_command(store.project_root(__file__), "mode", 'warn --reason "<why>"')
    except Exception:  # noqa: BLE001 - the message must print whatever broke
        command = 'sh .claude/hooks/package_guard/pg mode warn --reason "<why>"'
    return ("If this keeps happening, the user can run, in their own terminal, from the "
            f"project folder:\n  {command}\nand report the bug.")


def main() -> int:
    _arm_watchdog()
    try:
        event = json.load(sys.stdin)
    except ValueError:
        print("Package Guard: hook received malformed JSON input; failing closed.", file=sys.stderr)
        return 2
    try:
        root = store.project_root(__file__)
        decision = evaluate(event, root)
        if decision is not None:
            decision = _with_migration_note(decision, root)
    except Exception as exc:  # fail closed on any internal error
        print(f"Package Guard: internal failure ({exc.__class__.__name__}: {exc}); failing closed.\n"
              f"{_way_out()}", file=sys.stderr)
        return 2
    if decision is not None:
        json.dump(decision, sys.stdout)
    return 0


def _exit_now(code: int) -> None:
    """Exit without joining abandoned worker threads, so the process ends inside the
    harness ceiling."""
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


if __name__ == "__main__":
    _exit_now(main())
