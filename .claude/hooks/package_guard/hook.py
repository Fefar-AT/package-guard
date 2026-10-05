#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Package Guard — Claude Code PreToolUse hook for Bash package commands.

Reads the hook event JSON on stdin and prints a PreToolUse permission
decision. Unrelated commands produce no output (normal permission flow).

Failure policy: internal errors while evaluating a package operation fail
closed (deny / exit 2). Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from concurrent import futures
from pathlib import Path

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
    import disk_guard  # noqa: E402
    import manifest as pg_manifest  # noqa: E402
    import parser as pg_parser  # noqa: E402
    import sources  # noqa: E402
    import store  # noqa: E402
    import transcript  # noqa: E402
    import vetting  # noqa: E402
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
# wrapped or prefixed form would run outside it.
_GUARD_CLI_HINT = re.compile(
    r"package_guard/cli\.py\s+(?:approve|decline|undecline|revoke|reconcile|audit)\b")

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
    """The installer's lock rules are in this project's settings."""
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


def _git_write(sub, args, here, protected, inside, opaque=False) -> bool:
    """Would this git command change a tracked or untracked guard file? `inside(word)` resolves a pathspec and tells whether
    it is in (True), above ("above") or outside (False) the guard files.
    Anything git cannot answer counts as a write; so does any tree-changing
    command run with GIT_* variables the hook cannot see through (`opaque`)."""
    if sub in ("rm", "mv") and not opaque:
        return any(inside(a) for a in args if not a.startswith("-"))
    # A pathspec inside the guard files is a write whatever git would make of it.
    if any(inside(a) is True for a in args if not a.startswith("-")):
        return True
    found = _git(["rev-parse", "--show-toplevel"], here)
    if found is None:
        return True
    if found[0] != 0:
        return False  # not a repository: git refuses, nothing is written
    top = os.path.realpath(found[1].strip())
    real = [os.path.realpath(p) for p in protected]
    guard = [os.path.relpath(p, top) for p in real if p == top or p.startswith(top + "/")]
    if not guard:
        return False
    if opaque:
        return True

    def differs(*revs) -> bool:
        result = _git(["diff", "--quiet", *revs, "--", *guard], top)
        return result is None or result[0] != 0

    def untracked(*extra) -> bool:
        result = _git(["ls-files", "--others", *extra, "--", *guard], top)
        return result is None or result[0] != 0 or bool(result[1].strip())

    def commit(rev) -> bool:
        result = _git(["rev-parse", "--verify", "--quiet", rev + "^{commit}"], top)
        return result is not None and result[0] == 0

    def remote(name) -> str | None:
        """The remote branch `git checkout/switch <name>` would create from."""
        listed = _git(["for-each-ref", "--format=%(refname)", "refs/remotes/*/" + name], top)
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
                tracked = _git(["ls-files", "--", *guard], top)
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
            third = _git(["ls-tree", "-r", "--name-only", ref + "^3", "--", *guard], top)
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
        listed = _git(["apply", "--numstat", "-z", *[os.path.join(here, o) for o in operands]],
                      top)
        if listed is None or listed[0] != 0:
            return True
        touched = []
        for field in listed[1].split("\0"):
            touched.append(field.split("\t")[-1])
        return any(t and (inside(os.path.join(top, t)) or inside(t)) for t in touched)
    return True


def _precise_guard_write(command: str, root, cwd, locked: bool):
    """Return (understood, kind-or-None)."""
    home = str(Path.home())
    root = os.path.normpath(str(root))
    state = [os.path.join(root, p) for p in _STATE_PATHS] + [os.path.join(home, ".config/package-guard")]
    source = [os.path.join(root, p) for p in _SOURCE_PATHS] if locked else []
    real_state = [os.path.realpath(p) for p in state]
    real_source = [os.path.realpath(p) for p in source]
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
            if name in ("cd", "pushd"):
                if len(operands) != 1 or len(args) != 1:
                    raise _NotUnderstood
                here, moved = resolve(operands[0]), True
                continue
            if name == "git":
                at = here
                while args and args[0].startswith("-"):
                    if args[0] == "-C" and len(args) > 1:
                        at, args = resolve(args[1]), args[2:]
                    elif args[0] == "-c" and len(args) > 1:
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
                opaque = any(n.startswith("GIT_") for n in assigned)
                wrote = _git_write(args[0], args[1:], here, source + state, inside, opaque)
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
                found = _coarse_guard_write(shlex.join(words), locked)
            if found:
                return True, found
    except _NotUnderstood:
        return False, None
    return True, None


def _guard_write(command: str, root, cwd=None, locked: bool | None = None):
    """'state', 'source', 'git', or None: what guard file a Bash command writes."""
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
    return _coarse_guard_write(command, locked)


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
    "`--locked` run reviews the new lock."
)


_SCRIPTS_OFF_HINT = ("or install with scripts off: add `--ignore-scripts` to the same "
                     "command")


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
        if piped and _SCRIPT_INTERPRETERS.match(command):
            return "runs-file", chain
        if _SCRIPT_INTERPRETERS.match(command) and (
                command == "make" or any(not a.startswith("-") for a in args)
                or any(a.split("=", 1)[0] in _INLINE_CODE_FLAGS for a in args)):
            return "runs-file", chain
        if "/" in words[0] and not words[0].startswith("node_modules/.bin/"):
            return "runs-file", chain
        if command != "npm":
            continue
        if any(a in ("--prefix", "-C", "--workspace", "-w", "--workspaces", "-ws")
               or a.startswith(("--prefix=", "--workspace=")) for a in args):
            return "unresolved", chain
        verbs = [a for a in args if not a.startswith("-")]
        if not verbs:
            continue
        verb = verbs[0]
        if verb in _NPM_RUN:
            if len(verbs) < 2:
                continue  # `npm run` alone lists the scripts
            targets = [verbs[1]]
        elif verb in _NPM_RUN_FIXED:
            targets = [_NPM_RUN_FIXED[verb]]
            if targets == ["restart"] and "restart" not in scripts:
                targets = ["stop", "start"]
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


def _render_script_problem(kind, chain) -> str:
    (first, body), path = chain[0], " -> ".join(
        f"`scripts.{n}`" + (f" (`{b}`)" if b is not None else " (missing)") for n, b in chain[1:])
    via = f", which leads to {path}" if path else ""
    head = f"PACKAGE_GUARD_UNSUPPORTED: package.json `scripts.{first}` runs `{body}`{via}"
    if kind == "acquires":
        return (f"{head}. npm executes it during this install and it acquires packages. Run "
                "that acquisition as its own command first so it is reviewed (pin it to an exact "
                f"version in the script), {_SCRIPTS_OFF_HINT}.")
    if kind == "runs-file":
        return (f"{head}. npm executes it during this install, and it runs code from a file, an "
                "inline interpreter or a pipe into a shell, which Package Guard cannot read, so "
                "it cannot tell what that code acquires. Install with scripts off: add "
                "`--ignore-scripts` to the same command. Then tell the user that this script did "
                "not run; whether to run it is theirs to decide.")
    return (f"{head}. npm executes it during this install, and Package Guard cannot resolve that "
            "script in this package.json (missing, a cycle, more than "
            f"{_SCRIPT_DEPTH} levels deep, unreadable, or another directory). Install with "
            "scripts off: add `--ignore-scripts` to the same command, and tell the user.")


def _lifecycle_check(directory, root):
    """With scripts on, `npm install` / `npm ci` run code the
    gate would otherwise never see: the root package.json's own lifecycle
    scripts, the sibling scripts they reach through `npm run`, and install
    scripts of locked packages. A root script that acquires packages must
    acquire only exact vetted versions; one that runs a file the gate cannot
    read is refused; a locked package that runs an install script must itself
    be vetted."""
    lifecycle = pg_manifest.npm_root_lifecycle_scripts(directory)
    scripts = _root_scripts(directory) if lifecycle else {}
    for name, body in lifecycle:
        found = _script_problem(name, body, scripts, root, [])
        if found:
            return _decision("deny", _render_script_problem(*found))
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


def _read_manifest(scope, directory):
    """(resolved, unresolved, where) for one ManifestScope."""
    if scope.kind == "npm":
        resolved, unresolved = pg_manifest.direct_dependencies(directory)
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
            more, missing = pg_manifest.build_requires(built)
            resolved, unresolved = resolved + more, unresolved + missing
        return resolved, unresolved, Path(directory) / "uv.lock"
    if scope.kind == "build-requires":
        resolved, unresolved = pg_manifest.build_requires(directory)
        return resolved, unresolved, Path(directory) / "pyproject.toml"
    raise pg_manifest.ManifestError(f"unknown manifest kind {scope.kind!r}")


def _create_reviews(requests, root, session_id, deadline=None):
    """(reports, abandoned) for PackageRequests, in the given order.

    `deadline` is a time.monotonic() value shared by every call in one hook
    invocation (None starts a fresh budget). `abandoned` counts requests whose
    review did not finish in time. Their reports are not returned; a review
    that was mid-flight may still land on disk afterwards, and the next run
    picks it up unchanged.
    """
    if not requests:
        return [], 0
    if deadline is None:
        deadline = time.monotonic() + _REVIEW_BUDGET_SECONDS
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return [], len(requests)

    def build(request):
        return vetting.create_review(request, root, session_id=session_id)

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
    "requirements": (
        "Let a resolver pin them into a fully-pinned requirements file, which "
        "installs nothing:",
        "  uv pip compile <input>.in -o <this-file>",
        "Editing every line to a bare name==version pin works too.",
    ),
    "build-requires": (
        "An isolated build fetches these build requirements from PyPI and runs them. "
        "Pin each in pyproject.toml's [build-system] requires to an exact version "
        "(name==version), or build without isolation:",
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


def _render_unpinned(unresolved, where, kind) -> str:
    """The manifest declares versions Package Guard cannot pin to an exact release."""
    lines = [
        "PACKAGE_GUARD_MANIFEST_UNPINNED",
        f"manifest: {where}",
        "",
        "This command installs everything the manifest lists, so these dependencies "
        "would land without ever being named on the command line. Package Guard "
        "cannot vet them because they are not pinned to exact versions:",
    ]
    lines += [f"  {name}: {spec}" for name, spec in unresolved]
    intro, fix, extra = _PIN_HELP.get(kind, _PIN_HELP["npm"])
    lines += ["", intro, fix]
    directory = Path(where).parent
    lines.append(f"Run it with {directory} as the working directory, so it resolves the "
                 "manifest above and not another one: change directory in its own command "
                 "first, then run the pinning command bare -- no `cd ... &&`, no pipe, no `;`.")
    lines += ["", "Then re-run the install. The exact pinned versions become the reviews."]
    if extra:
        lines.append(extra)
    return "\n".join(lines)


def _age(days) -> str:
    if not isinstance(days, int):
        return "unknown"
    if days >= 365:
        return f"{days // 365}y"
    return f"{days}d"


def _render_install_time_code(identity: dict, evidence: dict) -> str:
    """npm lists lifecycle scripts; PyPI says whether a wheel exists."""
    if identity.get("ecosystem") == "pypi":
        distribution = evidence.get("distribution")
        if distribution == "wheel":
            return "  install-time code: wheel (none)"
        if distribution == "sdist-only":
            return "  install-time code: sdist only (setup.py may run)"
        if distribution == "sdist-build":
            return "  install-time code: no wheel for this platform (setup.py may run)"
        return "  install-time code: not determined"
    return f"  install scripts: {', '.join(evidence.get('install_scripts') or []) or 'none'}"


def _render_verdict(verdict: dict) -> list:
    """Only the sanitised fields transcript.vetter_verdicts kept:
    the verdict token, an integer, a status token, red-flag codes and a package
    reference. Free text from the vetter never reaches the prompt."""
    lines = [
        f"  vetter: {verdict['verdict']}  confidence {verdict['confidence']}  "
        f"evidence: {verdict['evidence_status']}"
    ]
    for flag in verdict.get("red_flags") or []:
        lines.append(f"  red flag: {flag}")
    if verdict.get("alternative"):
        lines.append(f"  alternative: {verdict['alternative']}")
    return lines


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
        return vetting.gather(request)

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
    view["risk_signals"] = found["risk_signals"]
    view["refreshed_at"] = store.utcnow()
    return view


def _render_package_block(report: dict, verdict: dict | None = None) -> list:
    identity = report["resolved_identity"]
    osv = report["mandatory_checks"].get("osv", {})
    evidence = report.get("evidence", {})
    provenance = (report.get("optional_checks") or {}).get("provenance")
    if isinstance(provenance, dict):
        attested = "attested" if provenance.get("attested") else "none"
    else:
        attested = "not checked"
    maintainers = evidence.get("maintainers") or []
    publisher = evidence.get("publisher")
    who = f"publisher: {publisher or 'unknown'}"
    if maintainers:
        who += f" (maintainers: {', '.join(str(m) for m in maintainers[:5])}"
        who += ", ..." if len(maintainers) > 5 else ")"
    lines = [
        f"{_label(identity)}",
        f"  registry: {identity['registry']}",
        f"  review: {report['review_id']}",
        "  checks: exists on official registry; "
        f"OSV malware records: {len(osv.get('malware_ids') or [])}; "
        f"known vulnerabilities: {len(evidence.get('known_vulnerabilities') or [])}",
        f"  repository: {evidence.get('repository_url') or 'none listed'}",
        _render_install_time_code(identity, evidence),
        f"  provenance: {attested}; {who}",
        f"  age: package {_age(evidence.get('package_age_days'))}, "
        f"version {_age(evidence.get('version_age_days'))}; "
        f"releases: {evidence.get('release_count') if evidence.get('release_count') is not None else 'unknown'}; "
        f"deps: {evidence.get('dependency_count') if evidence.get('dependency_count') is not None else 'unknown'}; "
        f"license: {evidence.get('license') or 'none declared'}",
    ]
    for signal in report.get("risk_signals") or []:
        lines.append(f"  risk signal: {signal}")
    lines += _render_reputation(report)
    if report.get("refreshed_at"):
        lines.append(f"  evidence refreshed: {report['refreshed_at']} (reviewed {report.get('created_at')})")
    if verdict:
        lines += _render_verdict(verdict)
    return lines


def _render_reputation(report: dict) -> list:
    """The deterministic tier and the facts behind it, for the prompt.

    Only numbers, booleans and fixed phrases from the hook's own block reach
    the prompt; `unmet` entries are the hook's own strings, never researched
    content."""
    reputation = (report.get("optional_checks") or {}).get("reputation")
    if not isinstance(reputation, dict):
        return ["  reputation: not checked"]
    trust = reputation.get("trust") or {}
    if trust.get("status") == "trusted":
        lines = [
            f"  user trust: TRUSTED IDENTITY (catalog {trust.get('catalog_version')})",
            f"  canonical repository: {trust.get('repository')}",
            "  project approval: HUMAN PERMISSION REQUIRED for this exact version",
            "  reputation: " + ("ESTABLISHED (catalog identity and release checks; no vetter run)"
                                 if reputation.get("tier") == "established" else "unresolved (release needs review)"),
        ]
        lines.extend(f"    unmet: {reason}" for reason in reputation.get("unmet") or [])
        return lines
    # A catalog fault withdrew the shortcut and decided nothing
    # else; the tier below stands on the package's own evidence.
    prefix = ([f"  user trust: catalog not consulted ({trust.get('reason')})"]
              if trust.get("status") in ("expired", "unavailable") else [])
    downloads = reputation.get("weekly_downloads")
    manifest = reputation.get("manifest") or {}
    names = manifest.get("names_package")
    manifest_text = {True: "names this package", False: "does NOT name this package"}.get(
        names, "not checked")
    near = reputation.get("near_names") or []
    if reputation.get("tier") == "established":
        near_text = (f"none of {len(near)} near name(s) has {vetting.LOOKALIKE_DOWNLOAD_RATIO}x its downloads"
                     if near else "no near name on the registry")
        return prefix + [
            "  reputation: ESTABLISHED (deterministic; no vetter run) -- "
            f"weekly downloads {downloads:,}; repository manifest {manifest_text}; {near_text}"
        ]
    lines = prefix + [
        f"  reputation: unresolved -- weekly downloads "
        f"{f'{downloads:,}' if isinstance(downloads, int) else 'unknown'}; "
        f"repository manifest {manifest_text}"
    ]
    for reason in reputation.get("unmet") or []:
        lines.append(f"    unmet: {reason}")
    return lines


def _render_approval(reports, verdicts: dict | None = None) -> str:
    verdicts = verdicts or {}
    count = len(reports)
    header = f"Package Guard approval — {count} package{'s' if count != 1 else ''}"
    said = [verdicts[r["review_id"]]["verdict"] for r in reports if r["review_id"] in verdicts]
    notes = []
    if said.count("DO_NOT_RECOMMEND"):
        notes.append(f"{said.count('DO_NOT_RECOMMEND')} not recommended by the vetter")
    if said.count("NEEDS_HUMAN_REVIEW"):
        notes.append(f"{said.count('NEEDS_HUMAN_REVIEW')} left to your judgement by the vetter")
    if notes:
        header += f" ({'; '.join(notes)})"
    lines = [header, ""]
    for report in reports:
        lines += _render_package_block(report, verdicts.get(report["review_id"]))
        lines.append("")
    if count == 1:
        lines.append("Approve this exact version for this project?")
    else:
        lines += [
            "Approve ALL of these exact versions for this project?",
            "To skip one: reject this prompt and tell Claude which to leave out; it re-approves "
            "the rest. A permanent decline is only for a package you never want here.",
        ]
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


def _handle_cli(call, root, transcript_path=None) -> dict:
    subcommand, review_ids = call
    if subcommand == "show":
        return _decision("allow", "Package Guard: read-only review display.")
    if subcommand in ("decline", "undecline", "revoke"):
        # Every verb that changes what may install is a human act: decline is
        # permanent and stamps `declined_by: human` (ungated, it would let an
        # agent blacklist canonical packages on its own), and revoke withdraws
        # an approval a human gave.
        if not review_ids:
            return _decision("deny", f"Package Guard: '{subcommand}' requires at least one review id.")
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
                f"Package Guard: cannot {subcommand} — " + " | ".join(problems)
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
        return _decision("deny", f"Package Guard CLI: unknown subcommand {subcommand!r}.")
    if not review_ids:
        return _decision("deny", "Package Guard: 'approve' requires at least one review id.")
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
            "Package Guard: cannot approve — nothing was vetted. "
            + " | ".join(problems)
            + ". Remove the offending id(s) and re-run approve with the rest.",
        )
    # The vetter's report exists only in the conversation, so the transcript is
    # the one copy this hook can read. No block for an id means the human would
    # be shown a prompt with no research behind it. The verdict itself is not
    # enforced: a DO_NOT_RECOMMEND still reaches the prompt, marked.
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
            "Package Guard: cannot approve — no package-vetter verdict in this session for "
            + " ".join(missing)
            + ". Wait for the vetter's notification. If its report arrived without a verdict "
            "for ids that vetter was launched with, ask the same vetter (SendMessage to its "
            "agent id) to resend its full report with the machine blocks; launch a new vetter "
            "only if it cannot be reached. A review id never given to a vetter needs a new "
            "package-vetter launch with that id; do not send it to an existing vetter. "
            "Approve only after a verdict has arrived.",
        )
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
            "Package Guard: cannot approve — the established reputation did not hold at approve time for "
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


def _locked_tree(scope, directory):
    """(ecosystem, [(name, version)], lockfile path) for a gated manifest, or None."""
    if scope.kind == "npm":
        return "npm", pg_manifest.npm_locked_tree(directory), Path(directory) / "package-lock.json"
    if scope.kind == "uv-project":
        return "pypi", pg_manifest.uv_locked_tree(directory), Path(directory) / "uv.lock"
    return None  # a requirements file is already flattened: every line is direct


def _check_transitives(scopes, directory, root) -> tuple:
    """(denial or None, notes) for the trees the command installs.

    Runs only on the allow path: direct dependencies are all vetted, so what
    lands now is the tree. Vetted and declined identities are skipped (they
    were judged individually); a MAL record on anything else denies; other
    advisories become notes on the allow. Cached per lockfile digest.
    """
    import hashlib
    notes = []
    calls = 0
    for scope in scopes:
        tree = _locked_tree(scope, directory)
        if tree is None:
            continue
        ecosystem, pairs, lock = tree
        if not pairs:
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
        if report.get("retry_command"):
            blocks.append(f"retry: {report['retry_command']}")
    unresolved_ids = " ".join(r["review_id"] for r in unresolved)
    established_ids = " ".join(r["review_id"] for r in established)
    blocks += [
        "",
        "STOP. Do not run any other install, npx, pip, or uv package command.",
    ]
    if established:
        blocks += [
            f"ESTABLISHED ids [{established_ids}]: the hook's own checks hold (age, releases, weekly "
            "downloads, repository manifest, no near-name giant, no install script, no advisory, "
            "allowed license, not fresh). No vetter is needed. State in one line per package whether "
            "it is the mainstream choice for its purpose and name a successor if you know one, then "
            "run ONE approve command with these ids, exactly as written and as a simple standalone "
            f"command (no `cd`, no `&&`): {store.cli_command(root, 'approve', established_ids)}",
        ]
    if unresolved:
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
            "THEN: for every RECOMMEND verdict, run ONE approve command with all of those ids, "
            "exactly as written and as a simple standalone command (no `cd`, no `&&`): "
            f"{store.cli_command(root, 'approve', unresolved_ids)}",
            "The user will see a single permission prompt carrying the vetter's verdict; approve is "
            "refused for an unresolved id until the vetter's notification has arrived. For "
            "DO_NOT_RECOMMEND / NEEDS_HUMAN_REVIEW, do not approve; ask the user, offering the "
            "alternative the vetter named.",
        ]
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


def _advance_watermark(event: dict, root) -> None:
    """Decide on everything already installed, before this command runs.

    After this, whatever the command puts on disk is attributable
    to *that* command rather than to the accumulated past, which is what makes
    the PostToolUse report readable.

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


def evaluate(event: dict, root) -> dict | None:
    if event.get("tool_name") != "Bash":
        return None
    tool_input = event.get("tool_input")
    command = (tool_input or {}).get("command") or ""

    advanced = _advance_watermark(event, root)

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = None
    if tokens:
        call = _guard_cli_call(tokens)
        if call:
            if not _clean_project_cli(tokens, root, event.get("cwd")):
                return _decision(
                    "deny",
                    "PACKAGE_GUARD_UNSUPPORTED: run this project's own Package Guard CLI, "
                    "with no other `uv` option, exactly as:\n  "
                    f"{store.cli_command(root, call[0] or '<subcommand>', ' '.join(call[1]) or '<review-id> ...')}",
                )
            return _handle_cli(call, root, event.get("transcript_path"))

    # The command names the guard CLI's approve/decline path but was not
    # recognised as a clean standalone invocation above. Falling through would
    # hand it to the normal permission flow, where an auto-accept mode runs it
    # with no human prompt — silently defeating the approval gate. Fail closed.
    if _GUARD_CLI_HINT.search(command):
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: a Package Guard approve/decline must be a simple "
            "standalone command — not wrapped in a `cd`, `&&`, `;`, subshell, or any other "
            "compound or dynamic shell syntax. Re-run it on its own, using this absolute "
            f"path so no directory change is needed:\n  {store.cli_command(root, '<approve|decline>', '<review-id> ...')}",
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
    if written == "state":
        return _decision(
            "deny",
            "PACKAGE_GUARD_UNSUPPORTED: Package Guard state under .claude/package-guard/ is written "
            "only by the guard CLI, behind a permission prompt. Read it freely (cat, ls, grep); "
            "change it only through: "
            f"{store.cli_command(root, '<approve|decline|undecline|revoke>', '<review-id> ...')}",
        )

    parsed = pg_parser.parse_command(command)
    if parsed.kind == "ignore":
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

    # A review vets registry/name@version; refuse when configuration, a
    # lock entry or a manifest spec would make the installer fetch from
    # anywhere else, so an approval always means what it says.
    def artifacts_of(ecosystem, name, version):
        return store.vetted_artifacts(root, {
            "ecosystem": ecosystem, "name": name, "version": version,
            "registry": pg_parser.NPM_REGISTRY if ecosystem == "npm" else pg_parser.PYPI_REGISTRY})

    try:
        problems = sources.problems_for(parsed, event.get("cwd") or root, artifacts_of=artifacts_of)
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

    def review(requests):
        nonlocal allowance, deferred
        batch, surplus = requests[:allowance], requests[allowance:]
        reports, abandoned = _create_reviews(batch, root, session_id, deadline)
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
        # Any npm install also reconciles the manifest in its working
        # directory. Those dependencies land on disk without ever being named
        # on the command line, so they need the same gate.
        for scope in parsed.manifests:
            directory = event.get("cwd") or root
            if (scope.kind == "uv-project" and not scope.locked and not scope.relocks
                    and (Path(directory) / "uv.lock").is_file()):
                return _decision("deny", _UV_UNLOCKED)
            try:
                resolved, unresolved, where = _read_manifest(scope, directory)
            except pg_manifest.ManifestError as exc:
                return _decision(
                    "deny",
                    f"PACKAGE_GUARD_ERROR: the manifest for {scope.kind} could not be read ({exc}). "
                    "Package operations are blocked until it is repaired.",
                )
            if unresolved:
                return _decision("deny", _render_unpinned(unresolved, where, scope.kind))
            if scope.kind == "npm" and scope.scripts:
                blocked = _lifecycle_check(directory, root)
                if blocked:
                    return blocked
            ecosystem = "npm" if scope.kind == "npm" else "pypi"
            registry = pg_parser.NPM_REGISTRY if ecosystem == "npm" else pg_parser.PYPI_REGISTRY
            # Local checks first (no network), so only genuinely new packages
            # cost a round trip.
            todo = []
            for name, version, _source in resolved:
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
                todo.append(pg_manifest.as_request(name, version, command, ecosystem))
            for report in review(todo):
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
    blocked, notes = _check_transitives(parsed.manifests, event.get("cwd") or root, root)
    if blocked:
        return blocked
    reason = "Package Guard: all direct external packages are exact vetted versions."
    if audit_notes:
        reason += " " + " | ".join(audit_notes) + "."
    if notes:
        reason += " Transitive check: " + " | ".join(notes) + "."
    # An allow's reason reaches the debug log, not the model.
    # Anything the agent must act on goes in additionalContext, and a material
    # risk is also shown to the user; a routine allow stays quiet.
    advisories = [n for n in audit_notes + notes if "advisories on" in n]
    context = []
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


def _watchdog(_signum, _frame):
    sys.stdout.write(json.dumps(_decision(
        "deny",
        "PACKAGE_GUARD_REVIEW_BUDGET: Package Guard ran out of time before deciding. "
        "Nothing was installed. Re-run the same command; reviews already opened are reused.")))
    sys.stdout.flush()
    os._exit(0)


def _arm_watchdog():
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _watchdog)
        signal.alarm(_WATCHDOG_SECONDS)


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
    except Exception as exc:  # fail closed on any internal error
        print(f"Package Guard: internal failure ({exc.__class__.__name__}: {exc}); failing closed.", file=sys.stderr)
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
