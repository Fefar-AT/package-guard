"""A small shell lexer: split a command into segments of words.

This exists because `shlex` cannot model the things the recognizer needs to
get right -- heredoc bodies, fd-prefixed redirects, quoted-versus-unquoted `$`,
and the command substitutions that run inside an ordinary word -- and getting
them wrong produces both silent installs and false positives.

It is NOT a shell. Arbitrary shell obfuscation is out of scope, and a universal
shell parser is deliberately not attempted. This handles the ordinary
forms an honest agent types and reports `ok=False` for anything else, so the
caller can fall back to a fail-closed text check.

Standard library only.
"""
from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass, field

# Operators that end a segment. Longest first: the scanner matches greedily.
_SEGMENT_OPS = ("&&", "||", "|&", ";;", ";", "|", "&", "\n")

# Redirection operators. The operator and its target are kept out of the
# segment's words, so `uv sync 2>&1 | tail` reduces to exactly `uv sync`; the
# target is kept on `Segment.redirects`, because a command that writes a
# manifest and then installs is reading a file the guard never saw.
_REDIR_OPS = ("&>>", "<<<", "&>", ">>", "<<-", "<<", ">|", ">&", "<&", ">", "<")

# The redirections that open their target for writing.
WRITE_REDIRECTS = frozenset({">", ">>", ">|", "&>", "&>>", ">&"})

# Constructs that make a word's value unknowable at parse time. A package name
# we cannot read is a package we must not guess at. The special parameters
# count too: `$1`, `$@` and `$*` are whatever the caller set them to.
_DYNAMIC = re.compile(r"\$\(|`|\$\{|\$[A-Za-z_0-9@*#?$!-]|<\(|>\(")
# Deliberately does NOT include `[`: a bracket in a package spec is almost
# always pip extras (`.[dev]`, `uvicorn[standard]`), not a character class.
# Treating it as a glob replaced correct, specific refusals with a misleading
# "identity is built dynamically" message.
_GLOB = re.compile(r"[*?]|\{[^}]*,[^}]*\}")

_GROUPING = set("(){}")


def is_dynamic(text) -> bool:
    """True when unquoted `text` holds an expansion, substitution or glob."""
    return bool(_DYNAMIC.search(text) or _GLOB.search(text))

# Shell keywords that may precede the real head of a segment.
KEYWORDS = {
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
    "case", "esac", "function", "select", "in", "!", "[[", "time", "{", "}",
}


@dataclass(frozen=True)
class Word:
    text: str
    quoted: bool = False        # any part of it was inside quotes
    dynamic: bool = False       # contains an unquoted expansion or glob
    glued_op: bool = False      # an operator was glued to it, e.g. requests>=2.0
    # It starts with an unquoted `NAME=`, which is what makes the shell read it
    # as an assignment. The value may be quoted: `X="a b" npm install x` runs
    # npm with X set, so it must not be read as a command named `X=a b`.
    assign: bool = False

    def __str__(self):
        return self.text


@dataclass
class Segment:
    words: list = field(default_factory=list)
    # A heredoc fed this segment. The body is never one of its words: a
    # heredoc body is data, not a command.
    had_heredoc: bool = False
    # (body, expands) for each heredoc. `expands` is False when the delimiter
    # was quoted (`<<'EOF'`), so `$(...)` in the body stays text.
    heredocs: list = field(default_factory=list)
    # (operator, Word) for each redirection: the file `>` writes, the text
    # `<<<` feeds.
    redirects: list = field(default_factory=list)
    # The text of each command substitution in the segment: `$(...)` and
    # backticks, bare, inside double quotes or in an expanding heredoc body,
    # and `<(...)` / `>(...)`. Each runs as a command of its own.
    substitutions: list = field(default_factory=list)
    # The segment reads the previous one's output: it follows `|` or `|&`.
    piped: bool = False

    def __bool__(self):
        return bool(self.words)


def _mark(raw_parts):
    """Build a Word from (text, was_quoted) fragments."""
    text = "".join(part for part, _q in raw_parts)
    quoted = any(q for _p, q in raw_parts)
    unquoted = "".join(part for part, q in raw_parts if not q)
    dynamic = bool(_DYNAMIC.search(unquoted) or _GLOB.search(unquoted))
    leading = []
    for part, was_quoted in raw_parts:
        if was_quoted:
            break
        leading.append(part)
    assign = bool(_ASSIGNMENT.match("".join(leading)))
    return Word(text=text, quoted=quoted, dynamic=dynamic, assign=assign)


# `NAME+=VALUE` appends, and bash and zsh both accept it before a command.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")


def segment(command):
    """Split `command` into Segments.

    Returns (segments, ok). ok=False means the text could not be lexed
    confidently -- an unbalanced quote or substitution, or an unterminated
    heredoc -- and the caller must fall back to a fail-closed check rather
    than trusting the partial result.
    """
    if not command or not command.strip():
        return [], True

    segments = []
    current = Segment()
    parts = []          # fragments of the word being built
    started = False     # a word is in progress (may be empty, e.g. "")
    pending_heredocs = []
    pending_redirect = None   # the operator whose target the next word is
    index = 0
    length = len(command)
    glue_next = False

    def flush_word():
        nonlocal parts, started, glue_next, pending_redirect
        if started:
            word = _mark(parts)
            if glue_next:
                word = dataclasses.replace(word, glued_op=True)
            if pending_redirect:
                current.redirects.append((pending_redirect, word))
                pending_redirect = None
            else:
                current.words.append(word)
        parts = []
        started = False
        glue_next = False

    def flush_segment(piped=False):
        nonlocal current, pending_redirect
        flush_word()
        pending_redirect = None
        if current.words or current.redirects or current.substitutions:
            segments.append(current)
        current = Segment(piped=piped)

    while index < length:
        char = command[index]

        # --- quoting -------------------------------------------------------
        if char == "'":
            close = command.find("'", index + 1)
            if close == -1:
                return segments, False
            parts.append((command[index + 1:close], True))
            started = True
            index = close + 1
            continue

        if char == '"':
            close = _close_double(command, index + 1)
            if close == -1:
                return segments, False
            text, found = _double_quoted(command[index + 1:close])
            current.substitutions.extend(found)
            # Double quotes still expand $ and `; keep it as an unquoted
            # fragment for dynamism purposes but quoted for splitting.
            dynamic = bool(_DYNAMIC.search(text))
            parts.append((text, not dynamic))
            if dynamic:
                parts.append(("", True))
            started = True
            index = close + 1
            continue

        if char == "\\":
            if command.startswith("\\\n", index):
                # A line continuation: the shell removes the pair and joins
                # the lines. Kept as a word, `A=1 \<newline> npm i x` had a
                # newline for its head and the install went unseen.
                index += 2
                continue
            if index + 1 < length:
                parts.append((command[index + 1], True))
                started = True
                index += 2
                continue
            index += 1
            continue

        # --- whitespace ----------------------------------------------------
        if char in " \t":
            flush_word()
            index += 1
            continue

        # --- substitutions: they run, wherever in a word they sit ----------
        # `$(...)` (and arithmetic `$((...))`), backticks, and process
        # substitution `<(...)` / `>(...)` stay part of the word, which makes
        # it dynamic; their text is kept so the caller can parse it as the
        # command it is.
        if command.startswith(("$(", "<(", ">("), index) or char == "`":
            if char == "`":
                close = _close_backtick(command, index + 1)
                inner = None if close == -1 else _unescape_backtick(command[index + 1:close])
            else:
                close = _close_paren(command, index + 2)
                inner = None if close == -1 else command[index + 2:close]
            if close == -1:
                return segments, False
            current.substitutions.append(inner)
            parts.append((command[index:close + 1], False))
            started = True
            index = close + 1
            continue

        # --- heredocs ------------------------------------------------------
        if command.startswith("<<", index) and not command.startswith("<<<", index):
            delim, strip, quoted_delim, index = _heredoc_delimiter(command, index)
            if delim:
                pending_heredocs.append((delim, strip, quoted_delim, current))
                current.had_heredoc = True
            flush_word()
            continue

        # --- other redirections: the target is the next word ---------------
        redir = next((op for op in _REDIR_OPS if command.startswith(op, index)), None)
        if redir:
            # A digit immediately before the operator is an fd, not a word:
            # `2>&1` must not leave a stray `2`.
            if started and parts and all(p.isdigit() for p, _q in parts if p):
                parts = []
                started = False
            elif started:
                # The operator is glued to a real word: `requests>=2.0`.
                glue_next = True
                flush_word()
            index += len(redir)
            pending_redirect = redir
            continue

        # --- segment operators ---------------------------------------------
        operator = next((op for op in _SEGMENT_OPS if command.startswith(op, index)), None)
        if operator:
            flush_segment(piped=operator in ("|", "|&"))
            index += len(operator)
            if operator == "\n" and pending_heredocs:
                index = _read_heredocs(command, index, pending_heredocs)
                if index is None:
                    return segments, False
            continue

        # --- comments ------------------------------------------------------
        # An unquoted '#' starting a word comments out the rest of the line.
        if char == "#" and not started:
            newline = command.find("\n", index)
            if newline == -1:
                break
            index = newline
            continue

        # --- grouping ------------------------------------------------------
        # `(` and `)` always bound a segment. `{` and `}` only do so when they
        # stand alone: `npm install {react,react-dom}` is brace EXPANSION, and
        # splitting it there would hide the package names from the dynamic
        # check instead of refusing them.
        if char in "()":
            flush_segment()
            index += 1
            continue
        if char in "{}" and not started:
            following = command[index + 1:index + 2]
            if following in ("", " ", "\t", "\n", ";"):
                flush_segment()
                index += 1
                continue

        parts.append((char, False))
        started = True
        index += 1

    flush_segment()
    if pending_heredocs:
        # An unterminated heredoc means the body was never closed; the text we
        # lexed is not the whole command.
        return segments, False
    return segments, True


def _heredoc_delimiter(command, index):
    """Read the delimiter after `<<` or `<<-` at `index`.

    Returns (delimiter, strip, quoted, index after it). A quoted delimiter
    (`'EOF'`, `"EOF"`, `\\EOF`) makes the body literal text.
    """
    strip = command.startswith("<<-", index)
    index += 3 if strip else 2
    while index < len(command) and command[index] in " \t":
        index += 1
    chars, quoted = [], False
    while index < len(command) and command[index] not in " \t\n;&|<>()":
        if command[index] in "'\"\\":
            quoted = True
            index += 1
            continue
        chars.append(command[index])
        index += 1
    return "".join(chars), strip, quoted, index


def _read_heredocs(command, index, pending):
    """Consume heredoc bodies up to their delimiters, attaching each to the
    segment that opened it. Returns the new index, or None when a body is
    never closed."""
    while pending:
        delim, strip, quoted, owner = pending.pop(0)
        lines = []
        while True:
            end = command.find("\n", index)
            line = command[index:] if end == -1 else command[index:end]
            candidate = line.strip() if strip else line
            if candidate == delim:
                index = length_or_end(command, end)
                break
            if end == -1:
                return None
            lines.append(line)
            index = end + 1
        if owner is not None:
            body = "\n".join(lines)
            owner.heredocs.append((body, not quoted))
            if not quoted:
                owner.substitutions.extend(_substitutions_in(body))
    return index


def length_or_end(command, end):
    return len(command) if end == -1 else end + 1


def _close_backtick(text, index):
    """Index of the backtick that closes one opened just before `index`, or -1."""
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == "`":
            return index
        index += 1
    return -1


def _unescape_backtick(text):
    """Inside backticks a backslash quotes only `$`, a backtick and itself."""
    return re.sub(r"\\([$`\\])", r"\1", text)


def _close_double(text, index):
    """Index of the `"` that closes a string opened just before `index`, or -1.

    A substitution inside the string is skipped whole: the quotes inside
    `"$(cd "app" && ls)"` belong to the substitution, not to the string.
    """
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index
        if text.startswith("$(", index) or char == "`":
            close = (_close_paren(text, index + 2) if char == "$"
                     else _close_backtick(text, index + 1))
            if close == -1:
                return -1
            index = close + 1
            continue
        index += 1
    return -1


def _close_paren(text, index):
    """Index of the `)` closing a `$(`, `<(` or `>(` whose body starts at
    `index`, or -1. Quotes, nested substitutions, comments and heredoc bodies
    inside it are skipped, so a `)` or a quote in them does not end it."""
    depth = 1
    heredocs = []
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "\n" and heredocs:
            index = _read_heredocs(text, index + 1, [(d, s, q, None) for d, s, q in heredocs])
            heredocs = []
            if index is None:
                return -1
            continue
        if char == "'":
            close = text.find("'", index + 1)
            if close == -1:
                return -1
            index = close + 1
            continue
        if char == '"':
            close = _close_double(text, index + 1)
            if close == -1:
                return -1
            index = close + 1
            continue
        if char == "`":
            close = _close_backtick(text, index + 1)
            if close == -1:
                return -1
            index = close + 1
            continue
        if char == "#" and (index == 0 or text[index - 1] in " \t\n;&|("):
            newline = text.find("\n", index)
            if newline == -1:
                return -1
            index = newline
            continue
        if text.startswith("<<", index) and not text.startswith("<<<", index):
            delim, strip, quoted, index = _heredoc_delimiter(text, index)
            if delim:
                heredocs.append((delim, strip, quoted))
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _double_quoted(raw):
    """The text of a double-quoted string, and the substitutions in it.

    A backslash quotes only `$`, a backtick, `"`, itself and a newline, as in
    the shell; before any other character it stays, so `"npm\\_x"` keeps its
    backslash for whoever reads the text next (`env -S` applies escapes of
    its own).
    """
    out, found = [], []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == "\\" and index + 1 < len(raw):
            following = raw[index + 1]
            if following == "\n":
                index += 2
                continue
            if following in '$`"\\':
                out.append(following)
                index += 2
                continue
            out.append(char)
            index += 1
            continue
        if raw.startswith("$(", index) or char == "`":
            if char == "`":
                close = _close_backtick(raw, index + 1)
                inner = None if close == -1 else _unescape_backtick(raw[index + 1:close])
            else:
                close = _close_paren(raw, index + 2)
                inner = None if close == -1 else raw[index + 2:close]
            if close != -1:
                found.append(inner)
                out.append(raw[index:close + 1])
                index = close + 1
                continue
        out.append(char)
        index += 1
    return "".join(out), found


def _substitutions_in(text):
    """The substitutions in an expanding heredoc body, where quotes are text."""
    found = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if text.startswith("$(", index) or char == "`":
            if char == "`":
                close = _close_backtick(text, index + 1)
                inner = None if close == -1 else _unescape_backtick(text[index + 1:close])
            else:
                close = _close_paren(text, index + 2)
                inner = None if close == -1 else text[index + 2:close]
            if close == -1:
                break
            found.append(inner)
            index = close + 1
            continue
        index += 1
    return found


def strip_assignments(words, loose=False):
    """Split leading NAME=VALUE words off the front of a segment.

    `CI=1 npm install react` must dispatch on `npm`, not on `CI=1`, and so
    must `CI="1" npm install react`: the shell reads a word as an assignment
    when its `NAME=` is unquoted, whatever the value's quoting. Returns
    (assignments, remaining_words).

    `loose` is for wrappers such as `env` and `sudo`, which parse their own
    arguments: to them `"X=a b"` is an assignment too, quotes and all.
    """
    assignments = []
    index = 0
    for word in words:
        if word.assign or (loose and re.match(r"^[^=\s-][^=\s]*=", word.text)):
            assignments.append(word)
            index += 1
            continue
        break
    return assignments, words[index:]


def strip_keywords(words):
    """Drop leading shell keywords so the real head is reachable.

    `time` takes `-p`. Followed by any other option it is the time utility,
    not the keyword: it is then kept as the head, a peel wrapper whose options
    the recognition table reads, so `time -v npm i x` is not read as `-v`.
    """
    index = 0
    while index < len(words) and words[index].text in KEYWORDS:
        if words[index].text == "time":
            start = index
            index += 1
            while index < len(words) and words[index].text in ("-p", "--"):
                index += 1
            if index < len(words) and words[index].text.startswith("-"):
                return words[start:]
            continue
        index += 1
    return words[index:]
