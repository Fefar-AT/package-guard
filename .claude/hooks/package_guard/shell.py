"""A small shell lexer: split a command into segments of words.

This exists because `shlex` cannot model the three things the recognizer needs
to get right -- heredoc bodies, fd-prefixed redirects, and quoted-versus-
unquoted `$` -- and getting them wrong produces both silent installs and false
positives.

It is NOT a shell. Arbitrary shell obfuscation is out of scope, and a universal
shell parser is deliberately not attempted. This handles the ordinary
forms an honest agent types and reports `ok=False` for anything else, so the
caller can fall back to a fail-closed text check.

Standard library only.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Operators that end a segment. Longest first: the scanner matches greedily.
_SEGMENT_OPS = ("&&", "||", "|&", ";;", ";", "|", "&", "\n")

# Redirection operators. The operator AND its target are dropped from the
# segment, so `uv sync 2>&1 | tail` must reduce to exactly `uv sync`.
_REDIR_OPS = ("&>>", "<<<", "&>", ">>", "<<-", "<<", ">|", ">&", "<&", ">", "<")

# Constructs that make a word's value unknowable at parse time. A package name
# we cannot read is a package we must not guess at.
_DYNAMIC = re.compile(r"\$\(|`|\$\{|\$[A-Za-z_]|\$\(\(|<\(|>\(")
# Deliberately does NOT include `[`: a bracket in a package spec is almost
# always pip extras (`.[dev]`, `uvicorn[standard]`), not a character class.
# Treating it as a glob replaced correct, specific refusals with a misleading
# "identity is built dynamically" message.
_GLOB = re.compile(r"[*?]|\{[^}]*,[^}]*\}")

_GROUPING = set("(){}")

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

    def __str__(self):
        return self.text


@dataclass
class Segment:
    words: list = field(default_factory=list)
    # Words that were carried by a heredoc body rather than the command line.
    # Kept out of `words` entirely: a heredoc body is data, not a command.
    had_heredoc: bool = False

    def __bool__(self):
        return bool(self.words)


def _mark(raw_parts):
    """Build a Word from (text, was_quoted) fragments."""
    text = "".join(part for part, _q in raw_parts)
    quoted = any(q for _p, q in raw_parts)
    unquoted = "".join(part for part, q in raw_parts if not q)
    dynamic = bool(_DYNAMIC.search(unquoted) or _GLOB.search(unquoted))
    return Word(text=text, quoted=quoted, dynamic=dynamic)


def segment(command):
    """Split `command` into Segments.

    Returns (segments, ok). ok=False means the text could not be lexed
    confidently -- an unbalanced quote, or an unterminated heredoc -- and the
    caller must fall back to a fail-closed check rather than trusting the
    partial result.
    """
    if not command or not command.strip():
        return [], True

    segments = []
    current = Segment()
    parts = []          # fragments of the word being built
    started = False     # a word is in progress (may be empty, e.g. "")
    pending_heredocs = []
    index = 0
    length = len(command)
    glue_next = False

    def flush_word():
        nonlocal parts, started, glue_next
        if started:
            word = _mark(parts)
            if glue_next:
                word = Word(word.text, word.quoted, word.dynamic, True)
            current.words.append(word)
        parts = []
        started = False
        glue_next = False

    def flush_segment():
        nonlocal current
        flush_word()
        if current.words:
            segments.append(current)
        current = Segment()

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
            buf = []
            index += 1
            while index < length and command[index] != '"':
                if command[index] == "\\" and index + 1 < length:
                    buf.append(command[index + 1])
                    index += 2
                    continue
                buf.append(command[index])
                index += 1
            if index >= length:
                return segments, False
            # Double quotes still expand $ and `; keep it as an unquoted
            # fragment for dynamism purposes but quoted for splitting.
            text = "".join(buf)
            parts.append((text, not bool(_DYNAMIC.search(text))))
            if _DYNAMIC.search(text):
                parts.append(("", True))
            started = True
            index += 1
            continue

        if char == "\\":
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

        # --- heredocs ------------------------------------------------------
        if command.startswith("<<", index) and not command.startswith("<<<", index):
            strip = command.startswith("<<-", index)
            index += 3 if strip else 2
            while index < length and command[index] in " \t":
                index += 1
            delim_chars = []
            quoted_delim = False
            while index < length and command[index] not in " \t\n;&|":
                if command[index] in "'\"":
                    quoted_delim = True
                    index += 1
                    continue
                delim_chars.append(command[index])
                index += 1
            if delim_chars:
                pending_heredocs.append(("".join(delim_chars), strip))
                current.had_heredoc = True
            flush_word()
            continue

        # --- other redirections: drop the operator and its target ----------
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
            # Skip the target.
            while index < length and command[index] in " \t":
                index += 1
            while index < length and command[index] not in " \t\n;&|":
                if command[index] in "'\"":
                    quote = command[index]
                    close = command.find(quote, index + 1)
                    index = length if close == -1 else close + 1
                    continue
                index += 1
            continue

        # --- segment operators ---------------------------------------------
        operator = next((op for op in _SEGMENT_OPS if command.startswith(op, index)), None)
        if operator:
            flush_segment()
            index += len(operator)
            if operator == "\n" and pending_heredocs:
                index = _skip_heredocs(command, index, pending_heredocs)
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


def _skip_heredocs(command, index, pending):
    """Consume heredoc bodies up to their delimiters. Returns the new index."""
    while pending:
        delim, strip = pending.pop(0)
        while True:
            end = command.find("\n", index)
            line = command[index:] if end == -1 else command[index:end]
            candidate = line.strip() if strip else line
            if candidate == delim:
                index = length_or_end(command, end)
                break
            if end == -1:
                return None
            index = end + 1
    return index


def length_or_end(command, end):
    return len(command) if end == -1 else end + 1


def strip_assignments(words):
    """Split leading NAME=VALUE words off the front of a segment.

    `CI=1 npm install react` must dispatch on `npm`, not on `CI=1`. Returns
    (assignments, remaining_words).
    """
    assignments = []
    index = 0
    for word in words:
        if not word.quoted and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", word.text):
            assignments.append(word)
            index += 1
            continue
        break
    return assignments, words[index:]


def strip_keywords(words):
    """Drop leading shell keywords so the real head is reachable."""
    index = 0
    while index < len(words) and words[index].text in KEYWORDS:
        index += 1
    return words[index:]
