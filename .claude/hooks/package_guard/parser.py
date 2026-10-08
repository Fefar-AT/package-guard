"""Strict recognizer for package-acquisition Bash commands.

Recognizes a small, explicit set of npm / pip / uv command forms and
normalizes them into PackageRequest objects. Anything that contains a
package-acquisition operation but cannot be parsed with confidence is
returned as "unsupported" so the hook can deny it.

Standard library only.
"""
from __future__ import annotations

import dataclasses
import os
import re
import shlex
from dataclasses import dataclass

import shell
import verbs

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org"

# Recognition is table-driven: verbs.py loads recognition.json and this module
# keeps no verb list of its own. A second hand-maintained vocabulary would drift
# from the dispatcher. The only text check is verbs.ACQUISITION_HINT, which is
# GENERATED from the same table and used only where the lexer could not analyse
# the text at all, or where a wrapper's options could not be read.

_NPM_EXACT = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?")
_NPM_NAME = re.compile(r"(@[a-z0-9\-_.~]+/)?[a-z0-9\-_.~]+", re.IGNORECASE)
_PY_NAME = re.compile(r"[A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?")
_PY_EXACT = re.compile(r"[0-9][0-9A-Za-z.!+\-_]*")
_PY_RANGE = re.compile(r"(>=|<=|~=|!=|===|>|<)")

# Wrappers come from the table too, split by how they must be handled:
# PEEL drops the wrapper and re-takes the head (`sudo npm install x`);
# RECURSIVE re-parses the payload (`sh -c "npm install x"`).
_PEEL_WRAPPERS = verbs.PEEL_WRAPPERS
_RECURSIVE_WRAPPERS = verbs.RECURSIVE_WRAPPERS


# The stable denial vocabulary. A reason is prose and free to be reworded; a
# code is the contract callers and tests assert. Without it a check could only
# record THAT a command was denied, not why, and a wrong reason (a range
# reported as "compound or dynamic shell syntax") would pass unnoticed. Closed
# set: every raise site names a member of it. This tuple is the names only;
# what each code means is stated once, elsewhere, so the two cannot drift.
DENIAL_CODES = (
    "alternate-source",
    "directory-change",
    "dynamic-spec",
    "foreign-manager",
    "install-target",
    "local-project",
    "same-command-write",
    "unknown-setting",
    "unknown-verb",
    "unparsable-spec",
    "unquoted-range",
    "unreadable-environment",
    "unsupported-flag",
    "unsupported-form",
    "untokenisable",
    "wrapper",
)


class _Unsupported(Exception):
    """Internal: a package operation was detected but cannot be parsed safely.

    Every raise site MUST name a `DENIAL_CODES` member. That is enforced by an
    AST walk over this module, not by convention -- a convention lets two
    vocabularies drift apart.
    """

    def __init__(self, reason: str, code: str):
        super().__init__(reason)
        self.code = code


@dataclass(frozen=True)
class PackageRequest:
    manager: str            # npm | npx | pip | pip3 | python -m pip | uv | uv pip | uvx | uv tool
    operation: str          # install | add | exec | tool | tool-install | run-with
    ecosystem: str          # npm | pypi
    name: str               # normalized comparison name
    display_name: str       # name as written
    requested_spec: str | None   # raw version spec as written (None if unpinned)
    exact_version: str | None    # set only when the request pins an exact version
    registry: str
    original_command: str


@dataclass(frozen=True)
class ManifestScope:
    """A manifest this command would install in full, beyond any named specs."""
    kind: str               # npm | requirements | uv-project
    path: str | None = None  # explicit file (requirements); None means "in cwd"
    # uv-project only. `locked`: the installer is told to install exactly the
    # lock (`--locked` / `--frozen`) rather than re-resolve pyproject.toml
    # first. `extras`: optional-dependency groups it adds, "*" for all.
    # `relocks`: the command rewrites the lock by design (`uv add`).
    locked: bool = True
    extras: tuple = ()
    relocks: bool = False
    # npm only. False when lifecycle scripts are off (`--ignore-scripts`, or
    # `npm_config_ignore_scripts=true`): nothing the lock or the root
    # package.json declares as a script will run.
    scripts: bool = True


@dataclass(frozen=True)
class ParseResult:
    kind: str               # ignore | package | unsupported
    requests: tuple = ()
    reason: str | None = None
    # Set exactly when kind == "unsupported". A member of DENIAL_CODES.
    code: str | None = None
    # Manifests this command reconciles in addition to the specs named on the
    # command line. `npm install` (every form, including bare, plus `npm ci`)
    # installs package.json; `pip install -r f` installs f; `uv sync` installs
    # the locked project.
    manifests: tuple = ()
    # Python environments outside the project tree this command installs into:
    # a literal `UV_PROJECT_ENVIRONMENT`, or a literal `VIRTUAL_ENV` that
    # `uv ... --active` or `uv pip` uses. The hook records them so
    # reconciliation reads them, as it reads `<project>/.venv`.
    environments: tuple = ()

    @property
    def manifest_scope(self) -> bool:
        return bool(self.manifests)


def _ignore() -> ParseResult:
    return ParseResult(kind="ignore")


def _package(requests, manifests=()) -> ParseResult:
    return ParseResult(kind="package", requests=tuple(requests), manifests=tuple(manifests))


def _manifest_only(*manifests) -> ParseResult:
    """No packages named, but a manifest still gets installed."""
    return ParseResult(kind="package", requests=(), manifests=tuple(manifests))


def parse_command(command: str) -> ParseResult:
    try:
        try:
            return _parse(command)
        except (_TooDeep, RecursionError):
            # Nesting no ordinary command reaches: read it as unlexable text.
            return _unlexable(command)
    except _Unsupported as exc:
        return ParseResult(kind="unsupported", reason=str(exc), code=exc.code)


class _TooDeep(Exception):
    """Internal: substitutions nested past `_MAX_NESTING`."""


# Command substitutions inside substitutions, deeper than any ordinary command
# nests them. Each level is parsed again, so the cost grows with the depth.
_MAX_NESTING = 16


def _unlexable(command):
    """What the lexer could not analyse: refused when it reads as an acquisition."""
    if verbs.ACQUISITION_HINT.search(command):
        raise _Unsupported(
            "could not safely tokenize a command containing a package operation",
            code="untokenisable",
        )
    return _ignore()


_CD_MESSAGE = (
    "package operation appears alongside a directory change; "
    "run the package command as a simple standalone command -- change "
    "directory in its own command first, then run the install bare "
    "(no `cd ... &&`, no pipe, no `;`)"
)


def _parse(command: str, depth: int = 0) -> ParseResult:
    """Segment the command, then run EVERY segment through the strict parser.

    The old design refused any command containing a metacharacter unless a loose
    regex recognised it, and ignored it otherwise. That made `uv sync | tail`
    invisible while `echo "npm install x" > f` was refused. Here a pipe is just a
    segment boundary and each side is parsed properly, so a decorated install
    behaves exactly like a bare one and quoted text is never mistaken for a
    command.
    """
    if not command or not command.strip():
        return _ignore()

    segments, ok = shell.segment(command)
    if not ok:
        # Unbalanced quotes or an unterminated heredoc: we do not know what this
        # says. Fail closed if it plausibly acquires.
        return _unlexable(command)

    results = []
    changed_directory = False
    allexport = False
    # Assignments an earlier segment made, which may reach every later one:
    # an `export`, and also a bare `NAME=VALUE`, which changes the value of a
    # variable that is already exported (HOME always is) and which a later
    # `export NAME` exports. They are checked like a segment's own
    # assignments, but never relax a check: the lexer cannot tell whether
    # one ran in this shell or in a subshell, pipeline or skipped branch.
    inherited = []
    # What an earlier segment did that the guard cannot follow: wrote a file
    # an installer reads, or set variables from text it cannot read. Either
    # refuses a later package segment; neither matters on its own.
    written = None
    unreadable = None
    symlink = False
    refusals = []   # ("written" | "unreadable", what) before a package segment
    for segment in segments:
        sub_written, sub_symlink = _check_substitutions(segment, depth)
        loop = _loop_variable(segment.words)
        words = shell.strip_keywords(segment.words)
        assignments, words = shell.strip_assignments(words)
        plain = _past_precommands(words)
        wrote = _written_file(segment, plain, _known_values(inherited + assignments)) or sub_written
        symlink = symlink or sub_symlink or _makes_symlink(plain)
        why = loop or _unreadable(plain, inherited + assignments)
        if _header(segment.words):
            pass  # `case WORD in PATTERN` and `for NAME in WORDS` run nothing
        elif not words:
            inherited.extend(assignments)
        elif plain and plain[0].text in _ASSIGNMENT_BUILTINS:
            inherited.extend(assignments)
            inherited.extend(w for w in plain[1:]
                             if "=" in w.text and not w.text.startswith(("-", "+")))
        elif _sets_allexport(plain):
            allexport = True
        else:
            result = _parse_segment(words, assignments, inherited, command,
                                    _stdin_text(segment, command))
            if result is _CD_MARKER:
                changed_directory = True
            elif result is not None and result.kind != "ignore":
                if written:
                    refusals.append(("written", written))
                if unreadable:
                    refusals.append(("unreadable", unreadable))
                results.append(result)
        written = written or wrote
        unreadable = unreadable or why

    if allexport and results:
        raise _Unsupported(_ALLEXPORT_MESSAGE, code="wrapper")

    if changed_directory and results:
        # The manifest gate reads the EVENT's working directory, so a permitted
        # `cd X && <install>` would vet the root manifest while the installer
        # reconciles X/. Same hazard the --prefix refusal exists to prevent.
        raise _Unsupported(_CD_MESSAGE, code="directory-change")

    if symlink and results:
        raise _Unsupported(_SYMLINK_MESSAGE, code="same-command-write")

    if refusals:
        kind, what = refusals[0]
        if kind == "written":
            raise _Unsupported(_WRITTEN_MESSAGE.format(file=what), code="same-command-write")
        raise _Unsupported(_UNREADABLE_MESSAGE.format(what=what), code="unreadable-environment")

    return _merge(results)


# Segments that open a compound command and run nothing themselves.
_HEADERS = {"case", "for", "select", "foreach"}


def _header(words) -> bool:
    for word in words:
        if word.text in _HEADERS:
            return True
        if word.text not in shell.KEYWORDS:
            return False
    return False


_CD_MARKER = object()

# `export npm_config_registry=E; npm install x` reaches npm exactly like the
# leading assignment that is refused, so the NAME=VALUE arguments of these
# builtins are checked as if they led every later segment.
_ASSIGNMENT_BUILTINS = {"export", "declare", "typeset", "local", "readonly"}

_ALLEXPORT_MESSAGE = (
    "`set -a` / `set -o allexport` (and zsh's `setopt allexport`, `unsetopt "
    "noallexport`) exports every later assignment, including ones that change where "
    "packages come from, and Package Guard cannot see them all; run the package "
    "command on its own, without turning allexport on"
)

_WRITTEN_MESSAGE = (
    "this command writes {file!r} and then runs a package command. Package Guard reads "
    "that file before the command starts, so it would check the old contents, not the "
    "ones the installer uses; run the write and the install as separate commands"
)

_SYMLINK_MESSAGE = (
    "this command makes a symbolic link and runs a package command. Package Guard "
    "resolves paths before the command starts, so it cannot see where the new link "
    "leads; run the `ln -s` and the install as separate commands"
)

_UNREADABLE_MESSAGE = (
    "{what} sets variables Package Guard cannot read before the package command runs, "
    "and npm, pip and uv read some of them (a registry, an index, their configuration "
    "files); run the package command on its own. To use a virtualenv, call its "
    "installer by path (`.venv/bin/pip install ...`) rather than activating it"
)


def _option_spelling(name):
    """(option, on) for a zsh-style option name: case, `_` and `-` do not
    matter, and a leading `no` inverts it (`NO_ALL_EXPORT`)."""
    folded = re.sub(r"[_-]", "", name).lower()
    if folded.startswith("no") and folded != "notify":
        return folded[2:], False
    return folded, True


def _sets_allexport(words) -> bool:
    """Every spelling that turns allexport on: `set -a`, `set -ea`,
    `set -o allexport`, `set +o noallexport`, zsh's `setopt allexport`,
    `setopt ALL_EXPORT`, `unsetopt noallexport`, `options[allexport]=on`."""
    if not words:
        return False
    head, args = words[0].text, [w.text for w in words[1:]]
    if head.startswith("options[") and "=" in head:
        key, _, value = head[len("options["):].partition("]=")
        option, on = _option_spelling(key)
        return option == "allexport" and on == (value.lower() == "on")
    if head in ("setopt", "unsetopt"):
        for arg in args:
            if arg.startswith(("-", "+")) and len(arg) > 1 and not arg.startswith("--"):
                # zsh's single-letter form: `setopt -a`.
                if "a" in arg[1:] and (arg[0] == "-") == (head == "setopt"):
                    return True
                continue
            if any(ch in arg for ch in "*?["):
                return True  # a pattern (`setopt -m '*export'`) may name it
            option, on = _option_spelling(arg)
            if option == "allexport" and on == (head == "setopt"):
                return True
        return False
    if head != "set":
        return False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--" or len(arg) < 2 or arg[0] not in "-+":
            break
        flags, has_o, attached = arg[1:].partition("o")
        if arg[0] == "-" and "a" in flags:
            return True
        if has_o:
            value = attached
            if not attached:
                index += 1
                value = args[index] if index < len(args) else ""
            option, on = _option_spelling(value)
            if option == "allexport" and on == (arg[0] == "-"):
                return True
        index += 1
    return False


# ---------------------------------------------------------------------------
# What an earlier segment does that the parser cannot follow
# ---------------------------------------------------------------------------

# Words that run the rest of the segment as a plain command: `builtin export`
# is `export`, `command cp` is `cp`, zsh's `- cmd` is `cmd`.
_PRECOMMANDS = {"builtin", "-", "noglob", "nocorrect", "command"}


def _past_precommands(words):
    index = 0
    while index < len(words) and words[index].text in _PRECOMMANDS:
        if words[index].text == "command":
            following = words[index + 1].text if index + 1 < len(words) else ""
            if following == "-p":
                index += 1
            elif following.startswith("-"):
                break  # `command -v x` prints
        index += 1
    return words[index:]


def _past_wrappers(words):
    """The command a chain of peel wrappers runs, read by their grammar."""
    words = _past_precommands(words)
    while words and _executable(words[0].text) in _PEEL_WRAPPERS:
        rest, _effects, unread = _unwrap(_executable(words[0].text), words)
        if unread:
            return []
        _assignments, words = shell.strip_assignments(rest, loose=True)
        words = _past_precommands(words)
    return words


def _guarded_path(path) -> bool:
    """A file an installer reads, or anything inside a `.claude/` directory."""
    return verbs.installer_file(path) or _names_guard_dir(path)


def _basename(path):
    return path.rstrip("/").rsplit("/", 1)[-1]


def _directory_like(path) -> bool:
    """`cp x dir` writes `dir/x`: a destination that is `.`, ends in `/`, or
    has no extension may be a directory."""
    return (path in (".", "..", "~") or path.endswith(("/", "/.", "/.."))
            or "." not in _basename(path))


def _option_value(args, short, long):
    for index, arg in enumerate(args):
        if arg == short and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(long + "="):
            return arg.partition("=")[2]
        if arg.startswith(short) and len(arg) > len(short) and not arg.startswith("--"):
            return arg[len(short):]
    return None


# Letters that take the rest of a cluster as their value, so an `i` after one
# is not the in-place flag (`sed -e`, `perl -Mstrict`).
_IN_PLACE_STOPS = {"sed": "efl", "perl": "eEMmIxFCdDV"}


def _in_place(head, args) -> bool:
    for arg in args:
        if arg == "--":
            return False
        if arg.startswith("--in-place"):
            return True
        if arg.startswith("-") and not arg.startswith("--"):
            for letter in arg[1:]:
                if letter == "i":
                    return True
                if letter in _IN_PLACE_STOPS[head]:
                    break
    return False


_COPIERS = {"cp", "mv", "install", "rsync", "ln", "gcp", "gmv", "ginstall", "gln"}


def _write_targets(head, args):
    """The paths a file utility writes, as far as its words say."""
    operands = [a for a in args if not a.startswith("-") and a != "--"]
    if head == "tee":
        return operands
    if head in _COPIERS:
        target = _option_value(args, "-t", "--target-directory")
        if target is not None:
            return [target] + [target.rstrip("/") + "/" + _basename(s) for s in operands]
        if len(operands) == 1 and head in ("ln", "gln"):
            return [_basename(operands[0])]  # `ln -s /x/package.json` links here
        if len(operands) < 2:
            return []
        dest, sources = operands[-1], operands[:-1]
        if _directory_like(dest):
            return [dest] + [dest.rstrip("/") + "/" + _basename(s) for s in sources]
        return [dest]
    if head in ("sed", "gsed", "perl"):
        return operands if _in_place("perl" if head == "perl" else "sed", args) else []
    if head in ("truncate", "gtruncate"):
        return operands
    if head in ("dd", "gdd"):
        return [a[3:] for a in args if a.startswith("of=")]
    return []


# Interpreters whose code can name a file: the code after the flag, or the
# script a heredoc feeds them. Each with the options before it that take a
# value, so the value is not read as the script.
_CODE_FLAGS = {
    "python": (("-c",), {"-W", "-X"}),
    "node": (("-e", "--eval", "-p", "--print"), {"-r", "--require", "--import", "--loader", "-C"}),
    "perl": (("-e", "-E"), {"-I", "-M", "-m"}),
    "ruby": (("-e",), {"-I", "-r"}),
}


def _inline_code(head, args, segment):
    """The code an interpreter runs from its command line or a heredoc, read
    up to its first positional (the script), `-m` or `-`."""
    if head not in _CODE_FLAGS:
        return []
    flags, valued = _CODE_FLAGS[head]
    code = [body for body, _expands in segment.heredocs]
    letters = [f[1] for f in flags if len(f) == 2]
    index = 0
    while index < len(args):
        arg = args[index]
        following = args[index + 1] if index + 1 < len(args) else ""
        name, equals, value = arg.partition("=")
        if not arg.startswith("-") or arg in ("-", "--", "-m"):
            break
        if arg in flags or (equals and name in flags):
            code.append(value if equals else following)
            break
        cluster = [l for l in letters if not arg.startswith("--") and l in arg[1:]]
        if cluster:
            # `python -Bc '...'`, `perl -pe '...'`: the value follows the letter.
            attached = arg[arg.index(cluster[0], 1) + 1:]
            code.append(attached or following)
            break
        index += 2 if arg in valued else 1
    return code


_GUARD_DIR_IN_TEXT = re.compile(r"(?:^|[\s'\"/=(])\.claude(?=[/\s'\")]|$)", re.IGNORECASE)


def _filled(text, known):
    """`text` with each variable an earlier literal assignment set filled in."""
    return _EXPANSION.sub(lambda m: known.get(_variable(m.group(0)), m.group(0)), text)


def _written_file(segment, words, known=None):
    """The first file an installer reads (or path into `.claude/`) that this
    segment writes, or None: a redirection, a file utility's target, or a
    file named in an interpreter's inline code. A variable an earlier
    literal assignment set is read as its value (`F=uv.lock; cp x $F`)."""
    known = known or {}
    for operator, target in segment.redirects:
        if operator not in shell.WRITE_REDIRECTS:
            continue
        if operator == ">&" and (target.text.isdigit() or target.text == "-"):
            continue
        if _guarded_path(_filled(target.text, known)):
            return target.text
    words = _past_wrappers(words)
    if not words or _makes_symlink(words):
        return None  # a symbolic link is refused on its own, wherever it is made
    head = _executable(words[0].text)
    args = [_filled(w.text, known) for w in words[1:]]
    for path in _write_targets(head, args):
        if _guarded_path(path):
            return path
    for code in _inline_code(head, args, segment):
        found = verbs.INSTALLER_FILE_IN_TEXT.search(code) or _GUARD_DIR_IN_TEXT.search(code)
        if found:
            return found.group(0).strip(" \t\n'\"/=(")
    return None


def _makes_symlink(words) -> bool:
    words = _past_wrappers(words)
    if not words or _executable(words[0].text) not in ("ln", "gln"):
        return False
    return any(w.text == "--symbolic" or (w.text.startswith("-") and not w.text.startswith("--")
                                          and "s" in w.text[1:]) for w in words[1:])


def _check_substitutions(segment, depth=0):
    """Refuse a substitution that acquires; return what the substitutions
    write, as (installer file or None, makes a symlink)."""
    if segment.substitutions and depth >= _MAX_NESTING:
        raise _TooDeep()
    written, symlink = None, False
    for text in segment.substitutions:
        if _parse(text, depth + 1).kind != "ignore":
            raise _Unsupported(_SUBSTITUTION_MESSAGE, code="wrapper")
        inner, ok = shell.segment(text)
        for part in inner if ok else ():
            words = _past_precommands(shell.strip_assignments(shell.strip_keywords(part.words))[1])
            written = written or _written_file(part, words)
            symlink = symlink or _makes_symlink(words)
    return written, symlink


_SUBSTITUTION_MESSAGE = (
    "a package operation inside a command substitution (`$(...)`, backticks, `<(...)`) "
    "cannot be vetted; run the package command directly, as its own command"
)


def _is_name(text) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text))


def _matters(word, text=None) -> bool:
    """A variable name the guard cannot follow and an installer may read:
    one built at run time, or one `verbs.installer_reads`."""
    text = word.text if text is None else text
    return word.dynamic or (_is_name(text) and verbs.installer_reads(text))


def _loop_variable(words):
    """`for NAME in ...` / `select NAME in ...` on a name that matters."""
    for index, word in enumerate(words):
        if word.text in ("for", "select", "foreach") and index + 1 < len(words):
            name = words[index + 1]
            return f"`{word.text} {name.text} in ...`" if _matters(name) else None
        if word.text not in shell.KEYWORDS:
            return None
    return None


# Builtins that set a variable from input: the options whose next word is a
# value rather than a name (`read -p PROMPT NAME`), and those whose next word
# is the name (`read -a NAME`, `printf -v NAME`).
_READERS = {
    "read": ("pdtnNuik", "aA"), "mapfile": ("dnOsuCc", ""), "readarray": ("dnOsuCc", ""),
    "getopts": ("", ""), "vared": ("pr", ""), "printf": ("", "v"),
}


def _reader_names(head, args):
    """The words a reader builtin assigns to: `read NAME`, `printf -v NAME`."""
    values, names = _READERS[head]
    found, index = [], 0
    while index < len(args):
        text = args[index].text
        if text == "--":
            found += [] if head == "printf" else list(args[index + 1:])
            break
        if text.startswith("-") and len(text) > 1:
            letters = text[1:]
            for position, letter in enumerate(letters):
                if letter not in names and letter not in values:
                    continue
                attached = letters[position + 1:]
                if attached:
                    if letter in names:
                        found.append(dataclasses.replace(args[index], text=attached))
                    index += 1
                else:
                    if letter in names and index + 1 < len(args):
                        found.append(args[index + 1])
                    index += 2
                break
            else:
                index += 1
            continue
        if head == "printf":
            break  # the format and its arguments
        if head == "getopts":
            found += list(args[index + 1:index + 2])  # `getopts OPTSTRING NAME`
            break
        found.append(args[index])
        index += 1
    return found


def _unreadable(words, earlier):
    """What this segment does that sets variables the parser cannot read,
    as a short description, or None."""
    if not words:
        return None
    head, args = words[0].text, words[1:]
    if head in ("source", ".", "eval") and args:
        return f"`{head} {args[0].text}`"
    if head in _READERS:
        for word in _reader_names(head, args):
            if _matters(word, word.text.split("?", 1)[0]):
                return f"`{head} {word.text}`"
        return None
    if head not in _ASSIGNMENT_BUILTINS:
        return None
    # `export -n` / `declare +x` remove the export; `export -p` prints.
    flags = "".join(w.text[1:] for w in args if w.text.startswith("-"))
    exports = (head == "export" and not set(flags) & set("np")) or "x" in flags
    nameref = head != "export" and "n" in flags
    literal = {_assignment(w)[0] for w in earlier if not w.dynamic}
    for word in args:
        if word.text.startswith(("-", "+")):
            continue
        if not word.assign:
            if word.dynamic:
                return f"`{head} {word.text}`"
            if (exports or nameref) and _matters(word) and word.text not in literal:
                return f"`{head} {word.text}`"
        elif nameref:
            name, value, _appends = _assignment(word)
            if word.dynamic or verbs.installer_reads(name) or verbs.installer_reads(value):
                return f"`{head} -n {word.text}`"
    return None


def _stdin_text(segment, command):
    """What the segment's command reads on standard input, as far as the text
    shows it: heredoc bodies, a `<<<` string, and after a pipe the command."""
    texts = [body for body, _expands in segment.heredocs]
    texts += [word.text for operator, word in segment.redirects if operator == "<<<"]
    if segment.piped:
        texts.append(command)
    return "\n".join(texts) if texts else None


def _assignment(word):
    """(name, value, appends) of a `NAME=VALUE` or `NAME+=VALUE` word."""
    name, _, value = word.text.partition("=")
    if name.endswith("+"):
        return name[:-1], value, True
    return name, value, False


def _parse_segment(words, assignments, inherited, command, stdin=None):
    """Parse one segment. Returns a ParseResult, None, or _CD_MARKER.

    `assignments` are the segment's own, which certainly reach its command;
    `inherited` are earlier segments' (see `_parse`). `stdin` is the text the
    segment reads on standard input, where the command shows it."""
    head_word = words[0]
    head = _executable(head_word.text)

    if head in verbs.CD_COMMANDS:
        return _CD_MARKER

    if head in _PEEL_WRAPPERS:
        return _parse_peeled(head, words, assignments, inherited, command, stdin)

    if head in _RECURSIVE_WRAPPERS:
        return _parse_wrapper_payload(head, words, command, stdin)

    installer = verbs.lookup(head)

    # `python -m pip` becomes the pip installer; nothing else about python does.
    if installer is None and head == "python":
        texts = [w.text for w in words]
        if texts[1:3] == ["-m", "pip"]:
            installer = verbs.lookup("pip")
            words = [head_word] + words[3:]
        elif texts[1:3] == ["-m", "uv"]:
            installer = verbs.lookup("uv")
            words = [head_word] + words[3:]

    if installer is None:
        if head in verbs.FOREIGN:
            return _parse_foreign(head, words)
        return _check_unknown_head(head_word, head, words, inherited + assignments, command, stdin)

    _check_env(inherited + assignments, installer, head)
    result = _dispatch(installer, head, words, command)
    if _scripts_off(assignments, inherited) and result is not None and result.manifests:
        result = dataclasses.replace(result, manifests=tuple(
            dataclasses.replace(m, scripts=False) if m.kind == "npm" else m
            for m in result.manifests))
    if installer.get("env") == "uv" and result is not None and result.kind == "package":
        result = _uv_env_effects(result, assignments, inherited, words)
    return result


# uv reads a boolean variable as true from any of these, in any case.
_UV_TRUE = {"1", "true", "yes", "y", "on", "t"}


def _literal(word, value, appends) -> bool:
    """The value is exactly what the installer reads: no expansion, no `+=`."""
    return not (word.dynamic or appends)


def _uv_locked(assignments) -> bool:
    """`UV_LOCKED=1` / `UV_FROZEN=1` among the segment's OWN assignments.

    Each one that uv could read as that variable must be spelt exactly as uv
    reads it on every platform and carry a literal true value. An export never
    counts: it may have run in a subshell, a pipeline or a skipped branch, and
    `export UV_LOCKED=1; UV_LOCKED=0 uv sync` runs unlocked."""
    by_name = {}
    for word in assignments:
        name, value, appends = _assignment(word)
        if verbs.classify_env("uv", name) == "locked":
            by_name.setdefault(name.upper(), []).append((word, name, value, appends))
    return any(all(name == canonical and _literal(word, value, appends)
                   and value.lower() in _UV_TRUE
                   for word, name, value, appends in found)
               for canonical, found in by_name.items())


def _scripts_off(assignments, inherited) -> bool:
    """`npm_config_ignore_scripts=true` among the segment's own assignments,
    and no assignment in reach giving that setting another value (npm reads
    the variable in any case, so two spellings can disagree)."""
    def ignore_scripts(word):
        return verbs.env_key("npm", _assignment(word)[0]) == "ignore-scripts"

    def true(word):
        _name, value, appends = _assignment(word)
        return _literal(word, value, appends) and value.lower() == "true"

    own = [w for w in assignments if ignore_scripts(w)]
    return bool(own) and all(true(w) for w in own + [w for w in inherited if ignore_scripts(w)])


def _uv_env_effects(result, assignments, inherited, words):
    """`UV_LOCKED=1` / `UV_FROZEN=1` are `--locked` / `--frozen`, and a literal
    environment path is carried on the result for the hook to record.

    Every path in reach is carried, the segment's own and an earlier
    segment's alike: which one uv ends up using can depend on a subshell the
    lexer does not model, and recording one too many costs a scan, while one
    too few leaves an install unreconciled."""
    if _uv_locked(assignments):
        result = dataclasses.replace(result, manifests=tuple(
            dataclasses.replace(m, locked=True) if m.kind == "uv-project" else m
            for m in result.manifests))
    texts = [w.text for w in words[1:]]
    # `uv ... --active` and `uv pip` install into $VIRTUAL_ENV.
    active = "--active" in texts or "pip" in texts
    environments = []
    for word in inherited + assignments:
        name, value, appends = _assignment(word)
        if verbs.classify_env("uv", name) == "path":
            # `_check_env` already refused one that is not a literal path.
            if _static_path(word, value, appends):
                environments.append(value)
        elif active and name.upper() == "VIRTUAL_ENV":
            if not _static_path(word, value, appends):
                raise _Unsupported(f"{name!r} " + verbs.env_reason("uv", "path", name),
                                   code="install-target")
            environments.append(value)
    if environments:
        result = dataclasses.replace(result, environments=tuple(dict.fromkeys(environments)))
    return result


# How each action of a wrapper's grammar (recognition.json `wrapper_grammar`)
# is read. These take a value: the next word, `--opt=value`, or `-ovalue`.
_WRAPPER_VALUE_ACTIONS = {"value", "unset", "chdir", "split", "setenv"}


def _option_cluster(text, options, plus):
    """getopt's reading of `-abc`: [(action, option, attached value or None)],
    or None when a letter is not in the grammar."""
    out = []
    for index, letter in enumerate(text[1:]):
        option = text[0] + letter
        action = options.get(option) or (options.get("-" + letter) if plus else None)
        if action is None:
            return None
        if action in _WRAPPER_VALUE_ACTIONS:
            out.append((action, option, text[index + 2:] or None))
            return out
        out.append((action, option, None))
    return out


def _unwrap(head, words):
    """Read a wrapper's own options by the table's grammar.

    Returns (rest, effects, unread). `rest` is what follows the options and
    positionals; `effects` lists (action, option, value word) for each option
    that is neither a plain flag nor a plain value; `unread` is True when an
    option the grammar does not know stopped the scan, and `rest` then starts
    at that option.
    """
    grammar = verbs.wrapper_grammar(head)
    options = grammar.get("options") or {}
    plus = bool(grammar.get("plus_options"))
    effects = []
    index = 1
    while index < len(words):
        word = words[index]
        text = word.text
        if text in options:
            items = [(options[text], text, None)]
        elif text == "--":
            index += 1
            break
        elif text.startswith("--") and text.partition("=")[0] in options:
            name, _, value = text.partition("=")
            items = [(options[name], name, value)]
        elif len(text) > 1 and (text[0] == "-" or (plus and text[0] == "+")):
            items = None if text.startswith("--") else _option_cluster(text, options, plus)
            if items is None:
                return words[index:], effects, True
        else:
            break
        for action, option, attached in items:
            value = None
            if action in _WRAPPER_VALUE_ACTIONS:
                if attached is not None:
                    value = dataclasses.replace(word, text=attached)
                else:
                    index += 1
                    value = words[index] if index < len(words) else None
            if action not in ("flag", "value"):
                effects.append((action, option, value))
        index += 1
    index += int(grammar.get("positionals") or 0)
    return words[index:], effects, False


def _wrapper_refusal(head, why, code="wrapper"):
    return _Unsupported(f"package operation wrapped in {head!r} {why}; "
                        "run the package command directly", code=code)


def _hint_fallback(head, text, why):
    """What a wrapper runs could not be read (an option the grammar does not
    know, a command line built dynamically): refuse when `text` reads as an
    acquisition by the generated hint, ignore it otherwise."""
    if verbs.ACQUISITION_HINT.search(text):
        raise _wrapper_refusal(head, why)
    return None


def _unread_option(head, rest):
    return _hint_fallback(head, " " + " ".join(w.text for w in rest),
                          f"with an option Package Guard cannot read ({rest[0].text!r})")


def _parse_peeled(head, words, assignments, inherited, command, stdin=None):
    """`sudo npm install x` is `npm install x`, read through sudo's options.

    An option that empties or edits the environment (`env -i`, `env -u`) or
    moves the command to another directory (`env -C`, `sudo -D`) is refused
    when the wrapped command acquires; `env -S` carries more command line,
    which is re-parsed like a shell wrapper's payload.
    """
    rest, effects, unread = _unwrap(head, words)
    if unread:
        return _unread_option(head, rest)
    actions = {action for action, _option, _value in effects}
    if "print" in actions:
        return None
    split = [value for action, _option, value in effects if action == "split" and value]
    if split:
        if any("\\" in word.text or "$" in word.text for word in split):
            # env applies its own escapes (`\_` is a space) and `${NAME}`
            # expansion to the -S text before splitting it, so the words it
            # runs are not the words written.
            raise _Unsupported(
                f"{head!r} -S text with a `\\` escape or a `$` expansion is rewritten by "
                f"{head} before it runs, and Package Guard does not read it that way; write "
                "the command as plain words, without -S", code="wrapper")
        payload = split + rest
        if any(word.dynamic for word in payload):
            return _hint_fallback(head, command, "with a command line built dynamically")
        if _parse(" ".join(word.text for word in payload)).kind == "ignore":
            return None
        raise _wrapper_refusal(head, "-S cannot be vetted")
    own = [] if verbs.wrapper_grammar(head).get("resets_environment") else assignments
    reach = inherited + [a for a in assignments if a not in own]
    more = [value for action, _option, value in effects if action == "setenv" and value]
    more_assignments, rest = shell.strip_assignments(rest, loose=True)
    if not rest:
        # `sudo -s` / `sudo -i` / `doas -s` with no command start a shell,
        # which reads its commands from standard input.
        options = words[1:len(words) - len(rest) - len(more_assignments)]
        if head in ("sudo", "doas") and stdin and any(
                w.text in ("--shell", "--login") or (w.text.startswith("-") and not w.text.startswith("--")
                                                     and set(w.text[1:]) & set("si"))
                for w in options) and verbs.ACQUISITION_HINT.search(stdin):
            raise _Unsupported(_STDIN_MESSAGE.format(head=head), code="wrapper")
        return None
    result = _parse_segment(rest, own + more + more_assignments, reach, command, stdin)
    if result is None or result is _CD_MARKER or result.kind == "ignore":
        return result
    for action, option, _value in effects:
        if action in ("clear", "unset"):
            raise _wrapper_refusal(head, f"with a modified environment ({option!r}) cannot be vetted")
        if action == "chdir":
            raise _Unsupported(_CD_MESSAGE, code="directory-change")
    return result


def _parse_wrapper_payload(head, words, command, stdin=None):
    """`sh -c "<payload>"`, `eval "<payload>"`, `xargs <installer>`, and a
    shell reading its commands from a pipe or a heredoc."""
    payload_words, effects, unread = _unwrap(head, words)
    if unread:
        return _unread_option(head, payload_words)
    if any(action == "print" for action, _option, _value in effects):
        return None
    if head in _SHELLS and _reads_stdin(words, payload_words):
        if stdin and verbs.ACQUISITION_HINT.search(stdin):
            raise _Unsupported(_STDIN_MESSAGE.format(head=head), code="wrapper")
        return None
    if (head == "xargs" and payload_words and stdin
            and _executable(payload_words[0].text) in _SHELLS | {"eval"}
            and verbs.ACQUISITION_HINT.search(stdin)):
        # `... | xargs -I{} sh -c '{}'` runs its input as commands.
        raise _Unsupported(_STDIN_MESSAGE.format(head=head), code="wrapper")
    if not payload_words:
        return None

    if any(word.dynamic for word in payload_words):
        # `eval "$CMD"` -- fall back to a text check rather than blanket-denying,
        # so `find . | xargs rm` does not start failing.
        if verbs.ACQUISITION_HINT.search(command) or any(
                verbs.ACQUISITION_HINT.search(reading)
                for reading in _readings(payload_words, {}, True)):
            raise _Unsupported(
                f"package operation wrapped in {head!r} cannot be vetted; "
                "run the package command directly",
                code="wrapper",
            )
        return None

    payload = " ".join(word.text for word in payload_words)
    inner = _parse(payload)
    if inner.kind == "ignore":
        return None
    raise _Unsupported(
        f"package operation wrapped in {head!r} cannot be vetted; "
        "run the package command directly",
        code="wrapper",
    )


# ---------------------------------------------------------------------------
# Command names the table does not know, and ones built at run time
# ---------------------------------------------------------------------------

_EXPANSION = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]")
_SUBSTITUTION_SPAN = re.compile(r"\$\((?:[^()]|\([^()]*\))*\)|`[^`]*`|[<>]\((?:[^()]|\([^()]*\))*\)")
_DELIMITERS = re.compile(r"\$\(\(?|\$\{|[<>]\(|[`()}\"']")


def _known_values(assignments):
    """NAME -> literal value of each assignment in reach, the last one winning."""
    known = {}
    for word in assignments:
        name, value, appends = _assignment(word)
        if word.dynamic or appends:
            known.pop(name, None)
        else:
            known[name] = value
    return known


def _variable(expansion):
    return expansion.strip("${}").partition(":")[0]


def _readings(words, known, strings):
    """The segment's words as the hint reads them, three ways: with the
    variables an earlier assignment set filled in, with each substitution's
    delimiters opened up (`$(command -v npm)` reads ` command -v npm `), and
    with every expansion removed (`n${X}pm` reads `npm`). A quoted string with
    spaces is one argument, data rather than a command word, and is left out
    unless the command runs such strings (`watch 'npm ci'`)."""
    filled, opened, removed = [], [], []
    for word in words:
        text = word.text
        if not strings and any(ch.isspace() for ch in _SUBSTITUTION_SPAN.sub("", text)):
            continue
        filled.append(_filled(text, known))
        opened.append(_DELIMITERS.sub(" ", text))
        removed.append(_EXPANSION.sub("", _SUBSTITUTION_SPAN.sub("", text)))
    return [" " + " ".join(reading) for reading in (filled, opened, removed)]


def _check_unknown_head(head_word, head, words, assignments, command="", stdin=None):
    """A command the table does not know may still run an installer
    (`flock /tmp/l npm install x`, `mise exec -- uv sync`), and a command
    name built at run time may be one (`$(command -v npm) install x`). Their
    words are read with the generated hint, and a match is refused; a
    command known to treat its words as data (`echo`, `grep`) is not read.
    A run-time name an earlier assignment spells out is also parsed as that
    command (`X=sh; $X -c '...'`). `su` with no command runs a shell on its
    standard input."""
    dynamic = bool(re.search(r"[$`*?]", head))
    if not dynamic and head in verbs.INERT_HEADS:
        return
    command_options = verbs.STDIN_SHELLS.get(head)
    if command_options is not None and stdin and verbs.ACQUISITION_HINT.search(stdin) and not any(
            w.text in command_options or w.text.startswith(tuple(o + "=" for o in command_options))
            for w in words[1:]):
        raise _Unsupported(_STDIN_MESSAGE.format(head=head), code="wrapper")
    for reading in _readings(words, _known_values(assignments), head in verbs.STRING_RUNNERS):
        if verbs.ACQUISITION_HINT.search(reading):
            if dynamic:
                raise _Unsupported(_DYNAMIC_HEAD_MESSAGE.format(name=head_word.text), code="wrapper")
            raise _Unsupported(_UNKNOWN_HEAD_MESSAGE.format(head=head), code="wrapper")
    if dynamic:
        verb = next((w for w in words[1:] if not w.text.startswith("-")), None)
        if verb is not None and not verb.dynamic and verb.text in verbs.ACQUIRING_VERBS:
            raise _Unsupported(_DYNAMIC_HEAD_MESSAGE.format(name=head_word.text), code="wrapper")
        spelled = _filled(head_word.text, _known_values(assignments)).split()
        if spelled and not shell.is_dynamic(" ".join(spelled)):
            resolved = [shell.Word(text=t) for t in spelled] + list(words[1:])
            try:
                result = _parse_segment(resolved, [], assignments, command, stdin)
            except _Unsupported as exc:
                raise _Unsupported(_DYNAMIC_HEAD_MESSAGE.format(name=head_word.text),
                                   code="wrapper") from exc
            if result is _CD_MARKER:
                return result
            if result is not None and result.kind != "ignore":
                raise _Unsupported(_DYNAMIC_HEAD_MESSAGE.format(name=head_word.text), code="wrapper")
    return None


_UNKNOWN_HEAD_MESSAGE = (
    "package operation run through {head!r}, which Package Guard does not read past; "
    "run the package command directly, as its own command"
)

_DYNAMIC_HEAD_MESSAGE = (
    "the command name {name!r} is only known when the command runs, and what follows "
    "reads as a package operation; run the package command directly, with the "
    "installer named"
)

_STDIN_MESSAGE = (
    "{head!r} reads its commands from standard input, and that input holds a package "
    "operation; run the package command directly, as its own command"
)

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}


def _reads_stdin(words, payload_words) -> bool:
    """A shell with no script or `-c` text, `-`, or `-s` reads standard input."""
    if not payload_words or payload_words[0].text == "-":
        return True
    options = words[1:len(words) - len(payload_words)]
    return any(w.text.startswith("-") and not w.text.startswith("--") and "s" in w.text[1:]
               for w in options)


def _parse_foreign(head, words):
    """Recognise-and-deny the package managers this project forbids."""
    verb = next((w.text for w in words[1:] if not w.text.startswith("-")), None)
    flags = [w.text for w in words[1:] if w.text.startswith("-")]
    if verb in verbs.FOREIGN_SAFE or (verb is None and set(flags) & verbs.FOREIGN_SAFE):
        return None
    raise _Unsupported(verbs.FOREIGN[head], code="foreign-manager")


_INERT = object()  # verb sentinel: a pre-verb flag made the command a print


def _consume_globals(installer, words):
    """Strip pre-verb global flags; return (verb, remaining_words).

    `verb` is `_INERT` when a flag such as `--version` ends the command."""
    globals_ = installer.get("globals") or {}
    index = 1
    while index < len(words):
        text = words[index].text
        if not text.startswith("-"):
            break
        base = text.partition("=")[0]
        action = globals_.get(base)
        if action == "deny_cwd":
            raise _Unsupported(
                f"{base!r} is not supported; to install into a subdirectory, "
                "cd there in its own command first, then run the install",
                code="install-target",
            )
        if action == "deny":
            raise _Unsupported(f"{base!r} is not supported", code="unsupported-flag")
        if action == "inert":
            # `npm -v`, `npm --help`: the flag makes the whole command a print
            # and nothing after it runs, so `node -v && npm -v` at the start
            # of a fresh project is not refused.
            return _INERT, words
        if action == "skip+arg":
            index += 2 if "=" not in text else 1
            continue
        if action == "skip":
            index += 1
            continue
        # An unknown pre-verb flag could hide anything, including a directory
        # change. Fail closed rather than guess which slot the verb is in.
        raise _Unsupported(
            f"unrecognized flag {base!r} before the subcommand; "
            "run the package command in its plain form",
            code="unknown-verb",
        )
    verb = words[index].text if index < len(words) else None
    return verb, [words[0]] + words[index:]


def _check_env(assignments, installer, head):
    """Check every variable the installer reads against its family's table.

    `npm_config_registry=... npm install x` is the env form of `--registry`.
    Location and mode variables pass; a variable that changes the source,
    adds requirements, retargets the project, weakens a check or reroutes
    downloads is refused, and so is any unknown name with the installer's
    prefix. Each refusal names the variable, why, and what to do instead.
    """
    family = installer.get("env")
    if not family:
        return
    for assignment in assignments:
        name, value, appends = _assignment(assignment)
        category = verbs.classify_env(family, name)
        if category in (None, "allow", "locked"):
            continue
        reason = f"{name!r} " + verbs.env_reason(family, category, name)
        if category == "path":
            if _static_path(assignment, value, appends):
                continue
            raise _Unsupported(reason, code="install-target")
        if category == "retarget":
            raise _Unsupported(reason, code="install-target")
        if category == "unknown":
            raise _Unsupported(reason, code="unknown-setting")
        raise _Unsupported(reason, code="alternate-source")


# A path whose value the shell or the installer would still change: a
# variable, a substitution, `~`, a glob, or an escape.
_PATH_SURPRISE = re.compile(r"[$`~*?\[\]{}\\]")


def _names_guard_dir(path) -> bool:
    """A `.claude` component, compared the way a case-insensitive filesystem
    compares it: `.CLAUDE` is the same directory on APFS and NTFS, and
    Windows drops a component's trailing dots and spaces."""
    return any(part.rstrip(". ").casefold() == ".claude" for part in path.split("/"))


def _static_path(word, value, appends=False) -> bool:
    """True for a literal absolute path that is not inside a `.claude/`.

    The hook records the path and reconciliation reads it later, so it must
    mean the same thing then as now, and never name the guard's own files,
    neither as written nor once its symlinks are resolved. `NAME+=VALUE`
    appends to a value the guard cannot see, so it is never literal.
    """
    if (appends or word.dynamic or not value.startswith("/")
            or _PATH_SURPRISE.search(value)):
        return False
    if ".." in value.split("/") or _names_guard_dir(value):
        return False
    return not _names_guard_dir(os.path.realpath(value))


def _dispatch(installer, head, words, command):
    if installer.get("head_only"):
        # npx / uvx take no subcommand: the first positional IS the package, and
        # their flags belong to the handler. Consuming "globals" here would
        # reject `npx --no-install eslint` as an unknown pre-verb flag.
        handler = installer["acquire"][""]["handler"]
        inert_flags = set(installer.get("inert_flags") or ())
        for word in words[1:]:
            if not word.text.startswith("-"):
                break
            if word.text in inert_flags:
                # `uvx --version`, `npx --help`: a print, before any tool is named.
                return None
        if any(word.dynamic for word in words[1:]):
            raise _Unsupported(
                "package identity is built dynamically (a variable, substitution or "
                "glob); name the exact package and version instead",
                code="dynamic-spec",
            )
        if installer.get("ecosystem") == "npm":
            # npx hands everything from the first positional on to the tool.
            _refuse_npm_flag_values([w.text for w in words[1:]], until_positional=True)
        return _run_handler(handler, [w.text for w in words], command, head)

    all_words = words
    verb, words = _consume_globals(installer, words)
    if verb is _INERT:
        return None

    subtables = installer.get("subtables") or {}
    if verb in subtables:
        sub = subtables[verb]
        inner = dict(installer)
        inner["acquire"] = sub.get("acquire", {})
        inner["inert"] = sub.get("inert", [])
        inner["subtables"] = {}
        inner["normalize"] = None
        subverb = words[2].text if len(words) > 2 else None
        kind = verbs.classify(inner, subverb)
        if kind == "inert":
            return None
        if kind == "unknown":
            raise _Unsupported(
                f"unrecognized {head} {verb} subcommand {subverb!r}; "
                "only its plain documented forms are supported",
                code="unknown-verb",
            )
        if any(word.dynamic for word in words[1:]):
            raise _Unsupported(
                "package identity is built dynamically (a variable, substitution or "
                "glob); name the exact package and version instead",
                code="dynamic-spec",
            )
        handler = inner["acquire"][subverb]["handler"]
        # tokens[0] is the head, tokens[1] the subtable name, tokens[2] the verb.
        return _run_handler(handler, [w.text for w in words], command, head)

    canonical = verbs.normalize(installer, verb)
    kind = verbs.classify(installer, canonical)
    if kind == "inert":
        return None
    if kind == "unknown":
        if installer.get("unknown_verb") == "ignore":
            return None
        raise _Unsupported(
            f"unrecognized {head} subcommand {verb!r}; "
            "run the package command in its plain documented form",
            code="unknown-verb",
        )

    handler_name = installer["acquire"][canonical]["handler"]
    # `uv run` acquires via `--with` and, in project mode, by syncing the
    # project; the command it then runs routinely carries shell variables.
    # Let its handler decide, then an unreadable `--with` value fails the name
    # grammar. Without this, `uv run python -c "...$VAR..."` -- an ordinary
    # command that acquires nothing -- would be refused.
    if handler_name != "uv_run" and any(word.dynamic for word in words[1:]):
        raise _Unsupported(
            "package identity is built dynamically (a variable, substitution or "
            "glob); name the exact package and version instead",
            code="dynamic-spec",
        )
    if any(word.glued_op for word in words[1:]):
        raise _Unsupported(
            "a version range containing '<' or '>' must be quoted, "
            "e.g. pip install 'requests>=2.0'",
            code="unquoted-range",
        )
    if installer.get("ecosystem") == "npm":
        # The flags before the verb count too: `npm --loglevel=... install x`.
        _refuse_npm_flag_values([w.text for w in all_words[1:]])

    handler = handler_name
    texts = [w.text for w in words]
    texts[1] = canonical if len(texts) > 1 else canonical
    return _run_handler(handler, texts, command, head)


def _merge(results):
    requests = []
    manifests = []
    environments = []
    for result in results:
        requests.extend(result.requests)
        for scope in result.manifests:
            if scope not in manifests:
                manifests.append(scope)
        environments.extend(e for e in result.environments if e not in environments)
    if not requests and not manifests:
        return _ignore()
    return ParseResult(kind="package", requests=tuple(requests), manifests=tuple(manifests),
                       environments=tuple(environments))


def _run_handler(name, tokens, command, head):
    """Call the handler a table entry names.

    Handlers take plain string tokens; Words are flattened at this boundary
    so the handlers stay independent of the lexer.
    """
    if name == "unsupported":
        verb = tokens[1] if len(tokens) > 1 else ""
        raise _Unsupported(
            f"'{head} {verb}'".strip()
            + " acquires or executes package code and cannot be vetted; "
            "use a plain install of an exact version instead",
            code="unsupported-form",
        )
    handler = HANDLERS.get(name)
    if handler is None:
        raise _Unsupported(f"no handler for {name!r}", code="unsupported-form")
    return handler(tokens, command)


def _executable(token: str) -> str:
    """The command word's basename.

    An installer invoked by path is the same installer: `.venv/bin/pip`,
    `/opt/homebrew/bin/npm`, `..\\Scripts\\pip.exe`. Dispatching on the raw
    token would let every one of those through ungated, which matters most for
    virtualenvs, where using the env's own pip is the normal thing to do.
    """
    name = re.split(r"[\\/]", token)[-1]
    if name.lower().endswith(".exe"):
        name = name[:-4]
    # Version-suffixed interpreters are the same interpreter: pip3, pip3.12,
    # python3.13. Matching only `pip`/`pip3` would let
    # `pip3.12 install requests` dispatch nowhere and install silently.
    match = re.match(r"^(pip|python)[0-9.]*$", name)
    return match.group(1) if match else name


def _bad_source(spec: str) -> str | None:
    """Why this spec names a source the guard cannot vet, or None.

    Refusals from here are `alternate-source`, not `unparsable-spec`: the
    spec parses perfectly, it just points somewhere the registry review
    cannot reach. Calling that a parse failure would mislabel the denial.
    """
    s = spec.lower()
    if s.startswith(("git+", "git://", "ssh://", "http://", "https://", "file:")):
        return "direct Git/URL/file package sources are not supported"
    if s in (".", "..") or s.startswith(("./", "../", "/", "~")):
        return "local path package sources are not supported"
    if s.endswith((".tgz", ".tar.gz", ".tar", ".tar.bz2", ".zip", ".whl")):
        return "package archive files are not supported"
    return None


# ---------------------------------------------------------------------------
# npm / npx
# ---------------------------------------------------------------------------

_NPM_SAFE_FLAGS = {
    "-D", "--save-dev", "-S", "--save", "-P", "--save-prod", "-E", "--save-exact",
    "-O", "--save-optional", "--no-save", "-g", "--global", "-q", "--quiet", "--silent",
    "--ignore-scripts",
    # A mount that refuses symlinks: executables get no `.bin` links, local
    # packages are copied. Neither changes what is fetched.
    "--no-bin-links", "--bin-links", "--install-links", "--no-install-links",
}
# Flags that make npm resolve versions and write a lockfile without putting
# anything in node_modules. `--package-lock-only` still runs the ROOT
# package.json's lifecycle scripts, so it is
# only resolve-only together with `--ignore-scripts`.
_NPM_RESOLVE_ONLY_FLAGS = {"--package-lock-only", "--dry-run"}
_LOCK_ONLY_NEEDS_SCRIPTS_OFF = (
    "'npm install --package-lock-only' still runs the project's own lifecycle "
    "scripts (preinstall, install, postinstall, prepare); run "
    "'npm install --package-lock-only --ignore-scripts' instead"
)
_NPX_SAFE_FLAGS = {"-y", "--yes", "--no-install", "--prefer-online", "--prefer-offline", "-q", "--quiet"}


def _parse_npm_install(tokens, original) -> ParseResult:
    """npm install / i / add / ci / install-test / install-ci-test.

    `tokens` is the whole segment, `tokens[1]` the canonical verb.
    """
    sub = tokens[1] if len(tokens) > 1 else None
    if True:
        specs = []
        resolve_only = False
        scripts = "--ignore-scripts" not in tokens[2:] and "--ignore-scripts=true" not in tokens[2:]
        for arg in tokens[2:]:
            if arg.startswith("-"):
                base = arg.partition("=")[0]
                if base == "--registry":
                    raise _Unsupported("alternate npm registries are not supported", code="alternate-source")
                if base in _NPM_RESOLVE_ONLY_FLAGS:
                    resolve_only = True
                    continue
                if arg == "--ignore-scripts=true":
                    continue
                if base in _NPM_SAFE_FLAGS:
                    continue
                if base in ("--prefix", "-C"):
                    # The manifest gate reads the working directory's package.json,
                    # so a prefix would vet one manifest and install another.
                    raise _Unsupported(
                        f"{base!r} is not supported; to install into a subdirectory, "
                        "cd there in its own command first, then run the install",
                        code="install-target",
                    )
                raise _Unsupported(
                    f"unrecognized npm flag {base!r}; use a plain 'npm install <pkg>@<version>' form",
                    code="unsupported-flag",
                )
            specs.append(arg)
        if resolve_only:
            # --dry-run, or --package-lock-only with scripts off, resolves
            # versions and writes a lockfile but puts nothing in node_modules
            # and runs no code, so nothing is acquired. This is the escape
            # hatch the hook points at when a manifest's ranges cannot be pinned.
            if "--package-lock-only" in tokens[2:] and scripts and "--dry-run" not in tokens[2:]:
                raise _Unsupported(_LOCK_ONLY_NEEDS_SCRIPTS_OFF, code="unsupported-flag")
            return _ignore()
        if sub in ("ci", "install-ci-test") and specs:
            raise _Unsupported(f"'npm {sub}' does not take package arguments", code="unsupported-form")
        scope = ManifestScope("npm", scripts=scripts)
        if not specs:
            # Bare 'npm install' and 'npm ci' install the entire manifest.
            return _manifest_only(scope)
        # A named install ALSO reconciles the rest of the manifest.
        return _package(
            (_npm_spec_to_request(s, "install", original, manager="npm") for s in specs),
            manifests=(scope,),
        )


# npm (nopt) accepts any unambiguous prefix of a long flag, and both a
# scoped registry and a whole config file redirect every fetch.
_NPM_SOURCE_LONG = ("--registry", "--userconfig", "--globalconfig")


# Complete flags that happen to prefix a source flag; nopt takes them as-is.
_NPM_EXACT_FLAGS = {"--global"}


def _refuse_npm_source_flags(tokens):
    _refuse_npm_source_args(tokens[2:])


def _refuse_npm_source_args(args):
    for arg in args:
        if arg == "--":
            return
        name = arg.partition("=")[0]
        if not name.startswith("--") or name in _NPM_EXACT_FLAGS:
            continue
        if name.endswith(":registry") or any(
                len(name) >= 5 and flag.startswith(name) for flag in _NPM_SOURCE_LONG):
            raise _Unsupported("alternate npm registries are not supported", code="alternate-source")


def _refuse_npm_flag_values(args, until_positional=False):
    """Refuse a flag whose `=value` starts with '-'.

    npm's option parser splits `--flag=value` and then reads a value that
    starts with '-' as a flag of its own, so `--save=--registry=https://x/`
    sets the registry and `-y=--workspace=x` retargets the command, with
    nothing for a check of the flag's name to see. This applies to every npm
    verb, flag and alias, and to the flags before the verb. No npm flag the
    guard accepts takes a value that starts with '-'. A flag written without
    `=` is unaffected: its name is the whole word, and the next word is read
    as its own.

    Words after `--` belong to the command, and, for npx, so do the words from
    the first positional on.
    """
    for arg in args:
        if arg == "--":
            return
        if not arg.startswith("-"):
            if until_positional:
                return
            continue
        _, equals, value = arg.partition("=")
        if equals and value.startswith("-"):
            _refuse_npm_source_args([value])  # a hidden registry or config file
            raise _Unsupported(
                f"{arg!r}: npm reads a value that starts with '-' as another flag; "
                "write that flag on its own, without '='",
                code="unsupported-flag",
            )


def _npm_scope(tokens) -> ManifestScope:
    return ManifestScope("npm", scripts=not ({"--ignore-scripts", "--ignore-scripts=true"} & set(tokens)))


def _parse_npm_update(tokens, original) -> ParseResult:
    """npm update / dedupe re-resolve dependencies from the registry."""
    _refuse_npm_source_flags(tokens)
    return _manifest_only(_npm_scope(tokens))


def _parse_npm_audit(tokens, original) -> ParseResult:
    """Only 'npm audit fix' installs; a plain audit just reports."""
    if any(arg == "fix" for arg in tokens[2:]):
        _refuse_npm_source_flags(tokens)
        return _manifest_only(_npm_scope(tokens))
    return _ignore()


# Flags of `npm config` / `pip config` that take a separate value; the value
# is not the key.
_CONFIG_VALUE_FLAGS = {"--location", "-L", "--userconfig", "--globalconfig", "--editor"}


def _config_set_key(tokens):
    """The key an `npm config set` / `npm set` / `pip config set` writes, or None."""
    args, skip = [], False
    for t in tokens[1:]:
        if skip:
            skip = False
        elif t in _CONFIG_VALUE_FLAGS:
            skip = True
        elif not t.startswith("-"):
            args.append(t)
    if args[:2] == ["config", "set"]:
        rest = args[2:]
    elif args[:1] == ["set"]:
        rest = args[1:]
    else:
        return None
    return rest[0].partition("=")[0].lower() if rest else None


def _parse_npm_config(tokens, original) -> ParseResult:
    """`npm config set registry E` persists the redirect for every later call."""
    key = _config_set_key(tokens)
    # Any value-taking flag can stand between `set` and the key, so a set
    # that names a registry anywhere is refused.
    if "set" in tokens and any("registry" in t for t in tokens):
        key = "registry"
    if key and "registry" in key:
        raise _Unsupported(
            f"'npm config set {key}' redirects every later npm install; "
            "alternate registries are not supported",
            code="alternate-source",
        )
    return _ignore()


_PIP_SOURCE_KEYS = ("index-url", "extra-index-url", "find-links", "trusted-host", "no-index")


def _parse_pip_config(tokens, original) -> ParseResult:
    """`pip config set global.index-url E` persists the redirect."""
    key = _config_set_key(tokens)
    # pip normalises option names: lower case, `_` to `-`, leading `--` dropped.
    option = key.rpartition(".")[2].replace("_", "-").lstrip("-") if key else ""
    if option in _PIP_SOURCE_KEYS:
        raise _Unsupported(
            f"'pip config set {key}' redirects every later pip install; "
            "alternate indexes are not supported",
            code="alternate-source",
        )
    return _ignore()


def _parse_npm_exec(tokens, original) -> ParseResult:
    # npm (unlike npx) reads config flags after the package too, up to `--`.
    _refuse_npm_source_args(tokens[2:])
    return _parse_npx(tokens[2:], original, manager="npm exec")


def _parse_npm_init_verb(tokens, original) -> ParseResult:
    sub = tokens[1] if len(tokens) > 1 else "init"
    return _parse_npm_init(tokens[2:], original, manager=f"npm {sub}")


# `npm init` with no initializer only writes package.json, and these are the
# config flags it reads while doing that. The guard must pick out the same word
# as the initializer that npm does, so each is read the way npm's option parser
# reads it, and only when spelled out in full: npm takes any unambiguous prefix
# of a long flag, and an abbreviation could be some other flag. `--init-module`
# is not among them: it makes npm load and run a local JavaScript file.
_NPM_INIT_VALUE_FLAGS = frozenset({
    "--init-type", "--init-license", "--init-version",
    "--init-author-name", "--init-author-email", "--init-author-url", "--scope",
})
_NPM_INIT_BOOLEAN_FLAGS = frozenset({"-y", "--yes", "-f", "--force", "--init-private"})
# npm 10 does not know --init-type: it reads the flag as a switch and leaves
# the word after it as the initializer. Only `--init-type=<value>` is safe.
_NPM_INIT_EQUALS_ONLY = frozenset({"--init-type"})


def _parse_npm_init(args, original, manager) -> ParseResult:
    """npm init <initializer> downloads and executes create-<initializer>."""
    _refuse_npm_source_args(args)
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if not arg.startswith("-"):
            return _package([_npm_spec_to_request(_initializer_package(arg), "exec", original, manager=manager)])
        name, equals, value = arg.partition("=")
        if name in _NPM_INIT_VALUE_FLAGS:
            if not equals:
                if name in _NPM_INIT_EQUALS_ONLY:
                    raise _Unsupported(
                        f"{manager} flag {arg!r}: write the value in the same word, {name}=<value>",
                        code="unsupported-flag",
                    )
                if i < len(args) and not args[i].startswith("-"):
                    i += 1  # the value; a '-' word is not one: npm reads it as the next flag
            continue
        if name in _NPM_INIT_BOOLEAN_FLAGS:
            if not equals:
                # A switch takes the true/false after it as its own value (and
                # null, for --yes), so that word is not the initializer.
                own = ("true", "false", "null") if name in ("-y", "--yes") else ("true", "false")
                if i < len(args) and args[i] in own:
                    i += 1
                continue
            if name.startswith("--") and value in ("true", "false"):
                continue
        raise _Unsupported(f"unrecognized {manager} flag {arg!r}", code="unsupported-flag")
    return _ignore()  # bare 'npm init' only writes package.json


def _initializer_package(spec: str) -> str:
    """Map an npm initializer name to the package npm actually runs."""
    if spec.startswith("@"):
        sep = spec.find("@", 1)
        name, version = (spec, "") if sep == -1 else (spec[:sep], spec[sep:])
        scope, _, rest = name.partition("/")
        name = f"{scope}/create-{rest}" if rest else f"{scope}/create"
        return name + version
    sep = spec.find("@")
    name, version = (spec, "") if sep == -1 else (spec[:sep], spec[sep:])
    if name.startswith("create-"):
        return spec
    return f"create-{name}{version}"


def _parse_npx(args, original, manager) -> ParseResult:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            base = arg.partition("=")[0]
            if base in ("-p", "--package", "-c", "--call"):
                raise _Unsupported(
                    f"{base} forms are not supported; use '{manager} <pkg>@<version>'",
                    code="unsupported-form",
                )
            if base in _NPX_SAFE_FLAGS:
                i += 1
                continue
            raise _Unsupported(f"unrecognized flag {base!r} before the package name", code="unsupported-flag")
        # First positional token is the package; everything after belongs to the tool.
        return _package([_npm_spec_to_request(arg, "exec", original, manager=manager)])
    return _ignore()


def _npm_spec_to_request(spec, operation, original, manager) -> PackageRequest:
    bad = _bad_source(spec)
    if bad:
        raise _Unsupported(f"{spec!r}: {bad}", code="alternate-source")
    sep = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    if sep == -1:
        name, version = spec, None
    else:
        name, version = spec[:sep], spec[sep + 1:]
    if not name or not _NPM_NAME.fullmatch(name):
        raise _Unsupported(f"cannot safely parse npm package spec {spec!r}", code="unparsable-spec")
    exact = version if version and _NPM_EXACT.fullmatch(version) else None
    return PackageRequest(
        manager=manager,
        operation=operation,
        ecosystem="npm",
        name=name.lower(),
        display_name=name,
        requested_spec=version,
        exact_version=exact,
        registry=NPM_REGISTRY,
        original_command=original,
    )


# ---------------------------------------------------------------------------
# pip / uv pip
# ---------------------------------------------------------------------------

_PIP_DENY_FLAGS = {
    "-i", "--index-url", "--extra-index-url", "-f", "--find-links",
    "--trusted-host", "--no-index",
}
_PIP_SAFE_FLAGS = {
    "-U", "--upgrade", "--user", "--no-cache-dir", "--no-deps",
    "-q", "--quiet", "-v", "--verbose", "--pre", "--no-build-isolation",
}


def _parse_pip(args, original, manager) -> ParseResult:
    if not args or args[0] != "install":
        return _ignore()
    return _parse_pip_install(args[1:], original, manager=manager, operation="install")


def _parse_pip_install_verb(tokens, original) -> ParseResult:
    """tokens: pip install <args>  (head already folded from pip3 / pip3.12)"""
    return _parse_pip_install(tokens[2:], original, manager=tokens[0], operation="install")


def _parse_pip_download(tokens, original) -> ParseResult:
    """pip download fetches registry artifacts to disk without installing."""
    return _parse_pip_install(tokens[2:], original, manager=tokens[0], operation="download")


def _parse_pip_wheel(tokens, original) -> ParseResult:
    """pip wheel fetches AND builds, which executes setup.py."""
    return _parse_pip_install(tokens[2:], original, manager=tokens[0], operation="wheel")


def _parse_npx_verb(tokens, original) -> ParseResult:
    """tokens: npx <args>. --no-install / --offline acquire nothing."""
    args = tokens[1:]
    if any(a in ("--no-install", "--offline") for a in args):
        return _ignore()
    return _parse_npx(args, original, manager="npx")


def _parse_uvx_verb(tokens, original) -> ParseResult:
    return _parse_uvx(tokens[1:], original, manager="uvx")


# Installing a local project ('.', '-e .') pulls in that project's pyproject
# dependencies, which are version ranges pip resolves on the spot -- there is no
# lockfile to pin them from, so the guard cannot vet what would land. Refuse and
# name the path that is gated: pin with a real resolver, install the pins
# through the requirements gate, then install the project alone.
_LOCAL_PROJECT_REASON = (
    "installing a local project ('.' or '-e .') acquires its pyproject dependencies "
    "unreviewed. Pin them, install the pins through the gate, then install the project "
    "without dependencies -- each as its own command: "
    "uv pip compile pyproject.toml -o requirements.txt / "
    "pip install -r requirements.txt / "
    "pip install --no-deps ."
)


def _is_local_project(target: str) -> bool:
    """'.', './', '.[extras]' and './sub' name the working tree, not a registry package."""
    return target == "." or target.startswith(("./", ".["))


def _parse_pip_install(args, original, manager, operation) -> ParseResult:
    specs = []
    manifests = []
    local_project, local_targets = False, []
    no_deps = False
    isolated_build = "--no-build-isolation" not in args
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            base, has_eq, value = arg.partition("=")
            if base in _PIP_DENY_FLAGS:
                raise _Unsupported(f"alternate index / source flag {base!r} is not supported", code="alternate-source")
            if base in ("-r", "--requirement"):
                # A requirements file installs everything it lists.
                target = value if has_eq else (args[i + 1] if i + 1 < len(args) else "")
                if not target:
                    raise _Unsupported(f"{base} needs a requirements file argument", code="unsupported-form")
                manifests.append(ManifestScope("requirements", target))
                if not has_eq:
                    i += 1
            elif base in ("-e", "--editable"):
                target = value if has_eq else (args[i + 1] if i + 1 < len(args) else "")
                if _is_local_project(target):
                    local_project = True
                    local_targets.append(target)
                    if not has_eq:
                        i += 1
                else:
                    raise _Unsupported("editable installs from non-local sources are not supported", code="unsupported-form")
            elif base in _PIP_SAFE_FLAGS:
                if base == "--no-deps":
                    no_deps = True
            else:
                raise _Unsupported(f"unrecognized pip flag {base!r}", code="unsupported-flag")
        elif _is_local_project(arg):
            local_project = True
            local_targets.append(arg)
        else:
            specs.append(arg)
        i += 1
    if local_project and not no_deps:
        raise _Unsupported(_LOCAL_PROJECT_REASON, code="local-project")
    # With --no-deps a local project install acquires nothing external --
    # except, under build isolation, the build backend: pip fetches the
    # pyproject's build-system.requires from PyPI and runs it.
    if local_project and isolated_build:
        # The build-requires scope reads the cwd's pyproject.
        if any(t.rstrip("/") not in (".", "") for t in local_targets):
            raise _Unsupported("an isolated build of another directory is not supported; cd "
                               "there in its own command first, then install '.'",
                               code="install-target")
        manifests.append(ManifestScope("build-requires"))
    if not specs:
        return _manifest_only(*manifests) if manifests else _ignore()
    return _package(
        (_py_spec_to_request(s, manager, operation, original) for s in specs),
        manifests=manifests,
    )


def _py_spec_to_request(spec, manager, operation, original) -> PackageRequest:
    bad = _bad_source(spec)
    if bad:
        raise _Unsupported(f"{spec!r}: {bad}", code="alternate-source")
    match = re.fullmatch(r"([A-Za-z0-9._\-]+)(\[[A-Za-z0-9._,\s\-]*\])?(.*)", spec)
    if not match:
        raise _Unsupported(f"cannot safely parse package spec {spec!r}", code="unparsable-spec")
    name, _extras, rest = match.group(1), match.group(2), match.group(3)
    if not _PY_NAME.fullmatch(name):
        raise _Unsupported(f"cannot safely parse package name in {spec!r}", code="unparsable-spec")
    exact = None
    requested = None
    if rest:
        requested = rest
        if rest.startswith("==") and not _PY_RANGE.search(rest[2:]) and "," not in rest and "*" not in rest:
            candidate = rest[2:]
            if not _PY_EXACT.fullmatch(candidate):
                raise _Unsupported(f"cannot safely parse version in {spec!r}", code="unparsable-spec")
            exact = candidate
        elif not _PY_RANGE.match(rest):
            raise _Unsupported(f"cannot safely parse version constraint in {spec!r}", code="unparsable-spec")
    return PackageRequest(
        manager=manager,
        operation=operation,
        ecosystem="pypi",
        name=_normalize_py_name(name),
        display_name=name,
        requested_spec=requested,
        exact_version=exact,
        registry=PYPI_REGISTRY,
        original_command=original,
    )


def _normalize_py_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# uv / uvx
# ---------------------------------------------------------------------------

_UV_ADD_DENY_FLAGS = {
    "--index", "--index-url", "--default-index", "--extra-index-url",
    "-f", "--find-links", "--git", "--path", "--url", "-e", "--editable",
}
_UV_ADD_SAFE_FLAGS = {"--dev", "-d", "-U", "--upgrade", "-q", "--quiet"}
_UVX_DENY_FLAGS = {"--from", "--with", "--index", "--index-url", "--default-index"}


def _parse_uv_add(tokens, original) -> ParseResult:
    """uv add <spec>...   tokens: uv add <specs>"""
    if True:
        specs = []
        for arg in tokens[2:]:
            if arg.startswith("-"):
                base = arg.partition("=")[0]
                if base in _UV_ADD_DENY_FLAGS:
                    raise _Unsupported("alternate/direct package sources are not supported for 'uv add'", code="alternate-source")
                if base in _UV_ADD_SAFE_FLAGS:
                    continue
                raise _Unsupported(f"unrecognized 'uv add' flag {base!r}", code="unsupported-flag")
            specs.append(arg)
        if not specs:
            return _ignore()
        # `uv add` re-locks and syncs the whole project, so the project's
        # locked set is gated with the new spec (relocks: no --locked expected).
        return _package((_py_spec_to_request(s, "uv", "add", original) for s in specs),
                        manifests=(ManifestScope("uv-project", relocks=True),))


# Long source flags. The short ones, `-i` and `-f`, are read by
# `_is_uv_source_flag`, which also finds them bundled with other short options.
_UV_SOURCE_FLAGS = {
    "--index", "--index-url", "--default-index", "--extra-index-url",
    "--find-links", "--no-index", "--config-file", "--allow-insecure-host",
    # Where a managed interpreter is downloaded from. uv takes these as settings
    # and variables, and `uv python install` as `--mirror`; a verb that does not
    # take one makes uv refuse it, so listing them here costs nothing.
    "--python-install-mirror", "--pypy-install-mirror", "--python-downloads-json-url",
    "--mirror", "--pypy-mirror",
}
# Short options, across the verbs that take a source, that read the rest of
# their bundle as the value: `-pfoo` is `-p foo`, `-Cname=x` is `-C name=x`.
_UV_SHORT_VALUE_OPTIONS = "CPbcmoprtw"


def _is_uv_source_flag(arg, value_shorts=_UV_SHORT_VALUE_OPTIONS) -> bool:
    if not arg.startswith("-"):
        return False
    if arg.startswith("--"):
        return arg.partition("=")[0] in _UV_SOURCE_FLAGS
    # clap reads short options bundled (`-qi URL` is `-q -i URL`) and with the
    # value attached (`-ihttp://x`, `-f/dir`), so walk the bundle up to the
    # option that takes the rest of it as its value.
    for letter in arg[1:].partition("=")[0]:
        if letter in "if":
            return True
        if letter in value_shorts:
            return False
    return False


def _refuse_uv_source_flags(args, verb, value_shorts=_UV_SHORT_VALUE_OPTIONS):
    for arg in args:
        if _is_uv_source_flag(arg, value_shorts):
            raise _Unsupported(
                f"alternate/direct package sources are not supported for {verb!r}",
                code="alternate-source",
            )


# `uv sync` / `uv run` options that take a value, so the value is not read as
# the start of the command `uv run` executes.
_UV_VALUE_OPTIONS = {
    "--extra", "--group", "--only-group", "--no-group", "--package", "-p", "--python",
    "--env-file", "--with", "--with-editable", "--with-requirements", "--upgrade-package",
    "-P", "--reinstall-package", "--no-install-package", "--index", "--index-url", "-i",
    "--default-index", "--extra-index-url", "-f", "--find-links", "--python-platform",
    "--exclude-newer", "--resolution", "--prerelease", "--link-mode", "--config-setting",
    "-C", "--refresh-package", "--no-binary-package", "--no-build-package", "--config-file",
    "--color", "--cache-dir", "--index-strategy", "--keyring-provider", "--allow-insecure-host",
    "--python-preference", "--fork-strategy", "--exclude-newer-package", "--no-sources-package",
    "--torch-backend", "--only-dev", "--directory", "--project", "--script",
    "--bump", "--output-format",
}
# Flags without a value. An option in neither set is refused rather than
# guessed at: guessing wrong reads its value as the command, and every option
# after it goes unchecked.
_UV_FLAG_OPTIONS = {
    "--locked", "--frozen", "--all-extras", "--no-dev", "--dev", "--all-groups",
    "--no-default-groups", "--no-install-project", "--no-install-workspace",
    "--no-install-local", "--inexact", "--exact", "--active", "--no-sync", "--no-project",
    "--isolated", "--offline", "--refresh", "--reinstall", "--upgrade", "-U", "--no-editable",
    "--no-build-isolation", "--no-build", "--no-binary", "--compile-bytecode", "--no-cache",
    "-n", "--quiet", "-q", "--verbose", "-v", "--native-tls", "--no-progress", "--no-config",
    "--no-python-downloads", "--managed-python", "--no-managed-python", "--all-packages",
    "-s", "--gui-script", "--module", "-m", "--no-env-file", "--dry-run", "--check",
    "--no-sources", "--preview", "--no-preview", "--show-resolution", "--help", "-h",
    "--no-extra", "--no-default-extras", "-qq", "-vv", "--frozen-lock", "--short",
}


def _uv_project_options(args):
    """(options, rest) for `uv sync` / `uv run`: leading options, then the command."""
    options, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return options, args[i + 1:]
        if not arg.startswith("-"):
            break
        name, eq, value = arg.partition("=")
        if name in ("--directory", "--project"):
            raise _Unsupported(f"'{name}' points uv at a project the guard did not read; cd "
                               "there in its own command first", code="install-target")
        if name in _UV_VALUE_OPTIONS and not eq:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 1
        elif not eq and name not in _UV_FLAG_OPTIONS and not _is_uv_source_flag(arg):
            raise _Unsupported(f"unrecognized uv option {name!r}; write it as {name}=<value> "
                               "if it takes one", code="unsupported-flag")
        options.append((name, value))
        i += 1
    return options, args[i:]


def _uv_project_scope(options, relocks=False) -> ManifestScope:
    names = {name for name, _value in options}
    extras = ("*",) if "--all-extras" in names else tuple(
        value for name, value in options if name == "--extra" and value)
    return ManifestScope("uv-project", locked=bool(names & {"--locked", "--frozen"}),
                         extras=extras, relocks=relocks)


def _parse_uv_build(tokens, original) -> ParseResult:
    """`uv build` fetches build-system.requires into an isolated env and runs
    the backend; with --no-build-isolation it fetches nothing."""
    _refuse_uv_source_flags(tokens[2:], "uv build")
    if "--no-build-isolation" in tokens[2:]:
        return _ignore()
    targets = [t for t in tokens[2:] if not t.startswith("-")]
    if any(t not in (".", "./") for t in targets):
        raise _Unsupported("'uv build' of another directory is not supported; cd there in its "
                           "own command first, then run 'uv build' bare", code="install-target")
    return _manifest_only(ManifestScope("build-requires"))


# `uv venv` reads -p (a value) and the flags -c -q -v -n -h; -i and -f are the
# sources. Its own list, because `-c` takes a value on other verbs.
_UV_VENV_VALUE_SHORTS = "p"


def _parse_uv_venv(tokens, original) -> ParseResult:
    """`uv venv --seed` installs pip, setuptools and wheel from whatever index
    or find-links location uv is given, so a source flag is refused. Without
    one the seeds come from the default index, and a venv installs nothing the
    guard reviews: it is ignored like the rest of the toolchain. `--directory`
    and `--project` move where uv discovers `uv.toml`, which can name the
    index, so they are refused as they are on `uv sync`."""
    args = tokens[2:]
    for arg in args:
        name = arg.partition("=")[0]
        if name in ("--directory", "--project"):
            raise _Unsupported(f"'{name}' points uv at a project the guard did not read; cd "
                               "there in its own command first", code="install-target")
    _refuse_uv_source_flags(args, "uv venv", _UV_VENV_VALUE_SHORTS)
    return _ignore()


def _parse_uv_sync(tokens, original) -> ParseResult:
    """uv sync installs the whole locked project, dev groups included."""
    _refuse_uv_source_flags(tokens[2:], "uv sync")
    options, _rest = _uv_project_options(tokens[2:])
    return _manifest_only(_uv_project_scope(options))


# `uv version` forms that install nothing even when given a new version:
# `--dry-run` writes nothing, `--frozen` neither re-locks nor syncs, and
# `--no-sync` re-locks without installing, as `uv lock` does.
_UV_VERSION_NO_INSTALL = {"--dry-run", "--frozen", "--no-sync"}


def _parse_uv_version(tokens, original) -> ParseResult:
    """`uv version` prints the version. Given a VALUE or `--bump`, it writes
    pyproject.toml, then re-locks and syncs the project like `uv sync`, so
    that form is gated as the project scope; `--locked` keeps the lock as is."""
    args = tokens[2:]
    _refuse_uv_source_flags(args, "uv version")
    names, values, i = set(), [], 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-") and arg != "-":
            name, eq, _value = arg.partition("=")
            if name in ("--directory", "--project"):
                raise _Unsupported(f"'{name}' points uv at a project the guard did not read; cd "
                                   "there in its own command first", code="install-target")
            if name in _UV_VALUE_OPTIONS and not eq:
                i += 1
            elif not eq and name not in _UV_FLAG_OPTIONS and not _is_uv_source_flag(arg):
                raise _Unsupported(f"unrecognized uv option {name!r}; write it as {name}=<value> "
                                   "if it takes one", code="unsupported-flag")
            names.add(name)
        else:
            values.append(arg)
        i += 1
    if not (values or "--bump" in names) or names & _UV_VERSION_NO_INSTALL:
        return _ignore()
    return _manifest_only(_uv_project_scope([(name, "") for name in sorted(names)]))


def _parse_uv_pip_install(tokens, original) -> ParseResult:
    # tokens: uv pip install <args>
    return _parse_pip_install(tokens[3:], original, manager="uv pip", operation="install")


def _parse_uv_pip_sync(tokens, original) -> ParseResult:
    # tokens: uv pip sync <files>
    for arg in tokens[3:]:
        if arg.startswith("-") and (arg.partition("=")[0] in _PIP_DENY_FLAGS
                                    or _is_uv_source_flag(arg)):
            raise _Unsupported("alternate/direct package sources are not supported for 'uv pip sync'",
                               code="alternate-source")
    targets = [t for t in tokens[3:] if not t.startswith("-")]
    if not targets:
        return _ignore()
    return _manifest_only(*(ManifestScope("requirements", t) for t in targets))


def _parse_uv_tool_run(tokens, original) -> ParseResult:
    return _parse_uvx(tokens[3:], original, manager="uv tool run")


def _parse_uv_tool_install_verb(tokens, original) -> ParseResult:
    return _parse_uv_tool_install(tokens[3:], original)


def _parse_uv_run_verb(tokens, original) -> ParseResult:
    return _parse_uv_run(tokens[2:], original)


def _parse_uv_tool_install(args, original) -> ParseResult:
    specs = []
    for arg in args:
        if arg.startswith("-"):
            base = arg.partition("=")[0]
            if base in _UV_ADD_DENY_FLAGS or base in _UVX_DENY_FLAGS:
                raise _Unsupported("alternate/direct package sources are not supported for 'uv tool install'", code="alternate-source")
            if base in ("-q", "--quiet", "-U", "--upgrade"):
                continue
            raise _Unsupported(f"unrecognized 'uv tool install' flag {base!r}", code="unsupported-flag")
        specs.append(arg)
    if not specs:
        return _ignore()
    requests = []
    for spec in specs:
        if "==" not in spec and "@" in spec:
            requests.append(_tool_spec_to_request(spec, "uv tool", "tool-install", original))
        else:
            req = _py_spec_to_request(spec, "uv tool", "tool-install", original)
            requests.append(req)
    return _package(requests)


# `--active` only picks $VIRTUAL_ENV as the target; the project is still
# locked and synced into it.
_UV_RUN_NO_PROJECT = {"--no-sync", "--no-project", "--script", "-s"}


def _parse_uv_run(args, original) -> ParseResult:
    """In project mode `uv run` locks and syncs the project before running,
    exactly like `uv sync`; only `--no-sync` / `--no-project` / `--script` skip it.
    `--with` packages are gated as named requests on top. The command it runs
    is read like any other: `uv run pip install x` is a package operation."""
    options, command = _uv_project_options(args)
    _refuse_uv_source_flags([name for name, _v in options], "uv run")
    if command and _parse(" ".join(shlex.quote(word) for word in command)).kind != "ignore":
        raise _Unsupported("'uv run' would run a package operation inside the project "
                           "environment; run the package command directly, as its own "
                           "command (for that environment, `uv pip install ...`)", code="wrapper")
    project = None
    if not {name for name, _v in options} & _UV_RUN_NO_PROJECT:
        project = _uv_project_scope(options)
    result = _parse_uv_run_withs(args, original)
    if project is None:
        return result
    if result.kind == "package":
        return _package(result.requests, manifests=tuple(result.manifests) + (project,))
    return _manifest_only(project)


def _parse_uv_run_withs(args, original) -> ParseResult:
    withs = []
    i = 0
    while i < len(args):
        arg = args[i]
        if re.match(r"https?://", arg):
            raise _Unsupported("running scripts from URLs is not supported", code="unsupported-form")
        if arg == "--with":
            if i + 1 >= len(args):
                raise _Unsupported("'uv run --with' is missing its package argument", code="unsupported-form")
            withs.append(args[i + 1])
            i += 2
            continue
        if arg.startswith("--with="):
            withs.append(arg.split("=", 1)[1])
        elif arg.startswith("--with-requirements"):
            raise _Unsupported("'uv run --with-requirements' is not supported", code="unsupported-form")
        i += 1
    if withs:
        return _package(_py_spec_to_request(s, "uv", "run-with", original) for s in withs)
    return _ignore()


def _parse_uvx(args, original, manager) -> ParseResult:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            base = arg.partition("=")[0]
            if base in _UVX_DENY_FLAGS:
                raise _Unsupported(f"{base} is not supported for tool execution; use '<tool>@<version>'", code="unsupported-form")
            if base in ("-q", "--quiet"):
                i += 1
                continue
            raise _Unsupported(f"unrecognized flag {base!r} before the tool name", code="unsupported-flag")
        return _package([_tool_spec_to_request(arg, manager, "tool", original)])
    return _ignore()


def _tool_spec_to_request(spec, manager, operation, original) -> PackageRequest:
    bad = _bad_source(spec)
    if bad:
        raise _Unsupported(f"{spec!r}: {bad}", code="alternate-source")
    sep = spec.rfind("@")
    if sep <= 0:
        name, version = spec, None
    else:
        name, version = spec[:sep], spec[sep + 1:]
    if not _PY_NAME.fullmatch(name):
        raise _Unsupported(f"cannot safely parse tool spec {spec!r}", code="unparsable-spec")
    exact = None
    if version and version != "latest" and "*" not in version and _PY_EXACT.fullmatch(version):
        exact = version
    return PackageRequest(
        manager=manager,
        operation=operation,
        ecosystem="pypi",
        name=_normalize_py_name(name),
        display_name=name,
        requested_spec=version,
        exact_version=exact,
        registry=PYPI_REGISTRY,
        original_command=original,
    )


# --------------------------------------------------------------------------
# The handler map. Every `handler` named in recognition.json must resolve here;
# tests/spec/test_recognition.py asserts that, so a table entry can never point
# at a function that does not exist.
#
# Every handler takes (tokens, original_command) where tokens[0] is the head.
# --------------------------------------------------------------------------
HANDLERS = {
    "npm_install": _parse_npm_install,
    "npm_ci": _parse_npm_install,
    "npm_exec": _parse_npm_exec,
    "npm_init": _parse_npm_init_verb,
    "npm_update": _parse_npm_update,
    "npm_audit": _parse_npm_audit,
    "npm_config": _parse_npm_config,
    "pip_config": _parse_pip_config,
    "npx": _parse_npx_verb,
    "uvx": _parse_uvx_verb,
    "uv_add": _parse_uv_add,
    "uv_sync": _parse_uv_sync,
    "uv_version": _parse_uv_version,
    "uv_build": _parse_uv_build,
    "uv_venv": _parse_uv_venv,
    "uv_run": _parse_uv_run_verb,
    "uv_tool_install": _parse_uv_tool_install_verb,
    "uv_tool_run": _parse_uv_tool_run,
    "uv_pip_install": _parse_uv_pip_install,
    "uv_pip_sync": _parse_uv_pip_sync,
    "pip_install": _parse_pip_install_verb,
    "pip_download": _parse_pip_download,
    "pip_wheel": _parse_pip_wheel,
    "pip_sync": _parse_uv_pip_sync,
}
