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

import bench_config
import bench_table
import pm_config
import protocols
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
    kind: str               # npm | pnpm | bun | yarn | requirements | uv-project | build-requires
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
    # yarn only. The verb word as typed after normalising ("", install, add, up,
    # upgrade) and the flags the command carried (`--frozen-lockfile`,
    # `--ignore-scripts`, `--mode=skip-build`, ...). Yarn Berry and Yarn Classic share a
    # head, so the parser cannot tell which one runs: the hook decides that from the
    # project (`pm_config.yarn_flavour`) and judges the verb and flags against it.
    verb: str = ""
    flags: tuple = ()
    # yarn only: what the shell will give the command that the hook cannot see for itself, as
    # (name, value) pairs: ("head", the command word as typed), ("PATH", the literal value, or None
    # when it is built at run time) and ("YARN_IGNORE_SCRIPTS", "true"). The hook resolves the
    # `yarn` that will run from these, and counts the variable as a scripts-off proof.
    env: tuple = ()


@dataclass(frozen=True)
class RunScope:
    """A pnpm, Bun or Yarn command that RUNS project code and acquires nothing by
    itself (`pnpm run`, `yarn run`, `bun run`, `bun file.ts`, `pnpm exec`).
    The hook still reads the manager's configuration (a pnpmfile, a Yarn plugin, a
    Bun preload run on every command) and checks the state the run needs.
    `autoinstall` (Bun only): Bun may install the packages it cannot find before
    running, unless `--no-install` is given."""
    kind: str               # pnpm | bun | yarn
    # run | exec | test | start | restart | stop | file | x   run project code
    # remove                                                  rewrites the manifest and lock
    # print                                                   a bare `--version` / `--help`: a
    #   `manager` run whose missing Yarn pin is not a reason to refuse (nothing is read or run
    #   of the project; a pin and `yarnPath` / plugins are still checked)
    # manager                                                 only runs the manager's own
    #   binary (a read-only verb, `config get`, `dlx`, a resolve-only install): the pinned
    #   release is downloaded and the manager's configuration is read, nothing else is
    #   checked of the project (v1.10.0 hardening, A2)
    verb: str
    autoinstall: bool = False
    # `remove` only: False when the command turns lifecycle scripts off (`--ignore-scripts`,
    # Yarn's `--mode=skip-build`). Anything else leaves the root project's own install
    # scripts to run (A4).
    scripts: bool = True
    # `remove` only: the package names it deletes (they may be the very ones the manifest and
    # the lock disagree about, which the drift check must not hold against the command).
    names: tuple = ()
    # yarn only: the verb word the command used (`explain`, `npm`, `list`, ...) and the flags it
    # carried. Berry and Classic share the head and differ in which words are builtins; a word
    # that is not one in the project's Yarn runs a package.json script of that name instead.
    word: str = ""
    flags: tuple = ()
    env: tuple = ()


# The package managers whose manifest is package.json. pnpm, Bun and Yarn each
# get their own scope kind, not kind "npm": npm's lock reader returns nothing
# when there is no package-lock.json, which would read as "nothing to check".
PM_KINDS = ("pnpm", "bun", "yarn")
NPM_FAMILY_KINDS = ("npm",) + PM_KINDS
# The `PackageRequest.manager` words (first word) of pnpm, Bun and Yarn.
PM_MANAGERS = ("pnpm", "pnpx", "pnx", "bun", "bunx", "yarn", "yarnpkg")

# THE SAFETY SWITCH. The hook reads this and, while it is False, denies every
# command that reaches pnpm, Bun or Yarn as an acquisition (hook.py), and the
# handlers below refuse the inert-by-flag forms (`remove`, resolve-only,
# `bunx --no-install`) rather than return "ignore". Nothing reads these managers'
# manifests or locks yet; P6 sets this to True once every stage does.
PNPM_BUN_YARN_ENABLED = True

# THE SWITCH for Frappe support. While it is False, every allow path and every check that
# exists only for Frappe stays off and the refusals of `bench` and the checks that
# apply to nothing else are as they were shipped. The last stage sets it to True.
FRAPPE_ENABLED = True

# THE SWITCH for Yarn Classic (v1), staged as the pnpm/Bun/Yarn one was. While it is False
# the hook reads a Classic project exactly as before Classic was supported (the Berry reader
# refuses its lock, the Classic-only flags and verbs are refused here) and `disk_guard`
# mirrors it (`YARN_CLASSIC_DISK`; a test pins the two together).
YARN_CLASSIC_ENABLED = True


def scope_ecosystem(kind: str) -> str:
    """The registry ecosystem a ManifestScope kind installs from: npm for
    npm, pnpm, bun and yarn; pypi for the Python kinds."""
    return "npm" if kind in NPM_FAMILY_KINDS else "pypi"


def pm_kinds(result) -> dict:
    """{kind: scoped} for every pnpm, Bun or Yarn the parse reaches: `scoped` is
    True when it installs a manifest in the project, False for the one-shot
    runners (`pnpm dlx`, `bunx`, `yarn dlx`), which have no project tree."""
    kinds = {m.kind: True for m in result.manifests if m.kind in PM_KINDS}
    kinds.update({r.kind: True for r in result.runs if r.verb not in ("manager", "print")})
    for run in result.runs:
        kinds.setdefault(run.kind, False)
    for request in result.requests:
        word = request.manager.split()[0] if request.manager else ""
        if word in PM_MANAGERS:
            kinds.setdefault(PM_NAMES[word], False)
    return kinds


def uses_pnpm_bun_yarn(result) -> bool:
    """True when the parse reaches pnpm, Bun or Yarn: a scope of their kind,
    or a request they make (`pnpm dlx`, `bunx`, `yarn dlx`)."""
    return (any(m.kind in PM_KINDS for m in result.manifests)
            or bool(result.runs)
            or any(r.manager.split()[0] in PM_MANAGERS for r in result.requests if r.manager))


@dataclass(frozen=True)
class BenchScope:
    """A `bench` verb that installs packages or runs project code, which the hook lets run only
    when every app it touches is covered and the guard's installer files hold (`bench_gate`).
    `verb` is one of setup-requirements, update-requirements, update-run, new-app, build;
    `apps` are the apps it names (empty: every app of the bench)."""
    verb: str
    apps: tuple = ()
    node: bool = False
    python: bool = False
    dev: bool = False
    executable: str = ""    # the word the command named (`bench`, `/opt/x/bin/bench`)


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
    # Kinds of a command that only resolves and writes a lock (kind "ignore",
    # nothing acquired). The hook still reads their project: npm's lock-only
    # forms are refused beside another manager's lock, and pnpm, Bun and Yarn
    # read configuration that runs code (a `yarnPath`, a `.pnpmfile.cjs`).
    resolve_only: tuple = ()
    # Python environments outside the project tree this command installs into:
    # a literal `UV_PROJECT_ENVIRONMENT`, or a literal `VIRTUAL_ENV` that
    # `uv ... --active` or `uv pip` uses. The hook records them so
    # reconciliation reads them, as it reads `<project>/.venv`.
    environments: tuple = ()
    # pnpm, Bun or Yarn commands that run project code (`RunScope`). Nothing is
    # acquired by them, so the kind stays "ignore" when they are all there is;
    # the hook checks each one (`hook._run_denial`).
    runs: tuple = ()
    # Installs into a Frappe bench's Python env, which the hook ties to the bench
    # the shell's directory belongs to (`bench_config.python_in_env_problem`): the
    # literal `--python` / `-p` of `uv pip` (`env/bin/python`), or `""` for
    # `bench pip`, which uses the env of the bench it runs in.
    bench_pythons: tuple = ()
    # The executable of a `pip` or `python -m pip` install, as written, when it is a path
    # (`nested/env/bin/pip`, `/srv/bench/env/bin/python`): the hook finds out whether it
    # is a bench's env, whatever directory the shell is in (`bench_config.executable_problem`).
    executables: tuple = ()
    # `bench` verbs this command runs under the hook's bench gate (`BenchScope`).
    bench: tuple = ()
    # False when this segment follows one that is not a known reader (a writer, a git verb that
    # changes the tree, an interpreter) or another package segment, or runs in the background:
    # the manifests the hook compared may have changed, or the install may still be running when
    # the disk is read. The hook refuses such a bench, Yarn Classic or env install.
    exclusive: bool = True
    # `--no-binary` / `--no-binary-package` among the words of a uv command: they name
    # packages to build from source, which a bench's `no-build = true` otherwise refuses
    # (uv exempts a package named there from it). The hook refuses them inside a bench.
    source_build_flags: tuple = ()

    @property
    def manifest_scope(self) -> bool:
        return bool(self.manifests)


def _inert(result) -> bool:
    """Nothing in `result` acquires, runs a project script or needs a hook
    check of its own. A wrapper (`sh -c`, `env -S`, `$(...)`) that hides anything
    else from the hook is refused: the hook reads the event's command, not what
    the wrapper later runs."""
    return result.kind == "ignore" and not result.runs and not result.resolve_only


def _ignore() -> ParseResult:
    return ParseResult(kind="ignore")


def _manager_run(head, result, verb="manager", word=""):
    """pnpm and Yarn run through Corepack: the release `package.json` pins is DOWNLOADED
    and run, whatever the verb (v1.10.0 hardening, A2). Every segment that executes one
    carries a `manager` RunScope so the hook checks that pin and the manager's
    configuration, including the read-only verbs (`list`, `why`, `config get`), `dlx`,
    `remove`, a resolve-only install and a bare `--version` / `--help` print (pnpm and
    Yarn switch to the pinned release / run `yarnPath` before they print; v1.10.0
    hardening). `result` None means nothing was found to run."""
    kind = _PM_NAMES.get(head)
    if kind not in ("pnpm", "yarn"):
        return result
    if result is None:
        result = ParseResult(kind="ignore")
    if (any(m.kind == kind for m in result.manifests)
            or any(r.kind == kind for r in result.runs)):
        return result  # an install reviews the pin; a runner or `remove` checks it
    if not PNPM_BUN_YARN_ENABLED:
        _pm_disabled(f"'{head}'")
    return dataclasses.replace(result, runs=result.runs + (RunScope(kind, verb, word=word),))


def _resolve_only(kind) -> ParseResult:
    """Nothing is acquired (a lock is resolved and written), but the manager
    still reads the project's configuration, so the hook checks it."""
    return ParseResult(kind="ignore", resolve_only=(kind,))


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
    # Per command segment, (runs Bun with auto-install, only reads): A5. Bun installs what it
    # cannot find when no node_modules exists at run time, and a segment of the same line
    # that removes or moves node_modules makes that so after the hook looked.
    command_kinds = []
    impure = False   # an earlier segment is not a known reader, or was a package segment
    for segment in segments:
        produced = False
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
            if result is not _CD_MARKER:
                runner = result is not None and any(r.autoinstall for r in result.runs)
                # The runner itself only has to be free of substitutions, which run first.
                command_kinds.append((runner, not segment.substitutions if runner
                                      else _only_reads(segment, plain)))
            if result is _CD_MARKER:
                changed_directory = True
            elif result is not None and (result.kind != "ignore" or result.resolve_only
                                         or result.runs):
                if written:
                    refusals.append(("written", written))
                if unreadable:
                    refusals.append(("unreadable", unreadable))
                produced = True
                results.append(dataclasses.replace(
                    result, exclusive=not impure and not segment.background
                    and not _backgrounded(plain)))
        written = written or wrote
        unreadable = unreadable or why
        if produced or (words and not _header(segment.words)
                        and not (plain and (plain[0].text in _ASSIGNMENT_BUILTINS
                                            or _sets_allexport(plain)
                                            or _only_reads(segment, plain)))):
            impure = True

    if allexport and results:
        raise _Unsupported(_ALLEXPORT_MESSAGE, code="wrapper")

    if changed_directory and results:
        # The manifest gate reads the EVENT's working directory, so a permitted
        # `cd X && <install>` would vet the root manifest while the installer
        # reconciles X/. Same hazard the --prefix refusal exists to prevent.
        raise _Unsupported(_CD_MESSAGE, code="directory-change")

    if symlink and results:
        raise _Unsupported(_SYMLINK_MESSAGE, code="same-command-write")

    runners = sum(1 for runner, _reads in command_kinds if runner)
    if runners and (runners > 1 or any(not reads for _runner, reads in command_kinds)):
        raise _Unsupported(_AUTOINSTALL_MESSAGE, code="same-command-write")

    if refusals:
        kind, what = refusals[0]
        if kind == "written":
            raise _Unsupported(_WRITTEN_MESSAGE.format(file=what), code="same-command-write")
        raise _Unsupported(_UNREADABLE_MESSAGE.format(what=what), code="unreadable-environment")

    for result in results:
        if result.bench and not result.exclusive:
            raise _Unsupported(_EXCLUSIVE_MESSAGE, code="unreadable-environment")

    return _merge(results)


_EXCLUSIVE_MESSAGE = (
    "a bench install follows another command of the same line that is not a plain reader (a "
    "writer, a git verb that changes the tree, an interpreter, another install), or runs in the "
    "background (`&`, `nohup`): the manifests could change after the gate compared them, or the "
    "install may still be running when the disk is read. Run it as its own command, in the "
    "foreground, with nothing before it that writes"
)


_AUTOINSTALL_MESSAGE = (
    "a Bun command that may install packages at run time (`bun run`, `bun test`, `bun <file>`; "
    "Bun installs what it cannot find when there is no node_modules) shares this line with "
    "another command that could remove or move node_modules, write files or run code first, "
    "after Package Guard looked at the disk. Run the Bun command on its own, as its own "
    "command (`--no-install`, before the script or file name, makes it run only what is "
    "already installed)"
)


_BACKGROUND_WRAPPERS = frozenset({"nohup", "setsid", "disown", "at", "batch", "coproc", "daemonize"})


def _backgrounded(plain) -> bool:
    """The segment starts with a wrapper that detaches what follows it from the shell."""
    return bool(plain) and _executable(plain[0].text) in _BACKGROUND_WRAPPERS


def _only_reads(segment, plain) -> bool:
    """True for a segment that only reads and prints: a head the table lists as read-only
    (`verbs.READ_ONLY_HEADS`, exact case), no command substitution, and no redirection
    that writes a file. `rm`, `mv`, `git` and every other head is not."""
    if not plain or segment.substitutions:
        return False
    if _executable(plain[0].text, fold=False) not in verbs.READ_ONLY_HEADS:
        return False
    for operator, target in segment.redirects:
        if operator not in shell.WRITE_REDIRECTS:
            continue
        if target.text == "/dev/null" or (operator == ">&" and (target.text.isdigit() or target.text == "-")):
            continue
        return False
    return True


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
        found = (verbs.INSTALLER_FILE_IN_TEXT.search(code)
                 or (verbs.INSTALLER_DIR_IN_TEXT and verbs.INSTALLER_DIR_IN_TEXT.search(code))
                 or _GUARD_DIR_IN_TEXT.search(code))
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
        if not _inert(_parse(text, depth + 1)):
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

    # A real `Cd` is not the shell builtin: only the exact-case name changes
    # the directory the guard evaluates (reducing site, no folding).
    if _executable(head_word.text, fold=False) in verbs.CD_COMMANDS:
        return _CD_MARKER

    if head in _PEEL_WRAPPERS:
        return _parse_peeled(head, words, assignments, inherited, command, stdin)

    if head in _RECURSIVE_WRAPPERS:
        return _parse_wrapper_payload(head, words, command, stdin)

    # `python setup.py develop` is `pip install -e .` with the app's dependencies (setuptools 80+), and
    # `install` / `easy_install` / `bdist_egg` fetch them too: not a command the table above reads.
    if head == "setup.py":
        _check_setup_py(words[1:])
    elif verbs.is_interpreter(head):
        script = _python_script(words, stdin=True)
        if script is not None and _executable(script[0].text) == "setup.py":
            _check_setup_py(script[1])
        elif script is not None and script[0].text in ("-", "/dev/stdin", "/dev/fd/0"):
            _check_setup_stdin(script[1])  # a setup.py piped in cannot be told from any other script
        module = _python_module(words)
        if module is not None and module[0] == "setup":   # `python -m setup develop` runs ./setup.py
            _check_setup_py(module[1])

    installer = verbs.lookup(head)

    # `python -m pip` becomes the pip installer; nothing else about python does,
    # except that a module it cannot tell from an installer is refused.
    if installer is None and head == "python":
        module = _python_module(words)
        if module is not None:
            name, rest = module
            if not name:
                return None
            if name in ("pip", "pip.__main__"):
                installer = verbs.lookup("pip")
                words = [head_word] + rest
            elif name in ("uv", "uv.__main__"):
                installer = verbs.lookup("uv")
                words = [head_word] + rest
            else:
                _refuse_module(name, rest)

    if installer is None:
        if head == "bench":
            bench = _check_bench(words, inherited + assignments, command)
            if bench is not None:
                return bench
        if head == "virtualenv":
            _check_virtualenv(words[1:])
        if head == "easy_install":
            raise _Unsupported(_EASY_INSTALL_MESSAGE, code="foreign-manager")
        if head in verbs.FOREIGN:
            return _parse_foreign(head, words)
        return _check_unknown_head(head_word, head, words, inherited + assignments, command, stdin)

    if _PM_NAMES.get(head) == "pnpm":
        # `--config.<key>=<value>` sets any pnpm setting, the registry and the Node
        # runtime included, and pnpm reads it wherever it stands in the arguments.
        for word in words[1:]:
            if word.text.startswith("--config."):
                raise _Unsupported(f"{word.text.partition('=')[0]!r} sets an installer setting "
                                   "and is not supported", code="alternate-source")
    _check_python_env(inherited + assignments, installer)
    _check_env(inherited + assignments, installer, head)
    result = _dispatch(installer, head, words, command)
    if result is not None and result.kind == "package" and any(
            r.ecosystem == "npm" and r.name.casefold() == "corepack" for r in result.requests):
        # `npx corepack ...` / `npm exec corepack ...` fetch corepack itself.
        raise _Unsupported(verbs.FOREIGN["corepack"], code="foreign-manager")
    if result is not None and result.kind == "package":
        runs_manager = [r for r in result.requests
                        if r.operation == "exec" and r.name.casefold() in _RUN_MANAGER_PACKAGES]
        if runs_manager:
            # `npx pnpm add evil`, `bunx yarn ...`: the manager is the package
            # being run and the rest of the line is its command, which is not read.
            raise _Unsupported(
                f"{runs_manager[0].display_name!r} is a package manager, and what follows it "
                "is a command Package Guard does not read past; run it directly, as its own "
                "command", code="wrapper")
    if _scripts_off(assignments, inherited) and result is not None and result.manifests:
        result = dataclasses.replace(result, manifests=tuple(
            dataclasses.replace(m, scripts=False) if m.kind in _ENV_SCRIPTS_OFF_KINDS else m
            for m in result.manifests))
    if installer.get("env") == "uv" and result is not None and result.kind == "package":
        result = _uv_env_effects(result, assignments, inherited, words)
        flags = _source_build_flags(words)
        if flags:
            result = dataclasses.replace(result, source_build_flags=flags)
    if (result is not None and result.kind == "package" and head in ("pip", "python")
            and re.search(r"[\\/]", head_word.text)):
        result = dataclasses.replace(result, executables=(_executable_path(head_word),))
    if result is not None:
        result = _manager_run(head, result)
        if _PM_NAMES.get(head) == "yarn":
            result = _yarn_invocation(result, head_word, inherited + assignments)
    return result


def _yarn_invocation(result, head_word, assignments):
    """Attach to every yarn scope what the shell gives the command: the word it was typed as, the
    PATH it searches, and an inline `YARN_IGNORE_SCRIPTS=true`. The last assignment of a name wins;
    one that is built at run time or appended to leaves the value unknown (None)."""
    facts = {"head": head_word.text}
    for word in assignments:
        name, value, appends = _assignment(word)
        if name == "PATH" or name.upper() == "YARN_IGNORE_SCRIPTS":
            key = "PATH" if name == "PATH" else "YARN_IGNORE_SCRIPTS"
            known = not (word.dynamic or appends or shell.is_dynamic(value))
            facts[key] = value if known else None
    env = tuple(sorted(facts.items(), key=lambda item: item[0]))
    return dataclasses.replace(
        result,
        manifests=tuple(dataclasses.replace(m, env=env) if m.kind == "yarn" else m
                        for m in result.manifests),
        runs=tuple(dataclasses.replace(r, env=env) if r.kind == "yarn" else r for r in result.runs))


_SOURCE_BUILD_FLAGS = ("--no-binary", "--no-binary-package")


def _source_build_flags(words) -> tuple:
    """The flags that force a source build among the words of a uv command that are uv's
    own (up to a bare `--`, after which a `uv run` command's words begin)."""
    found = []
    for word in words[1:]:
        if word.text == "--":
            break
        name = word.text.partition("=")[0]
        if name in _SOURCE_BUILD_FLAGS and name not in found:
            found.append(name)
    return tuple(found)


def _executable_path(word) -> str:
    """The path of a `pip` / `python` command word, for the hook to tie to a bench. A
    leading `~/` is the home directory (the hook expands it, as the shell would), unless
    it was quoted, when it names a directory called `~`. A path the shell would still
    expand (`$B/env/bin/pip`) is passed as written; the hook refuses it inside a bench."""
    text = word.text
    return "./" + text if text.startswith("~") and word.quoted else text


# CPython's option parsing (Python/getopt.c, `bBc:dEhiIJm:OPqRsStuvVW:xX:?`, and Python 2's
# `Q:`): short flags combine (`-Im pip`), `-m` takes the rest of its word or else the next
# word (`-mpip`), `-W`/`-X` take a value the same way, so `-W -m pip` runs no module, and
# `--check-hash-based-pycs` is the one long option with a value (a separate word; `=` is an
# error). `-c`, `-`, `--` and the first non-option word end the options; only `-m` names a module.
_PYTHON_VALUE_FLAGS = "WXQ"
_PYTHON_VALUE_LONG = {"--check-hash-based-pycs"}
_PYTHON_PRINT_LONG = {"--help", "--help-env", "--help-xoptions", "--help-all", "--version"}


def _python_module(words):
    """(module, words after it) of the `-m <module>` an interpreter command line
    runs, the module name case-folded; None when it runs no module."""
    i = 1
    prints = False  # `-V`, `-h`: the interpreter prints and exits, whatever follows
    while i < len(words):
        text = words[i].text
        if text in ("-", "--") or not text.startswith("-"):
            return None
        if text.startswith("--"):
            prints = prints or text in _PYTHON_PRINT_LONG
            i += 2 if text in _PYTHON_VALUE_LONG else 1
            continue
        for j, flag in enumerate(text[1:], 1):
            if flag == "c":
                return None
            if flag in "hV?":
                prints = True
            if flag == "m":
                if prints:
                    return "", []  # prints and exits: runs nothing
                attached, value = text[j + 1:], words[i]
                if not attached:
                    i += 1
                    if i >= len(words):
                        return None
                    attached, value = words[i].text, words[i]
                # a name built at run time (`-m "$M"`) is marked with a `$`
                name = ("$" if value.dynamic else "") + attached.casefold()
                return name, words[i + 1:]
            if flag in _PYTHON_VALUE_FLAGS:
                if j == len(text) - 1:
                    i += 1
                break
        i += 1
    return None


def _python_script(words, stdin=False):
    """(script word, the words after it) of the file an interpreter command line runs; None when it
    runs a module (`-m`), a string (`-c`) or, unless `stdin`, standard input. The options are read as in
    `_python_module`."""
    i = 1
    while i < len(words):
        text = words[i].text
        if text == "--":
            return (words[i + 1], list(words[i + 2:])) if i + 1 < len(words) else None
        if text == "-":
            return (words[i], list(words[i + 1:])) if stdin else None
        if not text.startswith("-"):
            return words[i], list(words[i + 1:])
        if text.startswith("--"):
            i += 2 if text in _PYTHON_VALUE_LONG else 1
            continue
        for j, flag in enumerate(text[1:], 1):
            if flag in "cm":
                return None
            if flag in _PYTHON_VALUE_FLAGS:
                if j == len(text) - 1:
                    i += 1
                break
        i += 1
    return None


# What `python setup.py <command>` does: `develop` runs `python -m pip install -e .` since setuptools 80
# (dependencies and `--index-url` included); `install*`, `easy_install` and `test` fetch `install_requires`
# / `tests_require`; `upload` publishes. And a `setup.cfg` or `~/.pydistutils.cfg` `[aliases]` section turns
# ANY command word into another (`build = develop --index-url ...`), so no command word is known to only
# build: the one thing that is read is a command line with none (`--version`, `--help`, `--name`).
_SETUP_PY_SOURCE_OPTIONS = ("--index-url", "--find-links", "--allow-hosts", "--index")
_SETUP_PY_MESSAGE = (
    "`setup.py {command}` may install this project and its dependencies, or fetch them, out of the "
    "hook's sight: setuptools 80 and later run `develop` as `pip install -e .` (with an `--index-url` "
    "of your choosing), and an `[aliases]` section of a setup.cfg turns any command word, `build` or "
    "`sdist` included, into one of those. Use the route Package Guard reviews: `bench setup "
    "requirements` for a Frappe app, or `pip install -e .` / `uv pip install -e .` elsewhere, which "
    "review every dependency; `uv build` builds a distribution. Only a command line with no "
    "command word (`setup.py --version`, `--help`) is not refused")


# The setup commands a script that is fed in on standard input is refused for naming (`python - develop
# < setup.py`): the file is not named, so this is the cheap reading, not the complete one.
_SETUP_STDIN_COMMANDS = frozenset({
    "develop", "install", "easy_install", "bdist_egg", "test", "upload", "register", "build", "build_py",
    "build_ext", "build_clib", "build_scripts", "sdist", "bdist", "bdist_wheel", "bdist_dumb", "egg_info",
    "dist_info", "editable_wheel", "check", "clean", "install_lib", "install_scripts", "install_data",
    "install_egg_info", "install_headers"})


def _check_setup_stdin(args):
    for word in args:
        if word.text in _SETUP_STDIN_COMMANDS:
            raise _Unsupported(_SETUP_PY_MESSAGE.format(command=word.text) + "; a script read from standard "
                               "input is run with it", code="unsupported-form")


def _check_setup_py(args):
    """Refuse a `setup.py` command line that names a command. `args` are the words after the file."""
    texts = [a.text for a in args]
    commands = [t for t in texts if not t.startswith("-")]
    for text in texts:
        if text.startswith(_SETUP_PY_SOURCE_OPTIONS) or text == "-i" or text.startswith("-i="):
            raise _Unsupported(_SETUP_PY_MESSAGE.format(command=" ".join(commands) or text)
                               + f"; `{text.split('=')[0]}` names where packages come from",
                               code="unsupported-form")
    for word in args:
        text = word.text
        if word.dynamic or "$" in text:
            raise _Unsupported(_SETUP_PY_MESSAGE.format(command=text) + "; the command is only known "
                               "when it runs", code="unsupported-form")
        if not text.startswith("-"):
            raise _Unsupported(_SETUP_PY_MESSAGE.format(command=text), code="unsupported-form")


# Modules that install, or run an installer, and that are not read as `pip` or `uv`
# themselves: `ensurepip`, `setuptools`, `easy_install`, and any dotted submodule of
# those or of `pip` / `uv` (`pip._internal.cli.main`, `uv.__main__`). Matched on the whole
# dotted name's first part, so `uvicorn`, `pipdeptree` and `setuptools_scm` are other
# modules. A module name built at run time cannot be told from them and is refused too.
_INSTALLER_MODULES = frozenset({"pip", "uv", "ensurepip", "setuptools", "easy_install"})


def _installer_module(name):
    return name.split(".")[0] in _INSTALLER_MODULES or "$" in name


_MODULE_RUNNERS = frozenset(m.casefold() for m in verbs.MODULE_RUNNERS)


def _refuse_module(name, rest):
    """Refuse `python -m <name> ...` when it can install: an installer module, a
    module that runs another by name (`runpy`, `pdb`, ...) with an installer or an
    unreadable target, `venv --upgrade-deps`, `virtualenv --download`."""
    if _installer_module(name):
        raise _Unsupported(_MODULE_MESSAGE.format(module=name.lstrip("$")), code="wrapper")
    if name in _MODULE_RUNNERS:
        # The target is a word after the options; any word naming an installer module,
        # or built at run time, is treated as it (`-m pdb -m pip`, `cProfile -o f -m pip`).
        for word in rest:
            if word.dynamic or _installer_module(word.text.casefold().lstrip("-m")):
                raise _Unsupported(_RUNNER_MESSAGE.format(runner=name), code="wrapper")
    elif name == "venv":
        if any(w.text.startswith("--upgrade-") for w in rest):
            raise _Unsupported(_VENV_MESSAGE, code="wrapper")
    elif name == "virtualenv":
        _check_virtualenv(rest)


def _check_virtualenv(rest):
    for word in rest:
        option = word.text.partition("=")[0]
        if len(option) > 2 and option.startswith("--") and (
                "--download".startswith(option) or "--upgrade-embed-wheels".startswith(option)):
            raise _Unsupported(_VENV_MESSAGE, code="wrapper")


_VENV_MESSAGE = (
    "`venv --upgrade-deps` and `virtualenv --download` fetch pip and setuptools from the "
    "package index, unreviewed; create the environment offline (`python -m venv env`, "
    "without it)"
)

_RUNNER_MESSAGE = (
    "`python -m {runner}` runs another module by name, and its target is an installer or "
    "cannot be read; run the installer directly (`pip install ...`, `uv pip install ...`), "
    "as its own command"
)

_EASY_INSTALL_MESSAGE = (
    "`easy_install` downloads, builds and installs packages outside any review; use "
    "`pip install <exact version>` instead"
)


_PYTHON_ENV_MESSAGE = (
    "{name!r} makes Python run code or load modules before the installer (a "
    "sitecustomize or .pth file, another stdlib or cache) that Package Guard cannot "
    "read, and `-E` / `-I` do not reach the builds the installer starts; run the "
    "installer without it"
)


def _check_python_env(assignments, installer):
    """A Python variable in front of a Python-run installer (pip, uv) refuses."""
    if installer.get("env") not in ("pip", "uv"):
        return
    for word in assignments:
        name = _assignment(word)[0]
        if verbs.python_env_refused(name):
            raise _Unsupported(_PYTHON_ENV_MESSAGE.format(name=name), code="alternate-source")


_MODULE_MESSAGE = (
    "`python -m {module}` can install packages, and Package Guard does not read what it "
    "runs; run the installer directly (`pip install ...`, `uv pip install ...`), as its "
    "own command"
)


# Packages that ARE a package manager: run through npx, npm exec, pnpm dlx or
# bunx they would take a command line of their own.
_RUN_MANAGER_PACKAGES = frozenset({
    "pnpm", "pnpx", "pnx", "yarn", "yarnpkg", "bun", "bunx", "@yarnpkg/cli-dist",
    "@yarnpkg/cli", "@pnpm/exe", "@pnpm/pnpm",
})

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


# `npm_config_ignore_scripts` is read by npm and pnpm only. Bun reads no npm_config_*
# variable and Yarn Berry has no such setting, so the variable proves nothing for them.
_ENV_SCRIPTS_OFF_KINDS = ("npm", "pnpm")


def _scripts_off(assignments, inherited) -> bool:
    """`npm_config_ignore_scripts=true` among the segment's own assignments,
    and no assignment in reach giving that setting another value (npm reads
    the variable in any case, so two spellings can disagree)."""
    def ignore_scripts(word):
        name = _assignment(word)[0]
        return "ignore-scripts" in (verbs.env_key("npm", name), verbs.env_key("pnpm", name))

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
    if verbs.ACQUISITION_HINT.search(text) or _wrapped_bench(text):
        raise _wrapper_refusal(head, why)
    return None


_BENCH_WORD = re.compile(r"(?:^|\s)(?:\S*/)?bench(?=\s)")


def _wrapped_bench(text) -> bool:
    """Whether the words of a command Package Guard cannot parse run a `bench` verb the gate would
    not simply let through (`flock /tmp/l bench retry-upgrade`, `script -q /dev/null bench setup
    requirements`): a refused or gated verb, or `bench pip`. A verb the table does not know is not
    a hit, so a word that merely reads `bench` (`rg bench src`) is not one. Frappe switch only."""
    if not FRAPPE_ENABLED:
        return False
    for match in _BENCH_WORD.finditer(text):
        verdict = bench_table.classify(text[match.end():].split())
        if verdict.action == "scope" or verdict.verb == "pip" and verdict.action == "inert":
            return True
        if verdict.action == "refuse" and verdict.code != "unknown-verb":
            return True
    return False


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
        if _inert(_parse(" ".join(word.text for word in payload))):
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
    if _inert(inner):
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
    # Exact case only: `Echo`/`./Echo` is not the builtin and may run its words.
    if not dynamic and _executable(head_word.text, fold=False) in verbs.INERT_HEADS:
        return
    command_options = verbs.STDIN_SHELLS.get(head)
    if command_options is not None and stdin and verbs.ACQUISITION_HINT.search(stdin) and not any(
            w.text in command_options or w.text.startswith(tuple(o + "=" for o in command_options))
            for w in words[1:]):
        raise _Unsupported(_STDIN_MESSAGE.format(head=head), code="wrapper")
    if dynamic or verbs.is_interpreter(head):
        # An interpreter the dispatch did not name (`python3.13t`, `pypy3`, `py -3`, `"$PY"`):
        # its own words are an interpreter command line.
        module = _python_module(words)
        if module is not None and not module[0]:
            return None
        if module is not None:
            _refuse_module(*module)
    # `bench`'s own verbs were decided by `_check_bench` (a refusal raised, or the table let the verb
    # run); the hint's `bench <verb>` alternative would refuse the verbs the table allows, so its
    # words are read without the head, and what a verb carries (`execute ... npm install`) still is.
    readable = words[1:] if head == "bench" else words
    for reading in _readings(readable, _known_values(assignments), head in verbs.STRING_RUNNERS):
        if verbs.ACQUISITION_HINT.search(reading) or (head != "bench" and _wrapped_bench(reading)):
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
            if result is not None and not _inert(result):
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


# Frappe's `bench` installs out of the hook's sight: it runs `yarn install --check-files`
# (dependency scripts on) in every app and `pip install` into `<bench>/env`, from Python.
# These verbs acquire packages (or pull app code that does); the rest of bench (`build`,
# `start`, `migrate`, `new-site`, `--site x ...`) runs project code and is read like
# `npm run`. `setup` acquires only through these subcommands. Also here: the verbs that pull
# app code (`retry-upgrade`, `switch-to-develop`), rebuild the env and reinstall every app
# (`migrate-env`), and run ansible under sudo with `pip install ansible` and apt roles
# (`install`, `setup role`, `setup production`); `remove` is an alias of `remove-app`.
# `bench pip` is not here: it is read as a pip install into the bench env.
_BENCH_INSTALL_VERBS = verbs.BENCH_INSTALL_VERBS
_BENCH_INSTALL_SETUP = verbs.BENCH_INSTALL_SETUP
# The click group's own options (bench/commands/__init__.py) and the context flags
# bench's get_cmd_from_sysargv skips; the rest of bench's options are read by its verbs.
_BENCH_VALUE_FLAGS = {"--site", "--use-feature"}
_BENCH_FLAGS = {"--version", "--help", "-v", "--verbose", "--profile", "--force"}
_BENCH_UNKNOWN_OPTION = (
    "`bench {option}` is an option Package Guard does not know, and it could select a verb "
    "that installs packages out of the hook's sight; use bench's own options "
    "(`--site`, `--use-feature`, `-v`) or run the verb without it")
_BENCH_MESSAGE = (
    "`bench {verb}` installs packages out of the hook's sight: bench runs `yarn install` "
    "with dependency scripts on and `pip install` into the bench env from Python. The bench "
    "install verbs are not supported by Package Guard yet. Tell the user; run "
    "`bench build`, `bench start`, `bench migrate` and site commands as usual, and install "
    "a package into the bench env with `<bench>/env/bin/pip install name==version` or "
    "`bench pip install name==version`.")
# What `bench pip` hands to pip and uv that installs nothing. Everything else it
# can reach (`download`, `wheel`, `config`, uv's `sync` and `compile`) is refused:
# only `install` maps to `<bench>/env/bin/python -m pip install`.
_BENCH_PIP_INERT = {"uninstall", "freeze", "list", "show", "check", "tree", "inspect", "help"}


def _check_bench_env(assignments):
    """The variables written in front of a bench verb: every family bench's installs read
    (pip, uv, yarn, npm and bench's own) is held to its table, and the names that swap the
    program or the interpreter it runs (`PATH` finds `uv` and `yarn`) are refused.
    The variables that only choose bench's installer, the link mode, the cache or a
    Docker build are in the table's allow lists, and pass."""
    table = verbs.BENCH_ENV
    _check_env(assignments, {"env": list(table["families"])}, "bench")
    refused = set(table["refuse"]["retarget"])
    prefixes = tuple(table["refuse_prefixes"]["retarget"])
    for assignment in assignments:
        name = _assignment(assignment)[0]
        if name.upper() in verbs.BENCH_RESOLUTION_VARS:
            raise _Unsupported(
                f"{name!r} changes which release uv picks (a pre-release, the lowest, one newer than the "
                "cool-down), and a bench's uv chooses the release of a range and of its default build "
                "requirement: run the bench command without it", code="unknown-setting")
        if name.upper() in refused or name.upper().startswith(prefixes):
            raise _Unsupported(
                f"{name!r} changes which program or interpreter bench's installs run: run the "
                "bench command without it", code="install-target")


def _check_bench_table(words, assignments, command):
    """The bench verb table (`bench_table`), applied while the Frappe switch is on: a refusal
    raises, a verb that installs or runs project code returns a `BenchScope` result, `bench pip`
    is read as the pip command it runs, and every other known verb returns None (it runs)."""
    texts = [w.text for w in words[1:]]
    verdict = bench_table.classify(texts)
    if verdict.action == "refuse":
        # A literal code at each raise site, which the denial-code test reads.
        if verdict.code == "foreign-manager":
            raise _Unsupported(verdict.reason, code="foreign-manager")
        if verdict.code == "unsupported-flag":
            raise _Unsupported(verdict.reason, code="unsupported-flag")
        if verdict.code == "unknown-verb":
            raise _Unsupported(verdict.reason, code="unknown-verb")
        raise _Unsupported(verdict.reason, code="unsupported-form")
    _check_bench_env(assignments)
    if verdict.action == "scope":
        return ParseResult(kind="package", bench=(BenchScope(
            verdict.verb, verdict.apps, verdict.node, verdict.python, verdict.dev,
            words[0].text),))
    if verdict.verb == "pip":
        rest = bench_table._after_group_flags(texts)
        return _parse_bench_pip(words[len(texts) - len(rest) + 2:], assignments, command)
    return None


def _check_bench(words, assignments=(), command=""):
    """Refuse the bench verbs that acquire packages; leave the rest to run.

    `bench pip` is the one verb that is read instead of refused (`_parse_bench_pip`). With the
    Frappe switch on, the whole table of `bench_table` decides instead."""
    if FRAPPE_ENABLED:
        return _check_bench_table(words, assignments, command)
    texts = [w.text for w in words[1:]]
    index = 0
    while index < len(texts) and texts[index].startswith("-"):
        option = texts[index]
        if option == "--":  # click: what follows is the command
            index += 1
            break
        if option in _BENCH_VALUE_FLAGS:
            index += 2
        elif option in _BENCH_FLAGS or option.partition("=")[0] in _BENCH_VALUE_FLAGS:
            index += 1
        else:
            raise _Unsupported(_BENCH_UNKNOWN_OPTION.format(option=option), code="foreign-manager")
    if index >= len(texts):
        return None
    verb = texts[index]
    if verb == "pip":
        return _parse_bench_pip(words[index + 2:], assignments, command)
    if FRAPPE_ENABLED:
        _check_bench_env(assignments)
    sub = index + 1
    if verb == "setup":
        while sub < len(texts) and texts[sub] == "--":
            sub += 1
    if verb in _BENCH_INSTALL_VERBS or (
            verb == "setup" and sub < len(texts) and texts[sub] in _BENCH_INSTALL_SETUP):
        shown = verb if verb != "setup" else f"setup {texts[sub]}"
        raise _Unsupported(_BENCH_MESSAGE.format(verb=shown), code="foreign-manager")
    return None


def _parse_bench_pip(args, assignments, command) -> ParseResult:
    """`bench pip <args>` is `<bench>/env/bin/python -m pip <args>`, or, when uv is
    in use (its default since bench 5.28), `uv pip <args> --python <env python>`
    (`bench/commands/make.py` `pip`, which execs one or the other). `install` is
    read as the pip install it is; the verbs that install nothing pass; the rest is
    refused. Both installers' environment variables are checked, and the hook checks
    that a bench holds the directory the command runs in (`bench_pythons`)."""
    _check_bench_env(assignments)
    if any(word.dynamic for word in args):
        raise _Unsupported("package identity is built dynamically (a variable, substitution "
                           "or glob); name the exact package and version instead",
                           code="dynamic-spec")
    if any(word.glued_op for word in args):
        raise _Unsupported("a version range containing '<' or '>' must be quoted, "
                           "e.g. bench pip install 'requests>=2.0'", code="unquoted-range")
    texts = [w.text for w in args]
    if not texts or texts[0] in ("-h", "--help") or texts[0] in _BENCH_PIP_INERT:
        return _ignore()
    if texts[0] != "install":
        raise _Unsupported(f"`bench pip {texts[0]}` is not supported; `bench pip install "
                           "name==version` is", code="unsupported-form")
    result = _parse_pip_install(texts[1:], command, manager="bench pip", operation="install")
    if result.kind == "package":
        result = dataclasses.replace(result, bench_pythons=("",))
    return result


def _parse_foreign(head, words):
    """Recognise-and-deny the package managers this project forbids."""
    # Only words[1] is the verb: a flag's value must never be read as one
    # (`pnpm -C list add evil`). A leading flag is safe only as a bare print.
    first = words[1].text if len(words) > 1 else None
    if head in verbs.FOREIGN_PRINT_ONLY:
        # corepack: only a bare --version/--help; any subcommand may download.
        if len(words) == 2 and first in verbs.FOREIGN_PRINT_ONLY[head]:
            return None
        raise _Unsupported(verbs.FOREIGN[head], code="foreign-manager")
    if head in verbs.FOREIGN_NO_SAFE:
        first = None  # a runner's first argument is the package it executes
    if first is not None and first in verbs.FOREIGN_SAFE:
        if first.startswith("-"):
            if len(words) == 2:
                return None
        elif first == "config":
            # read-only forms only: `config get ...` / `config list`
            if len(words) > 2 and words[2].text in ("get", "list"):
                return None
        else:
            return None
    raise _Unsupported(verbs.FOREIGN[head], code="foreign-manager")


_INERT = object()  # verb sentinel: a pre-verb flag made the command a print


def _consume_globals(installer, words):
    """Strip pre-verb global flags; return (verb, remaining_words).

    `verb` is `_INERT` when a flag such as `--version` ends the command."""
    globals_ = installer.get("globals") or {}
    index = 1
    moved = []   # Yarn Classic's install flags written before the verb: they belong after it
    while index < len(words):
        text = words[index].text
        if not text.startswith("-"):
            break
        base = text.partition("=")[0]
        action = globals_.get(base)
        if action in ("move", "move+arg") and not words[index].dynamic:
            take = 2 if action == "move+arg" and "=" not in text else 1
            moved.extend(words[index:index + take])
            index += take
            continue
        if action is None and base.startswith(tuple(installer.get("globals_deny_prefixes") or ())):
            # pnpm's `--config.<key>` sets any setting, the registry included.
            raise _Unsupported(f"{base!r} is not supported", code="alternate-source")
        if action == "deny_cwd":
            raise _Unsupported(
                f"{base!r} is not supported; to install into a subdirectory, "
                "cd there in its own command first, then run the install",
                code="install-target",
            )
        if action == "deny_source":
            raise _Unsupported(f"{base!r} names another registry or configuration; "
                               "alternate sources are not supported", code="alternate-source")
        if action == "deny":
            raise _Unsupported(f"{base!r} is not supported", code="unsupported-flag")
        if action == "inert":
            if installer.get("print_bare_only") and index != len(words) - 1:
                # `pnpm --version add evil`: whether the rest runs is the
                # manager's business, not ours; only a bare print is a print.
                raise _Unsupported(
                    f"{base!r} is a print only on its own; run the package command without it",
                    code="unsupported-form")
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
    if moved:
        if verb not in (None, "install", "add", "upgrade", "remove", "up"):
            raise _Unsupported(
                f"{moved[0].text!r} before the subcommand is supported only for an install; write "
                "it after the subcommand", code="unknown-verb")
        if verb is None:
            # `yarn --frozen-lockfile --ignore-scripts`: a bare yarn is an install; the empty verb
            # keeps the slot the handlers read the verb from.
            return verb, [words[0], shell.Word(text="")] + moved
        return verb, [words[0], words[index]] + moved + words[index + 1:]
    return verb, [words[0]] + words[index:]


def _check_env(assignments, installer, head):
    """Check every variable the installer reads against its family's table.

    `npm_config_registry=... npm install x` is the env form of `--registry`.
    Location and mode variables pass; a variable that changes the source,
    adds requirements, retargets the project, weakens a check or reroutes
    downloads is refused, and so is any unknown name with the installer's
    prefix. Each refusal names the variable, why, and what to do instead.
    """
    families = installer.get("env")
    if not families:
        return
    if isinstance(families, str):
        families = [families]
    for assignment in assignments:
        name, value, appends = _assignment(assignment)
        if "yarn" in families and pm_config.yarn_env_key(name):
            # Yarn: the rc rule on the setting the name overrides, the one the
            # hook applies to its own environment and to .yarnrc.yml.
            problem = pm_config.yarn_env_problem(name, value)
            if problem is None and not appends:
                continue
            category = verbs.classify_env("yarn", name)
            reason = f"{name!r} " + (problem or "appends to a value Package Guard cannot see")
            if category == "retarget":
                raise _Unsupported(reason, code="install-target")
            if category in (None, "allow", "locked", "unknown"):
                raise _Unsupported(reason, code="unknown-setting")
            raise _Unsupported(reason, code="alternate-source")
        # An installer may read several families (pnpm: pnpm_config_ and
        # npm_config_); the first that refuses the name decides.
        family, category = next(
            ((f, c) for f in families for c in [verbs.classify_env(f, name)]
             if c not in (None, "allow", "locked")), (families[0], None))
        if category is None:
            continue
        if ((set(families) & {"pnpm", "bun"} or family == "corepack") and not appends
                and pm_config.env_value_allows(family, category, name, value)):
            continue  # a source variable naming the official registry
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
        # A print still starts the manager, and pnpm and Yarn switch to the
        # release `packageManager` pins (or run `yarnPath`) before they print,
        # so `pnpm --version` / `yarn -h` get the same pin and config checks as
        # any other verb. Without a pin or a config hazard it passes.
        return _manager_run(head, None, "print")

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
            return _manager_run(head, None)
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
        # `help [verb]` only prints, like `--help`; every other inert verb reads the project.
        return _manager_run(head, None, "print" if canonical == "help" else "manager",
                            word=canonical if _PM_NAMES.get(head) == "yarn" else "")
    if kind == "unknown":
        if installer.get("unknown_verb") == "ignore":
            return _manager_run(head, None)
        file_handler = installer.get("file_handler")
        if file_handler and _is_bun_file(verb):
            # `bun ./x.ts`: Bun's shorthand for `bun run ./x.ts`.
            _refuse_dynamic_before_name(words[1:], _PM_RUN_VALUE["bun"])
            if any(word.glued_op for word in words[1:]):
                raise _Unsupported("a redirect or operator is glued to a word",
                                   code="unquoted-range")
            texts = [w.text for w in words]
            if _pre_verb_no_install(all_words, words):
                texts.insert(1, "--no-install")
            return _run_handler(file_handler, texts, command, head)
        hint = installer.get("unknown_hint")
        raise _Unsupported(
            f"unrecognized {head} subcommand {verb!r}; "
            + (f"{hint}" if hint else "run the package command in its plain documented form"),
            code="unknown-verb",
        )

    handler_name = installer["acquire"][canonical]["handler"]
    # `uv run` acquires via `--with` and, in project mode, by syncing the
    # project; the command it then runs routinely carries shell variables.
    # Let its handler decide, then an unreadable `--with` value fails the name
    # grammar. Without this, `uv run python -c "...$VAR..."` -- an ordinary
    # command that acquires nothing -- would be refused.
    if handler_name in _RUN_HANDLERS:
        # A runner's own arguments are the script's, and routinely carry shell
        # variables. A variable BEFORE the script name could be a flag.
        _refuse_dynamic_before_name(words[2:], _PM_RUN_VALUE.get(_executable(head), set()))
    elif handler_name != "uv_run" and any(word.dynamic for word in words[1:]):
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
    if len(texts) > 1:
        texts[1] = canonical
    else:
        texts.append(canonical)  # a bare command (`yarn`) is the empty verb
    if handler_name in _RUN_HANDLERS and _pre_verb_no_install(all_words, words):
        texts.insert(2, "--no-install")  # `bun --no-install run x`
    result = _run_handler(handler, texts, command, head)
    if _PM_NAMES.get(head) == "yarn":
        # Yarn Berry and Yarn Classic differ in which words are builtins: carry the word, so
        # the hook can refuse one that is not a builtin of the project's Yarn (it would run a
        # package.json script of that name).
        result = _manager_run(head, result, word=canonical)
    return result


_RUN_HANDLERS = frozenset({"pnpm_run", "pnpm_exec", "yarn_run", "bun_run"})


def _refuse_dynamic_before_name(words, value_flags):
    """Words up to the first plain positional are read as flags; a variable, glob
    or substitution there could be any flag."""
    skip = False
    for word in words:
        if skip:
            skip = False
            continue
        if word.dynamic:
            raise _Unsupported(
                "a flag before the script name is built dynamically (a variable, "
                "substitution or glob); write it out", code="dynamic-spec")
        if not word.text.startswith("-"):
            return
        if word.text in value_flags:
            skip = True


def _pre_verb_no_install(all_words, words) -> bool:
    """`bun --no-install run x`: a flag the global scan skipped before the verb."""
    before = all_words[1:len(all_words) - len(words) + 1]
    return any(w.text == "--no-install" for w in before)


def _merge(results):
    requests = []
    manifests = []
    environments = []
    resolve_only = []
    runs = []
    bench_pythons = []
    bench = []
    executables = []
    source_build_flags = []
    for result in results:
        bench.extend(b for b in result.bench if b not in bench)
        source_build_flags.extend(f for f in result.source_build_flags if f not in source_build_flags)
        bench_pythons.extend(b for b in result.bench_pythons if b not in bench_pythons)
        executables.extend(e for e in result.executables if e not in executables)
        resolve_only.extend(k for k in result.resolve_only if k not in resolve_only)
        runs.extend(r for r in result.runs if r not in runs)
        requests.extend(result.requests)
        for scope in result.manifests:
            if scope not in manifests:
                manifests.append(scope)
        environments.extend(e for e in result.environments if e not in environments)
    if not requests and not manifests and not bench:
        return ParseResult(kind="ignore", resolve_only=tuple(resolve_only), runs=tuple(runs))
    return ParseResult(kind="package", requests=tuple(requests), manifests=tuple(manifests),
                       environments=tuple(environments), resolve_only=tuple(resolve_only),
                       runs=tuple(runs), bench_pythons=tuple(bench_pythons), bench=tuple(bench),
                       executables=tuple(executables),
                       source_build_flags=tuple(source_build_flags),
                       exclusive=all(r.exclusive for r in results))


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


def _executable(token: str, fold: bool = True) -> str:
    """The command word's basename.

    An installer invoked by path is the same installer: `.venv/bin/pip`,
    `/opt/homebrew/bin/npm`, `..\\Scripts\\pip.exe`. Dispatching on the raw
    token would let every one of those through ungated, which matters most for
    virtualenvs, where using the env's own pip is the normal thing to do.

    Folding rule. `fold=True` (casefold, .exe/.cmd/.bat/.ps1 stripped) is for
    lookups that ADD scrutiny, where a wrong match only refuses more:
      - _past_wrappers / _PEEL_WRAPPERS, _RECURSIVE_WRAPPERS (payload parsed)
      - verbs.lookup installers, FOREIGN managers, python -m pip/uv
      - _SHELLS / STRING_RUNNERS / STDIN_SHELLS / eval / xargs (payload re-read)
      - ln/gln symlink detection, _write_targets, _inline_code
    `fold=False` (exact case, only the historical `.exe` strip) is for lookups
    that REDUCE scrutiny or change context, where a loose match fails open:
      - verbs.INERT_HEADS (`Echo npm i x` must still be hint-scanned)
      - verbs.CD_COMMANDS (`Cd /tmp` is not the builtin; the guard would
        evaluate the wrong directory)
    Never add a new allow/skip table lookup with fold=True.
    """
    name = re.split(r"[\\/]", token)[-1]
    if fold:
        name = name.casefold()
        for suffix in (".exe", ".cmd", ".bat", ".ps1"):
            if name.endswith(suffix):
                name = name[:-len(suffix)]
                break
    elif name.lower().endswith(".exe"):
        name = name[:-4]
    # Version-suffixed interpreters are the same interpreter: pip3, pip3.12,
    # python3.13. Matching only `pip`/`pip3` would let
    # `pip3.12 install requests` dispatch nowhere and install silently.
    match = re.match(r"^(pip|python)[0-9.]*$", name)
    if match:
        return match.group(1)
    if verbs.is_interpreter(name):
        return "python"
    # `easy_install`, `easy_install-3.9`: setuptools' legacy installer executable.
    return "easy_install" if re.fullmatch(r"easy_install(?:-[0-9.]+)?", name) else name


def _bad_source(spec: str) -> str | None:
    """Why this spec names a source the guard cannot vet, or None.

    Refusals from here are `alternate-source`, not `unparsable-spec`: the
    spec parses perfectly, it just points somewhere the registry review
    cannot reach. Calling that a parse failure would mislabel the denial.
    """
    s = spec.lower()
    if s.startswith(protocols.NON_REGISTRY_PREFIXES):
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
            # It is resolve-only, not plain ignore: the hook still refuses it in a
            # project another manager owns (`hook._npm_project_problem`).
            if "--package-lock-only" in tokens[2:] and scripts and "--dry-run" not in tokens[2:]:
                raise _Unsupported(_LOCK_ONLY_NEEDS_SCRIPTS_OFF, code="unsupported-flag")
            return _resolve_only("npm")
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
# pnpm / Bun / Yarn Berry
#
# Flags are an allow-list per manager, as `_NPM_SAFE_FLAGS` is for npm: a flag
# not listed is `unsupported-flag`. Each manager has its own table because the
# same spelling means different things (`-C` is pnpm's directory and Yarn's
# caret; `-w` is pnpm's workspace root).
# ---------------------------------------------------------------------------

_PM_NAMES = PM_NAMES = {"pnpm": "pnpm", "pnpx": "pnpm", "pnx": "pnpm", "bun": "bun",
                        "bunx": "bun", "yarn": "yarn", "yarnpkg": "yarn"}

_PM_FLAGS = {
    "pnpm": {
        "safe": {"-D", "--save-dev", "-P", "--save-prod", "-O", "--save-optional", "-E",
                 "--save-exact", "--frozen-lockfile", "--production", "--prod", "--dev",
                 "--no-optional", "-q", "--quiet", "-s", "--silent", "--no-color", "--color",
                 "--offline", "--prefer-offline", "--ignore-scripts"},
        "value": {"--reporter", "--loglevel"},
        "target": {"-C", "--dir", "--filter", "-F", "--filter-prod", "-r", "--recursive", "-w",
                   "--workspace-root", "--ignore-workspace", "-g", "--global", "--prefix"},
        "source": {"--registry", "--userconfig", "--globalconfig", "--config"},
        "resolve_only": {"--lockfile-only"},
    },
    "bun": {
        "safe": {"-d", "-D", "--dev", "--development", "-p", "--production", "-O", "--optional",
                 "--peer", "-E", "--exact", "--frozen-lockfile", "--ignore-scripts", "--silent",
                 "--verbose", "--no-progress", "--no-summary", "--offline"},
        "value": {"--linker"},
        "target": {"--cwd", "-g", "--global", "--filter"},
        "source": {"--registry", "-c", "--config"},
        "resolve_only": {"--dry-run", "--lockfile-only"},
    },
    "yarn": {
        # Berry has no --ignore-scripts: `--mode=skip-build` is the safe flag.
        "safe": {"-D", "--dev", "-P", "--peer", "-O", "--optional", "-E", "--exact", "-T",
                 "--tilde", "-C", "--caret", "--immutable", "--immutable-cache", "--check-cache",
                 "--json"},
        "value": set(),
        "target": {"--cwd", "-A", "--all", "-W"},
        "source": {"--registry", "--config"},
        "resolve_only": set(),
    },
}
_PM_SCRIPTS_OFF = {"pnpm": {"--ignore-scripts", "--ignore-scripts=true"},
                   "bun": {"--ignore-scripts", "--ignore-scripts=true"},
                   "yarn": {"--mode=skip-build"}}

# A spec's version part (or its whole text) naming something other than a
# registry version: an alias, a repository, a path, a patch, a protocol.
_PM_SPEC_PREFIXES = protocols.NON_REGISTRY_PREFIXES


def _pm_disabled(what):
    """The forms that would be inert once pnpm, Bun and Yarn are read end to end
    are refused until then, so nothing here returns "ignore"."""
    raise _Unsupported(f"{what}: support for pnpm, Bun and Yarn lands in v1.10.0",
                       code="unsupported-form")


def _pm_spec_to_request(spec, operation, original, manager):
    lowered = spec.lower()
    sep = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    version = spec[sep + 1:].lower() if sep != -1 else ""
    if (lowered.startswith(_PM_SPEC_PREFIXES) or version.startswith(_PM_SPEC_PREFIXES)
            or (manager.startswith("pnpm") and spec.partition("@")[0].lower() == "rust")):
        raise _Unsupported(f"{spec!r}: only a plain registry package name and version is supported",
                           code="alternate-source")
    return _npm_spec_to_request(spec, operation, original, manager=manager)


def _pm_scan(manager, args, verb):
    """Classify the arguments of an acquiring verb: (specs, scripts, resolve_only).

    Flags come from the manager's allow-list. A flag that names another source,
    another directory or any scope other than this project is refused under its
    own code; one the table does not list is `unsupported-flag`."""
    table = _PM_FLAGS[manager]
    _refuse_npm_source_args(args)
    specs, resolve_only, scripts = [], False, True
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if not arg.startswith("-"):
            specs.append(arg)
            continue
        base, equals, value = arg.partition("=")
        if base.startswith("--config."):
            raise _Unsupported(f"{base!r} sets an installer setting and is not supported",
                       code="alternate-source")
        if base in table["source"]:
            raise _Unsupported(f"{base!r} names another registry or configuration; "
                                            "alternate sources are not supported",
                       code="alternate-source")
        if base in table["target"]:
            raise _Unsupported(f"{base!r} is not supported: it installs somewhere other "
                                          "than this project (a global, workspace or other "
                                          "directory); to use a subdirectory, cd there in its own "
                                          "command first, then run the install",
                       code="install-target")
        if base == "--mode" and manager == "yarn":
            mode = value if equals else (args[index] if index < len(args) else "")
            if mode not in ("skip-build", "update-lockfile"):
                raise _Unsupported(f"yarn --mode={mode}: only --mode=skip-build and "
                                   "--mode=update-lockfile are supported",
                       code="unsupported-flag")
            if not equals:
                index += 1
            if mode == "update-lockfile":
                # Resolves and writes yarn.lock; skips the link and build steps.
                resolve_only = True
            else:
                scripts = False
            continue
        if arg in _PM_SCRIPTS_OFF[manager]:
            scripts = False
            continue
        if base in table["resolve_only"]:
            resolve_only = True
            continue
        if base in table["value"]:
            if not equals:
                index += 1  # the flag's value, never a package
            continue
        if base in table["safe"] and not (equals and base == "--ignore-scripts"):
            continue
        hint = (" (Yarn Berry has no --ignore-scripts; use --mode=skip-build)"
                if manager == "yarn" and base == "--ignore-scripts" else "")
        raise _Unsupported(f"unrecognized {manager} flag {base!r}{hint}; "
                                        f"use a plain '{manager} {verb} <pkg>@<version>' form",
                       code="unsupported-flag")
    return specs, scripts, resolve_only


# ---------------------------------------------------------------------------
# Yarn: Berry and Classic (v1) share the `yarn` head
#
# The parser cannot see which one runs, so it accepts the union of both flag sets (each
# one a flag the project's Yarn would itself refuse otherwise) and records what it saw on
# the scope. `hook._yarn_flavour_denial` judges the verb and the flags against the Yarn the
# project uses. Flags that would change where packages come from, where they go, or that
# skip the lock, are refused here whatever the Yarn: they are never safe.
# ---------------------------------------------------------------------------

# Yarn Classic's own flags (yarn 1.22.22, src/cli/index.js and the install/add/remove commands).
YARN_CLASSIC_FLAGS = frozenset({
    "--frozen-lockfile", "--pure-lockfile", "--ignore-scripts", "--offline", "--prefer-offline",
    "--check-files", "--non-interactive", "--no-progress", "-s", "--silent", "--verbose",
    "--ignore-engines", "--ignore-platform", "--ignore-optional", "--no-bin-links",
    "--no-node-version-check", "--production", "--prod", "--emoji", "--network-concurrency",
    "--network-timeout", "--json",
})
# Yarn Berry's (4.x): `--mode` is judged on its value in `_yarn_scan`.
YARN_BERRY_FLAGS = frozenset({"--immutable", "--immutable-cache", "--check-cache", "--mode",
                              "-C", "--caret", "--json"})
# Save-spec flags both know (Berry's `-C --caret` is above; Classic's `upgrade -C` is the same idea).
_YARN_SAVE_FLAGS = frozenset({"-D", "--dev", "-P", "--peer", "-O", "--optional", "-E", "--exact",
                              "-T", "--tilde"})
# Flags that carry a boolean: only the true spelling is accepted (a negation changes what the
# command does and could undo the proof the hook looks for).
_YARN_BOOL_FLAGS = YARN_CLASSIC_FLAGS - {"--network-concurrency", "--network-timeout", "--production",
                                         "--prod", "--emoji"}
# `--production [prod]` and `--emoji [bool]` read the NEXT word as their value, so a package
# written after one is not a package to Yarn.
_YARN_OPTIONAL_VALUE_FLAGS = frozenset({"--production", "--prod", "--emoji"})
_YARN_VALUE_FLAGS = frozenset({"--network-concurrency", "--network-timeout"})
_YARN_SOURCE_FLAGS = frozenset({"--registry", "--proxy", "--https-proxy", "--use-yarnrc",
                                "--no-default-rc", "--config"})
_YARN_TARGET_FLAGS = frozenset({"--cwd", "--modules-folder", "--link-folder", "--global-folder",
                                "--cache-folder", "--preferred-cache-folder", "-g", "--global",
                                "-W", "--ignore-workspace-root-check", "--focus", "-A", "--all",
                                "--audit"})
_YARN_REFUSED_WHY = {
    "--no-lockfile": "it ignores the reviewed lock",
    "--force": "it refetches and rewrites the lock",
    "--update-checksums": "it rewrites the lock's checksums from whatever the registry serves",
    "--flat": "it re-resolves versions interactively",
    "--pnp": "Plug'n'Play has no node_modules tree Package Guard can inspect",
    "--enable-pnp": "Plug'n'Play has no node_modules tree Package Guard can inspect",
    "--disable-pnp": "it changes how the project is linked",
    "--har": "it writes network traces",
    "--mutex": "it takes a lock outside this project",
    "--link-duplicates": "it changes how the tree is written",
    "--skip-integrity-check": "it skips verifying what is installed",
}
# `upgrade`'s own flags (they read differently from `add`'s: `-P` is a pattern there).
_YARN_UPGRADE_REFUSED = frozenset({"-L", "--latest", "-P", "--pattern", "-S", "--scope"})


def _yarn_scan(args, verb):
    """Classify the arguments of a yarn verb that installs: (specs, scripts, resolve_only,
    flags). `scripts` is False only for Berry's `--mode=skip-build`; whether Classic's
    `--ignore-scripts` (recorded in `flags`) counts is the hook's decision, per project."""
    _refuse_npm_source_args(args)
    specs, flags, resolve_only, scripts = [], [], False, True
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if not arg.startswith("-") or arg == "-":
            specs.append(arg)
            continue
        base, equals, value = arg.partition("=")
        if base.startswith("--config."):
            raise _Unsupported(f"{base!r} sets an installer setting and is not supported",
                               code="alternate-source")
        if base in _YARN_SOURCE_FLAGS:
            raise _Unsupported(f"{base!r} names another registry, proxy or configuration; "
                               "alternate sources are not supported", code="alternate-source")
        if base in _YARN_TARGET_FLAGS:
            raise _Unsupported(f"{base!r} is not supported: it installs somewhere other than "
                               "this project (a global, workspace or other directory); to use a "
                               "subdirectory, cd there in its own command first, then run the "
                               "install", code="install-target")
        if verb == "upgrade" and base in _YARN_UPGRADE_REFUSED:
            raise _Unsupported(f"yarn upgrade {base!r} re-resolves packages that are already "
                               "locked; name one package at an exact version instead",
                               code="unsupported-flag")
        if base in _YARN_REFUSED_WHY:
            raise _Unsupported(f"{base!r} is not supported: {_YARN_REFUSED_WHY[base]}",
                               code="unsupported-flag")
        if base == "--mode":
            mode = value if equals else (args[index] if index < len(args) else "")
            if mode not in ("skip-build", "update-lockfile"):
                raise _Unsupported(f"yarn --mode={mode}: only --mode=skip-build and "
                                   "--mode=update-lockfile are supported", code="unsupported-flag")
            if not equals:
                index += 1
            flags.append(f"--mode={mode}")
            if mode == "update-lockfile":
                resolve_only = True  # resolves and writes yarn.lock; skips link and build
            else:
                scripts = False
            continue
        if base in _YARN_VALUE_FLAGS:
            if not equals:
                index += 1  # the flag's value, never a package
            flags.append(base)
            continue
        if base in _YARN_OPTIONAL_VALUE_FLAGS:
            if equals:
                if value not in ("true", "false"):
                    raise _Unsupported(f"{arg!r}: unrecognized value", code="unsupported-flag")
            elif index < len(args) and not args[index].startswith("-"):
                raise _Unsupported(f"{base!r} reads the next word ({args[index]!r}) as its value, "
                                   "not as a package; put the flag last or write "
                                   f"{base}=true", code="unsupported-flag")
            flags.append(base)
            continue
        if base in _YARN_BOOL_FLAGS or base in _YARN_SAVE_FLAGS or base in YARN_BERRY_FLAGS:
            if equals and value != "true":
                raise _Unsupported(f"{arg!r} negates or changes a flag whose true spelling the "
                                   "gate relies on; write it without a value",
                                   code="unsupported-flag")
            flags.append(base)
            continue
        plain = f"yarn {verb} <pkg>@<version>".replace("  ", " ")
        raise _Unsupported(f"unrecognized yarn flag {base!r}; use a plain '{plain}' form",
                           code="unsupported-flag")
    return specs, scripts, resolve_only, tuple(dict.fromkeys(flags))


def _classic_flags_disabled(flags):
    """With the Classic switch off, Classic's own flags are refused as they were before."""
    if YARN_CLASSIC_ENABLED:
        return
    for flag in flags:
        if flag in YARN_CLASSIC_FLAGS - YARN_BERRY_FLAGS:
            hint = (" (Yarn Berry has no --ignore-scripts; use --mode=skip-build)"
                    if flag == "--ignore-scripts" else "")
            raise _Unsupported(f"unrecognized yarn flag {flag!r}{hint}; Yarn Classic is not "
                               "supported", code="unsupported-flag")


def _parse_yarn_install(tokens, original):
    """bare yarn, install, add, up (Berry), upgrade (Classic)."""
    verb = tokens[1] if len(tokens) > 1 else ""
    if verb == "upgrade" and not YARN_CLASSIC_ENABLED:
        raise _Unsupported("unrecognized yarn subcommand 'upgrade'; use yarn run <script>",
                           code="unknown-verb")
    specs, scripts, resolve_only, flags = _yarn_scan(tokens[2:], verb)
    _classic_flags_disabled(flags)
    if resolve_only:
        # `yarn install --mode=update-lockfile`: resolves and writes yarn.lock and skips
        # linking and building, so there is no `--ignore-scripts` to ask for. The hook reads
        # the configuration and refuses a root install-time script all the same
        # (hook._resolve_only_denial).
        if specs or verb not in ("", "install"):
            raise _Unsupported("yarn --mode=update-lockfile is supported only as "
                               "'yarn install --mode=update-lockfile' with no package arguments",
                               code="unsupported-form")
        if not PNPM_BUN_YARN_ENABLED:
            _pm_disabled("'yarn install --mode=update-lockfile'")
        return _resolve_only("yarn")
    if specs and verb in ("", "install"):
        raise _Unsupported(f"'yarn {verb}'".rstrip() + " does not take package arguments",
                           code="unsupported-form")
    if verb == "upgrade" and not specs:
        raise _Unsupported("'yarn upgrade' with no package re-resolves every dependency to a "
                           "version nobody reviewed; name one package at an exact version "
                           "(`yarn upgrade <pkg>@<version>`)", code="unsupported-form")
    scope = ManifestScope("yarn", scripts=scripts, verb=verb, flags=flags)
    if not specs:
        return _manifest_only(scope)
    return _package((_pm_spec_to_request(s, "install", original, "yarn") for s in specs),
                    manifests=(scope,))


def _parse_yarn_global(tokens, original):
    raise _Unsupported("'yarn global' installs and runs packages outside this project's tree, "
                       "where nothing is reconciled; to use a global tool, ask the user to "
                       "install it", code="install-target")


def _yarn_readonly_flags(args):
    for arg in args:
        base = arg.partition("=")[0]
        if base in _YARN_SOURCE_FLAGS:
            raise _Unsupported(f"{base!r} names another registry, proxy or configuration; "
                               "alternate sources are not supported", code="alternate-source")
        if base in _YARN_TARGET_FLAGS or base in ("--mode",):
            raise _Unsupported(f"{base!r} is not supported: it reads somewhere other than this "
                               "project", code="install-target")


def _parse_yarn_readonly(tokens, original):
    """Yarn Classic's read-only verbs (list, ls, outdated, licenses, check, audit, versions)."""
    verb = tokens[1] if len(tokens) > 1 else ""
    if not YARN_CLASSIC_ENABLED:
        raise _Unsupported(f"unrecognized yarn subcommand {verb!r}; use yarn run <script>",
                           code="unknown-verb")
    _refuse_npm_source_args(tokens[2:])
    _yarn_readonly_flags(tokens[2:])
    if verb == "licenses" and (len(tokens) < 3 or tokens[2] not in ("list", "ls")):
        raise _Unsupported("'yarn licenses' is supported only as 'licenses list'",
                           code="unsupported-form")
    return _ignore()


def _parse_yarn_cache(tokens, original):
    if not YARN_CLASSIC_ENABLED:
        raise _Unsupported("unrecognized yarn subcommand 'cache'; use yarn run <script>",
                           code="unknown-verb")
    if len(tokens) > 2 and tokens[2] in ("dir", "list"):
        _yarn_readonly_flags(tokens[3:])
        return _ignore()
    raise _Unsupported("'yarn cache' is supported only as 'cache dir' and 'cache list'; "
                       "'cache clean' deletes what other projects use", code="unsupported-form")


def _pm_install(manager):
    def handler(tokens, original):
        verb = tokens[1] if len(tokens) > 1 else ""
        specs, scripts, resolve_only = _pm_scan(manager, tokens[2:], verb)
        if resolve_only and manager == "yarn":
            # `yarn install --mode=update-lockfile`: resolves and writes yarn.lock
            # and skips linking and building, so there is no `--ignore-scripts`
            # to ask for. The hook reads the configuration and refuses a root
            # install-time script all the same (hook._resolve_only_denial).
            if specs or verb not in ("", "install"):
                raise _Unsupported("yarn --mode=update-lockfile is supported only as "
                                   "'yarn install --mode=update-lockfile' with no package arguments",
                                   code="unsupported-form")
            if not PNPM_BUN_YARN_ENABLED:
                _pm_disabled("'yarn install --mode=update-lockfile'")
            return _resolve_only(manager)
        if resolve_only:
            # Resolves and writes the lock without installing, but still runs the
            # root project's own lifecycle scripts unless they are off.
            if scripts:
                raise _Unsupported(f"'{manager} {verb}' with a resolve-only flag still "
                                                "runs the project's lifecycle scripts; add --ignore-scripts",
                       code="unsupported-flag")
            if not PNPM_BUN_YARN_ENABLED:
                _pm_disabled(f"'{manager} {verb}' with a resolve-only flag")
            return _resolve_only(manager)
        if specs and (verb in ("fetch", "dedupe") or (manager == "yarn" and verb in ("", "install"))):
            raise _Unsupported(f"'{manager} {verb}'".rstrip()
                        + " does not take package arguments",
                       code="unsupported-form")
        scope = ManifestScope(manager, scripts=scripts)
        if not specs:
            return _manifest_only(scope)
        return _package((_pm_spec_to_request(s, "install", original, manager) for s in specs),
                        manifests=(scope,))
    return handler


def _parse_pm_remove(tokens, original):
    """`remove` acquires nothing, so it stays `ignore` and the printed remedy for an
    unreviewed package on disk (`disk_guard.removal_command`) stays reachable while a
    finding is open. It is NOT inert, though: it rewrites package.json and the lock,
    relinks node_modules and runs the root project's lifecycle scripts, so the hook
    checks the manager's configuration, the pin, the lock and the scripts first
    (`hook._run_denial`, v1.10.0 hardening A4). A source or target flag is refused.
    Yarn's `--mode=skip-build` and Bun's `--ignore-scripts` turn scripts off (each
    suppresses the root postinstall that otherwise runs; verified live). pnpm rejects
    `--ignore-scripts` on `remove` ("Unknown option") and never ran the root postinstall, so
    its scripts stay on: the denial for a root install script is the safe, documented one."""
    manager = _PM_NAMES[_executable(tokens[0])]
    flags = ()
    if manager == "yarn":
        names, scripts, _resolve, flags = _yarn_scan(tokens[2:], "remove")
        _classic_flags_disabled(flags)
    else:
        names, scripts, _resolve = _pm_scan(manager, tokens[2:], "remove")
    if not PNPM_BUN_YARN_ENABLED:
        _pm_disabled(f"'{manager} remove'")
    return ParseResult(kind="ignore", runs=(RunScope(
        manager, "remove", scripts=scripts or manager == "pnpm", names=tuple(names),
        word="remove" if manager == "yarn" else "", flags=flags),))


def _parse_pm_config(tokens, original):
    """Only `config get` / `config list` read; a registry key set is refused as
    a redirect, any other config verb is not supported."""
    manager = _PM_NAMES[_executable(tokens[0])]
    sub = tokens[2] if len(tokens) > 2 else None
    if sub in ("get", "list"):
        return _ignore()
    if sub == "set" and any("registry" in t.lower() for t in tokens[3:]):
        raise _Unsupported(f"'{manager} config set' of a registry key redirects every "
                                        "later install; alternate registries are not supported",
                       code="alternate-source")
    raise _Unsupported(f"'{manager} config {sub or ''}'".rstrip()
                + " changes configuration; only 'config get' and 'config list' are supported",
                       code="unsupported-form")


def _parse_pm_audit(tokens, original):
    if any(t == "fix" or t.startswith("--fix") for t in tokens[2:]):
        raise _Unsupported(f"'{_PM_NAMES[_executable(tokens[0])]} audit fix' installs "
                                        "packages and cannot be vetted",
                       code="unsupported-form")
    return _ignore()


def _parse_pm_store(tokens, original):
    if len(tokens) > 2 and tokens[2] in ("path", "status"):
        return _ignore()
    raise _Unsupported("'pnpm store' is supported only as path or status; "
                                    "'store add' fetches packages",
                       code="unsupported-form")


def _parse_yarn_npm(tokens, original):
    if len(tokens) > 2 and tokens[2] in ("info", "audit"):
        return _ignore()
    raise _Unsupported("'yarn npm' is supported only as 'npm info' and 'npm audit'",
                       code="unsupported-form")


_PM_EXEC_VALUE_REFUSED = ("-p", "--package", "-c", "--call", "--shell-mode")


def _parse_pm_exec(args, original, manager, safe_flags=frozenset(), initializer=False):
    """`pnpm dlx`, `pnpx`, `bun x`, `bunx`, `yarn dlx`, `pnpm create`: the first
    positional is the package, the rest belongs to the tool."""
    for arg in args:
        if arg.startswith("-"):
            base = arg.partition("=")[0]
            if base in _PM_EXEC_VALUE_REFUSED:
                raise _Unsupported(f"{base} forms are not supported; use "
                                                f"'{manager} <pkg>@<version>'",
                       code="unsupported-form")
            _refuse_npm_source_args([arg])
            if base in ("--registry", "--config", "-c") or base.startswith("--config."):
                raise _Unsupported(f"{base!r} names another registry or configuration",
                       code="alternate-source")
            if base in safe_flags:
                continue
            raise _Unsupported(f"unrecognized {manager} flag {base!r} before the package name",
                       code="unsupported-flag")
        spec = _initializer_package(arg) if initializer else arg
        return _package([_pm_spec_to_request(spec, "exec", original, manager)])
    raise _Unsupported(f"'{manager}' needs a package to run",
                       code="unsupported-form")


_PM_DLX_SAFE = {"pnpm": {"-q", "--quiet", "-s", "--silent"}, "bun": {"--bun", "--silent"},
                "yarn": {"-q", "--quiet"}}


def _parse_pnpm_dlx(tokens, original):
    return _parse_pm_exec(tokens[2:], original, "pnpm dlx", _PM_DLX_SAFE["pnpm"])


def _parse_pnpm_create(tokens, original):
    return _parse_pm_exec(tokens[2:], original, "pnpm create", initializer=True)


def _parse_pnpm_dlx_head(tokens, original):
    return _parse_pm_exec(tokens[1:], original, _executable(tokens[0]), _PM_DLX_SAFE["pnpm"])


def _bun_exec(args, original, manager):
    """`bun x` / `bunx`. `--no-install` makes it run only what is already installed, and
    only BEFORE the package name: after it, the flag belongs to the tool being run
    (`bunx evil@1.0.0 --no-install` still installs and runs `evil`). A flag before the
    name is read as `bun run`'s are, so `--registry` and the like stay refused."""
    before = []
    for arg in args:
        if not arg.startswith("-"):
            break
        before.append(arg)
    if any(arg.partition("=")[0] == "--no-install" for arg in before):
        # Runs what is already installed and fetches nothing, but it still runs
        # code under the project's bunfig (preload) and pinned manager, so it is
        # a runner the hook checks (`hook._run_denial`), not a bare `ignore`.
        _pm_run_scan("bun", args, True)
        return _runner_result("bun", "x")
    return _parse_pm_exec(args, original, manager, _PM_DLX_SAFE["bun"])


def _parse_bun_x(tokens, original):
    return _bun_exec(tokens[2:], original, "bun x")


def _parse_bunx_head(tokens, original):
    return _bun_exec(tokens[1:], original, "bunx")


def _parse_yarn_dlx(tokens, original):
    return _parse_pm_exec(tokens[2:], original, "yarn dlx", _PM_DLX_SAFE["yarn"])


# ---------------------------------------------------------------------------
# Runners: pnpm run|exec|test|start, yarn run, bun run|test|<file> (design 7)
#
# They acquire nothing themselves, so they are `ignore` as `npm run` is, with
# a RunScope for the hook: the manager's configuration still applies (a pnpmfile,
# a Yarn plugin, a Bun preload), Bun may install what it cannot find, and Yarn
# refuses to run on a stale install. The script's body is read no more than
# `npm run`'s is. Until the switch flips each is refused, as `remove` is.
# ---------------------------------------------------------------------------

_PM_RUN_PRE = {
    # Flags that may come before the script name. Anything else there is refused:
    # an unknown flag could retarget the command or change what it installs.
    "pnpm": {"--if-present", "-s", "--silent", "-q", "--quiet", "--no-color", "--color",
             "--stream", "--no-bail", "--aggregate-output"},
    "bun": {"--bun", "--silent", "--if-present", "--no-install", "--watch", "--hot",
            "--no-clear-screen", "--smol"},
    "yarn": {"-T", "--top-level", "-B", "--binaries-only"},
}
_PM_RUN_VALUE = {"pnpm": {"--reporter", "--loglevel"}, "bun": set(), "yarn": set()}
# Refused wherever they appear before `--` (pnpm) or before the script name (Bun, Yarn).
_PM_RUN_REFUSED = {
    "pnpm": {"-C", "--dir", "--filter", "-F", "--filter-prod", "-r", "--recursive", "-w",
             "--workspace-root", "--ignore-workspace", "-g", "--global", "--prefix",
             "--parallel", "--sequential", "--workspace-concurrency", "--resume-from",
             "--report-summary", "--test-pattern", "--changed-files-ignore-pattern",
             "--shell-mode", "-c", "--use-stderr"},
    "bun": {"-i", "--install", "--preload", "-r", "--require", "--import", "--cwd", "--filter",
            "--workspaces", "--env-file", "--config", "-c", "--shell", "--eval", "-e",
            "--print", "-p", "--tsconfig-override", "--define", "-d", "--loader", "--inspect",
            "--inspect-brk", "--inspect-wait", "--registry"},
    "yarn": {"--cwd", "-A", "--all", "-W", "--inspect", "--inspect-brk"},
}


def _pm_run_scan(manager, args, takes_name, name_required=False):
    """Flags up to the script name (or the first positional); returns (name,
    no_install, args after the name). The script's own arguments are not read,
    except that a flag that names another source or directory is refused where
    the manager itself might read it."""
    pre, refused, value = _PM_RUN_PRE[manager], _PM_RUN_REFUSED[manager], _PM_RUN_VALUE[manager]
    _refuse_npm_source_args(args)
    no_install, name, index = False, None, 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            break
        base = arg.partition("=")[0]
        if arg.startswith("-"):
            if base.startswith("--config."):
                raise _Unsupported(f"{base!r} sets an installer setting and is not supported",
                                   code="alternate-source")
            if base in refused:
                raise _Unsupported(
                    f"{arg!r} is not supported on '{manager} run': it runs more than this "
                    "project's one script (a workspace, another directory, an install "
                    "mode, preloaded code or inline code)", code="install-target")
            if name is None:
                if base == "--no-install" and manager == "bun":
                    no_install = True
                    continue
                if base in value:
                    if "=" not in arg:
                        index += 1
                    continue
                if base in pre:
                    continue
                if takes_name:
                    raise _Unsupported(
                        f"unrecognized {manager} flag {base!r} before the script name; "
                        f"use a plain '{manager} run <script>' form", code="unsupported-flag")
            continue
        if name is None:
            name = arg
            if takes_name:
                break
    rest = args[index:]
    if name_required and name is None:
        raise _Unsupported(f"'{manager}' needs a command to run", code="unsupported-form")
    return name, no_install, rest


def _after_name_refused(manager, rest):
    """pnpm reads some flags after the script name too: refused before `--`."""
    if manager != "pnpm":
        return
    _refuse_npm_source_args(rest)
    for arg in rest:
        if arg == "--":
            return
        base = arg.partition("=")[0]
        if arg.startswith("-") and base in _PM_RUN_REFUSED["pnpm"]:
            raise _Unsupported(f"{arg!r} is not supported on 'pnpm run': it runs more than this "
                               "project's one script", code="install-target")


def _runner_result(kind, verb, autoinstall=False):
    if not PNPM_BUN_YARN_ENABLED:
        _pm_disabled(f"'{kind} {verb}'")
    return ParseResult(kind="ignore", runs=(RunScope(kind, verb, autoinstall),))


def _parse_pnpm_run(tokens, original):
    verb = tokens[1]
    takes_name = verb == "run"
    name, _ni, rest = _pm_run_scan("pnpm", tokens[2:], takes_name)
    _after_name_refused("pnpm", rest if takes_name else tokens[2:])
    return _runner_result("pnpm", verb)


def _parse_pnpm_exec(tokens, original):
    """`pnpm exec <bin> ...` runs a binary of this project's node_modules/.bin; it
    does not fetch (that is `pnpm dlx`). A shell string (`-c`) is refused."""
    _pm_run_scan("pnpm", tokens[2:], True, name_required=True)
    return _runner_result("pnpm", "exec")


def _parse_yarn_run(tokens, original):
    _pm_run_scan("yarn", tokens[2:], True)
    return _runner_result("yarn", "run")


def _parse_bun_run(tokens, original):
    verb = tokens[1]
    if verb == "test":
        # `bun test` takes filters and flags of its own and resolves like `bun run`.
        _name, no_install, _rest = _pm_run_scan("bun", tokens[2:], False)
        no_install = no_install or "--no-install" in tokens[2:]
    else:
        _name, no_install, _rest = _pm_run_scan("bun", tokens[2:], True)
    return _runner_result("bun", verb, autoinstall=not no_install)


_BUN_FILE = re.compile(r"(?:^|/)[^/]+\.(?:[cm]?[jt]sx?|jsonc?|json5|toml|html|sh)$|/")


def _is_bun_file(word) -> bool:
    return bool(word) and not word.startswith("-") and bool(_BUN_FILE.search(word))


def _parse_bun_file(tokens, original):
    """`bun ./x.ts args...`: runs a file; Bun installs what it cannot find first."""
    _name, no_install, _rest = _pm_run_scan("bun", tokens[1:], True)
    return _runner_result("bun", "file", autoinstall=not no_install)


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


_BENCH_EDITABLE_MESSAGE = (
    "`-e apps/<app>` installs a bench app together with its whole unpinned dependency set, in one "
    "step no baseline or review covers. Install an app with `bench setup requirements <app>`, which "
    "does the same Python install and the yarn install, behind the gate; to add one package to an "
    "app, name it with an exact version (`env/bin/pip install name==version`)")
_BENCH_APP_PATH = re.compile(r"(?:\./)?apps/[^/]+/?\Z|/apps/[^/]+/?\Z")


def _bench_app_path(target) -> bool:
    """`apps/erpnext`, `./apps/erpnext`, `/srv/bench/apps/erpnext`: a path to an app directory."""
    return bool(_BENCH_APP_PATH.search(target))


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
                if FRAPPE_ENABLED and _bench_app_path(target):
                    raise _Unsupported(_BENCH_EDITABLE_MESSAGE, code="local-project")
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


def _split_env_python(args):
    """(env python or None, the other arguments) for `uv pip install` / `sync`.

    uv's `--python` / `-p` can name any interpreter, so only one that is written
    as a bench env's (`.../env/bin/python`, a literal path) is carried, for the
    hook to tie to the bench (`bench_config.python_in_env_problem`); any other
    value is refused as `--python` always was, and so is a path the shell would
    still change (`~`, `$`, a glob). Attached short forms (`-pPATH`) stay
    unrecognised and are refused with the rest."""
    value, rest, index = None, [], 0
    while index < len(args):
        arg = args[index]
        base, equals, attached = arg.partition("=")
        if base in ("--python", "-p"):
            if equals:
                found, step = attached, 1
            elif index + 1 < len(args):
                found, step = args[index + 1], 2
            else:
                rest.append(arg)
                index += 1
                continue
            if value is not None:
                raise _Unsupported("`--python` is given twice", code="unsupported-flag")
            if (not bench_config.ENV_PYTHON.search(found) or _PATH_SURPRISE.search(found)
                    or _names_guard_dir(found)):
                raise _Unsupported(
                    f"`--python {found}` names an interpreter Package Guard cannot tie to a "
                    "reviewed environment; only a Frappe bench's own `env/bin/python` is "
                    "supported, so drop `--python` or name that path",
                    code="unsupported-flag")
            value = found
            index += step
            continue
        rest.append(arg)
        index += 1
    return value, rest


def _with_env_python(result, value):
    return dataclasses.replace(result, bench_pythons=(value,)) if value is not None else result


def _parse_uv_pip_install(tokens, original) -> ParseResult:
    # tokens: uv pip install <args>
    value, args = _split_env_python(tokens[3:])
    result = _parse_pip_install(args, original, manager="uv pip", operation="install")
    return _with_env_python(result, value)


def _parse_uv_pip_sync(tokens, original) -> ParseResult:
    # tokens: uv pip sync <files>
    value, args = _split_env_python(tokens[3:])
    for arg in args:
        if arg.startswith("-") and (arg.partition("=")[0] in _PIP_DENY_FLAGS
                                    or _is_uv_source_flag(arg)):
            raise _Unsupported("alternate/direct package sources are not supported for 'uv pip sync'",
                               code="alternate-source")
    targets = [t for t in args if not t.startswith("-")]
    if not targets:
        return _ignore()
    return _with_env_python(_manifest_only(*(ManifestScope("requirements", t) for t in targets)),
                            value)


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
    if command and not _inert(_parse(" ".join(shlex.quote(word) for word in command))):
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
    "pnpm_install": _pm_install("pnpm"),
    "bun_install": _pm_install("bun"),
    "yarn_install": _parse_yarn_install,
    "yarn_global": _parse_yarn_global,
    "yarn_readonly": _parse_yarn_readonly,
    "yarn_cache": _parse_yarn_cache,
    "pm_remove": _parse_pm_remove,
    "pm_config": _parse_pm_config,
    "pm_audit": _parse_pm_audit,
    "pm_store": _parse_pm_store,
    "yarn_npm": _parse_yarn_npm,
    "pnpm_dlx": _parse_pnpm_dlx,
    "pnpm_dlx_head": _parse_pnpm_dlx_head,
    "pnpm_create": _parse_pnpm_create,
    "bunx": _parse_bunx_head,
    "bun_x": _parse_bun_x,
    "yarn_dlx": _parse_yarn_dlx,
    "pnpm_run": _parse_pnpm_run,
    "pnpm_exec": _parse_pnpm_exec,
    "yarn_run": _parse_yarn_run,
    "bun_run": _parse_bun_run,
    "bun_file": _parse_bun_file,
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
