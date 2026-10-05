"""Strict recognizer for package-acquisition Bash commands.

Recognizes a small, explicit set of npm / pip / uv command forms and
normalizes them into PackageRequest objects. Anything that contains a
package-acquisition operation but cannot be parsed with confidence is
returned as "unsupported" so the hook can deny it.

Standard library only.
"""
from __future__ import annotations

import dataclasses
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
# the text at all.

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
    "unknown-verb",
    "unparsable-spec",
    "unquoted-range",
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
        return _parse(command)
    except _Unsupported as exc:
        return ParseResult(kind="unsupported", reason=str(exc), code=exc.code)


_CD_MESSAGE = (
    "package operation appears alongside a directory change; "
    "run the package command as a simple standalone command -- change "
    "directory in its own command first, then run the install bare "
    "(no `cd ... &&`, no pipe, no `;`)"
)


def _parse(command: str) -> ParseResult:
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
        if verbs.ACQUISITION_HINT.search(command):
            raise _Unsupported(
                "could not safely tokenize a command containing a package operation",
                code="untokenisable",
            )
        return _ignore()

    results = []
    changed_directory = False
    exported = []
    for segment in segments:
        words = shell.strip_keywords(segment.words)
        assignments, words = shell.strip_assignments(words)
        if not words:
            continue
        if words[0].text in _EXPORT_COMMANDS:
            exported.extend(w for w in words[1:] if "=" in w.text)
            continue
        result = _parse_segment(words, assignments + exported, command)
        if result is _CD_MARKER:
            changed_directory = True
            continue
        if result is not None and result.kind != "ignore":
            results.append(result)

    if changed_directory and results:
        # The manifest gate reads the EVENT's working directory, so a permitted
        # `cd X && <install>` would vet the root manifest while the installer
        # reconciles X/. Same hazard the --prefix refusal exists to prevent.
        raise _Unsupported(_CD_MESSAGE, code="directory-change")

    return _merge(results)


_CD_MARKER = object()

# `export npm_config_registry=E; npm install x` reaches npm exactly like the
# leading assignment that is refused, so an earlier segment's exports are
# checked as if they led every later segment.
_EXPORT_COMMANDS = {"export", "declare", "typeset"}


def _parse_segment(words, assignments, command):
    """Parse one segment. Returns a ParseResult, None, or _CD_MARKER."""
    head_word = words[0]
    head = _executable(head_word.text)

    if head in verbs.CD_COMMANDS:
        return _CD_MARKER

    if head in _PEEL_WRAPPERS:
        # `sudo npm install x` is `npm install x`. `env -i` changes the
        # environment wholesale, which we cannot reason about.
        rest = words[1:]
        while rest and rest[0].text.startswith("-"):
            if rest[0].text in ("-i", "--ignore-environment", "-u", "--unset"):
                raise _Unsupported(
                    f"package operation wrapped in {head!r} with a modified "
                    "environment cannot be vetted; run the package command directly",
                    code="wrapper",
                )
            rest = rest[1:]
        more_assignments, rest = shell.strip_assignments(rest)
        if not rest:
            return None
        return _parse_segment(rest, assignments + more_assignments, command)

    if head in _RECURSIVE_WRAPPERS:
        return _parse_wrapper_payload(head, words, command)

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
        return None

    _check_env(assignments, installer, head)
    result = _dispatch(installer, head, words, command)
    if (any(a.text.lower() in _SCRIPTS_OFF_ASSIGNMENTS for a in assignments)
            and result is not None and result.manifests):
        result = dataclasses.replace(result, manifests=tuple(
            dataclasses.replace(m, scripts=False) if m.kind == "npm" else m
            for m in result.manifests))
    return result


def _parse_wrapper_payload(head, words, command):
    """`sh -c "<payload>"`, `eval "<payload>"`, `xargs <installer>`."""
    payload_words = words[1:]
    while payload_words and payload_words[0].text.startswith("-"):
        if payload_words[0].text in ("-c",):
            payload_words = payload_words[1:]
            break
        payload_words = payload_words[1:]
    if not payload_words:
        return None

    if any(word.dynamic for word in payload_words):
        # `eval "$CMD"` -- fall back to a text check rather than blanket-denying,
        # so `find . | xargs rm` does not start failing.
        if verbs.ACQUISITION_HINT.search(command):
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


_SCRIPTS_OFF_ASSIGNMENTS = {"npm_config_ignore_scripts=true"}


def _check_env(assignments, installer, head):
    """`npm_config_registry=... npm install x` is the env form of --registry."""
    for prefix in installer.get("env_deny_prefixes") or ():
        for assignment in assignments:
            if assignment.text.lower() in _SCRIPTS_OFF_ASSIGNMENTS:
                continue  # turns lifecycle scripts off; redirects nothing
            name = assignment.text.partition("=")[0]
            if name.upper().startswith(prefix):
                raise _Unsupported(
                    f"{name!r} changes how {head!r} resolves packages; "
                    "alternate registries and index URLs are not supported",
                    code="alternate-source",
                )


def _dispatch(installer, head, words, command):
    if installer.get("head_only"):
        # npx / uvx take no subcommand: the first positional IS the package, and
        # their flags belong to the handler. Consuming "globals" here would
        # reject `npx --no-install eslint` as an unknown pre-verb flag.
        handler = installer["acquire"][""]["handler"]
        if any(word.dynamic for word in words[1:]):
            raise _Unsupported(
                "package identity is built dynamically (a variable, substitution or "
                "glob); name the exact package and version instead",
                code="dynamic-spec",
            )
        return _run_handler(handler, [w.text for w in words], command, head)

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

    handler = handler_name
    texts = [w.text for w in words]
    texts[1] = canonical if len(texts) > 1 else canonical
    return _run_handler(handler, texts, command, head)


def _merge(results):
    requests = []
    manifests = []
    for result in results:
        requests.extend(result.requests)
        for scope in result.manifests:
            if scope not in manifests:
                manifests.append(scope)
    if not requests and not manifests:
        return _ignore()
    return ParseResult(kind="package", requests=tuple(requests), manifests=tuple(manifests))


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


def _parse_npm_init(args, original, manager) -> ParseResult:
    """npm init <initializer> downloads and executes create-<initializer>."""
    _refuse_npm_source_args(args)
    for arg in args:
        if arg.startswith("-"):
            if arg in ("-y", "--yes", "-f", "--force", "--scope") or arg.startswith("--scope="):
                continue
            raise _Unsupported(f"unrecognized {manager} flag {arg!r}", code="unsupported-flag")
        return _package([_npm_spec_to_request(_initializer_package(arg), "exec", original, manager=manager)])
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


_UV_SOURCE_FLAGS = {
    "--index", "--index-url", "-i", "--default-index", "--extra-index-url",
    "-f", "--find-links", "--no-index", "--config-file",
}


def _is_uv_source_flag(arg) -> bool:
    # clap also takes a short option's value attached: `-ihttp://x`, `-f/dir`.
    return arg.startswith("-") and (
        arg.partition("=")[0] in _UV_SOURCE_FLAGS
        or (not arg.startswith("--") and len(arg) > 2 and arg[1] in "if"))


def _refuse_uv_source_flags(args, verb):
    for arg in args:
        if _is_uv_source_flag(arg):
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
    "--no-extra", "--no-default-extras", "-qq", "-vv", "--frozen-lock",
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


def _parse_uv_sync(tokens, original) -> ParseResult:
    """uv sync installs the whole locked project, dev groups included."""
    _refuse_uv_source_flags(tokens[2:], "uv sync")
    options, _rest = _uv_project_options(tokens[2:])
    return _manifest_only(_uv_project_scope(options))


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
    `--with` packages are gated as named requests on top."""
    options, _command = _uv_project_options(args)
    _refuse_uv_source_flags([name for name, _v in options], "uv run")
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
    "uv_build": _parse_uv_build,
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
