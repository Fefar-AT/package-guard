"""The recognition table: one source of truth for what counts as acquisition.

The table is DATA, in `recognition.json`, loaded here at import. `parser.py`
keeps no verb list of its own, so a verb cannot be added to the parser without
adding it to the table.

One table, not two vocabularies: a loose regex over raw text and a tokenized
dispatcher kept by hand will drift apart, and a verb one knows and the other
does not becomes an ungated install (`uv sync 2>&1 | tail -40` is the shape).

Standard library only.
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

TABLE_PATH = Path(__file__).resolve().parent / "recognition.json"
TABLE = json.loads(TABLE_PATH.read_text(encoding="utf-8"))

METACHARS = set(TABLE["metacharacters"])
PEEL_WRAPPERS = set(TABLE["peel_wrappers"])
RECURSIVE_WRAPPERS = set(TABLE["recursive_wrappers"])
WRAPPER_GRAMMAR = TABLE.get("wrapper_grammar") or {}
INERT_HEADS = set(TABLE.get("inert_heads") or ())
# Heads that only read and print (generator: READ_ONLY_HEADS). Stricter than INERT_HEADS.
READ_ONLY_HEADS = set(TABLE.get("read_only_heads") or ())
STRING_RUNNERS = set(TABLE.get("string_runners") or ())
STDIN_SHELLS = TABLE.get("stdin_shells") or {}
CD_COMMANDS = set(TABLE["cd_commands"])
FOREIGN = TABLE["foreign"]["managers"]
FOREIGN_SAFE = set(TABLE["foreign"]["safe_verbs"])
# Runners execute their first argument as a package: no verb is read-only.
FOREIGN_NO_SAFE = set(TABLE["foreign"].get("no_safe_verbs") or ())
# Heads allowed only as a bare print (`corepack --version`), nothing else.
FOREIGN_PRINT_ONLY = {h: set(f) for h, f in (TABLE["foreign"].get("print_only") or {}).items()}

ENV_REASONS = TABLE.get("env_reasons") or {}
ENVIRONMENT = TABLE.get("environment") or {}
ENV_SHARED_REFUSE = TABLE.get("env_shared_refuse") or {}
ENV_REACH = TABLE.get("env_reach") or {}
# A `bench` head names several families at once and these swap-the-program names.
BENCH_ENV = TABLE.get("bench_env") or {}
# The variables that choose which release uv takes. Other projects let them pass (every package there is
# named with an exact version); a bench's uv resolves ranges and its default build requirement, so the
# bench verbs refuse them, inline and in the environment the hook runs in.
BENCH_RESOLUTION_VARS = frozenset({"UV_PRERELEASE", "UV_RESOLUTION", "UV_FORK_STRATEGY", "UV_EXCLUDE_NEWER",
                                   "UV_EXCLUDE_NEWER_PACKAGE", "UV_INDEX_STRATEGY"})

_FILES = TABLE.get("installer_files") or {}
_FILE_NAMES = {name.casefold() for name in _FILES.get("names", ())}
_FILE_PATTERNS = [re.compile(fnmatch.translate(p.casefold())) for p in _FILES.get("patterns", ())]
# Directories whose every file an installer reads (Yarn's `.yarn/`).
_FILE_DIRS = {name.casefold() for name in _FILES.get("dirs", ())}


def installer_file(path):
    """True when the last component of `path` is a file an installer reads, or
    any component names a directory it reads wholesale (`.yarn/releases/x.cjs`)."""
    parts = re.split(r"[\\/]", path)
    name = parts[-1].casefold()
    if _FILE_DIRS and (name in _FILE_DIRS or any(p.casefold() in _FILE_DIRS for p in parts[:-1])):
        return True
    return name in _FILE_NAMES or any(p.match(name) for p in _FILE_PATTERNS)


# The same names as they appear inside code (`python -c "open('uv.lock')"`):
# not part of a longer name.
INSTALLER_FILE_IN_TEXT = re.compile(
    r"(?<![\w.-])(?:%s)(?![\w-]|\.\w)" % "|".join(
        [re.escape(n) for n in sorted(_FILES.get("names", ()), key=len, reverse=True)]
        + [re.escape(p).replace(r"\*", r"[\w.-]*") for p in _FILES.get("patterns", ())]),
    re.IGNORECASE,
)
# `.yarn/releases/yarn.cjs` inside code: the directory, not a longer name.
INSTALLER_DIR_IN_TEXT = re.compile(
    r"(?<![\w.-])(?:%s)(?=[/\\])" % "|".join(re.escape(d) for d in sorted(_FILE_DIRS)),
    re.IGNORECASE,
) if _FILE_DIRS else None


def installer_reads(name):
    """True when an installer reads the variable `name`: its family's prefix,
    a shared refusal, or one of the table's `env_reach` names."""
    upper = name.upper()
    if any(upper in names for names in ENV_SHARED_REFUSE.values()):
        return True
    if upper in ENV_REACH.get("names", ()) or upper.startswith(tuple(ENV_REACH.get("prefixes", ()))):
        return True
    return any(upper.startswith(table["prefix"].upper()) for table in ENVIRONMENT.values())

INSTALLERS = TABLE["installers"]
_BY_HEAD = {}
for _inst in INSTALLERS:
    for _head in _inst["heads"]:
        _BY_HEAD[_head] = _inst

_NPM = _BY_HEAD["npm"]
NPM_COMMANDS = tuple(_NPM["commands"])
NPM_ALIASES = dict(_NPM["aliases"])


# --------------------------------------------------------------------------
# npm resolves verbs through abbrev(): camelCase, then aliases, then ANY
# unambiguous prefix. 87 spellings reach an acquiring verb; a hand-written list
# can never be complete, which is the argument for deriving it.
# --------------------------------------------------------------------------

def _abbrev(words):
    """npm's abbrev(): map every unambiguous prefix to its word.

    An exact word always wins over being a prefix of a longer one.
    """
    words = sorted(set(words))
    table = {}
    for word in words:
        for size in range(1, len(word)):
            prefix = word[:size]
            table[prefix] = None if prefix in table else word
    for word in words:
        table[word] = word
    return {k: v for k, v in table.items() if v is not None}


_ABBREV = _abbrev(list(NPM_COMMANDS) + list(NPM_ALIASES))


def npm_deref(verb):
    """Resolve an npm verb spelling to its canonical command, or None."""
    if not verb:
        return None
    if any(char.isupper() for char in verb):
        verb = re.sub(r"([A-Z])", lambda m: "-" + m.group(1).lower(), verb)
    if verb in NPM_COMMANDS:
        return verb
    if verb in NPM_ALIASES:
        return NPM_ALIASES[verb]
    canonical = _ABBREV.get(verb)
    seen = 0
    while canonical in NPM_ALIASES and seen < 10:
        canonical = NPM_ALIASES[canonical]
        seen += 1
    return canonical


# One answer to "is this word a Python interpreter": python, python3, python3.13t, pythonw,
# pypy, pypy3, the `py` / `pyw` launchers, Jython, GraalPy, IronPython; any directory,
# any `.exe`. Broad on purpose: a wrong match only reads one more command line for `-m`.
_INTERPRETER = re.compile(
    r"(?:(?:python|pypy|jython|graalpy|ironpython|rustpython)[\w.+-]*|pyw?|ipy(?:64)?)", re.IGNORECASE)


def is_interpreter(name):
    """True when a command basename (no directory) names a Python interpreter."""
    name = re.split(r"[\\/]", name)[-1]
    if name.lower().endswith(".exe"):
        name = name[:-4]
    return bool(_INTERPRETER.fullmatch(name))


# Variables CPython (and PyPy) read that change what runs before or around the module
# (`PYTHONPATH`'s sitecustomize, `PYTHONHOME`, `PYTHONUSERBASE`'s usercustomize,
# `PYTHONSTARTUP`, `PYTHONPYCACHEPREFIX`, `PYTHON_PRESITE`, `PYTHONSAFEPATH`, ...): every
# name starting `PYTHON` is refused in front of an installer except these, which only
# tune output, hashing, bytecode writing or text encoding. `-E` / `-I` make the
# interpreter ignore them, but the builds pip and uv start do not: no flag excuses one.
PYTHON_ENV_HARMLESS = frozenset({
    "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED", "PYTHONHASHSEED", "PYTHONUTF8",
    "PYTHONIOENCODING", "PYTHONNOUSERSITE", "PYTHONFAULTHANDLER", "PYTHONCOERCECLOCALE",
    "PYTHONDEVMODE", "PYTHONOPTIMIZE", "PYTHONVERBOSE", "PYTHONDEBUG", "PYTHONCASEOK",
    "PYTHONINTMAXSTRDIGITS", "PYTHONPROFILEIMPORTTIME", "PYTHONTRACEMALLOC",
    "PYTHONASYNCIODEBUG", "PYTHON_COLORS", "PYTHONLEGACYWINDOWSSTDIO",
})


def python_env_refused(name):
    """True when `name` is a Python variable that may add code to an installer's run."""
    upper = name.upper()
    return upper.startswith("PYTHON") and upper not in PYTHON_ENV_HARMLESS


# Frappe's bench: the verbs that acquire packages or pull app code, and the `setup`
# subcommands that do. Here so the fallback hint reads the same words as the parser.
BENCH_INSTALL_VERBS = frozenset({
    "init", "get-app", "get", "update", "new-app", "pip", "switch-to-branch", "remove-app",
    "remove", "rm", "retry-upgrade", "switch-to-develop", "migrate-env", "install"})
BENCH_INSTALL_SETUP = frozenset({
    "requirements", "env", "socketio", "manager", "role", "production", "firewall"})


def lookup(head):
    """The installer entry for a command basename, or None."""
    return _BY_HEAD.get(head)


def wrapper_grammar(head):
    """A wrapper's own options and positionals, as the table states them."""
    return WRAPPER_GRAMMAR.get(head) or {}


# --------------------------------------------------------------------------
# Environment variables an installer reads
# --------------------------------------------------------------------------

def env_key(family, name):
    """`name` as the family's installer reads it, or None when it reads no such variable.

    Matched case-insensitively, as Windows reads the environment. npm keys
    take npm's own form: `npm_config_bin_links` is the `bin-links` setting.
    """
    table = ENVIRONMENT.get(family)
    if not table or not name.upper().startswith(table["prefix"].upper()):
        return None
    if table.get("normalise") == "npm":
        key = name[len(table["prefix"]):]
        if not key.startswith("//"):
            key = (key[:1] + key[1:].replace("_", "-")).lower()
        return key
    return name.upper()


def classify_env(family, name, shared=True):
    """What `name=...` in front of this family's installer means.

    None when the installer does not read it. Otherwise `allow`, `locked`
    (counts as --locked), `path` (allowed as a literal absolute path), a
    refusal category of `env_reasons`, or `unknown`: a name with the family's
    prefix that no list carries is refused by default.
    """
    upper = name.upper()
    # `shared`: the names every installer reads (HOME, a proxy, a CA bundle).
    # They matter in a command's own prefix; the environment the hook itself
    # runs in carries HOME and the like in every session.
    for category, names in (ENV_SHARED_REFUSE.items() if shared else ()):
        if upper in names:
            return category
    # A whole name with no family prefix that the installer reads (`PNPM_HOME`).
    for category, names in ((ENVIRONMENT.get(family) or {}).get("exact_refuse") or {}).items():
        if upper in names:
            return category
    key = env_key(family, name)
    if key is None:
        return None
    table = ENVIRONMENT[family]
    if key in table.get("paths", ()):
        return "path"
    if key in table.get("locked", ()):
        return "locked"
    if key in table.get("allow", ()) or any(key.startswith(p) for p in table.get("allow_prefixes", ())):
        return "allow"
    for category, names in (table.get("refuse") or {}).items():
        if key in names:
            return category
    for category, prefixes in (table.get("refuse_prefixes") or {}).items():
        if any(key.startswith(p) for p in prefixes):
            return category
    for category, suffixes in (table.get("refuse_suffixes") or {}).items():
        if any(key.endswith(s) for s in suffixes):
            return category
    return "unknown"


def env_reason(family, category, name):
    """Why `name` is refused, and what to do instead."""
    tool = (ENVIRONMENT.get(family) or {}).get("tool", family)
    return ENV_REASONS[category].format(tool=tool, name=name)


def normalize(installer, verb):
    """Canonicalise a verb for this installer."""
    if installer.get("normalize") == "npm_deref":
        return npm_deref(verb)
    if verb is None:
        # A bare command (`yarn`) is the empty verb when the table has one.
        return "" if "" in installer.get("acquire", {}) else None
    return (installer.get("aliases") or {}).get(verb, verb)


def classify(installer, verb):
    """'acquire' | 'inert' | 'unknown' for a canonical verb."""
    if verb in installer.get("acquire", {}):
        return "acquire"
    if verb in set(installer.get("inert", ())):
        return "inert"
    return "unknown"


def samples():
    """Every canonical acquisition sample command, for the conformance tests."""
    out = []
    for installer in INSTALLERS:
        for verb, spec in installer.get("acquire", {}).items():
            out.append((installer["heads"][0], verb, spec["sample"], spec["handler"]))
        for name, sub in (installer.get("subtables") or {}).items():
            for verb, spec in sub.get("acquire", {}).items():
                out.append((installer["heads"][0], "%s %s" % (name, verb),
                            spec["sample"], spec["handler"]))
    return out


# --------------------------------------------------------------------------
# The generated fallback hint.
#
# Used ONLY where the parser cannot read the command: text the lexer could not
# analyse (unbalanced quotes), a wrapper option or command name the table does
# not know, a command name built at run time, or the text a shell reads from
# its standard input. It is derived from the table, never hand-edited, so it
# cannot drift from the dispatcher the way `_ACQ_HINT` did.
# --------------------------------------------------------------------------

def _npm_spellings():
    """Every spelling that derefs to an acquiring npm verb."""
    acquiring = set(_NPM["acquire"])
    found = {s for s in _ABBREV if npm_deref(s) in acquiring}
    found |= {a for a in NPM_ALIASES if npm_deref(a) in acquiring}
    found |= acquiring
    return sorted(found, key=len, reverse=True)


# A launcher script is the same command: `pnpm.cmd`, `npm.ps1`, `pip.exe`.
_HEAD_SUFFIX = r"(?:\.(?:exe|cmd|bat|ps1))?"


# Modules `python -m` runs that install, or run an installer, and that the parser does not
# read as `pip` or `uv` themselves (`parser._installer_module` is the same rule).
INSTALLER_MODULE = r"(?:pip|uv|ensurepip|setuptools|easy_install)(?:\.[\w.]+)?"

# Modules whose job is to run another module by name (`python -m runpy pip.__main__ ...`).
MODULE_RUNNERS = ("runpy", "pdb", "cProfile", "profile", "trace")


def _build_hint():
    alternatives = []
    for installer in INSTALLERS:
        heads = "(?:%s)%s" % ("|".join(re.escape(h) for h in installer["heads"]), _HEAD_SUFFIX)
        # Versioned interpreters: pip3.12, python3.13.
        if "pip" in installer["heads"]:
            heads = r"pip[0-9.]*" + _HEAD_SUFFIX
        if installer.get("head_only"):
            alternatives.append(r"%s\s+" % heads)
            continue
        verbs = (_npm_spellings() if installer.get("normalize") == "npm_deref"
                 else sorted((v for v in installer.get("acquire", {}) if v), key=len, reverse=True))
        # Verb aliases name the same verbs (`pnpm i x`, `bun rm x`).
        verbs += [a for a, canonical in (installer.get("aliases") or {}).items()
                  if canonical in installer.get("acquire", {})]
        if verbs:
            alternatives.append(r"(?:%s)\s+(?:%s)\b" % (heads, "|".join(re.escape(v) for v in verbs)))
        scripts = installer.get("hint_scripts")
        if scripts:
            alternatives.append(r"(?:%s)(?:\s+|$)" % "|".join(scripts))
        # The head alone, whatever follows: a wrapped shorthand is not read.
        hint_heads = installer.get("hint_heads")
        if hint_heads:
            alternatives.append(r"(?:%s)%s(?:\s+|$)" % (
                "|".join(re.escape(h) for h in hint_heads), _HEAD_SUFFIX))
        for name, sub in (installer.get("subtables") or {}).items():
            subverbs = sorted(sub.get("acquire", {}), key=len, reverse=True)
            if subverbs:
                alternatives.append(r"(?:%s)\s+%s\s+(?:%s)\b" % (
                    heads, re.escape(name), "|".join(re.escape(v) for v in subverbs)))
    # An interpreter run on a module that installs, however `-m` is spelt: `python -mpip`,
    # `py -3 -Im pip.__main__`, `pypy3 -W error -m ensurepip` (parser._python_module reads
    # the same options; this is the reading for the words of a command it does not parse).
    interpreter = (r"(?:[\w.-]*(?:python|pypy|jython|graalpy)[\w.-]*|pyw?|ipy(?:64)?)%s(?:\s+"
                   r"(?:-[WXQ]\s+\S+|--check-hash-based-pycs\s+\S+|-\S*))*?" % _HEAD_SUFFIX)
    alternatives.append(r"%s\s+-[A-Za-z]*m\s*['\"]?%s['\"]?(?:\s|$)" % (interpreter, INSTALLER_MODULE))
    # `-m runpy pip.__main__`, `-m pdb -m pip`: a module that runs another by name.
    alternatives.append(r"%s\s+-[A-Za-z]*m\s*['\"]?(?:%s)['\"]?\s+(?:\S+\s+)*?['\"]?%s['\"]?(?:\s|$)"
                        % (interpreter, "|".join(MODULE_RUNNERS), INSTALLER_MODULE))
    # `-m venv --upgrade-deps` runs pip against the index.
    alternatives.append(r"%s\s+-[A-Za-z]*m\s*['\"]?venv['\"]?\s+(?:\S+\s+)*?--upgrade-"
                        % interpreter)
    # `python setup.py <command>`: `develop|install|easy_install|bdist_egg|test|upload` install the project
    # and fetch its dependencies, and a setup.cfg `[aliases]` makes any command word one of them (the
    # parser reads the interpreter forms; this reads the words of a command it does not parse,
    # `flock /tmp/l python setup.py sdist`). Any word after the options is a command.
    alternatives.append(r"setup\.py\s+(?:-\S*\s+)*[A-Za-z_]\w*(?:\s|$)")
    # The legacy installer executable: `easy_install`, `easy_install-3.9`.
    alternatives.append(r"easy_install(?:-[0-9.]+)?%s(?:\s+|$)" % _HEAD_SUFFIX)
    # bench's refused verbs, past the options of its click group (`--use-feature x`).
    alternatives.append(
        r"bench%s\s+(?:--?[\w-]+(?:=\S*)?\s+(?:[^-\s]\S*\s+)?)*(?:%s|setup\s+(?:--\s+)?(?:%s))(?:\s|$)"
        % (_HEAD_SUFFIX, "|".join(sorted(BENCH_INSTALL_VERBS, key=len, reverse=True)),
           "|".join(sorted(BENCH_INSTALL_SETUP, key=len, reverse=True))))
    for manager in FOREIGN:
        alternatives.append(r"%s%s\s+" % (re.escape(manager), _HEAD_SUFFIX))
    # `=` leads too: zsh runs `=npm` as the npm on PATH, and an alias body
    # reads `x=npm ...`.
    return re.compile(
        r"(?:^|[\s;&|(`'\"=])(?:\S*[\\/])?(?:" + "|".join(alternatives) + r")",
        re.IGNORECASE,
    )


ACQUISITION_HINT = _build_hint()


def _verb_words():
    """Every spelling of a verb whose bare form acquires, for any installer:
    what follows a command name the parser cannot read (`$CMD install x`)."""
    always = {"npm_install", "npm_ci", "npm_exec", "npm_update", "uv_add", "uv_sync",
              "pip_install", "pip_download", "pip_wheel",
              "pnpm_install", "bun_install", "yarn_install"}
    found = set()
    for installer in INSTALLERS:
        verbs_ = {verb for verb, spec in installer.get("acquire", {}).items()
                  if verb and spec["handler"] in always}
        found |= verbs_
        if installer.get("normalize") == "npm_deref":
            found |= {s for s in list(_ABBREV) + list(NPM_ALIASES) if npm_deref(s) in verbs_}
    return frozenset(found)


ACQUIRING_VERBS = _verb_words()


def acquisition_hint():
    return ACQUISITION_HINT


def render_table():
    """Render the table as a markdown block.

    Documentation embeds this rendering byte for byte, so it never keeps its
    own copy of the data.
    """
    rows = ["| head | acquiring verbs | inert verbs |", "|---|---|---|"]
    for installer in INSTALLERS:
        heads = " / ".join("`%s`" % h for h in installer["heads"])
        acquiring = [v or "(bare)" for v in sorted(installer.get("acquire", {}))]
        for name, sub in sorted((installer.get("subtables") or {}).items()):
            acquiring += ["%s %s" % (name, v) for v in sorted(sub.get("acquire", {}))]
        inert = len(installer.get("inert", []))
        for name, sub in (installer.get("subtables") or {}).items():
            inert += len(sub.get("inert", []))
        rows.append("| %s | %s | %d |" % (
            heads, ", ".join("`%s`" % a for a in acquiring), inert))
    rows.append("| %s | *(all denied)* | %d safe read-only verbs |" % (
        " / ".join("`%s`" % m for m in sorted(FOREIGN)), len(FOREIGN_SAFE)))
    return "\n".join(rows)
