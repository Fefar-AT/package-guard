"""Configuration pnpm, Bun and Yarn Berry read on their own (v1.10.0, P3).

`sources.py` asks this module what the command line cannot show: a registry
redirect, code that runs before any package is reviewed (a Yarn plugin or
`yarnPath`, a `.pnpmfile.cjs`, a Bun `preload`), a setting that moves the
directories reconciliation reads, a check turned off. Design section 5; D9, D10.

Every file is read with a restricted reader and checked against an ALLOW-LIST:
a key that is not listed is refused and named (Q14), and a file the reader
cannot account for byte for byte is refused too. Nothing here decides; each
check returns reasons, as `sources.py` does.

Allow-lists (a key's value is checked when the rule says so; every other key
is refused by name):

  .yarnrc.yml     nodeLinker (node-modules, required), npmRegistryServer (the
                  official registry only), enableScripts (false only),
                  checksumBehavior (throw only), npmMinimalAgeGate (not below
                  1d), cacheFolder / globalFolder (the default places),
                  unsafeHttpWhitelist / npmScopes / npmRegistries (empty only),
                  enableStrictSsl (true only), and the benign display, network
                  tuning, cache and install-mode keys in `_YARN_BENIGN`.
                  Always refused: yarnPath, plugins, packageExtensions,
                  injectEnvironmentFiles, httpProxy, httpsProxy,
                  networkSettings, httpsCaFilePath, httpsKeyFilePath,
                  httpsCertFilePath, npmPreapprovedPackages.
  bunfig.toml     see `_BUN_*`: [install] keys exact, production, frozenLockfile,
                  ignoreScripts, minimumReleaseAge, dev, optional, peer,
                  linker, auto, saveTextLockfile (not false), cache.disable;
                  registry / scopes only when official; preload, security.scanner
                  and every path key refused.
  pnpm yaml/json  see `_PNPM_*`: the pnpm-workspace.yaml and package.json `pnpm`
                  settings, plus pnpm's own global rc and config.yaml.

  .yarnrc         Yarn Classic (v1), see `yarn_classic_config`: the files Yarn 1.22 reads
                  in its own order, an allow-list of keys (`registry` official only,
                  `ignore-scripts`, `--install.frozen-lockfile`, display and tuning
                  options), and the effective scripts-off and frozen-lockfile proofs.

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path
from typing import NamedTuple

import pnpm_lock
import protocols
import verbs
from lock_errors import LockReadError

_redact = protocols.redact


# ---------------------------------------------------------------------------
# The YAML subset (.yarnrc.yml, pnpm-workspace.yaml)
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """A configuration file this module cannot read safely."""


def _strip_comments(text: str) -> str:
    """Drop `#` comments, quote-aware. A `#` starts a comment at the start of a
    line or after whitespace, outside a quoted scalar."""
    out = []
    for raw in text.split("\n"):
        quote = None
        cut = len(raw)
        for i, ch in enumerate(raw):
            before = raw[i - 1] if i else " "
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "'\"" and (before in " [{,:" or i == 0):
                quote = ch
            elif ch == "#" and before in " \t":
                cut = i
                break
            elif ch == "#" and i == 0:
                cut = 0
                break
        out.append(raw[:cut].rstrip())
    return "\n".join(out)


def parse_yaml_config(text: str, what: str) -> dict:
    """Parse the block-mapping subset, comments allowed. The reader is the
    lock reader's, so anchors, aliases, tags, block scalars, nulls, tabs, CRLF
    and sequences of mappings are refused rather than guessed at. A file with
    no content is an empty mapping."""
    if "\r" in text or "\t" in text:
        raise ConfigError(f"{what}: CRLF line endings and tabs are not supported")
    text = _strip_comments(text)
    if not any(line.strip() and line.strip() != "---" for line in text.split("\n")):
        return {}
    try:
        documents = pnpm_lock.parse_yaml(text)
    except LockReadError as exc:
        raise ConfigError(f"{what}: {str(exc).removeprefix('pnpm-lock.yaml: ')}") from exc
    if len(documents) != 1:
        raise ConfigError(f"{what}: more than one YAML document")
    return documents[0]


def _read_yaml(path: Path) -> dict:
    try:
        text = path.read_bytes().decode("utf-8")  # bytes: universal newlines would hide a CR
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: cannot be read ({exc.__class__.__name__})") from exc
    return parse_yaml_config(text, str(path))


def _ancestors(directory) -> list:
    """`directory` and every parent up to the filesystem root, nearest first."""
    base = Path(os.path.realpath(directory))
    return [base, *base.parents]


def _distinct(paths) -> list:
    """`paths` without repeats, two spellings of one file counted once."""
    seen, out = set(), []
    for path in paths:
        real = os.path.realpath(path)
        if real not in seen:
            seen.add(real)
            out.append(path)
    return out


def _bad_text(value) -> bool:
    """A value Yarn would interpolate (`${VAR}`) or the reader cannot judge."""
    return isinstance(value, str) and "${" in value


def _scalar(value) -> bool:
    return isinstance(value, (bool, str)) and not _bad_text(value)


def _empty(value) -> bool:
    return value in ([], {}) or value is None


# ---------------------------------------------------------------------------
# Yarn Berry: .yarnrc.yml
# ---------------------------------------------------------------------------

# Settings that run code before a package is reviewed, reroute or re-trust
# downloads, add dependencies no review saw, or bypass the age gate.
_YARN_REFUSED = {
    "yarnPath": "runs a replacement Yarn binary before any package is reviewed",
    "plugins": "loads plugins, which run code before any package is reviewed",
    "packageExtensions": "adds dependencies to reviewed packages that no review saw",
    "injectEnvironmentFiles": "loads environment files into Yarn's own environment",
    "httpProxy": "routes downloads through a proxy",
    "httpsProxy": "routes downloads through a proxy",
    "networkSettings": "changes how Yarn reaches the network",
    "httpsCaFilePath": "changes which certificates Yarn trusts",
    "httpsKeyFilePath": "changes which certificates Yarn trusts",
    "httpsCertFilePath": "changes which certificates Yarn trusts",
    "npmPreapprovedPackages": "exempts packages from the minimum-age gate",
}
# Settings with no effect on what is fetched, run or where it lands.
_YARN_BENIGN = frozenset({
    "enableTelemetry", "enableColors", "enableProgressBars", "enableHyperlinks",
    "enableMessageNames", "enableInlineBuilds", "enableTimers", "progressBarStyle",
    "preferInteractive", "preferAggregateCacheInfo", "preferTruncatedLines",
    "networkConcurrency", "httpTimeout", "httpRetry", "compressionLevel", "enableMirror",
    "enableGlobalCache", "enableImmutableInstalls", "enableImmutableCache",
    "defaultSemverRangePrefix", "initScope",
})
_YARN_DEFAULT_AGE_MINUTES = 24 * 60
_DURATION = re.compile(r"^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?$")
_UNIT_MINUTES = {"ms": 1 / 60000, "s": 1 / 60, "m": 1, "h": 60, "d": 1440, "w": 10080}


def _minutes(value):
    match = _DURATION.match(str(value).strip())
    if not match or isinstance(value, bool):
        return None
    return float(match.group(1)) * _UNIT_MINUTES.get(match.group(2) or "m")


def _yarn_default_folders(home):
    return {"cacheFolder": {str(Path(home) / ".yarn" / "berry" / "cache")},
            "globalFolder": {str(Path(home) / ".yarn" / "berry"), "~/.yarn/berry"}}


# The project's own cache, which reconciliation reads. Berry resolves a
# relative path against the directory of the rc file that wrote it, so these
# mean the project's only when that file is the project's own.
_PROJECT_CACHE = {"./.yarn/cache", ".yarn/cache"}


def yarn_key_problem(key, value, home, in_project=False):
    """Why one Yarn setting is refused, or None: the ONE rule the rc reader, the
    process environment and the parser's command-prefix check all apply.
    `value` is the parsed value (bool, str, list or dict); `in_project` is True
    when a relative path in it resolves against the project's own directory."""
    if key in _YARN_REFUSED:
        return _YARN_REFUSED[key]
    if _bad_text(value) or (isinstance(value, list) and any(_bad_text(v) for v in value)):
        return "uses ${...} interpolation, which Package Guard cannot resolve"
    if key == "nodeLinker":
        return None if value == "node-modules" else (
            f"is {value!r}; only node-modules is supported (the disk scanner reads node_modules)")
    if key == "npmRegistryServer":
        return None if protocols.is_official_registry(value) else (
            f"is {_redact(value)!r}; only the default registry is supported")
    if key == "enableScripts":
        return None if value is False else "must be false or absent (dependency scripts run unreviewed)"
    if key == "checksumBehavior":
        return None if value == "throw" else "must be throw: it is the check on what is downloaded"
    if key == "enableStrictSsl":
        return None if value is True else "turns TLS verification off"
    if key == "npmMinimalAgeGate":
        minutes = _minutes(value)
        return None if minutes is not None and minutes >= _YARN_DEFAULT_AGE_MINUTES else (
            f"is {value!r}, below the default of 1d")
    if key in ("cacheFolder", "globalFolder"):
        if isinstance(value, str) and value in _yarn_default_folders(home)[key]:
            return None
        if key == "cacheFolder" and in_project and value in _PROJECT_CACHE:
            return None
        return "moves a directory reconciliation reads; only the default place is supported"
    if key in ("unsafeHttpWhitelist", "npmScopes", "npmRegistries"):
        return None if _empty(value) else {
            "unsafeHttpWhitelist": "allows plain-HTTP downloads",
            "npmScopes": "configures a scope's registry or credentials",
            "npmRegistries": "configures a registry or its credentials"}[key]
    if key in _YARN_BENIGN:
        return None if _scalar(value) else "must be a single value"
    return "is not a setting Package Guard knows to be safe"


_ENV_BOOLS = {"true": True, "false": False, "1": True, "0": False}


def yarn_env_key(name):
    """`YARN_ENABLE_SCRIPTS` -> `enableScripts`; None when it is not a YARN_ name."""
    if not name.upper().startswith("YARN_") or len(name) == 5:
        return None
    first, *rest = name[5:].lower().split("_")
    return first + "".join(part.capitalize() for part in rest)


def yarn_env_problem(name, value, home=None):
    """Why `NAME=value` in a command's prefix or in the hook's environment is
    refused, or None. The rc rule on the setting the name overrides; the
    names no rule knows, and YARN_RC_FILENAME (it renames the file the guard
    reads), are refused."""
    key = yarn_env_key(name)
    if key is None:
        return None
    if name.upper() == "YARN_RC_FILENAME":
        return "renames the rc file Package Guard reads"
    classic = _classic_env_problem(name.upper(), value)
    if classic is not _NOT_CLASSIC:
        return classic
    value = _ENV_BOOLS.get(str(value).strip().lower(), value)
    home = Path.home() if home is None else home
    return yarn_key_problem(key, value, home, in_project=True)


def _yarn_rc_paths(directory, home) -> list:
    """Every .yarnrc.yml Berry merges, nearest first: the directory, each
    parent up to the root, then ~."""
    paths = [parent / ".yarnrc.yml" for parent in _ancestors(directory)]
    home_rc = Path(home) / ".yarnrc.yml"
    if home_rc not in paths:
        paths.append(home_rc)
    return [p for p in paths if p.is_file()]


def yarn_rc(directory, home) -> list:
    """[(path, mapping)] for every .yarnrc.yml in precedence order. Raises
    ConfigError for a file that cannot be read in full."""
    out = []
    for path in _yarn_rc_paths(directory, home):
        data = _read_yaml(path)
        out.append((path, data))
    return out


_TOP_KEY = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)\s*:(.*)$")


def _refused_complex_keys(path, home, in_project) -> list:
    """`plugins:` and its kind (a sequence of mappings, a nested map) are not in the reader's
    subset, so the whole file fails to parse and the denial would read "ambiguous plain
    scalar (line 3)" and name nothing. Look for the TOP-LEVEL keys with a nested value before
    any value is parsed, and name each one the setting rule refuses (B6): `plugins`,
    `packageExtensions`, a non-empty `npmScopes`, `npmRegistries`, ..."""
    try:
        text = _strip_comments(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError):
        return []
    lines = text.split("\n")
    out = []
    for index, line in enumerate(lines):
        match = _TOP_KEY.match(line)
        if match is None:
            continue
        key, inline = match.group(1), match.group(2).strip()
        following = next((later for later in lines[index + 1:] if later.strip()), "")
        nested = (not inline and following[:1] in (" ", "-")) or inline[:1] in ("[", "{")
        if not nested:
            continue
        reason = yarn_key_problem(key, ["nested"], home, in_project=in_project)
        if reason:
            out.append(f"{path}: `{key}` {reason}")
    return out


def yarn_config_problems(directory, home, environ=None, require_linker=True) -> list:
    problems = []
    files, unreadable = [], False
    project = Path(os.path.realpath(directory))
    for path in _yarn_rc_paths(directory, home):
        try:
            files.append((path, _read_yaml(path)))
        except ConfigError as exc:
            unreadable = True
            named = _refused_complex_keys(path, home, path.parent == project)
            problems += named or [
                f"{exc}; Package Guard reads only plain `key: value` settings in .yarnrc.yml"]
    # An environment variable beats every rc file: its linker is the effective one.
    effective_linker = next((_ENV_BOOLS.get(str(v).lower(), v) for n, v in (environ or {}).items()
                             if n.upper() == "YARN_NODE_LINKER"), None)
    for path, data in files:
        for key, value in data.items():
            if key == "nodeLinker" and effective_linker is None:
                effective_linker = value
            reason = yarn_key_problem(key, value, home, in_project=path.parent == project)
            if reason:
                problems.append(f"{path}: `{key}` {reason}")
    if require_linker and effective_linker is None and not unreadable:
        problems.append(
            f"{Path(directory) / '.yarnrc.yml'}: `nodeLinker: node-modules` is not set. Yarn "
            "defaults to Plug'n'Play, which has no node_modules tree Package Guard can inspect; "
            "add `nodeLinker: node-modules` (the human's to do)")
    return problems


# ---------------------------------------------------------------------------
# Yarn Classic (v1): which Yarn, and the configuration it reads
#
# Everything below is read from Yarn 1.22.22's own source (src/rc.js, src/util/rc.js,
# src/registries/yarn-registry.js, src/registries/base-registry.js, src/config.js,
# src/cli/index.js), not assumed. The facts the gate rests on:
#
#   * `.yarnrc` keys that start `--` are CLI flags: `--install.frozen-lockfile true` becomes
#     `--frozen-lockfile` for the `install` command only; a key with no `<command>.` applies to
#     every command. Only a bare `true` pushes a boolean flag. A bare key (`frozen-lockfile
#     true`) is an option no command reads.
#   * `ignore-scripts` is OR-ed: `config.ignoreScripts = flag || Boolean(option)`. The flag
#     comes from the command line or a `--...ignore-scripts true` rc key; the option from the
#     env (`YARN_IGNORE_SCRIPTS`) over the rc files.
#   * The flag keys are read by `rc.js` from every `.yarnrc` AND `.yarnrc.yml` from the root down
#     to the working directory, then /etc/yarn/config, /etc/yarnrc, the user files under
#     ~/.config/yarn, ~/.yarn and ~/.yarnrc, then the file named by YARN_CONFIG; a LATER file
#     wins, so the user's files beat the project's. The option keys are read by the registry
#     from the PROJECT ROOT's `.yarnrc` (the nearest ancestor with a package.json: install, add
#     and remove run there, `findProjectRoot`), then `~/.yarnrc`, then <prefix>/etc/yarnrc, then
#     each parent's `.yarnrc`; the FIRST file wins, and `.yarnrc.yml` is not among them.
#   * `yarn-path` / `yarnPath` in any rc file (a `.yml` too) hands the whole command to
#     another program. `--use-yarnrc` and `--no-default-rc` change which files are read.
#   * `YARN_<NAME>` (lower-cased, `_` to `-`) sets the option of that name before any rc file.
# ---------------------------------------------------------------------------

CLASSIC, BERRY = "classic", "berry"
_NOT_CLASSIC = object()


class Flavour(NamedTuple):
    """Which Yarn a project uses. `kind` is "classic", "berry" or None; `conflict` says why
    the evidence points both ways; `evidence` lists what was found; `project` is the
    directory it was found in."""
    kind: object
    evidence: tuple
    conflict: object
    project: object


def classic_enabled() -> bool:
    import parser as pg_parser  # local: parser imports this module
    return pg_parser.YARN_CLASSIC_ENABLED


def _yarn_project_dir(directory):
    """The project a shell directory belongs to: the nearest directory at or above it with a
    package.json or a yarn.lock, else the directory itself."""
    for candidate in _ancestors(directory):
        if (candidate / "package.json").is_file() or (candidate / "yarn.lock").is_file():
            return candidate
    return Path(os.path.realpath(directory))


def _declared_yarn(project):
    """[(where, version)] for each `yarn` entry of package.json's packageManager and
    devEngines.packageManager. A pin that names another manager is not Yarn evidence."""
    data = _package_json(project)
    if not isinstance(data, dict):
        return []
    found = []
    field = data.get("packageManager")
    if isinstance(field, str):
        name, _, version = field.partition("@")
        if name == "yarn":
            found.append(("packageManager", version.partition("+")[0]))
    dev = data.get("devEngines")
    entries = dev.get("packageManager") if isinstance(dev, dict) else None
    if isinstance(entries, dict):
        entries = [entries]
    for entry in entries if isinstance(entries, list) else ():
        if isinstance(entry, dict) and entry.get("name") == "yarn":
            version = entry.get("version")
            found.append(("devEngines.packageManager", version if isinstance(version, str) else ""))
    return found


def _lock_flavour(path):
    try:
        with path.open("rb") as handle:
            head = handle.read(8192).decode("utf-8", "replace")
    except OSError:
        return None
    lines = ("\n" + head.lstrip("\ufeff")).split("\n")
    if any(line.strip() == "# yarn lockfile v1" for line in lines if line.startswith("#")):
        return CLASSIC
    if any(line.startswith("__metadata:") for line in lines):
        return BERRY
    return None


# Directories whose `.yarnrc` is one `bench-config apply` wrote and nobody has changed since: the
# hook fills this at the start of each decision. A `.yarnrc` the guard did not write is not evidence
# (Berry ignores it too); one the guard wrote for a bench app says which Yarn that app is meant for,
# which an app with no yarn.lock yet cannot say itself.
GUARD_YARNRC_DIRS: set = set()


def yarn_flavour(directory) -> Flavour:
    """Classify `directory`'s yarn ONCE: every Classic rule and every Berry rule calls this.

    Evidence: `packageManager` / `devEngines.packageManager` (yarn@1.x is Classic, yarn@2 or
    later is Berry), a `.yarnrc.yml` in the directory chain (Berry), the header of yarn.lock
    (`# yarn lockfile v1` is Classic, `__metadata` is Berry). Evidence that points both ways
    is a conflict. No evidence is not Classic: a `yarn` on PATH may be Berry, which migrates a
    v1 lock silently. With the Classic switch off nothing is ever Classic."""
    project = _yarn_project_dir(directory)
    if not classic_enabled():
        return Flavour(None, (), None, project)
    evidence = {CLASSIC: [], BERRY: []}
    for where, version in _declared_yarn(project):
        match = re.match(r"^[~^>=<\s]*(\d+)", version or "")
        if match:
            major = int(match.group(1))
            evidence[CLASSIC if major == 1 else BERRY if major >= 2 else CLASSIC].append(
                f"{where} yarn@{version}")
    for parent in _ancestors(directory):
        if (parent / ".yarnrc.yml").is_file():
            evidence[BERRY].append(f"{parent / '.yarnrc.yml'}")
            break
    if os.path.realpath(project) in GUARD_YARNRC_DIRS:
        evidence[CLASSIC].append(f"{project / '.yarnrc'} is the Classic rc file the guard wrote for this bench")
    lock = project / "yarn.lock"
    if lock.is_file():
        found = _lock_flavour(lock)
        if found:
            evidence[found].append(f"{lock} is a {'Classic v1' if found == CLASSIC else 'Berry'} lock")
    both = tuple(evidence[CLASSIC] + evidence[BERRY])
    if evidence[CLASSIC] and evidence[BERRY]:
        return Flavour(None, both, (
            f"Evidence of Yarn Classic ({'; '.join(evidence[CLASSIC])}) conflicts with evidence of "
            f"Yarn Berry ({'; '.join(evidence[BERRY])}); a Berry binary would migrate a Classic "
            "lock and install versions nobody reviewed"), project)
    kind = CLASSIC if evidence[CLASSIC] else BERRY if evidence[BERRY] else None
    return Flavour(kind, both, None, project)


# -- the .yarnrc reader -------------------------------------------------------

def _rc_token(text, pos, path, no):
    if pos >= len(text):
        raise ConfigError(f"{path} line {no}: a key with no value")
    if text[pos] == '"':
        try:
            value, length = json.JSONDecoder().raw_decode(text[pos:])
        except ValueError:
            raise ConfigError(f"{path} line {no}: an unterminated or invalid quoted string") from None
        if not isinstance(value, str):
            raise ConfigError(f"{path} line {no}: a quoted string that is not text")
        if "\\" in text[pos:pos + length]:
            # Yarn's quote scanner and JSON disagree about an escaped quote; a real .yarnrc has none.
            raise ConfigError(f"{path} line {no}: a backslash inside a quoted string")
        return value, pos + length, True
    end = pos
    while end < len(text) and text[end] not in ' \t':
        end += 1
    word = text[pos:end]
    if not word or any(c in word for c in ':,"[]\\'):
        raise ConfigError(f"{path} line {no}: {word!r} is not a plain word (quote it)")
    # Yarn's tokenizer reads a bare word only if it starts with a letter, `/`, `.` or `-`; a run of
    # digits is a number; `true` and `false` are booleans WHERE THEY START, so `trueish` is a
    # boolean followed by garbage. Anything else fails its native parse, and Yarn then reads the
    # whole file as YAML, which is not the mapping this reader saw.
    if word.startswith(("true", "false")) and word not in ("true", "false"):
        raise ConfigError(f"{path} line {no}: {word!r} starts with a boolean; Yarn reads it as one "
                          "followed by garbage and then reads the whole file differently (quote it)")
    if not (re.match(r"[A-Za-z/.\-]", word) or word.isdigit()):
        raise ConfigError(f"{path} line {no}: {word!r} is not a word Yarn's own reader accepts "
                          "unquoted (quote it)")
    return word, end, False


def _parse_classic_rc(text, path):
    """A `.yarnrc` as Yarn's own lockfile parser reads it, restricted to what it writes: one
    `key value` pair per line, each a bare word or a JSON string, `#` comments, no nesting.
    A value is `true`/`false` (a boolean), digits (a number) or text; a duplicate key (Yarn
    keeps the last) is refused. Anything else cannot be read the way Yarn reads it."""
    out = {}
    for no, raw in enumerate(text.replace("\r\n", "\n").split("\n"), 1):
        line = raw.strip()
        if "\r" in raw:
            raise ConfigError(f"{path} line {no}: a bare carriage return")
        if line.startswith(("<<<<<<<", "=======", ">>>>>>>")):
            raise ConfigError(f"{path} line {no}: a merge-conflict marker")
        if line.startswith("#"):
            if re.match(r"#\s*yarn lockfile v", line) and line != "# yarn lockfile v1":
                raise ConfigError(f"{path} line {no}: a lockfile version comment Yarn would reject")
            continue
        if not line:
            continue
        if raw[:1] in " \t":
            raise ConfigError(f"{path} line {no}: an indented line (a nested value is not read)")
        key, pos, key_quoted = _rc_token(line, 0, path, no)
        if not key_quoted and (key.isdigit() or key in ("true", "false")):
            raise ConfigError(f"{path} line {no}: a key that Yarn reads as a number or a boolean")
        if line[pos:pos + 1] != " ":
            raise ConfigError(f"{path} line {no}: {key!r} is not followed by a value")
        value, end, quoted = _rc_token(line, pos + 1, path, no)
        if end != len(line):
            raise ConfigError(f"{path} line {no}: unexpected text after the value")
        if not quoted:
            if value == "true":
                value = True
            elif value == "false":
                value = False
            elif value.isdigit():
                value = int(value)
            elif value[:1].isdigit():
                raise ConfigError(f"{path} line {no}: {value!r} reads as a number and then garbage; quote it")
        if key in out:
            raise ConfigError(f"{path} line {no}: {key!r} appears twice (Yarn keeps the last)")
        out[key] = value
    return out


def _classic_rc_read(path):
    """The mapping in one rc file, or None when there is no file. Raises ConfigError."""
    try:
        if not path.is_file():
            return None
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: cannot be read ({exc.__class__.__name__})") from exc
    if path.name.endswith(".yml"):
        # Git for Windows writes CRLF: read it as LF, and refuse a CR that is not part of one.
        text = text.replace("\r\n", "\n")
        if "\r" in text:
            raise ConfigError(f"{path}: a bare carriage return")
        return parse_yaml_config(text, str(path))
    return _parse_classic_rc(text, path)


def _classic_project_root(cwd):
    """Where Yarn reads its OPTION keys from: `cli/index.js` runs install, add and remove in
    `findProjectRoot(cwd)`, the nearest directory at or above the shell's with a package.json
    (the shell's own when there is none). The `--` flag keys are read from the shell's directory
    (`rc.js`), so the two chains differ when the shell is below the project."""
    for candidate in _ancestors(cwd):
        if (candidate / "package.json").is_file():
            return candidate
    return _ancestors(cwd)[0]


def _classic_rc_orders(cwd, home, environ):
    """(args_order, option_order): the rc files in the order Yarn merges each kind of key.
    `args_order` is lowest precedence first (a later file wins) and starts from the shell's
    directory; `option_order` is highest first (the first file that sets a key wins) and starts
    from the project root."""
    chain = _ancestors(cwd)  # nearest first
    option_chain = _ancestors(_classic_project_root(cwd))
    home = Path(home)
    xdg = environ.get("XDG_CONFIG_HOME")
    user = [home / ".config" / "yarn" / "config", home / ".config" / "yarn", home / ".yarn" / "config",
            home / ".yarnrc", home / ".yarnrc.yml"]
    if xdg:
        user.insert(0, Path(xdg) / "yarn" / "config")
    system = [Path("/etc/yarn/config"), Path("/etc/yarnrc"), Path("/etc/yarnrc.yml")]
    args_order = []
    for parent in reversed(chain):
        args_order += [parent / ".yarnrc", parent / ".yarnrc.yml"]
    args_order += system + user
    extra = next((v for n, v in environ.items() if n.upper() == "YARN_CONFIG"), None)
    if extra:
        args_order.append(Path(extra))
    prefixes = {environ.get("PREFIX"), "/usr/local", "/usr", "/opt/homebrew"}
    option_order = [option_chain[0] / ".yarnrc", home / ".yarnrc",
                    *[Path(p) / "etc" / "yarnrc" for p in sorted(x for x in prefixes if x)],
                    *[parent / ".yarnrc" for parent in option_chain[1:]]]
    return args_order, option_order


# Settings that matter, and why the ones refused are refused.
_CLASSIC_REFUSED = {
    "yarn-path": "hands the whole command to another program before any package is reviewed",
    "yarnPath": "hands the whole command to another program before any package is reviewed",
    "yarn-offline-mirror": "installs from a local mirror of tarballs no review saw",
    "yarn-offline-mirror-pruning": "changes a local mirror of tarballs no review saw",
    "offline-cache-folder": "installs from a local mirror of tarballs no review saw",
    "cache-folder": "moves a directory reconciliation reads",
    "preferred-cache-folder": "moves a directory reconciliation reads",
    "global-folder": "moves a directory reconciliation reads",
    "link-folder": "moves a directory reconciliation reads",
    "modules-folder": "installs somewhere reconciliation does not read",
    "prefix": "moves where Yarn writes its global files",
    "cwd": "runs Yarn in another directory than the one that was checked",
    "proxy": "routes downloads through a proxy",
    "https-proxy": "routes downloads through a proxy",
    "cafile": "changes which certificates Yarn trusts",
    "ca": "changes which certificates Yarn trusts",
    "cert": "changes which certificates Yarn trusts",
    "key": "changes which certificates Yarn trusts",
    "env": "sets the environment of every script",
    "workspaces-experimental": "enables workspaces, whose members Package Guard does not read",
    "workspaces-nohoist-experimental": "enables workspaces, whose members Package Guard does not read",
    "plugnplay-override": "Plug'n'Play has no node_modules tree Package Guard can inspect",
    "plugnplay-shebang": "Plug'n'Play has no node_modules tree Package Guard can inspect",
    "plugnplay-blacklist": "Plug'n'Play has no node_modules tree Package Guard can inspect",
    "unsafe-disable-integrity-migration": "turns off the integrity record Yarn adds to a lock",
    "yarn-enable-lockfile-versions": "changes how the lock is written",
    "yarn-link-file-dependencies": "changes how file: dependencies are installed",
    "experimental-pack-script-packages-in-mirror": "writes built packages into a mirror",
    "enable-meta-folder": "changes where Yarn writes package metadata",
}
# Options with no effect on what is fetched, run or where it lands (value: bool/int/text).
_CLASSIC_BENIGN = frozenset({
    "ignore-scripts", "ignore-optional", "ignore-engines", "ignore-platform", "network-concurrency",
    "network-timeout", "child-concurrency", "no-progress", "disable-self-update-check",
    "lastUpdateCheck", "save-prefix", "bin-links", "emoji", "silent", "production", "prefer-offline",
    "scripts-prepend-node-path", "user-agent", "version-tag-prefix", "version-git-tag",
    "version-commit-hooks", "version-git-sign", "version-git-message", "init-version",
    "init-license", "init-author-name", "init-author-email", "init-author-url",
})
_CLASSIC_BOOL_KEYS = frozenset({"ignore-scripts", "ignore-optional", "ignore-engines", "ignore-platform",
                                "no-progress", "disable-self-update-check", "bin-links", "emoji",
                                "silent", "production", "prefer-offline"})
# `--<flag> true` keys: the flags a `.yarnrc` may preset, and the commands whose flags they are.
_CLASSIC_FLAG_KEYS = frozenset({
    "ignore-scripts", "frozen-lockfile", "pure-lockfile", "check-files", "production", "ignore-engines",
    "ignore-platform", "ignore-optional", "non-interactive", "no-progress", "no-bin-links", "silent", "emoji",
    "network-concurrency", "network-timeout", "prefer-offline", "offline", "exact", "tilde", "dev",
    "peer", "optional", "verbose",
})
_CLASSIC_FLAG_COMMANDS = frozenset({"install", "add", "remove", "upgrade"})
_CLASSIC_NUMERIC_FLAGS = frozenset({"network-concurrency", "network-timeout"})
_FLAG_KEY = re.compile(r"^--(?:(?P<command>[A-Za-z][A-Za-z-]*)\.)?(?P<flag>[a-z][a-z-]*)$")
_SCOPE_REGISTRY = re.compile(r"^@[A-Za-z0-9._~-]+:registry$")


def _classic_key_problem(key, value):
    """Why one `.yarnrc` key is refused, or None: the ONE rule every Classic rc file is held to."""
    if _bad_text(value):
        return "uses ${...} interpolation, which Package Guard cannot resolve"
    flag = _FLAG_KEY.match(key)
    if key.startswith("--"):
        if flag is None:
            return "is not a flag key Package Guard can read"
        command, name = flag.group("command"), flag.group("flag")
        if command is not None and command not in _CLASSIC_FLAG_COMMANDS:
            return f"presets a flag of `{command}`, which Package Guard does not read"
        if name not in _CLASSIC_FLAG_KEYS:
            why = _CLASSIC_REFUSED.get(name)
            return f"presets `--{name}`" + (f", which {why}" if why else ", a flag Package Guard does not know to be safe")
        if name in _CLASSIC_NUMERIC_FLAGS:
            return None if isinstance(value, int) and not isinstance(value, bool) else "must be a number"
        return None if isinstance(value, bool) else "must be true or false"
    if key in _CLASSIC_REFUSED:
        return _CLASSIC_REFUSED[key]
    if key == "registry" or _SCOPE_REGISTRY.match(key):
        return None if protocols.is_official_registry(value) else (
            f"is {_redact(str(value))!r}; only the default registry is supported")
    if key == "strict-ssl":
        return None if value is True else "turns TLS verification off"
    if key in _CLASSIC_BOOL_KEYS:
        return None if isinstance(value, bool) else "must be true or false"
    if key in _CLASSIC_BENIGN:
        return None if isinstance(value, (bool, int, str)) and not _bad_text(value) else "must be a single value"
    return "is not a setting Package Guard knows to be safe"


_CLASSIC_ENV_BENIGN = frozenset({
    "YARN_SILENT", "YARN_NO_PROGRESS", "YARN_NETWORK_TIMEOUT", "YARN_CHILD_CONCURRENCY",
    "YARN_IGNORE_ENGINES", "YARN_IGNORE_PLATFORM", "YARN_DISABLE_SELF_UPDATE_CHECK",
    "YARN_WRAP_OUTPUT", "YARN_PRODUCTION", "YARN_EMOJI",
})


def _classic_env_problem(name, value):
    """The verdict for a Yarn Classic setting spelled as an environment variable, or
    `_NOT_CLASSIC` for a name this does not judge (the Berry rule then does)."""
    if name == "YARN_IGNORE_SCRIPTS":
        return None if str(value).strip().lower() == "true" else (
            "undoes the scripts-off proof: Yarn reads it before every `.yarnrc`; only `true` is "
            "supported")
    if name == "YARN_REGISTRY":
        return None if protocols.is_official_registry(value) else (
            f"is {_redact(str(value))!r}; only the default registry is supported")
    if name in _CLASSIC_ENV_BENIGN:
        return None
    if name in ("YARN_CONFIG", "YARN_IGNORE_PATH"):
        return "changes which rc files or which Yarn binary runs"
    return _NOT_CLASSIC


class YarnExe(NamedTuple):
    """The `yarn` a command will run, found without running it. `major` is 1 for Yarn Classic,
    2 or more for Berry, None when it could not be established; `why` says how, or why not."""
    major: object
    version: object
    path: object
    why: str


def _package_of(real):
    """(name, version) of the npm package that holds the file `real`, from the nearest package.json
    above it (up to six directories), or None."""
    for parent in list(Path(real).parents)[:6]:
        manifest = parent / "package.json"
        if manifest.is_file():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError, RecursionError):
                return None
            if isinstance(data, dict) and isinstance(data.get("name"), str):
                return data["name"], data.get("version") if isinstance(data.get("version"), str) else None
            return None
    return None


def yarn_executable(head, path_value, cwd, pin_version=None) -> YarnExe:
    """Resolve the `yarn` a command word will run, from the command word and the PATH it searches
    (the hook's own, or the one the command sets). Symlinks are followed to the package.json of
    the package that holds the file: `yarn` 1.x is the npm package `yarn`, Berry's is
    `@yarnpkg/cli-dist`. A Corepack shim runs the release `package.json` pins, so it counts only
    with an exact `yarn@1.x.y` pin. Nothing is executed. `path_value` None means the PATH is built
    at run time and cannot be known."""
    cwd = Path(cwd)
    name = Path(head).name.lower()
    name = name[:-4] if name.endswith((".cmd", ".exe", ".ps1")) else name
    if "/" in head or "\\" in head:
        found = Path(head) if Path(head).is_absolute() else cwd / head
        candidates = [found] if found.is_file() else []
    else:
        if path_value is None:
            return YarnExe(None, None, None, "the PATH is built when the command runs")
        candidates = []
        for entry in path_value.split(os.pathsep):
            directory = cwd if entry == "" else (Path(entry) if Path(entry).is_absolute() else cwd / entry)
            for candidate in (directory / name, directory / (name + ".exe")):
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    candidates.append(candidate)
                    break
            if candidates:
                break
    if not candidates:
        return YarnExe(None, None, None, f"no `{name}` was found on the PATH")
    found = candidates[0]
    real = Path(os.path.realpath(found))
    owner = _package_of(real)
    if owner is not None:
        pkg, version = owner
        match = re.match(r"^(\d+)\.", version or "")
        if pkg == "yarn" and match:
            return YarnExe(int(match.group(1)), version, real, f"{found} is the npm package yarn@{version}")
        if pkg in ("@yarnpkg/cli-dist", "@yarnpkg/cli") and match:
            return YarnExe(int(match.group(1)), version, real, f"{found} is Yarn Berry {version}")
        if pkg == "corepack":
            if pin_version and re.match(r"^1\.\d+\.\d+$", pin_version):
                return YarnExe(1, pin_version, real, f"{found} is a Corepack shim and package.json pins yarn@{pin_version}")
            return YarnExe(None, None, real, f"{found} is a Corepack shim and package.json does not pin yarn@1.x.y")
        return YarnExe(None, None, real, f"{found} belongs to the package {pkg!r}, not to yarn")
    try:
        head_text = real.read_bytes()[:2048].decode("utf-8", "replace")
    except OSError:
        head_text = ""
    if "corepack" in head_text:
        if pin_version and re.match(r"^1\.\d+\.\d+$", pin_version):
            return YarnExe(1, pin_version, real, f"{found} is a Corepack shim and package.json pins yarn@{pin_version}")
        return YarnExe(None, None, real, f"{found} is a Corepack shim and package.json does not pin yarn@1.x.y")
    return YarnExe(None, None, real, f"{found} is not inside a package whose package.json says which yarn it is")


class ClassicConfig(NamedTuple):
    problems: list            # what the rc files and the environment would do that is refused
    scripts_off: bool         # dependency and root lifecycle scripts are proven off
    scripts_reason: str       # how, or why not
    frozen: bool              # `--frozen-lockfile` is proven (flag or `--install.frozen-lockfile true`)
    frozen_reason: str


def yarn_classic_config(cwd, home, environ=None, command="install", flags=(), trust_rc=True,
                        untrusted_why="") -> ClassicConfig:
    """The effective Yarn Classic configuration for `command` run in `cwd`, computed in Yarn's
    own order (see the block comment above), not assumed. `flags` are the command line's own
    (`--ignore-scripts`, `--frozen-lockfile`): a flag beats every file.

    `trust_rc` is False when the `yarn` that will run is not known to be Yarn Classic: a Berry
    binary ignores every Classic rc key and environment variable, so only the two flags count
    (Berry rejects both and installs nothing). The rc files are still scanned for what they
    would redirect."""
    environ = os.environ if environ is None else environ
    problems, scripts_off, frozen = [], None, None
    args_order, option_order = _classic_rc_orders(cwd, home, environ)
    loaded = {}
    for path in dict.fromkeys(args_order + option_order):
        try:
            data = _classic_rc_read(path)
        except ConfigError as exc:
            problems.append(f"{exc}; Package Guard reads only plain `key value` lines in a .yarnrc")
            loaded[path] = None
            continue
        if data is None:
            continue
        loaded[path] = data
        for key, value in data.items():
            reason = _classic_key_problem(key, value)
            if path.name.endswith(".yml"):
                # Yarn reads only `--` flag keys and `yarnPath` from a .yarnrc.yml in Classic mode.
                reason = reason if key.startswith("--") or key in ("yarnPath", "yarn-path") else None
            if reason:
                problems.append(f"{path}: `{key}` {reason}")

    def args_value(name):
        found, seen = None, False
        for path in args_order:
            data = loaded.get(path)
            if not data:
                continue
            for key in (f"--{name}", f"--{command}.{name}"):
                if key in data:
                    found, seen = data[key], True
        return found if seen else None

    # scripts: the flag (command line, or a `--[command.]ignore-scripts true` rc key) OR the
    # option (the environment over the first rc file that sets it).
    env_scripts = next((v for n, v in environ.items() if n.upper() == "YARN_IGNORE_SCRIPTS"), None)
    option = None
    if env_scripts is not None:
        option = str(env_scripts).strip().lower() == "true"
    else:
        for path in option_order:
            data = loaded.get(path)
            if data and "ignore-scripts" in data:
                option = data["ignore-scripts"] is True
                break
    if "--ignore-scripts" in flags:
        scripts_off, scripts_why = True, "the command carries --ignore-scripts"
    elif not trust_rc:
        scripts_off, scripts_why = False, (
            f"{untrusted_why}, so no .yarnrc or YARN_ variable can be counted: only a "
            "--ignore-scripts on the command does")
    elif args_value("ignore-scripts") is True:
        scripts_off, scripts_why = True, "a .yarnrc presets `--ignore-scripts true` for this command"
    elif option:
        scripts_off, scripts_why = True, (
            "YARN_IGNORE_SCRIPTS=true" if env_scripts is not None else "a .yarnrc sets `ignore-scripts true`")
    else:
        scripts_off = False
        scripts_why = ("YARN_IGNORE_SCRIPTS is set to something other than true, which beats every "
                       ".yarnrc" if env_scripts is not None else
                       "neither the command nor the .yarnrc files Yarn reads turn scripts off")
    if "--frozen-lockfile" in flags:
        frozen, frozen_why = True, "the command carries --frozen-lockfile"
    elif not trust_rc:
        frozen, frozen_why = False, (
            f"{untrusted_why}, so no .yarnrc can be counted: only a --frozen-lockfile on the command does")
    elif args_value("frozen-lockfile") is True:
        frozen, frozen_why = True, "a .yarnrc presets `--install.frozen-lockfile true`"
    else:
        frozen, frozen_why = False, ("neither the command nor the .yarnrc files Yarn reads freeze the "
                                     "lockfile (a bare `frozen-lockfile true` key is ignored by Yarn)")
    return ClassicConfig(problems, scripts_off, scripts_why, frozen, frozen_why)


# ---------------------------------------------------------------------------
# Environment (the process's own, at hook time)
# ---------------------------------------------------------------------------

# The families the hook's own environment is read against. Both of pnpm's
# prefixes, as `recognition.json` lists them for the installer; Bun and Yarn
# read only their own (the table's `npm-unread` family would refuse every
# `npm_config_*` name npm itself exports into a session, which a command's own
# prefix never does).
_ENV_FAMILY = {"pnpm": "pnpm", "bun": "bun", "yarn": "yarn"}


def _default_homes(home, environ):
    xdg = environ.get("XDG_DATA_HOME")
    return {"BUN_INSTALL": {str(Path(home) / ".bun")},
            "PNPM_HOME": {str(Path(home) / "Library" / "pnpm"),
                          str(Path(home) / ".local" / "share" / "pnpm"),
                          *([str(Path(xdg) / "pnpm")] if xdg else [])}}


def env_value_allows(family, category, name, value) -> bool:
    """Whether a name the family table refuses is allowed by its VALUE: Yarn by
    the rc rule, pnpm and Bun when a source variable names the official
    registry (the same rule as a `registry=` line in .npmrc). Used by the
    parser's command-prefix check and by the hook-time check below, so the two
    cannot drift."""
    if family == "yarn":
        return yarn_env_problem(name, value) is None
    if family == "corepack":
        # The one Corepack setting most developers export: off keeps it from writing a pin.
        return name.upper() == "COREPACK_ENABLE_AUTO_PIN" and str(value).strip() in ("0", "false")
    return category == "source" and protocols.is_official_registry(value)


def env_problems(kind, environ, home) -> list:
    """The family table the parser checks command-prefix variables against
    (`verbs.classify_env`), applied to the environment the hook itself runs in.
    `BUN_INSTALL` and `PNPM_HOME` are in nearly every developer's profile: they
    pass at their default places. Only the hook's own process environment is
    visible: a variable a later `export` in the shell sets is the parser's."""
    problems = []
    if kind in ("pnpm", "yarn"):
        # Corepack downloads and runs the pinned release: a variable that redirects it, changes
        # whose signatures count or turns off the pin check defeats the review of that pin (A3).
        for name, value in sorted(environ.items()):
            category = verbs.classify_env("corepack", name, shared=False)
            if category in (None, "allow", "locked") or env_value_allows("corepack", category, name, value):
                continue
            problems.append(f"environment: {name} {verbs.env_reason('corepack', category, name)}")
    if kind == "yarn":
        for name, value in sorted(environ.items()):
            reason = yarn_env_problem(name, value, home)
            if reason:
                problems.append(f"environment: {name} {reason}")
        return problems
    family = _ENV_FAMILY[kind]
    defaults = _default_homes(home, environ)
    for name, value in sorted(environ.items()):
        category = verbs.classify_env(family, name, shared=False)
        if category in (None, "allow", "locked"):
            continue
        if value in defaults.get(name.upper(), ()):
            continue
        if env_value_allows(family, category, name, value):
            continue
        problems.append(f"environment: {name} {verbs.env_reason(family, category, name)}")
    if kind == "pnpm":
        # pnpm reads npm_config_* by the same rules as .npmrc: the settings that
        # move a directory or load code, which the family table has no name for.
        for name, value in sorted(environ.items()):
            for prefix in ("pnpm_config_", "npm_config_"):
                if name.lower().startswith(prefix):
                    key = name[len(prefix):].replace("_", "-").lower()
                    reason = _pnpm_rc_key_problem(key, value, registry=False)
                    if reason:
                        problems.append(f"environment: {name} {reason}")
    return problems


# ---------------------------------------------------------------------------
# .npmrc and pnpm's own rc files
# ---------------------------------------------------------------------------

# Settings that move a directory reconciliation reads, or load code or packages
# before resolution. Any value is refused: the default is not knowable here. These are
# named so the refusal says why; every key NOT in `_PNPM_RC_BENIGN` is refused anyway.
_PNPM_RC_REFUSED = {
    "store-dir", "virtual-store-dir", "modules-dir", "global-dir", "cache-dir", "state-dir",
    "global-bin-dir", "pnpmfile", "global-pnpmfile", "config-dependencies", "package-extensions",
    "patched-dependencies",
}
# Keys the pnpm `.npmrc` / rc files may carry (Q14, v1.10.0 hardening A8): an ALLOW-LIST, as
# every other configuration file here is. A key that is not listed is refused naming the key
# and the file, because pnpm reads far more from an rc file than any deny-list can follow
# (`use-node-version` and `node-mirror:*` download a Node runtime, `script-shell` picks the
# shell scripts run in, `https-proxy` / `cafile` / `strict-ssl` reroute or re-trust every
# download, `store-dir` moves the content store reconciliation reads). These have no effect
# on what is fetched, run, or where it lands:
#   display and network tuning  loglevel reporter color progress use-stderr fund audit
#                               update-notifier fetch-* network-concurrency child-concurrency
#                               prefer-offline prefer-online offline maxsockets
#   resolution and layout       auto-install-peers strict-peer-dependencies dedupe-peer-dependents
#                               shamefully-hoist hoist hoist-pattern public-hoist-pattern
#                               hoist-workspace-packages node-linker (hoisted|isolated)
#                               package-import-method symlink resolution-mode lockfile
#                               prefer-frozen-lockfile frozen-lockfile merge-git-branch-lockfiles
#                               save-exact save-prefix engine-strict sort
#   scripts                     ignore-scripts enable-pre-post-scripts foreground-scripts
#                               (their effect is the lifecycle check's) and the build
#                               allow-lists `only-built-dependencies[]` and friends, whose
#                               content `pnpm_build_settings` reads
#   safety settings             side-effects-cache verify-store-integrity (never weakened by a
#                               listed value: `false` is refused) enable-global-virtual-store
#                               (false only) verify-deps-before-run (off only)
#   registry                    registry and `@scope:registry` (official only), and the
#                               per-registry CREDENTIAL keys `//host/:_authToken`, `:_auth`,
#                               `:username`, `:_password`, `:always-auth`, `:email`. The other
#                               `//host/:` keys are refused: `:tokenHelper` names a program
#                               pnpm runs, and `:cafile` / `:certfile` / `:keyfile` re-trust
#                               the registry
#   lockfile                    `lockfile` only as true (false makes pnpm resolve from the
#                               manifest's ranges and ignore the lock that was reviewed).
#                               `merge-git-branch-lockfiles` is not listed: it reads
#                               `pnpm-lock.<branch>.yaml` files nothing here reads
#   npm leftovers               init-* email always-auth legacy-peer-deps bin-links
#                               install-links yes save-prefix
_PNPM_RC_BENIGN = frozenset({
    "loglevel", "reporter", "color", "progress", "use-stderr", "fund", "audit", "update-notifier",
    "network-concurrency", "child-concurrency", "prefer-offline", "prefer-online", "offline",
    "maxsockets", "auto-install-peers", "strict-peer-dependencies", "dedupe-peer-dependents",
    "shamefully-hoist", "hoist", "hoist-pattern", "public-hoist-pattern",
    "hoist-workspace-packages", "package-import-method", "symlink", "resolution-mode",
    "lockfile", "prefer-frozen-lockfile", "frozen-lockfile",
    "save-exact", "save-prefix", "engine-strict", "sort", "ignore-scripts",
    "enable-pre-post-scripts", "foreground-scripts", "side-effects-cache",
    "only-built-dependencies", "never-built-dependencies", "ignored-built-dependencies",
    "dangerously-allow-all-builds", "minimum-release-age", "email", "always-auth",
    "legacy-peer-deps", "bin-links", "install-links", "yes",
    "node-linker", "enable-global-virtual-store", "verify-deps-before-run",
    "verify-store-integrity", "registry",
})
_PNPM_RC_BENIGN_PREFIXES = ("fetch-", "init-", "allow-builds", "only-built-dependencies")
_PNPM_RC_CREDENTIAL_SUFFIXES = (":_authtoken", ":_auth", ":username", ":_password",
                                ":always-auth", ":email")
# What a hook-time `npm_config_*` / `pnpm_config_*` VARIABLE may not set. An environment that
# npm launched exports dozens of unrelated `npm_config_*` names, so the variables stay a
# deny-list (the refused keys above, and these).
_PNPM_ENV_REFUSED = {
    "use-node-version", "script-shell", "https-proxy", "proxy", "noproxy", "cafile", "ca",
    "cert", "key", "strict-ssl", "node-mirror", "shell-emulator", "manage-package-manager-versions",
}


def _rc_lines(path: Path):
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            # pnpm reads a bare key as boolean true (v1.10.0 hardening):
            # `dangerously-allow-all-builds` alone turns every build on.
            out.append((line.lower(), "true"))
            continue
        key, _, value = line.partition("=")
        out.append((key.strip().lower(), value.strip()))
    return out


def _pnpm_global_dirs(home, environ) -> list:
    home = Path(home)
    dirs = [home / ".config" / "pnpm", home / "Library" / "Preferences" / "pnpm",
            home / "AppData" / "Local" / "pnpm" / "config"]
    xdg = environ.get("XDG_CONFIG_HOME")
    if xdg:
        dirs.append(Path(xdg) / "pnpm")
    return list(dict.fromkeys(dirs))


def pnpm_rc_problems(directory, home, environ) -> list:
    """`.npmrc` in the project and every parent (pnpm reads the workspace
    root's), and pnpm's own global rc: a redirect, a moved inventory root, a
    pnpmfile, or any key not on the allow-list (`_PNPM_RC_BENIGN`). The registry is also
    checked for `.npmrc` by `sources`; the reasons are worded alike so they merge."""
    paths = [p / ".npmrc" for p in _ancestors(directory)]
    # The user's ~/.npmrc applies to a project outside $HOME too, as in
    # `pnpm_build_settings` (v1.10.0 hardening).
    paths.append(Path(home) / ".npmrc")
    paths += [d / "rc" for d in _pnpm_global_dirs(home, environ)]
    problems = []
    for path in _distinct(paths):
        for key, value in _rc_lines(path):
            reason = _pnpm_rc_key_problem(key, value, file_rule=True)
            if reason:
                shown = "=" + _redact(value) if "registry" in key else ""
                problems.append(f"{path}: `{key}{shown}` {reason}")
    return problems


def _pnpm_rc_key_problem(key, value, registry=True, file_rule=False):
    """Why one pnpm/npm setting is refused, or None. `file_rule` is True for a line of an
    rc file, which is judged against the allow-list; False for a hook-time `npm_config_*`
    / `pnpm_config_*` variable, which is judged against the deny-list (`registry=False`
    leaves its registry to `npm_config_problems`)."""
    if key == "registry" or key.endswith(":registry"):
        if registry and not protocols.is_official_registry(value):
            return "redirects npm"
        return None  # a variable's registry is `npm_config_problems`'
    if key in _PNPM_RC_REFUSED:
        return "moves a directory or loads code that Package Guard cannot check"
    if key == "node-linker" and value not in ("hoisted", "isolated"):
        return "is not supported (hoisted or isolated only)"
    if key == "enable-global-virtual-store" and str(value).lower() == "true":
        return "keeps files where Package Guard cannot see them"
    if key == "verify-deps-before-run" and str(value).lower() not in ("false", "off"):
        return "may install on run; set it off"
    if key == "verify-store-integrity" and str(value).lower() == "false":
        return "turns off the check on what the store holds"
    if key == "lockfile" and str(value).lower() != "true":
        return "makes pnpm ignore the lock that was reviewed and resolve from the manifest"
    if not file_rule:
        if key in _PNPM_ENV_REFUSED or key.startswith("node-mirror"):
            return "changes where pnpm downloads from, what it trusts or which shell runs scripts"
        return None
    bare = key.removesuffix("[]")
    if key.startswith("//"):
        if key.endswith(_PNPM_RC_CREDENTIAL_SUFFIXES):
            return None
        return ("is a per-registry setting that is not a credential (`:tokenHelper` runs a "
                "program, `:cafile` / `:certfile` / `:keyfile` change what is trusted)")
    if bare in _PNPM_RC_BENIGN or bare.startswith(_PNPM_RC_BENIGN_PREFIXES):
        return None
    return ("is not a setting Package Guard knows to be safe (a downloaded Node runtime, "
            "another shell, a proxy or CA, a moved directory: any of these changes what "
            "pnpm fetches, trusts or runs); the human removes it or has it reviewed")


# ---------------------------------------------------------------------------
# pnpm: pnpm-workspace.yaml, package.json `pnpm`, config.yaml
# ---------------------------------------------------------------------------

_PNPM_BENIGN = frozenset({
    "autoInstallPeers", "strictPeerDependencies", "shamefullyHoist", "hoistPattern",
    "publicHoistPattern", "dedupePeerDependents", "savePrefix", "preferFrozenLockfile",
    "frozenLockfile", "ignoreScripts", "minimumReleaseAge", "preferOffline", "offline",
    "engineStrict", "resolutionMode", "saveExact", "enablePrePostScripts", "reporter",
})
# Their CONTENT is the lifecycle check's (P4); the keys are allowed here.
_PNPM_BUILD_KEYS = frozenset({
    "onlyBuiltDependencies", "neverBuiltDependencies", "ignoredBuiltDependencies",
    "allowBuilds", "dangerouslyAllowAllBuilds",
})
_PNPM_PATH_KEYS = frozenset({
    "storeDir", "virtualStoreDir", "modulesDir", "globalDir", "cacheDir", "stateDir",
    "globalBinDir", "pnpmfile", "globalPnpmfile",
})
_PNPM_NONEMPTY_REFUSED = {
    "packages": "declares workspace packages (workspaces are not supported)",
    "packageExtensions": "adds dependencies to reviewed packages that no review saw",
    "patchedDependencies": "applies local code to installed packages",
    "configDependencies": "fetches packages before resolution",
    "minimumReleaseAgeExclude": "exempts packages from the minimum-age gate",
    "updateConfig": "can rewrite what is fetched",
}


def pnpm_settings_problems(table, where, spec_problem=None) -> list:
    """Reasons for one pnpm settings table (pnpm-workspace.yaml, package.json
    `pnpm`, config.yaml). Unknown keys are refused by name."""
    if not isinstance(table, dict):
        return [f"{where}: is not a mapping"]
    problems = []
    for key, value in table.items():
        if key in _PNPM_NONEMPTY_REFUSED:
            if not _empty(value):
                problems.append(f"{where}: `{key}` {_PNPM_NONEMPTY_REFUSED[key]}")
        elif key in _PNPM_PATH_KEYS:
            problems.append(f"{where}: `{key}` moves a directory or loads code that Package "
                            "Guard cannot check")
        elif key == "registry" or key.endswith(":registry"):
            if not protocols.is_official_registry(value):
                problems.append(f"{where}: `{key}` is {_redact(value)!r}; only the default "
                                "registry is supported")
        elif key == "registries":
            if not _empty(value):
                problems.append(f"{where}: `registries` redirects npm")
        elif key == "nodeLinker":
            if value not in ("hoisted", "isolated"):
                problems.append(f"{where}: `nodeLinker` is {value!r}; hoisted or isolated only")
        elif key == "enableGlobalVirtualStore":
            if value is not False:
                problems.append(f"{where}: `enableGlobalVirtualStore` keeps files where Package "
                                "Guard cannot see them")
        elif key == "verifyDepsBeforeRun":
            if value not in (False, "off", "false"):
                problems.append(f"{where}: `verifyDepsBeforeRun` may install on run; set it off")
        elif key == "overrides":
            if isinstance(value, dict) and spec_problem:
                for name, spec in value.items():
                    problem = spec_problem(name, spec)
                    if problem:
                        problems.append(f"{where}: overrides: {problem}")
            elif not isinstance(value, dict) and not _empty(value):
                problems.append(f"{where}: `overrides` is not a mapping")
        elif key in _PNPM_BUILD_KEYS or key in _PNPM_BENIGN:
            pass
        else:
            problems.append(f"{where}: `{key}` is not a setting Package Guard knows to be safe")
    return problems


def pnpm_config_problems(directory, home, environ, spec_problem=None) -> list:
    problems = pnpm_rc_problems(directory, home, environ)
    for parent in _ancestors(directory):
        for name in (".pnpmfile.cjs", ".pnpmfile.mjs"):
            if (parent / name).is_file():
                problems.append(f"{parent / name}: a pnpmfile runs code on install (and can "
                                "rewrite registries); --ignore-scripts does not stop it")
        workspace = parent / "pnpm-workspace.yaml"
        if workspace.is_file():
            try:
                problems += pnpm_settings_problems(_read_yaml(workspace), str(workspace), spec_problem)
            except ConfigError as exc:
                problems.append(f"{exc}; Package Guard reads only plain `key: value` settings")
    for directory_ in _pnpm_global_dirs(home, environ):
        path = directory_ / "config.yaml"
        if path.is_file():
            try:
                problems += pnpm_settings_problems(_read_yaml(path), str(path), spec_problem)
            except ConfigError as exc:
                problems.append(f"{exc}; Package Guard reads only plain `key: value` settings")
    package = _package_json(directory)
    if isinstance(package, dict) and "pnpm" in package:
        problems += pnpm_settings_problems(package["pnpm"], "package.json `pnpm`", spec_problem)
    if isinstance(package, dict):
        problems += pnpm_runtime_problems(package)
    return problems


def pnpm_runtime_problems(package) -> list:
    """`devEngines.runtime` / `engines.runtime` with an `onFail` that makes pnpm download a
    Node (or other) runtime: code fetched and run before any review (A8). Only an absent
    `onFail`, `ignore`, `warn` and `error` leave the runtime alone."""
    problems = []
    for field in ("devEngines", "engines"):
        table = package.get(field)
        if not isinstance(table, dict) or "runtime" not in table:
            continue
        where = f"package.json `{field}.runtime`"
        entries = table["runtime"]
        for entry in entries if isinstance(entries, list) else [entries]:
            if not isinstance(entry, dict):
                problems.append(f"{where} is not an object or a list of objects")
                continue
            onfail = entry.get("onFail")
            if onfail is not None and onfail not in ("ignore", "warn", "error"):
                name = entry.get("name")
                problems.append(
                    f"{where}{f' ({name})' if isinstance(name, str) else ''}: `onFail: "
                    f"{_redact(str(onfail))}` makes pnpm download a runtime and run it before "
                    "any review; only an absent onFail, ignore, warn or error is supported")
    return problems


def _package_json(directory):
    try:
        return json.loads((Path(directory) / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


# ---------------------------------------------------------------------------
# Dependency build scripts, as each manager's configuration allows them (P4)
# ---------------------------------------------------------------------------

_BUILD_NAME = re.compile(
    r"^(?P<name>(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*)(?:@[0-9A-Za-z.+\-]+)?$",
    re.IGNORECASE)


class PnpmBuildSettings:
    """What pnpm's configuration says about dependency build scripts.

    `allow` is None when no source sets an explicit allow-list
    (`onlyBuiltDependencies` or `allowBuilds`); otherwise the set of package
    names every source allows together (a union: the strictest reading). `never`
    is True when `neverBuiltDependencies` is set anywhere, `danger` when
    `dangerouslyAllowAllBuilds` is truthy anywhere. `bad` names what could not
    be read."""

    def __init__(self):
        self.allow = None
        self.never = False
        self.danger = False
        self.bad = []

    def _names(self, values, where, key):
        if not isinstance(values, (list, tuple)) or not all(isinstance(v, str) for v in values):
            self.bad.append(f"{where}: `{key}` is not a list of package names")
            return
        self.allow = (self.allow or set())
        for value in values:
            self._add(value, where, key)

    def _add(self, value, where, key):
        match = _BUILD_NAME.match(value)
        if match is None:
            self.bad.append(f"{where}: `{key}` entry {_redact(value)!r} is not a plain package name")
        else:
            self.allow.add(match.group("name").lower())

    def table(self, table, where):
        if not isinstance(table, dict):
            return
        if "onlyBuiltDependencies" in table:
            self._names(table["onlyBuiltDependencies"], where, "onlyBuiltDependencies")
        if "allowBuilds" in table:
            value = table["allowBuilds"]
            if not isinstance(value, dict):
                self.bad.append(f"{where}: `allowBuilds` is not a mapping")
            else:
                self.allow = self.allow or set()
                for name, flag in value.items():
                    if flag in (True, "true"):
                        self._add(str(name), where, "allowBuilds")
                    elif flag not in (False, "false"):
                        self.bad.append(f"{where}: `allowBuilds.{name}` is not true or false")
        if "neverBuiltDependencies" in table:
            self.never = True
        flag = table.get("dangerouslyAllowAllBuilds")
        if flag not in (None, False, "false"):
            self.danger = True


def pnpm_build_settings(directory, home, environ=None) -> PnpmBuildSettings:
    """Every place pnpm reads a build-script setting from: package.json `pnpm`,
    `pnpm-workspace.yaml` in the project and each parent, pnpm's global
    `config.yaml`, and `.npmrc` / pnpm's global rc."""
    environ = os.environ if environ is None else environ
    found = PnpmBuildSettings()
    package = _package_json(directory)
    if isinstance(package, dict) and "pnpm" in package:
        found.table(package["pnpm"], "package.json `pnpm`")
    paths = [parent / "pnpm-workspace.yaml" for parent in _ancestors(directory)]
    paths += [d / "config.yaml" for d in _pnpm_global_dirs(home, environ)]
    for path in paths:
        if path.is_file():
            try:
                found.table(_read_yaml(path), str(path))
            except ConfigError as exc:
                found.bad.append(str(exc))
    rcs = [p / ".npmrc" for p in _ancestors(directory)] + [
        d / "rc" for d in _pnpm_global_dirs(home, environ)]
    rcs.append(Path(home) / ".npmrc")
    for path in _distinct(rcs):
        for key, value in _rc_lines(path):
            bare = key.removesuffix("[]")
            if bare == "only-built-dependencies":
                found.allow = found.allow or set()
                found._add(value, str(path), key)
            elif bare == "never-built-dependencies":
                found.never = True
            elif bare == "dangerously-allow-all-builds":
                if value.lower() not in ("false", "0", ""):
                    found.danger = True
            elif bare.startswith("allow-builds") or bare == "only-built-dependencies-file":
                found.bad.append(f"{path}: `{key}` sets build permissions in a form Package "
                                 "Guard does not read")
    return found


def trusted_dependencies(directory):
    """package.json `trustedDependencies` (Bun): None when absent, else the list.
    Raises ConfigError for anything but a list of names."""
    data = _package_json(directory)
    if not isinstance(data, dict) or "trustedDependencies" not in data:
        return None
    value = data["trustedDependencies"]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError("package.json: trustedDependencies is not a list of package names")
    return list(value)


def yarn_scripts_disabled(directory, home, environ=None) -> bool:
    """True when Yarn's own configuration turns every script off
    (`enableScripts: false`, or YARN_ENABLE_SCRIPTS=false, which beats the files).
    Unreadable files read as False: the caller then keeps scripts on."""
    environ = os.environ if environ is None else environ
    for name, value in environ.items():
        if name.upper() == "YARN_ENABLE_SCRIPTS":
            return str(value).lower() in ("false", "0")
    try:
        files = yarn_rc(directory, home)
    except ConfigError:
        return False
    for _path, data in files:
        if "enableScripts" in data:
            return data["enableScripts"] in (False, "false")
    return False


# ---------------------------------------------------------------------------
# Bun: bunfig.toml
# ---------------------------------------------------------------------------

_BUN_TOP = frozenset({"install", "run", "test", "telemetry", "logLevel"})
_BUN_RUN = frozenset({"silent", "bun", "shell"})
_BUN_TEST = frozenset({"coverage", "coverageThreshold", "coverageReporter", "coverageDir",
                       "coverageSkipTestFiles", "timeout", "smol", "rerunEach", "randomize", "seed"})
_BUN_INSTALL_BENIGN = frozenset({"exact", "production", "frozenLockfile", "ignoreScripts",
                                 "minimumReleaseAge", "dev", "optional", "peer"})
_BUN_INSTALL_PATHS = frozenset({"globalDir", "globalBinDir", "linkerPaths"})


def _bunfig_paths(directory, home, environ) -> list:
    home = Path(home)
    paths = [Path(directory) / "bunfig.toml", Path(directory) / ".bunfig.toml",
             home / ".bunfig.toml", home / ".config" / ".bunfig.toml"]
    xdg = environ.get("XDG_CONFIG_HOME")
    if xdg:
        paths.append(Path(xdg) / ".bunfig.toml")
    return [p for p in dict.fromkeys(paths) if p.is_file()]


def bunfig_problems(table, where) -> list:
    problems = []
    for key, value in table.items():
        if key == "preload":
            if value:
                problems.append(f"{where}: `preload` runs code before every script and command")
        elif key not in _BUN_TOP:
            problems.append(f"{where}: `{key}` is not a setting Package Guard knows to be safe")
    run = table.get("run")
    if isinstance(run, dict):
        problems += [f"{where}: [run] `{k}` is not a setting Package Guard knows to be safe"
                     for k in run if k not in _BUN_RUN]
    test = table.get("test")
    if isinstance(test, dict):
        for key, value in test.items():
            if key == "preload":
                if value:
                    problems.append(f"{where}: [test] `preload` runs code before the tests")
            elif key not in _BUN_TEST:
                problems.append(f"{where}: [test] `{key}` is not a setting Package Guard knows to be safe")
    install = table.get("install")
    if isinstance(install, dict):
        problems += _bun_install_problems(install, where)
    elif install is not None:
        problems.append(f"{where}: [install] is not a table")
    return problems


def _bun_install_problems(install, where) -> list:
    problems = []
    for key, value in install.items():
        label = f"{where}: [install] `{key}`"
        if key in _BUN_INSTALL_BENIGN:
            continue
        if key == "registry":
            url = value.get("url") if isinstance(value, dict) else value
            if not protocols.is_official_registry(url) or (isinstance(value, dict) and set(value) - {"url"}):
                problems.append(f"{label} redirects npm or carries credentials")
        elif key == "scopes":
            if not _empty(value):
                problems.append(f"{label} redirects a scope to another registry")
        elif key == "linker":
            if value not in ("hoisted", "isolated"):
                problems.append(f"{label} is {value!r}; hoisted or isolated only")
        elif key == "auto":
            if value not in ("disable", "auto"):
                problems.append(f"{label} is {value!r}; it installs packages on run")
        elif key == "saveTextLockfile":
            if value is not True:
                problems.append(f"{label} must not be false: Bun would write the binary bun.lockb")
        elif key == "cache":
            if not isinstance(value, dict) or set(value) - {"disable", "disableManifest"}:
                problems.append(f"{label} moves the cache Package Guard reads")
        elif key == "security":
            if isinstance(value, dict) and value.get("scanner"):
                problems.append(f"{label}.scanner is an npm package executed during install")
            elif not isinstance(value, dict) or value:
                problems.append(f"{label} is not a setting Package Guard knows to be safe")
        elif key in _BUN_INSTALL_PATHS:
            problems.append(f"{label} moves a directory reconciliation reads")
        else:
            problems.append(f"{label} is not a setting Package Guard knows to be safe")
    return problems


def bun_auto_install_disabled(directory, home, environ=None) -> bool:
    """True when the nearest bunfig that sets `[install] auto` sets "disable":
    Bun then never installs at run time. Anything unreadable reads as False."""
    environ = os.environ if environ is None else environ
    for path in _bunfig_paths(directory, home, environ):
        try:
            with path.open("rb") as handle:
                table = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            return False
        install = table.get("install")
        if isinstance(install, dict) and "auto" in install:
            return install["auto"] == "disable"
    return False


def bun_config_problems(directory, home, environ) -> list:
    problems = []
    for path in _bunfig_paths(directory, home, environ):
        try:
            with path.open("rb") as handle:
                table = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
            problems.append(f"{path}: cannot be read as TOML")
            continue
        problems += bunfig_problems(table, str(path))
    return problems


# ---------------------------------------------------------------------------
# package.json fields only these managers read
# ---------------------------------------------------------------------------

def package_json_problems(kind, directory, spec_problem) -> list:
    """`resolutions` (Yarn, pnpm and Bun all honour it) and Bun's top-level
    `patchedDependencies`: the same spec rules as `overrides`."""
    data = _package_json(directory)
    if not isinstance(data, dict):
        return []
    problems = []
    resolutions = data.get("resolutions")
    if isinstance(resolutions, dict):
        for name, spec in resolutions.items():
            problem = spec_problem(name, spec)
            if problem:
                problems.append(f"{problem} (resolutions)")
    if kind == "bun" and not _empty(data.get("patchedDependencies")):
        problems.append("package.json: patchedDependencies applies local code to installed packages")
    return problems


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def pm_config_problems(kind, directory, home, environ, spec_problem=None, require_linker=True) -> list:
    """Every reason a pnpm, Bun or Yarn command run in `directory` would fetch
    from, run, or install somewhere Package Guard did not check."""
    problems = env_problems(kind, environ, home)
    if kind == "yarn":
        flavour = yarn_flavour(directory)
        if flavour.kind == CLASSIC and flavour.conflict is None:
            problems += yarn_classic_config(directory, home, environ).problems
        else:
            problems += yarn_config_problems(directory, home, environ, require_linker)
    elif kind == "bun":
        problems += bun_config_problems(directory, home, environ)
    elif kind == "pnpm":
        problems += pnpm_config_problems(directory, home, environ, spec_problem)
    if spec_problem is not None:
        problems += package_json_problems(kind, directory, spec_problem)
    return problems
