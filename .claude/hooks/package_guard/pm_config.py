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

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path

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
        problems += yarn_config_problems(directory, home, environ, require_linker)
    elif kind == "bun":
        problems += bun_config_problems(directory, home, environ)
    elif kind == "pnpm":
        problems += pnpm_config_problems(directory, home, environ, spec_problem)
    if spec_problem is not None:
        problems += package_json_problems(kind, directory, spec_problem)
    return problems
