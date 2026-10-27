"""What is actually installed, read off the filesystem. No policy.

The PreToolUse gate reads a Bash command and decides whether it acquires
packages. That is a decision about text, and it is incomplete by construction:
`npm run serve` runs `npx serve` out of package.json and `uv sync 2>&1 | tail`
installs a whole locked project through a pipe. This module is the
input to the layer that does not read commands at all -- it reads directories.

Every reader here answers one question ("what is installed, at what version,
where") and answers nothing else. It does not know what `vetted.json` is, does
not read a manifest, and never decides that anything is a problem. That split
is what lets `disk_guard` be tested without a filesystem and this module be
tested without any guard state.

Every global root is a PARAMETER with a module-level default.
`~/.npm/_npx` and `~/.cache/uv` are machine-global and already hold packages
from unrelated projects; a reader that looked them up internally could only be
tested against whatever the developer happened to have installed.

Standard library only.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest as pg_manifest  # noqa: E402

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org"

# Machine-global roots. Overridable per call so the tests are hermetic.
#
# These must follow the env vars npm and uv actually honour, not just the
# defaults. _iter_dirs() returns [] on OSError, so a root that has moved is
# indistinguishable from a root that is empty: the scan reports clean and the
# reconciliation layer goes blind, silently. XDG_CACHE_HOME is common on Linux,
# which makes this a same-OS failure rather than a theoretical one.
def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value) if value else default


_XDG_DATA_HOME = _env_path("XDG_DATA_HOME", Path.home() / ".local" / "share")
_XDG_CACHE_HOME = _env_path("XDG_CACHE_HOME", Path.home() / ".cache")

NPX_CACHE_ROOT = _env_path("npm_config_cache", Path.home() / ".npm") / "_npx"
UV_TOOLS_ROOT = _env_path("UV_TOOL_DIR", _XDG_DATA_HOME / "uv" / "tools")
UV_ENVIRONMENTS_ROOT = _env_path("UV_CACHE_DIR", _XDG_CACHE_HOME / "uv") / "environments-v2"

# Sources, in the order a finding renders them. Mirrored by the `source` enum
# in disk-findings.schema.json.
NODE_MODULES = "node_modules"
NPX_CACHE = "npx-cache"
VENV = "venv"
UV_TOOL = "uv-tool"
UVX_ENV = "uvx-env"
# pnpm, Bun and Yarn Berry. The caches are content stores: a package in one was
# FETCHED, not installed, and `yarn install --mode=update-lockfile` fetches into
# the Yarn cache without linking anything, which is the reason they are read.
PNPM_STORE = "pnpm-store"              # machine-global content-addressed index files
PNPM_DLX = "pnpm-dlx"                  # machine-global `pnpm dlx` projects
BUN_CACHE = "bun-cache"                # machine-global ~/.bun/install/cache
BUNX_CACHE = "bunx-cache"              # machine-global `bunx-<uid>-<spec>` temp projects
YARN_CACHE = "yarn-cache"              # machine-global ~/.yarn/berry/cache
YARN_LOCAL_CACHE = "yarn-local-cache"  # a project's own .yarn/cache

# The `version` of an entry whose name or version could not be decoded. It is
# never a real version, so no approval can match it: such an entry stays a
# finding until it is removed (fail closed), and the CLI opens no review of it.
UNIDENTIFIED = "unidentified"


# Every layout below is read from documentation and source, NOT from a machine
# with the manager installed (the guard never runs them). Where a layout is a
# best guess it is marked UNVERIFIED.
def pnpm_home_default(platform=None, env=None, home=None) -> Path:
    """`$PNPM_HOME`, else the per-OS default (macOS ~/Library/pnpm, Windows
    %LOCALAPPDATA%/pnpm, otherwise $XDG_DATA_HOME/pnpm)."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    if env.get("PNPM_HOME"):
        return Path(env["PNPM_HOME"])
    if platform == "win32":
        return Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local") / "pnpm"
    if platform == "darwin":
        return home / "Library" / "pnpm"
    return Path(env.get("XDG_DATA_HOME") or home / ".local" / "share") / "pnpm"


def pnpm_store_default(platform=None, env=None, home=None) -> Path:
    """The pnpm store directory (the one that holds `v10/`)."""
    env = os.environ if env is None else env
    for key in ("PNPM_STORE_DIR", "npm_config_store_dir"):
        if env.get(key):
            return Path(env[key])
    return pnpm_home_default(platform, env, home) / "store"


def pnpm_mount_stores(directory) -> list:
    """The store pnpm falls back to when the project is on another filesystem than the
    home store: `<mount point of the project>/.pnpm-store` (it holds `v10/`, like the
    default store). Hard links cannot cross filesystems, so pnpm writes there instead of
    under `$PNPM_HOME`; without this a project on a mounted volume fetches into a store
    nothing reads (v1.10.0 hardening, B5). `store-dir` is not read: the pnpm
    configuration check refuses it, so the store cannot have been moved by a setting."""
    path = Path(os.path.realpath(directory))
    while not os.path.ismount(path) and path != path.parent:
        path = path.parent
    return [path / ".pnpm-store"]


def pnpm_dlx_default(platform=None, env=None, home=None) -> Path:
    """The `pnpm dlx` cache (UNVERIFIED layout: <cache>/dlx/<hash>/<id>/)."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    if platform == "win32":
        base = Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local") / "pnpm-cache"
    elif platform == "darwin":
        base = home / "Library" / "Caches" / "pnpm"
    else:
        base = Path(env.get("XDG_CACHE_HOME") or home / ".cache") / "pnpm"
    return base / "dlx"


def bun_cache_default(env=None, home=None) -> Path:
    """`$BUN_INSTALL_CACHE_DIR`, else `$BUN_INSTALL/install/cache`, else ~/.bun/..."""
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    if env.get("BUN_INSTALL_CACHE_DIR"):
        return Path(env["BUN_INSTALL_CACHE_DIR"])
    return Path(env.get("BUN_INSTALL") or home / ".bun") / "install" / "cache"


def bunx_tmp_default(env=None) -> Path:
    """Where `bunx-<uid>-<spec>` temp projects live (UNVERIFIED on Windows)."""
    env = os.environ if env is None else env
    return Path(env.get("BUN_TMPDIR") or env.get("TMPDIR") or tempfile.gettempdir())


def yarn_global_cache_default(platform=None, env=None, home=None) -> Path:
    """`$YARN_GLOBAL_FOLDER/cache`, else Berry's default global folder
    (~/.yarn/berry, Windows %LOCALAPPDATA%/Yarn/Berry) plus `cache`."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    if env.get("YARN_GLOBAL_FOLDER"):
        return Path(env["YARN_GLOBAL_FOLDER"]) / "cache"
    if platform == "win32":
        return Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local") / "Yarn" / "Berry" / "cache"
    return home / ".yarn" / "berry" / "cache"


PNPM_STORE_ROOT = pnpm_store_default()
PNPM_DLX_ROOT = pnpm_dlx_default()
BUN_CACHE_ROOT = bun_cache_default()
BUNX_TMP_ROOT = bunx_tmp_default()
YARN_GLOBAL_CACHE_ROOT = yarn_global_cache_default()
# pnpm, Bun and Yarn Berry. The caches are content stores: a package in one was
# FETCHED, not installed, and `yarn install --mode=update-lockfile` fetches into
# the Yarn cache without linking anything, which is the whole reason they are read.
PNPM_STORE = "pnpm-store"          # machine-global content-addressed index files
PNPM_DLX = "pnpm-dlx"              # machine-global `pnpm dlx` projects
BUN_CACHE = "bun-cache"            # machine-global ~/.bun/install/cache
BUNX_CACHE = "bunx-cache"          # machine-global `bunx-<uid>-<spec>` temp projects
YARN_CACHE = "yarn-cache"          # machine-global ~/.yarn/berry/cache
YARN_LOCAL_CACHE = "yarn-local-cache"  # a project's own .yarn/cache

# The `version` of an entry whose name or version could not be decoded. It is
# never a real version, so no approval can match it: such an entry stays a
# finding until it is removed (fail closed), and the CLI does not open a review
# of it.
UNIDENTIFIED = "unidentified"


# Every layout below is read from documentation and source, NOT from a machine
# with the manager installed (the guard never runs them). Where a layout is a
# best-known guess it is marked UNVERIFIED, and a reader that cannot decode an
# entry says so with a finding rather than skipping it, except where noted.
def pnpm_home_default(platform=None, env=None, home=None) -> Path:
    """`$PNPM_HOME`, else the per-OS default (macOS ~/Library/pnpm, Windows
    %LOCALAPPDATA%\\pnpm, otherwise $XDG_DATA_HOME/pnpm)."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    if env.get("PNPM_HOME"):
        return Path(env["PNPM_HOME"])
    if platform == "win32":
        return Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local") / "pnpm"
    if platform == "darwin":
        return home / "Library" / "pnpm"
    return Path(env.get("XDG_DATA_HOME") or home / ".local" / "share") / "pnpm"


def pnpm_store_default(platform=None, env=None, home=None) -> Path:
    """The pnpm store directory (the one that holds `v10/`)."""
    env = os.environ if env is None else env
    for key in ("PNPM_STORE_DIR", "npm_config_store_dir"):
        if env.get(key):
            return Path(env[key])
    return pnpm_home_default(platform, env, home) / "store"


def pnpm_dlx_default(platform=None, env=None, home=None) -> Path:
    """The `pnpm dlx` cache (UNVERIFIED layout: <cache>/dlx/<hash>/<id>/)."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    if platform == "win32":
        base = Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local") / "pnpm-cache"
    elif platform == "darwin":
        base = home / "Library" / "Caches" / "pnpm"
    else:
        base = Path(env.get("XDG_CACHE_HOME") or home / ".cache") / "pnpm"
    return base / "dlx"


def bun_cache_default(env=None, home=None) -> Path:
    """`$BUN_INSTALL_CACHE_DIR`, else `$BUN_INSTALL/install/cache`, else ~/.bun/..."""
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    if env.get("BUN_INSTALL_CACHE_DIR"):
        return Path(env["BUN_INSTALL_CACHE_DIR"])
    return Path(env.get("BUN_INSTALL") or home / ".bun") / "install" / "cache"


def bunx_tmp_default(env=None) -> Path:
    """Where `bunx-<uid>-<spec>` temp projects live (UNVERIFIED on Windows)."""
    env = os.environ if env is None else env
    return Path(env.get("BUN_TMPDIR") or env.get("TMPDIR") or tempfile.gettempdir())


def yarn_global_cache_default(platform=None, env=None, home=None) -> Path:
    """`$YARN_GLOBAL_FOLDER/cache`, else Berry's default global folder
    (~/.yarn/berry, Windows %LOCALAPPDATA%\\Yarn\\Berry) plus `cache`."""
    platform = platform or sys.platform
    env = os.environ if env is None else env
    home = Path.home() if home is None else Path(home)
    if env.get("YARN_GLOBAL_FOLDER"):
        return Path(env["YARN_GLOBAL_FOLDER"]) / "cache"
    if platform == "win32":
        return Path(env.get("LOCALAPPDATA") or home / "AppData" / "Local") / "Yarn" / "Berry" / "cache"
    return home / ".yarn" / "berry" / "cache"


PNPM_STORE_ROOT = pnpm_store_default()
PNPM_DLX_ROOT = pnpm_dlx_default()
BUN_CACHE_ROOT = bun_cache_default()
BUNX_TMP_ROOT = bunx_tmp_default()
YARN_GLOBAL_CACHE_ROOT = yarn_global_cache_default()


class Installed(NamedTuple):
    """One package found on disk.

    `path` is the directory whose mtime dates the install: the package
    directory for npm, the dist-info directory for Python. It is part of the
    watermark key, and it is what a removal command has to name.
    """

    source: str
    ecosystem: str
    name: str
    version: str
    path: str

    @property
    def identity(self) -> dict:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "registry": NPM_REGISTRY if self.ecosystem == "npm" else PYPI_REGISTRY,
        }


def _read_json(path: Path):
    """Parsed JSON, or None. A malformed file is a missing file here.

    A reader that raised would take down a hook over a half-written
    package.json in somebody's cache. The consequence of returning None is that
    one package goes unreported, which the next scan re-checks.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _mtime_ns(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def _changed_ns(path: Path) -> int | None:
    """The later of mtime and ctime, or None when the path cannot be stat-ed.

    `touch -t`, `cp -a`, `tar -p` and `os.utime` set the mtime to any date, but
    the kernel sets the ctime to now on each of them, and no unprivileged call
    on macOS or Linux sets it back.
    """
    try:
        info = path.stat()
    except OSError:
        return None
    return max(info.st_mtime_ns, info.st_ctime_ns)


def _iter_dirs(root: Path):
    """Immediate subdirectories of `root`, sorted. Empty when unreadable."""
    try:
        return sorted((p for p in root.iterdir() if p.is_dir()), key=lambda p: p.name)
    except OSError:
        return []


# ---------------------------------------------------------------------------
# npm: a project's node_modules
# ---------------------------------------------------------------------------

def node_modules_packages(project_dir) -> list:
    """Every package installed under `<project_dir>/node_modules`.

    This is the INSTALLED set, transitives included -- npm hoists, so a
    manifest declaring a handful of packages can leave dozens of directories.
    It is only ever the right-hand side of the reconciliation intersection;
    the direct set comes from the manifest.
    """
    root = Path(project_dir) / "node_modules"
    found = []
    for entry in _iter_dirs(root):
        if entry.name.startswith("."):
            continue  # .bin, .package-lock.json, .cache
        directories = _iter_dirs(entry) if entry.name.startswith("@") else [entry]
        for directory in directories:
            name = (
                f"{entry.name}/{directory.name}" if entry.name.startswith("@") else entry.name
            )
            data = _read_json(directory / "package.json")
            version = (data or {}).get("version")
            if not isinstance(version, str) or not version:
                continue
            found.append(Installed(NODE_MODULES, "npm", name, version, str(directory)))
    return found


# ---------------------------------------------------------------------------
# npx: the machine-global ephemeral cache
# ---------------------------------------------------------------------------

def npx_cache_packages(cache_root=None) -> list:
    """Every package the npx cache holds, one entry per <hash> directory.

    Names come from the entry's package.json `dependencies` KEYS. The values
    are semver ranges (`"serve": "^14.2.6"`) and must never be read as
    versions; the exact version comes from the sibling package-lock.json at
    packages["node_modules/<name>"].version.

    Only the named dependencies are reported. The lockfile also carries the
    transitive tree -- 100+ entries for `serve` -- and reporting those would be
    noise: only direct packages are findings.
    """
    root = Path(cache_root if cache_root is not None else NPX_CACHE_ROOT)
    found = []
    for entry in _iter_dirs(root):
        declared = _read_json(entry / "package.json") or {}
        names = declared.get("dependencies")
        if not isinstance(names, dict):
            continue
        lock = _read_json(entry / "package-lock.json") or {}
        packages = lock.get("packages")
        if not isinstance(packages, dict):
            continue
        for name in sorted(names):
            locked = packages.get(f"node_modules/{name}")
            version = (locked or {}).get("version")
            if not isinstance(version, str) or not version:
                continue  # no lockfile entry: never guess from the range
            installed = entry / "node_modules" / name
            if not installed.is_dir():
                # The entry's manifest outlives the package: removing the
                # package directory, as the removal advice says, leaves both
                # JSON files behind. Reporting from them alone would keep a
                # removed package's finding open forever.
                continue
            found.append(Installed(NPX_CACHE, "npm", name, version, str(installed)))
    return found


# ---------------------------------------------------------------------------
# Python environments
# ---------------------------------------------------------------------------

def site_packages_dirs(venv_dir) -> list:
    """Every site-packages directory in a virtual environment."""
    root = Path(venv_dir)
    if not root.is_dir():
        return []
    found = sorted(root.glob("lib/*/site-packages"))
    # Windows layout, harmless to check and cheap.
    windows = root / "Lib" / "site-packages"
    if windows.is_dir():
        found.append(windows)
    return [p for p in found if p.is_dir()]


def dist_info_packages(venv_dir, source=VENV) -> list:
    """Every distribution installed in a venv, from its dist-info directories.

    The name is normalised through manifest.normalize_py, the same function the
    manifest readers use, so `python_multipart-0.0.32.dist-info` matches the
    manifest's `python-multipart`.

    A `REQUESTED` marker inside a dist-info is deliberately NOT consulted: uv
    writes it for pure transitives, so it is not a direct-ness signal.
    Direct-ness comes from the manifest.
    """
    found = []
    for site in site_packages_dirs(venv_dir):
        for entry in _iter_dirs(site):
            if not entry.name.endswith(".dist-info"):
                continue
            stem = entry.name[: -len(".dist-info")]
            raw, sep, version = stem.partition("-")
            if not sep or not version:
                continue
            found.append(
                Installed(
                    source,
                    "pypi",
                    pg_manifest.normalize_py(raw),
                    version,
                    str(entry),
                )
            )
    return found


# ---------------------------------------------------------------------------
# uv tools: persistent, machine-global
# ---------------------------------------------------------------------------

def _receipt_requirement_names(receipt_path: Path) -> list:
    """`[tool].requirements[].name` from a uv-receipt.toml.

    Requirements carrying `git` or `editable` are not registry installs and are
    skipped: the gate denies those sources outright, so reporting them as
    reviewable packages would offer an approval that cannot exist.
    """
    import tomllib

    try:
        with receipt_path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        return []
    requirements = ((data.get("tool") or {}) if isinstance(data, dict) else {}).get(
        "requirements"
    )
    if not isinstance(requirements, list):
        return []
    names = []
    for item in requirements:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        if "git" in item or "editable" in item or "url" in item or "path" in item:
            continue
        names.append(pg_manifest.normalize_py(item["name"]))
    return names


def uv_tool_packages(tools_root=None) -> list:
    """Every package a `uv tool install` put on this machine, direct only.

    The receipt names what was asked for; the tool's own venv supplies the
    version. Machine-global, like the npx cache.
    """
    root = Path(tools_root if tools_root is not None else UV_TOOLS_ROOT)
    found = []
    for entry in _iter_dirs(root):
        wanted = set(_receipt_requirement_names(entry / "uv-receipt.toml"))
        if not wanted:
            continue
        for installed in dist_info_packages(entry, source=UV_TOOL):
            if installed.name in wanted:
                found.append(installed)
    return found


# ---------------------------------------------------------------------------
# uvx ephemeral environments
# ---------------------------------------------------------------------------

def uvx_environment_packages(environments_root=None) -> list:
    """Direct packages of each `uvx` environment, by the bin/ proxy.

    These environments carry NO receipt, so which package was asked for is
    unrecoverable from disk. The only proxy available is the console script: a
    distribution whose normalised name matches an executable in the
    environment's `bin/` is treated as the direct one.

    The proxy fails in a knowable way and the failure is specified rather than
    hidden: an environment created for a LIBRARY publishes no script, so
    nothing in it is ever reported. An environment holding only `pyyaml`, for
    example, yields no record.
    """
    root = Path(environments_root if environments_root is not None else UV_ENVIRONMENTS_ROOT)
    found = []
    for outer in _iter_dirs(root):
        for env in _iter_dirs(outer):
            scripts = set()
            try:
                scripts = {
                    pg_manifest.normalize_py(p.name)
                    for p in (env / "bin").iterdir()
                    if p.is_file()
                }
            except OSError:
                continue
            if not scripts:
                continue
            for installed in dist_info_packages(env, source=UVX_ENV):
                if installed.name in scripts:
                    found.append(installed)
    return found


# ---------------------------------------------------------------------------
# pnpm, Bun and Yarn Berry: project trees
# ---------------------------------------------------------------------------

def _scoped_dirs(root: Path):
    """(name, directory) for every package directly under a node_modules-shaped
    `root`, scoped packages included, dot entries skipped."""
    for entry in _iter_dirs(root):
        if entry.name.startswith("."):
            continue
        if entry.name.startswith("@"):
            for child in _iter_dirs(entry):
                yield f"{entry.name}/{child.name}", child
        else:
            yield entry.name, entry


def decode_isolated_entry(dirname: str):
    """(name, version) from a `.pnpm` or `.bun` entry name, or None.

    `@scope+pkg@1.0.0_react@18` -> ("@scope/pkg", "1.0.0"). The encoding is
    lossy (a `+` stands for `/`, `_` opens the peer suffix, long names are
    truncated with a hash), so this is only the FALLBACK for a version the
    package's own package.json does not give. A name never contains `@` past its
    first character, and a semver version never contains `_`.
    """
    at = dirname.find("@", 1)
    if at <= 0:
        return None
    name, rest = dirname[:at], dirname[at + 1:]
    version = rest.split("_", 1)[0]
    if name.startswith("@"):
        scope, plus, tail = name.partition("+")
        if not plus or not tail:
            return None
        name = f"{scope}/{tail}"
    if not name or not version:
        return None
    return name, version


def isolated_store_packages(project_dir, store_name) -> list:
    """The packages inside `node_modules/.pnpm` or `node_modules/.bun`.

    Each entry is `<name>@<ver>[_peers]/node_modules/<name>`. The NAME is the
    path under the entry's own node_modules (exact, never truncated) and the
    version is the package.json's; the directory name is decoded only when that
    file gives no version, and an entry neither can name is returned with the
    UNIDENTIFIED version (fail closed). Only the entry's own package is read:
    its siblings are symlinks to other entries.
    """
    root = Path(project_dir) / "node_modules" / store_name
    found = []
    for entry in _iter_dirs(root):
        if entry.name.startswith(".") or entry.name == "node_modules":
            continue  # `.pnpm/node_modules` is the private hoisting directory
        decoded = decode_isolated_entry(entry.name)
        for name, directory in _scoped_dirs(entry / "node_modules"):
            if directory.is_symlink():
                continue
            version = (_read_json(directory / "package.json") or {}).get("version")
            if not isinstance(version, str) or not version:
                version = decoded[1] if decoded and decoded[0] == name else UNIDENTIFIED
            found.append(Installed(NODE_MODULES, "npm", name, version, str(directory)))
    return found


def _state_locator(text: str):
    """(name, reference) from a state-file key `name@npm:1.2.3`, or None."""
    at = text.find("@", 1)
    if at <= 0 or at == len(text) - 1:
        return None
    return text[:at], text[at + 1:]


def parse_yarn_state(text: str):
    """{locator: [location, ...]} from a `.yarn-state.yml`, or None.

    A strict reader of the only shape Berry writes: `#` comments and blank
    lines, then top-level `"locator":` keys, each with a `locations:` list of
    quoted paths (and optionally an `aliases:` list). Anything else (flow
    syntax, anchors, a stray scalar, a tab) makes the whole file unreadable, and
    the caller then reads package.json files alone.
    """
    entries, current, section = {}, None, None
    for raw in text.replace("\r\n", "\n").split("\n"):
        if not raw.strip() or raw.startswith("#"):
            continue
        if "\t" in raw or raw != raw.rstrip():
            return None
        indent = len(raw) - len(raw.lstrip(" "))
        body = raw.strip()
        if indent == 0:
            if not body.endswith(":") or body.startswith(("-", "&", "*", "{", "[", "!", "|", ">")):
                return None
            key = body[:-1]
            if key.startswith('"') and key.endswith('"') and len(key) >= 2:
                key = key[1:-1]
            if not key or '"' in key or key in entries:
                return None
            current, section = key, None
            entries[current] = []
        elif indent == 2 and current is not None and body.endswith(":"):
            section = body[:-1]
            if section not in ("locations", "aliases"):
                return None
        elif indent == 4 and section is not None and body.startswith("- "):
            value = body[2:].strip()
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                value = value[1:-1]
            if section == "locations":
                entries[current].append(value)
        else:
            return None
    return entries


def yarn_state_packages(project_dir) -> list:
    """Packages `node_modules/.yarn-state.yml` says Berry's node-modules linker
    installed, as the state file names them. A reference that is not `npm:<ver>`
    (a patch, a git source) is returned with UNIDENTIFIED. An unreadable state
    file reads as no entries; the package.json walk still runs."""
    project = Path(project_dir)
    try:
        text = (project / "node_modules" / ".yarn-state.yml").read_text(encoding="utf-8")
    except (OSError, ValueError):
        return []
    entries = parse_yarn_state(text)
    if not entries:
        return []
    found = []
    for locator, locations in entries.items():
        parsed = _state_locator(locator)
        if parsed is None:
            continue
        name, reference = parsed
        if reference.startswith("workspace:"):
            continue
        version = reference[4:] if reference.startswith("npm:") else ""
        version = version or UNIDENTIFIED
        for location in locations:
            parts = Path(location).parts
            if not location or Path(location).is_absolute() or ".." in parts:
                continue  # never follow a location out of the project
            directory = project / location
            if directory.is_dir():
                found.append(Installed(NODE_MODULES, "npm", name, version, str(directory)))
    return found


def yarn_install_state_present(project_dir) -> bool:
    """Whether `.yarn/install-state.gz` exists. Presence only: it is a binary
    blob and is never parsed."""
    return (Path(project_dir) / ".yarn" / "install-state.gz").is_file()


def has_pnpm_markers(project_dir) -> bool:
    modules = Path(project_dir) / "node_modules"
    return (modules / ".modules.yaml").is_file() or (modules / ".pnpm").is_dir()


def has_bun_markers(project_dir) -> bool:
    return (Path(project_dir) / "node_modules" / ".bun").is_dir()


def has_yarn_markers(project_dir) -> bool:
    return (Path(project_dir) / "node_modules" / ".yarn-state.yml").is_file() or \
        yarn_install_state_present(project_dir)


# ---------------------------------------------------------------------------
# Yarn Berry: cache zips
# ---------------------------------------------------------------------------

# `<slug>-npm-<version>-<hash>-<cachekey>.zip`: the slug is the package name with
# `/` turned into `-` (`@scope-name`). UNVERIFIED against a live Yarn here; the
# shape is Berry's `slugifyLocator` plus the cache key.
_YARN_ZIP = re.compile(
    r"^(?P<slug>.+)-npm-(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+?)?(?:\+[0-9A-Za-z.]+?)?)"
    r"-(?P<hash>[0-9a-f]{10})-(?P<key>[0-9a-z]+)\.zip$")
# Berry's own `optional!builtin<compat/...>` patches are cached as
# `<name>-patch-<hash>-<hash>-<key>.zip`, for exactly these packages.
_YARN_BUILTIN_PATCHES = frozenset({"typescript", "resolve", "fsevents"})
_YARN_PATCH_ZIP = re.compile(
    r"^(?P<slug>.+)-patch-[0-9a-f]{10}-[0-9a-f]{10}-[0-9a-z]+\.zip$")


def yarn_zip_candidates(filename: str):
    """What a cache file name says.

    ("npm", [(name, version), ...]) for a registry zip; the list holds every way
    a scoped slug can be split (`@a-b-c` is `@a/b-c` or `@a-b/c`), because the
    encoding is ambiguous and only the caller's direct-name set can resolve it.
    ("exempt", []) for Berry's builtin compat patches. None for anything else,
    which the caller reports rather than skips.
    """
    match = _YARN_ZIP.match(filename)
    if match:
        slug, version = match.group("slug"), match.group("version")
        if not slug.startswith("@"):
            return "npm", [(slug, version)]
        names = [(f"{slug[:i]}/{slug[i + 1:]}", version)
                 for i, char in enumerate(slug) if char == "-" and 1 < i < len(slug) - 1]
        return ("npm", names) if names else None
    patch = _YARN_PATCH_ZIP.match(filename)
    if patch and patch.group("slug") in _YARN_BUILTIN_PATCHES:
        return "exempt", []
    return None


def yarn_cache_packages(cache_dir, source, direct) -> list:
    """Direct packages with a zip in a Yarn cache directory.

    Only a name in `direct` is a candidate (a transitive is the lock's business,
    exactly as for npm), but a zip that cannot be decoded at all is returned
    with the UNIDENTIFIED version: an unreadable entry in a cache that
    `--mode=update-lockfile` fills must not read as clean.
    """
    root = Path(cache_dir)
    direct = set(direct)
    found = []
    try:
        files = sorted(p for p in root.iterdir() if p.is_file() and p.name.endswith(".zip"))
    except OSError:
        return []
    for path in files:
        decoded = yarn_zip_candidates(path.name)
        if decoded is None:
            found.append(Installed(source, "npm", path.name[:-len(".zip")], UNIDENTIFIED,
                                   str(path)))
            continue
        kind, candidates = decoded
        if kind == "exempt":
            continue
        for name, version in candidates:
            if name in direct:
                found.append(Installed(source, "npm", name, version, str(path)))
    return found


# ---------------------------------------------------------------------------
# Bun: the global cache and bunx temp projects
# ---------------------------------------------------------------------------

_BUN_CACHE_KEY = re.compile(r"@@@\d+$")


def decode_bun_cache_entry(dirname: str, scope=None):
    """(name, version) from `<name>@<ver>@@@1`, or None. `scope` is the parent
    `@scope` directory when the cache nests scoped packages (UNVERIFIED: a flat
    `@scope+name@ver@@@1` is accepted too)."""
    if not _BUN_CACHE_KEY.search(dirname):
        return None
    stem = _BUN_CACHE_KEY.sub("", dirname)
    at = stem.find("@", 1)
    if at <= 0:
        return None
    name, version = stem[:at], stem[at + 1:]
    if scope:
        name = f"{scope}/{name}"
    elif name.startswith("@"):
        head, plus, tail = name.partition("+")
        if not plus or not tail:
            return None
        name = f"{head}/{tail}"
    if not name or not version:
        return None
    return name, version


def bun_cache_packages(cache_root, direct) -> list:
    """Direct packages in Bun's global install cache (`<name>@<ver>@@@1`).
    An entry that looks like a cache directory (carries the `@@@<n>` key) but
    cannot be decoded is reported UNIDENTIFIED."""
    root = Path(cache_root)
    direct = set(direct)
    found = []

    def visit(entry, scope):
        decoded = decode_bun_cache_entry(entry.name, scope)
        if decoded is None:
            if "@@@" in entry.name:
                found.append(Installed(BUN_CACHE, "npm", entry.name, UNIDENTIFIED, str(entry)))
            return
        name, version = decoded
        if name in direct:
            found.append(Installed(BUN_CACHE, "npm", name, version, str(entry)))

    for entry in _iter_dirs(root):
        if entry.name.startswith("@") and "@" not in entry.name[1:]:
            for child in _iter_dirs(entry):
                visit(child, entry.name)
        else:
            visit(entry, None)
    return found


def bunx_cache_packages(tmp_root) -> list:
    """The package each `bunx-<uid>-<spec>` temp project was made for. Like the
    npx cache the spec is its own direct set; the version comes from the
    installed package.json. UNVERIFIED layout."""
    root = Path(tmp_root)
    found = []
    try:
        entries = sorted(p for p in root.iterdir() if p.name.startswith("bunx-") and p.is_dir())
    except OSError:
        return []
    for entry in entries:
        match = re.match(r"^bunx-\d+-(?P<spec>.+)$", entry.name)
        spec = match.group("spec") if match else ""
        at = spec.find("@", 1)
        name = spec[:at] if at > 0 else spec
        if name.startswith("@") and "/" not in name:
            head, _plus, tail = name.partition("+")
            name = f"{head}/{tail}" if tail else name
        if not name:
            found.append(Installed(BUNX_CACHE, "npm", entry.name, UNIDENTIFIED, str(entry)))
            continue
        installed = entry / "node_modules" / name
        if not installed.is_dir():
            continue
        version = (_read_json(installed / "package.json") or {}).get("version")
        if not isinstance(version, str) or not version:
            version = UNIDENTIFIED
        found.append(Installed(BUNX_CACHE, "npm", name, version, str(installed)))
    return found


# ---------------------------------------------------------------------------
# pnpm: the content store and dlx projects
# ---------------------------------------------------------------------------

_PNPM_INDEX = re.compile(r"^[0-9a-f]+-(?P<spec>.+)\.json$")


def pnpm_store_packages(store_root, direct) -> list:
    """Direct packages the pnpm store holds index files for.

    UNVERIFIED layout: `<store>/v10/index/<2 hex>/<hash>-<name>@<ver>.json`
    with `/` written `+`. The name and version come from the FILE NAME alone:
    the store holds thousands of entries and this runs on every command, so no
    index is ever opened. A file name that does not fit the shape is skipped,
    which is a stated gap (a pnpm that writes bare `<hash>-index.json` names is
    invisible here), not a clean bill.
    """
    root = Path(store_root)
    direct = set(direct)
    found = []
    for version_dir in _iter_dirs(root):
        for bucket in _iter_dirs(version_dir / "index"):
            try:
                files = sorted(p for p in bucket.iterdir() if p.name.endswith(".json"))
            except OSError:
                continue
            for path in files:
                match = _PNPM_INDEX.match(path.name)
                if not match:
                    continue
                spec = match.group("spec")
                at = spec.find("@", 1)
                if at <= 0:
                    continue
                name, version = spec[:at], spec[at + 1:]
                if name.startswith("@"):
                    name = name.replace("+", "/", 1)
                if name in direct and version:
                    found.append(Installed(PNPM_STORE, "npm", name, version, str(path)))
    return found


def pnpm_dlx_packages(dlx_root) -> list:
    """Packages of every `pnpm dlx` project: `<dlx>/<hash>/<id>/` holding a
    package.json whose `dependencies` keys are what was asked for and a
    node_modules with the installed copy (UNVERIFIED layout). A symlinked
    `<hash>` is followed once, by real path."""
    root = Path(dlx_root)
    found, seen = [], set()
    for first in _iter_dirs(root):
        for entry in [first] + _iter_dirs(first):
            real = os.path.realpath(entry)
            if real in seen:
                continue
            seen.add(real)
            declared = (_read_json(entry / "package.json") or {}).get("dependencies")
            if not isinstance(declared, dict):
                continue
            for name in sorted(declared):
                installed = entry / "node_modules" / name
                if not installed.is_dir():
                    continue
                version = (_read_json(installed / "package.json") or {}).get("version")
                if not isinstance(version, str) or not version:
                    version = UNIDENTIFIED
                found.append(Installed(PNPM_DLX, "npm", name, version, str(installed)))
    return found


# ---------------------------------------------------------------------------
# mtimes, for the watermark
# ---------------------------------------------------------------------------

def mtimes(packages) -> dict:
    """{Installed: st_mtime_ns}. A path that cannot be stat-ed reads as 0."""
    return {package: _mtime_ns(Path(package.path)) for package in packages}


def changed_at(packages) -> dict:
    """{Installed: max(st_mtime_ns, st_ctime_ns) or None}, for the session cutoff.

    Not the watermark: a ctime moves on chmod or rename, and the watermark
    would re-raise an entry already decided.
    """
    return {package: _changed_ns(Path(package.path)) for package in packages}
