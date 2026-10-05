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
import sys
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
