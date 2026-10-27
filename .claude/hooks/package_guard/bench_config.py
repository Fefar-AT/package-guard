"""A Frappe bench: where it is, and the installer configuration the guard keeps in it.

One place says where a bench is, where its Python environment is, and which
names are its apps, so recognition (`parser`), the Python environments the
disk check reads (`disk_guard`) and the requirement checks (`hook`) cannot
disagree about any of them.

A bench is a directory that holds `apps/` and `sites/`. A command may run in
the bench root or anywhere below it (`apps/<app>/<app>/doctype`), so every
ancestor of the path as written is tried, nearest first. Finding a bench only
ever adds scrutiny: nothing here makes a command pass.

The second half writes and checks the files that pin what bench's installs may
fetch: `env/pip.conf`, `<bench>/uv.toml`, the constraint files and a `.yarnrc`
for each yarn directory (`apply`, `expected_files`), and computes what pip, uv
and yarn would really read, layer by layer (`verify`). The pins themselves come
in as a `ConfigInput`; nothing here reads a baseline.

Standard library, and the guard's own `verbs` and `pm_config`.
"""
from __future__ import annotations

import configparser
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

import pm_config
import verbs

# The interpreter of a bench env as a command line writes it: `env/bin/python`,
# `./env/bin/python3`, `../../env/bin/python3.12`, `/srv/bench/env/bin/python`.
# Matched on the text, before anything reads the disk; `python_in_env_problem`
# then ties it to the bench.
ENV_PYTHON = re.compile(r"(?:^|/)env/bin/python[0-9]*(?:\.[0-9]+)*$")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def bench_root(directory) -> Path | None:
    """The bench that `directory` is, or is inside, or None."""
    here = Path(os.path.abspath(directory))
    for candidate in (here, *here.parents):
        if (candidate / "apps").is_dir() and (candidate / "sites").is_dir():
            return candidate
    return None


# Bench's own rule for "the bench" (frappe-bench 5.31.x `bench/utils/__init__.py`): `paths_in_bench` is
# `("apps", "sites", "config", "logs", "config/pids")`, `is_bench_directory` is true when every one of them
# EXISTS (`os.path.exists`, so a link counts when its target is there), and `find_parent_bench` looks at
# the working directory and then each parent, stopping after it has looked at the home directory or `/`.
# `change_working_directory` (cli.py) starts from `os.path.abspath(".")`, which is the real path of the
# working directory, and changes into what it finds. `bench_root` above is the looser rule (apps/ and
# sites/ only) that the rest of the guard uses to say where a bench may be; a bench verb is judged by the
# rule bench uses, in `bench_for_verb`.
PATHS_IN_BENCH = ("apps", "sites", "config", "logs", "config/pids")


def is_bench_directory(directory) -> bool:
    return all(os.path.exists(os.path.abspath(os.path.join(directory, folder))) for folder in PATHS_IN_BENCH)


def bench_as_bench_finds(directory, home=None) -> Path | None:
    """The directory bench changes into when it is run from `directory` (`find_parent_bench`): the
    real path of the nearest directory, from there up, that `is_bench_directory`, looking at the
    home directory but no further; None when bench finds none."""
    path = os.path.realpath(directory)
    home = os.path.expanduser("~") if home is None else str(home)
    stops = {home, os.path.abspath(os.sep)}
    while True:
        if is_bench_directory(path):
            return Path(path)
        if path in stops:
            return None
        parent = os.path.split(path)[0]
        if parent == path:
            return None
        path = parent


def _benchlike(directory) -> bool:
    """A directory with `apps/` and `sites/`: a bench, or one `mkdir` away from being one."""
    return os.path.isdir(os.path.join(directory, "apps")) and os.path.isdir(os.path.join(directory, "sites"))


def bench_for_verb(directory) -> tuple:
    """(bench, None) or (None, why) for a bench verb run in `directory`: the bench the verb acts on is
    the one bench finds (`bench_as_bench_finds`), and the call refuses, with the reason in plain words, when
    it cannot say it is the one the guard checks.

    (a) The nearest directory with apps/ and sites/ (`bench_root`, what the guard used to take for the bench) is
    not the directory bench changes into: bench would install into another env under other settings.
    (b) is `recorded_bench_problem`, which the hook asks next.
    (c) A directory that bench could take for the bench lies above the one it uses, all the way to `/` whatever
    `HOME` says (a full bench, or one with apps/ and sites/ that a `mkdir` finishes): removing one folder of
    the bench, or setting `HOME`, in a command that runs at the same time moves bench there, and the check
    made now would be of the wrong one. When unsure, refuse."""
    loose = bench_root(directory)
    found = bench_as_bench_finds(directory)
    if found is None:
        if loose is None:
            return None, ("no Frappe bench (a directory with apps/ and sites/) holds "
                          f"{directory}; run the command from the bench root or from an app inside it")
        missing = [f for f in PATHS_IN_BENCH if not os.path.exists(os.path.join(loose, f))]
        return None, (f"bench does not take {loose} for a bench: it has no {', '.join(missing) or 'folder it needs'} "
                      f"(a bench is a directory with {', '.join(PATHS_IN_BENCH)}), so bench would act on "
                      "something else, or on the working directory itself. Tell the user")
    if loose is None or os.path.realpath(loose) != str(found):
        return None, (f"the nearest directory with apps/ and sites/ is {loose}, but bench changes into {found} "
                      f"(the nearest directory that also has config/, logs/ and config/pids/): bench would install into "
                      "that one's env and settings, not the ones Package Guard checked. Tell the user")
    # (c): everything above the bench that bench could take for a bench, with or without HOME
    above, path = [], str(found)
    while True:
        parent = os.path.split(path)[0]
        if parent == path:
            break
        path = parent
        if is_bench_directory(path) or _benchlike(path):
            above.append(path)
    if above:
        return None, (f"{above[0]} lies above the bench at {found} and has "
                      f"{'everything bench needs for a bench' if is_bench_directory(above[0]) else 'apps/ and sites/'}: "
                      "if one folder of this bench were gone when the command runs, bench would use that one "
                      "instead. Tell the user")
    return Path(loose), None


def recorded_bench_problem(bench, root) -> str | None:
    """Why `bench` is not a bench the guard's installer files are recorded for, or None. The record
    (`bench-config.json`) names every file `apply` wrote; a bench whose `env/pip.conf` is not among
    them is not one the baselines and files of this project belong to. An empty record is not judged here
    (`verify` reports the missing files)."""
    try:
        record = read_record(root)
    except BenchConfigError:
        return None
    if not record:
        return None
    recorded = {os.path.realpath(Path(root) / name) for name in record}
    if os.path.realpath(Path(bench) / "env" / "pip.conf") in recorded:
        return None
    return (f"the installer files Package Guard wrote are not those of the bench at {bench}: bench will act on "
            "this one, and no baseline or file of the guard's is recorded for it. Tell the user; `bench-config apply` "
            "run in that bench records it")


def bench_env(directory) -> Path | None:
    """`<bench>/env` when `directory` is in a bench whose env exists."""
    root = bench_root(directory)
    if root is not None and (root / "env" / "pyvenv.cfg").is_file():
        return root / "env"
    return None


# What is an app of the bench: every entry of `apps/` that ANY of the programs that run in it would
# treat as one. `bench.utils.is_frappe_app` finds `hooks.py`, `modules.txt` and `patches.txt` one
# directory below the app (`glob(<app>/**/<file>)` without `recursive`). Frappe v16's build
# (`esbuild/utils.js` `get_cloned_apps`) finds each of them at ANY depth, the app root and hidden
# folders included, and builds the app. Frappe v15's build takes the lines of `sites/apps.txt` and needs
# no app files at all. `yarn install` and `yarn build` run in what the build finds, so an app is the
# union of the three rules. This is the one definition: the gate, `baseline.config_input`, the local
# names of D7, the `.yarnrc` directories and the scan of the env all call `bench_apps`, so a stray
# directory in `apps/` is not an app anywhere and a directory any of them builds is one everywhere.
_APP_FILES = ("hooks.py", "modules.txt", "patches.txt")
_WALK_LIMIT = 200000


def _has_app_files(app) -> bool:
    """True when all three app files are in `app`: one directory below it (bench), or at any depth
    (Frappe v16's build, which follows symlinks and reads hidden folders). A tree too large to walk
    counts as an app, the stricter answer."""
    missing = {name for name in _APP_FILES
               if not glob.glob(os.path.join(glob.escape(str(app)), "**", name))}
    if not missing:
        return True
    seen, count = set(), 0
    for here, dirs, files in os.walk(str(app), followlinks=True):
        real = os.path.realpath(here)
        if real in seen:
            dirs[:] = []
            continue
        seen.add(real)
        count += len(dirs) + len(files)
        if count > _WALK_LIMIT:
            return True
        missing.difference_update(files)
        if not missing:
            return True
    return False


def apps_txt_names(bench) -> list:
    """The lines of `sites/apps.txt` as Frappe v15's build reads them (split on newlines, empty ones
    dropped), the text kept as written. [] when the file cannot be read."""
    try:
        text = (Path(bench) / "sites" / "apps.txt").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    return [line for line in text.split("\n") if line]


def apps_txt_resolve(bench) -> tuple:
    """(names of the entries of `apps/` that `sites/apps.txt` lists, lines it cannot map).

    A line is read the way the builds and bench read it: as written and stripped (CRLF, spaces),
    joined to `apps/` and path-normalised (`./plain`, `plain/`, `plain/.`, `x/../plain`), and matched
    to an entry by the folder itself, so `PLAIN` finds `plain` on a disk that ignores case. A line that
    names nothing is ignored (the build finds nothing there). A line that names a folder that is not
    exactly one entry directly in `apps/` (outside it, below an app, or two entries for one folder)
    cannot be mapped; the build verbs refuse it."""
    bench = Path(bench)
    apps = os.path.join(os.path.realpath(bench), "apps")
    try:
        entries = [e for e in os.scandir(apps) if e.is_dir()]
    except OSError:
        entries = []
    by_id = {}
    for entry in entries:
        try:
            info = os.stat(entry.path)
        except OSError:
            continue
        by_id.setdefault((info.st_dev, info.st_ino), []).append(entry.name)
    mapped, unmapped = set(), []
    for line in apps_txt_names(bench):
        for variant in dict.fromkeys((line, line.strip())):
            if not variant:
                continue
            target = os.path.normpath(os.path.join(apps, variant))
            try:
                info = os.stat(target)
            except (OSError, ValueError):
                continue
            if not os.path.isdir(target):
                continue
            hit = by_id.get((info.st_dev, info.st_ino), [])
            if len(hit) == 1 and os.path.dirname(target) == apps:
                mapped.add(hit[0])
            elif line not in unmapped:
                unmapped.append(line)
    return mapped, unmapped


def apps_txt_strays(bench) -> list:
    """The lines of `sites/apps.txt` that name an existing folder which is not exactly one entry
    directly in `apps/` (`../x`, `a/b`, an absolute path, two entries for one folder): a build
    changes into it and runs `yarn` there, and no app rule can cover it."""
    return apps_txt_resolve(bench)[1]


def bench_apps(bench) -> list:
    """The apps of the bench at `bench`, as directories, sorted by name."""
    bench = Path(bench)
    try:
        entries = sorted(os.scandir(bench / "apps"), key=lambda e: e.name)
    except OSError:
        return []
    listed = apps_txt_resolve(bench)[0]
    return [Path(entry.path) for entry in entries
            if entry.is_dir() and (entry.name in listed or _has_app_files(entry.path))]


def app_names(root) -> dict:
    """{normalized name: where it is listed} for the apps of the bench at `root`.

    The apps of the bench (`bench_apps`: their directory names and the `[project].name` of each
    `pyproject.toml`) and the lines of `sites/apps.txt`: a name listed there is local too, because
    resolving it from an index is the harm.
    """
    root = Path(root)
    names = {}
    for entry in bench_apps(root):
        names.setdefault(_normalize(entry.name), f"apps/{entry.name}")
        project = _toml(entry / "pyproject.toml").get("project")
        declared = project.get("name") if isinstance(project, dict) else None
        if isinstance(declared, str) and declared.strip():
            names.setdefault(_normalize(declared), f"apps/{entry.name}")
    try:
        lines = (root / "sites" / "apps.txt").read_text(encoding="utf-8").splitlines()
    except (OSError, ValueError):
        lines = []
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            names.setdefault(_normalize(line), "sites/apps.txt")
    return names


def env_problem(directory):
    """(bench root, None) when `directory` is in a bench that has a Python env,
    else (None, why not)."""
    if bench_root(directory) is None:
        return None, "no Frappe bench (a directory with `apps/` and `sites/`) holds this directory"
    root, why = bench_for_verb(directory)  # the bench bench changes into, not only the nearest apps/ + sites/
    if root is None:
        return None, why
    if not (root / "env" / "pyvenv.cfg").is_file():
        return None, f"the bench at {root} has no Python environment in `env/` yet"
    return root, None


def python_in_env_problem(value, directory) -> str | None:
    """Why `value` (a `--python` argument) is not the Python of the bench env
    that `directory` belongs to, or None when it is.

    Compared by where the interpreter's own directory is, never by what the
    interpreter file resolves to: a venv's `bin/python` is a link to the base
    interpreter, so resolving it would make `/usr/bin/python3` look like it.
    """
    if not isinstance(value, str) or not ENV_PYTHON.search(value):
        return "it is not a bench env interpreter (`<bench>/env/bin/python`)"
    root, why = env_problem(directory)
    if root is None:
        return why
    path = Path(value) if value.startswith("/") else Path(directory) / value
    if os.path.realpath(path.parent) != os.path.realpath(root / "env" / "bin"):
        return (f"it is not the env of the bench at {root}: `--python` may name only "
                "that bench's own `env/bin/python`")
    return None


# Bench's own CLI reads this file and, when it exists, changes to the bench it names before
# any command runs (`bench/cli.py` `change_dir`), whichever bench the shell is in. A module
# constant so a test can point it somewhere else.
BENCH_DIR_FILE = "/etc/frappe_bench_dir"


def redirect_problem() -> str | None:
    """Why a `bench` command may run in another bench than the shell's, or None."""
    if os.path.lexists(BENCH_DIR_FILE):
        return (f"`{BENCH_DIR_FILE}` exists: bench changes to the bench it names before it "
                "runs pip, so the env, the apps and the settings it uses are that bench's, "
                "not the ones Package Guard checked")
    return None


def env_bin_bench(path, directory) -> Path | None:
    """The bench whose `env/bin` holds the executable `path` (as a command line writes
    it, relative to `directory`), or None when it is not inside a bench env.

    The directory is resolved, links included, and is compared to `<bench>/env/bin` of a
    directory that holds `apps/` and `sites/`; the file itself is not resolved, since a
    venv's `bin/pip` links elsewhere. `<bench>/apps/<app>/env/bin` is not a bench env."""
    path = str(path)
    if path.startswith("~/"):
        # the shell expands an unquoted `~/` to the home directory
        path = os.path.expanduser(path)
    target = Path(path) if path.startswith("/") else Path(directory) / path
    parent = Path(os.path.realpath(target.parent))
    if parent.name != "bin" or parent.parent.name != "env":
        return None
    bench = parent.parent.parent
    if (bench / "apps").is_dir() and (bench / "sites").is_dir():
        return bench
    return None


# An executable path the shell would still expand when the command runs: a variable, a
# substitution, a glob, `~user`. A leading `~/` is the home directory and is read.
_EXPANDS = re.compile(r"[$`*?\[\]{}]|^~[^/]|^~$")


def executable_is_dynamic(path) -> bool:
    text = str(path)
    return bool(_EXPANDS.search(text[2:] if text.startswith("~/") else text))


def executable_problem(path, directory) -> str | None:
    """Why installing with the executable `path` is not an install into the env of the
    bench `directory` belongs to, or None (it is that env, or not a bench env at all)."""
    bench = env_bin_bench(path, directory)
    if bench is None:
        return None
    root, why = env_problem(directory)
    if root is None:
        return f"`{path}` is the Python env of the bench at {bench}, and {why}"
    if os.path.realpath(root) != os.path.realpath(bench):
        return (f"`{path}` is the Python env of the bench at {bench}, not the env of the "
                f"bench at {root} this directory belongs to")
    return None


def _toml(path) -> dict:
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


_REQUIREMENT_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")


def requirement_name(text) -> str | None:
    """The normalized distribution name a requirement string starts with."""
    if not isinstance(text, str):
        return None
    match = _REQUIREMENT_NAME.match(text)
    return _normalize(match.group(1)) if match else None


def requirements_file_names(path) -> list:
    """[(line number, normalized name, line)] for a requirements file.

    Option lines (`-r`, `-e`, `--hash`) and comments are not requirements.
    A file that cannot be read has none: the install gate reports it.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, ValueError):
        return []
    found = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-")):
            continue
        name = requirement_name(line)
        if name:
            found.append((number, name, line))
    return found


def pyproject_names(path, build_only=False) -> list:
    """[(where, normalized name)] for every requirement a pyproject.toml lists:
    `[project].dependencies` and `optional-dependencies`, `[dependency-groups]`,
    `[tool.uv].dev-dependencies`, `[build-system].requires` and the names of
    `[tool.bench.dev-dependencies]`.

    `build_only` is for a local build whose dependencies are not fetched
    (`pip install --no-deps .`): only `[build-system].requires` is then installed.
    Every other caller reads every list on purpose, selected or not (a name in an
    extra nobody asked for, a group, a marker that is false here): it is rare, and
    refusing is the safe error; do not narrow it without a reason like this one."""
    data = _toml(path)
    found = []

    def take(where, items):
        for item in items if isinstance(items, list) else ():
            name = requirement_name(item)
            if name:
                found.append((where, name))

    if build_only:
        build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
        take("build-system.requires", build.get("requires"))
        return found

    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    take("dependencies", project.get("dependencies"))
    optional = project.get("optional-dependencies")
    for group, items in (optional.items() if isinstance(optional, dict) else ()):
        take(f"optional-dependencies.{group}", items)
    groups = data.get("dependency-groups")
    for group, items in (groups.items() if isinstance(groups, dict) else ()):
        take(f"dependency-groups.{group}", items)
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
    take("tool.uv.dev-dependencies", uv.get("dev-dependencies"))
    build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
    take("build-system.requires", build.get("requires"))
    bench = tool.get("bench") if isinstance(tool.get("bench"), dict) else {}
    dev = bench.get("dev-dependencies")
    for name in (dev if isinstance(dev, dict) else ()):
        normalized = requirement_name(name)
        if normalized:
            found.append(("tool.bench.dev-dependencies", normalized))
    return found


def pyproject_requirement_text(path, name) -> str | None:
    """The first requirement string of a pyproject.toml that names `name` (normalized) and carries a
    version specifier, `build-system.requires` included; None when none does. What a review is asked
    about must be a version the app's own range admits (`flit_core >=3.4,<4` is not 4.1.0)."""
    data = _toml(path)
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
    optional = project.get("optional-dependencies")
    groups = data.get("dependency-groups")
    lists = [project.get("dependencies"), build.get("requires"),
             *(optional.values() if isinstance(optional, dict) else ()),
             *(groups.values() if isinstance(groups, dict) else ())]
    for items in lists:
        for item in items if isinstance(items, list) else ():
            if isinstance(item, str) and requirement_name(item) == name \
                    and re.search(r"[<>=!~]", item.split(";", 1)[0]):
                return item
    return None


# ---------------------------------------------------------------------------
# The installer configuration the guard writes for a bench, and its check
# ---------------------------------------------------------------------------
#
# `apply` writes `env/pip.conf`, `<bench>/uv.toml`, the constraint files under
# the guard root's state directory and a `.yarnrc` per yarn directory, all LF.
# `verify` computes what pip, uv and yarn would really read, layer by layer,
# and says what would weaken them. The constraint content is an input
# (`ConfigInput`) that the baselines will build; nothing here reads a baseline.

PYPI_INDEX = "https://pypi.org/simple"
UV_REQUIRED_VERSION = ">=0.12.5"
LOCAL_PIN = "local-app-not-from-index"
RECORD_NAME = "bench-config.json"
CONSTRAINTS_DIR = "constraints"
RUNTIME_FILE = "runtime.txt"
BUILD_FILE = "build.txt"
YARNRC_LINES = ("--install.frozen-lockfile true", "ignore-scripts true")
YARNRC_NO_BIN_LINKS = "--install.no-bin-links true"
GITATTRIBUTE_LINES = ("/uv.toml text eol=lf", "/.yarnrc text eol=lf")

# Directories the walk for nested yarn locks never enters.
_WALK_SKIP = frozenset({"node_modules", ".git", "env", ".venv", "sites", "archived",
                        "__pycache__", ".claude"})
_WALK_DEPTH = 4


class BenchConfigError(Exception):
    """The configuration cannot be written or read; the message says why."""


class PinConflict(BenchConfigError):
    """Two sources pin one name to two versions."""


class FileConflict(BenchConfigError):
    """A file that is there already is not one the guard wrote, or was edited."""


class Pin(NamedTuple):
    name: str          # PEP 503 normalised
    version: str
    marker: str = ""   # the environment marker, kept as written
    source: str = ""   # where the pin came from (a baseline id), for a conflict message


@dataclass(frozen=True)
class ConfigInput:
    """What the written files are computed from. Plain tuples, so the baselines
    can build one directly.

    runtime, build    the approved pins of the apps in the bench (`Pin`)
    toolchain         pins both files carry: pip, wheel, setuptools, the backends
    allowed_builds    normalised names a person allowed to build from source
    local_apps        (distribution name, local version) of every app in `apps/`
    other_local_names names that are local but not present; no constraint is written for
                      them (see `constraint_lines`), the field is kept for the baselines
    new_apps          normalised names of apps the person said they are about to create with
                      `bench new-app` (`apply --new-app`): uv may build them (see `_uv_toml_text`)
    unpinned          (app, name, section, why) of a custom app's version range that no approved release
                      satisfies, or that an extra or group of the app contradicts, so the pin is not
                      one the app can install (the bench verbs refuse; see `hook`)
    requirement_names every package name some requirement of the bench names (the baselines' pins, the
                      toolchain, the allowed builds, the custom apps' declarations)
    dev_blocked       normalised names of the direct development requirements of every app whose approved
                      baseline does not pin its development set (`python.dev.pinned` false); see
                      `constraint_lines`
    """
    runtime: tuple = ()
    build: tuple = ()
    toolchain: tuple = ()
    allowed_builds: tuple = ()
    local_apps: tuple = ()
    other_local_names: tuple = ()
    index: str = PYPI_INDEX
    no_symlinks: bool = False
    new_apps: tuple = ()
    unpinned: tuple = ()
    requirement_names: tuple = ()
    dev_blocked: tuple = ()


def _marker(pin) -> str:
    return f" ; {pin.marker}" if pin.marker else ""


def _union(pins) -> dict:
    """{(name, marker): Pin}; refuses two versions of one name that can apply at
    once (the same marker, or either unmarked), naming both sources."""
    chosen, by_name = {}, {}
    for pin in pins:
        name = _normalize(pin.name)
        pin = pin._replace(name=name)
        key = (name, pin.marker)
        for other in by_name.get(name, ()):
            if other.version != pin.version and (not other.marker or not pin.marker
                                                 or other.marker == pin.marker):
                raise PinConflict(
                    f"{name} is pinned to {other.version} by {other.source or 'one source'} and "
                    f"to {pin.version} by {pin.source or 'another'}: the constraint files cannot "
                    "hold both")
        if key not in chosen:
            chosen[key] = pin
            by_name.setdefault(name, []).append(pin)
    return chosen


def constraint_lines(config: ConfigInput) -> tuple:
    """(runtime lines, build lines): the union of the pins, the toolchain, and the
    local app pins (`<dist>==<its version>` for each app in `apps/`).

    A local name that is not present gets no line. The unsatisfiable `===` pin an
    earlier version wrote for it is not a requirement uv can read (it rejects the
    version, and every `uv pip install` then fails before it resolves anything), and an
    absent app is not installed by anything the guard lets through."""
    local = [Pin(_normalize(dist), version, "", "apps/") for dist, version in config.local_apps]
    runtime = _union((*config.runtime, *config.toolchain, *local))
    # A build can ask for runtime packages too (flit_core reports an app's dependencies as build
    # requirements when it must import the app to read a dynamic description or version), so every
    # runtime pin also holds in the build environments, unless a build pin of its own names it.
    built = {_normalize(p.name) for p in (*config.build, *config.toolchain)}
    build = _union((*config.build, *config.toolchain, *(p for p in runtime.values() if p.name not in built)))

    def render(table):
        return tuple(f"{p.name}=={p.version}{_marker(p)}" for _key, p in sorted(table.items()))

    return (*render(runtime), *blocking_lines(config, runtime)), render(build)


# The constraint that no release satisfies. `uv pip install hypothesis` (or pip) with it fails with
# "you require hypothesis<0, which does not allow any versions" and installs nothing; an install
# that does not ask for the package, directly or through another, is not touched by it. (The `===`
# form is not used: neither tool reads it as a constraint, and every install then fails.)
NO_RELEASE = "<0"


def blocking_lines(config: ConfigInput, runtime: dict) -> tuple:
    """The lines that make a development package uninstallable, for every app whose baseline does
    not pin its development set.

    With `developer_mode` on, bench installs an app's development dependencies (`uv pip install
    <name><spec> ... --python <env>/bin/python`, run in the bench root, or `<env>/bin/python -m pip
    install` when `BENCH_DISABLE_UV` is set: `install_python_dev_dependencies`) and it reads
    `developer_mode` again for every app it installs. The hook reads it once, so a value changed
    while `bench setup requirements` runs would install the unpinned set. The decision therefore does
    not rest on that value: each direct development requirement of such an app that has no approved
    pin gets a constraint no release satisfies, in the runtime constraint file (pip.conf) and in
    uv.toml, and any install of it fails. Transitive development packages need nothing: they come
    only through the direct ones, which cannot be installed. A name that has a pin (a runtime pin, the
    toolchain, a local app, with or without a marker) gets no line: `name<0` beside `name==X` would
    fail every install of it, runtime ones included."""
    pinned = {p.name for p in runtime.values()}
    return tuple(f"{name}{NO_RELEASE}" for name in sorted({_normalize(n) for n in config.dev_blocked} - pinned))


def _constraint_text(lines) -> str:
    return "".join(f"{line}\n" for line in lines)


def _state_dir(root) -> Path:
    return Path(os.path.abspath(root)) / ".claude" / "package-guard"


def _guard_files(root) -> tuple:
    base = _state_dir(root) / CONSTRAINTS_DIR
    return base / RUNTIME_FILE, base / BUILD_FILE


def _pip_conf_text(config, runtime_path, build_path, allowed) -> str:
    # `only-binary` is written before `no-binary`: pip's `:all:` clears what was
    # set before it, so the allowed names must come after it, in each section.
    section = [f"constraint = {runtime_path}", f"build-constraint = {build_path}",
               f"index-url = {config.index}", "only-binary = :all:"]
    if allowed:
        section.append(f"no-binary = {','.join(allowed)}")
    lines = []
    for name in ("global", "install"):
        lines += [f"[{name}]", *section]
    return "\n".join(lines) + "\n"


def _toml_list(key, items) -> list:
    if not items:
        return [f"{key} = []"]
    return [f"{key} = [", *[f"    {json.dumps(item)}," for item in items], "]"]


def _uv_toml_text(config, runtime, build, allowed) -> str:
    # `no-build = true` refuses every source build, and uv lets a package named in
    # `no-binary-package` (built from source, never from a wheel) through it
    # (uv-configuration `BuildOptions::no_build_package`: "Allow `all` to be overridden
    # by specific binary exclusions"). The names there are exactly the approved builds
    # and the bench's own apps: nothing fetched from an index or a git source and not
    # listed can be built, a new dependency included. The apps are named because uv
    # runs the build backend to read the metadata of a local app whose version is
    # dynamic (every Frappe app: `dynamic = ["version"]`), and that is refused for a
    # package that is not in the list (checked with uv 0.12.5 and 0.13.5: "Building
    # source distributions for `frappe` is disabled"). An app's build requirements
    # are fetched under the same options, so they are wheels, pinned by
    # `build-constraint-dependencies`. A local app is never installed from the index
    # (its constraint is `LOCAL_PIN`, and a requirement naming it is refused), so
    # listing its name lets nothing else build. `bench new-app` installs the app it has just made, before
    # any `apply` could see it, so the person names it first (`apply --new-app`, which they confirm).
    # `required-version` is checked by uv before it reads anything else, so a uv older than the
    # one this was read from stops with an error instead of ignoring a key it does not know:
    # the source-build refusal (top-level `no-build` reaching `uv pip install`, and the
    # exemption) is read from 0.12.5, and an older uv may do neither.
    exempt = sorted({*allowed, *(_normalize(name) for name, _version in config.local_apps),
                     *(_normalize(name) for name in config.new_apps)})
    lines = [f"required-version = {json.dumps(UV_REQUIRED_VERSION)}"]
    lines += _toml_list("constraint-dependencies", runtime)
    lines += _toml_list("build-constraint-dependencies", build)
    lines.append("no-build = true")
    # `[tool.uv.sources]` in an app's pyproject.toml swaps a requirement's source for a path, a URL or a
    # git repository; `no-build` does not stop a wheel from there. Off, uv installs from the index.
    lines.append("no-sources = true")
    if exempt:
        lines += _toml_list("no-binary-package", exempt)
    lines.append(f"index-url = {json.dumps(config.index)}")
    return "\n".join(lines) + "\n"


def yarn_dirs(bench) -> list:
    """The directories that get a `.yarnrc`: the bench root, each app directory
    with a `package.json`, and each directory below an app that holds a
    `yarn.lock` (hrms has `frontend/` and `roster/`). Local reads only."""
    bench = Path(bench)
    found = [bench]
    for app in bench_apps(bench):
        if (app / "package.json").is_file():
            found.append(app)
        stack = [(app, 0)]
        while stack:
            directory, depth = stack.pop()
            try:
                children = sorted(directory.iterdir())
            except OSError:
                continue
            for child in children:
                if child.name in _WALK_SKIP or not child.is_dir() or child.is_symlink():
                    continue
                if (child / "yarn.lock").is_file() and child not in found:
                    found.append(child)
                if depth + 1 < _WALK_DEPTH:
                    stack.append((child, depth + 1))
    return found


def expected_files(bench, root, config: ConfigInput) -> dict:
    """{path: text} for every file `apply` writes, recomputed from `config`."""
    bench, root = Path(os.path.abspath(bench)), Path(os.path.abspath(root))
    runtime, build = constraint_lines(config)
    runtime_path, build_path = _guard_files(root)
    allowed = sorted({_normalize(n) for n in config.allowed_builds})
    for path in (runtime_path, build_path):
        if re.search(r"\s", str(path)):
            raise BenchConfigError(
                f"{path} contains whitespace, which pip splits a constraint list on: move the "
                "project to a path without spaces")
    files = {
        runtime_path: _constraint_text(runtime),
        build_path: _constraint_text(build),
        bench / "env" / "pip.conf": _pip_conf_text(config, runtime_path, build_path, allowed),
        bench / "uv.toml": _uv_toml_text(config, runtime, build, allowed),
    }
    rc = "".join(f"{line}\n" for line in (*YARNRC_LINES, *([YARNRC_NO_BIN_LINKS]
                                                          if config.no_symlinks else [])))
    for directory in yarn_dirs(bench):
        files[directory / ".yarnrc"] = rc
    return files


# -- text, as the tools read it ------------------------------------------------

def read_text_lf(path) -> str:
    """The text of `path` with each CRLF read as LF; a CR that remains refuses the
    file, naming it and the line (a Windows checkout writes CRLF, a mount shows it)."""
    try:
        text = Path(path).read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BenchConfigError(f"{path}: cannot be read ({exc.__class__.__name__})") from exc
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        line = text[:text.index("\r")].count("\n") + 1
        raise BenchConfigError(f"{path}: a bare carriage return on line {line}")
    return text


def _sha256(text) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -- the record of what the CLI wrote ------------------------------------------

def record_path(root) -> Path:
    return _state_dir(root) / RECORD_NAME


def read_record(root) -> dict:
    """{relative path: sha256}; empty when the CLI wrote nothing yet. An unreadable
    record raises: it is the evidence that a file is the guard's."""
    path = record_path(root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise BenchConfigError(f"{path} is unreadable ({exc.__class__.__name__})") from exc
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict) or not all(isinstance(k, str) and isinstance(v, str)
                                              for k, v in files.items()):
        raise BenchConfigError(f"{path} is not a bench-config record")
    return files


def read_options(root) -> dict:
    """The choices `apply` recorded: `toolchain` (a list of {name, version}) and `no_symlinks`. They
    are inputs the baselines do not hold, so the hook's recomputation reads them here; a record
    without them has none."""
    path = record_path(root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise BenchConfigError(f"{path} is unreadable ({exc.__class__.__name__})") from exc
    options = data.get("options") if isinstance(data, dict) else None
    return options if isinstance(options, dict) else {}


def recorded_paths(root) -> list:
    """Absolute paths the CLI wrote, for the lock on the guard's own files. An
    unreadable record protects nothing it cannot name, so it reads as empty here
    and `verify` reports it."""
    try:
        files = read_record(root)
    except BenchConfigError:
        return []
    return [Path(os.path.abspath(Path(root) / name)) for name in files]


def drift(root) -> list:
    """[(path, why)] for each recorded file whose content is no longer what the CLI wrote:
    missing, unreadable, or a different digest. The record's digest is of the exact text
    for a `.yarnrc` (yarn keeps a carriage return in a value) and of the text with CRLF
    read as LF for the other files (their tools read either). Nothing is compared when
    there is no record, and an unreadable record holds no digest to compare (`verify`
    reports it). Local reads only: the post-hook runs this after every Bash command."""
    try:
        files = read_record(root)
    except BenchConfigError:
        return []
    found = []
    for name, digest in sorted(files.items()):
        path = Path(os.path.abspath(Path(root) / name))
        if not os.path.lexists(path):
            found.append((path, "is missing"))
            continue
        try:
            text = (path.read_bytes().decode("utf-8") if path.name.casefold() == ".yarnrc"
                    else read_text_lf(path))
        except (OSError, UnicodeDecodeError, BenchConfigError):
            found.append((path, "cannot be read as the text the guard wrote"))
            continue
        if _sha256(text) != digest:
            found.append((path, "is not what the guard wrote"))
    return found


def _key(root, path) -> str:
    return Path(os.path.relpath(Path(os.path.abspath(path)), Path(os.path.abspath(root)))).as_posix()


def _write_text(path, text) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp, path.stat().st_mode & 0o777)
        except OSError:
            os.chmod(tmp, 0o666 & ~_umask())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _umask() -> int:
    current = os.umask(0)
    os.umask(current)
    return current


def _casefolded(name) -> str:
    """A file name as NTFS compares it: case-folded, trailing dots and spaces dropped."""
    return name.rstrip(". ").casefold()


def existing_name(directory, name):
    """The entry of `directory` that is `name` by NTFS's comparison, or None."""
    try:
        for entry in os.listdir(directory):
            if _casefolded(entry) == _casefolded(name):
                return entry
    except OSError:
        return None
    return None


# -- apply -------------------------------------------------------------------

class ApplyResult(NamedTuple):
    written: tuple
    unchanged: tuple
    notes: tuple
    dropped: tuple = ()   # recorded files of apps no longer in the bench, now no longer recorded


def _tracked(repo, relative) -> bool:
    try:
        done = subprocess.run(["git", "-C", str(repo), "ls-files", "--", relative],
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(done.stdout.strip())


def _repository_of(path, bench):
    """(repository root, .git entry) of the nearest repository that holds `path`,
    below the bench root; None when there is none."""
    bench = Path(os.path.abspath(bench))
    for parent in Path(os.path.abspath(path)).parents:
        if parent == bench or bench not in parent.parents:
            return None
        if (parent / ".git").exists():
            return parent, parent / ".git"
    return None


def apply(bench, root, config: ConfigInput) -> ApplyResult:
    """Write the files of `expected_files` and record them.

    Every file is planned first and the call refuses, writing nothing, when any
    file that is there is neither equal to what would be written nor equal to the
    record of what this command wrote before: an edited file, or one it never
    wrote, is never overwritten. The bench must be inside the guard root, and its
    env must exist (creating it is the person's step)."""
    bench, root = Path(os.path.abspath(bench)), Path(os.path.abspath(root))
    if bench_root(bench) != bench:
        raise BenchConfigError(f"{bench} is not a bench root (a directory with apps/ and sites/)")
    if root != bench and root not in bench.parents:
        raise BenchConfigError(f"the bench at {bench} is outside the project {root}: its "
                               "baselines and configuration would be somebody else's")
    if not (bench / "env" / "pyvenv.cfg").is_file():
        raise BenchConfigError(f"the bench at {bench} has no Python environment in env/: "
                               "creating it is a step for the person (bench init / setup env)")
    files = expected_files(bench, root, config)
    record = read_record(root)
    stale = stale_entries(bench, root, files)
    plan, unchanged, conflicts, notes = [], [], [], []
    for path, text in files.items():
        entry = existing_name(path.parent, path.name)
        if entry is None:
            plan.append((path, text))
            continue
        target = path.parent / entry
        try:
            raw = target.read_bytes().decode("utf-8")
            current = read_text_lf(target)
        except (OSError, UnicodeDecodeError, BenchConfigError):
            raw = current = None
        if target == path and raw == text:
            unchanged.append(path)
            if record.get(_key(root, path)) != _sha256(text):
                plan.append((path, text))  # exactly what would be written, with no record: adopt it
            continue
        recorded = record.get(_key(root, target))
        if (target == path and current is not None and recorded is not None
                and recorded == _sha256(current)):
            plan.append((path, text))  # what the CLI wrote before (or its CRLF copy): replace it
            continue
        conflicts.append(_diff(target, text, current, recorded))
    if conflicts:
        raise FileConflict("\n".join(conflicts))
    rc = [p for p in files if p.name == ".yarnrc" and p.parent != bench]
    excludes = {}
    for path in rc:
        found = _repository_of(path, bench)
        if found is None:
            continue
        repo, git = found
        relative = Path(os.path.relpath(path, repo)).as_posix()
        if _tracked(repo, relative):
            raise FileConflict(f"{path} is tracked by the git repository at {repo}: the guard "
                               "does not write a file an app commits")
        if git.is_dir():
            excludes.setdefault(git, []).append(f"/{relative}")
        else:
            notes.append(f"{repo} keeps its git directory elsewhere (a worktree or submodule): "
                         f"add /{relative} to its exclude file yourself, or bench will refuse to "
                         "pull")
    for path, text in plan:
        _write_text(path, text)
    for git, lines in excludes.items():
        _append_missing(git / "info" / "exclude", lines)
    if (bench / ".git").exists():
        _append_missing(bench / ".gitattributes", GITATTRIBUTE_LINES)
    # What is recorded is what the apps now in the bench call for: a removed app's file is dropped from
    # the record (the file itself is never touched), and nothing a remaining app needs is.
    updated = {name: digest for name, digest in record.items()
               if Path(os.path.abspath(Path(root) / name)) not in stale}
    for path, text in files.items():
        updated[_key(root, path)] = _sha256(text)
    _write_record(root, updated, config)
    return ApplyResult(tuple(p for p, _t in plan), tuple(unchanged), tuple(notes), tuple(stale))


def stale_entries(bench, root, files) -> list:
    """The recorded files below `bench` that `files` (what `expected_files` computes from the apps
    now in the bench) no longer has: the `.yarnrc` of an app that was removed, or of a folder that
    holds no `package.json` or lock any more. Another bench's entries, and the guard's own state
    files, are never in it."""
    bench = Path(os.path.abspath(bench))
    wanted = {_key(root, path) for path in files}
    found = []
    for name in read_record(root):
        path = Path(os.path.abspath(Path(root) / name))
        if name not in wanted and bench in path.parents and ".claude" not in path.relative_to(bench).parts:
            found.append(path)
    return found


def _stale_text(path) -> str:
    return (f"{path} is recorded as written by the guard, but its app is no longer in the bench: "
            "run bench-config apply to stop recording it")


def _diff(path, expected, current, recorded) -> str:
    import difflib
    if current is None:
        return f"{path} cannot be read as text (a binary file or a bare carriage return)"
    why = ("it has no record of the guard having written it" if recorded is None
           else "it was edited after the guard wrote it")
    diff = "".join(difflib.unified_diff(current.splitlines(True), expected.splitlines(True),
                                        "what is there", "what the guard would write"))
    return f"{path}: {why}, so it is not overwritten.\n{diff}"


def _append_missing(path, lines) -> None:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        text = ""
    present = set(text.splitlines())
    missing = [line for line in lines if line not in present]
    if not missing:
        return
    if text and not text.endswith("\n"):
        text += "\n"
    _write_text(Path(path), text + "\n".join(missing) + "\n")


def _write_record(root, files, config=None) -> None:
    record = {"schema_version": 1, "files": dict(sorted(files.items()))}
    if config is not None:
        record["options"] = {
            "toolchain": [{"name": _normalize(p.name), "version": p.version} for p in sorted(config.toolchain)],
            "no_symlinks": bool(config.no_symlinks),
            "new_apps": sorted({_normalize(n) for n in config.new_apps}),
        }
    body = json.dumps(record, indent=2) + "\n"
    _write_text(record_path(root), body)


# ---------------------------------------------------------------------------
# What the installers will really read
# ---------------------------------------------------------------------------

# pip keys that undo what the guard writes, normalised as pip normalises them
# (lower case, `_` to `-`, a leading `--` dropped). A file other than the
# guard's that sets one, in any section pip reads, is refused.
PIP_GUARDED_KEYS = frozenset({
    "constraint", "build-constraint", "index-url", "extra-index-url", "find-links", "no-index",
    "only-binary", "no-binary", "prefer-binary", "no-build-isolation", "use-pep517", "isolated",
    "trusted-host", "cert", "client-cert", "proxy", "target", "prefix", "root", "user",
    "break-system-packages", "config-settings", "global-option",
    "install-option", "no-deps", "requirement", "editable", "src", "ignore-requires-python",
})
# The sections pip applies to `pip install`: [global], [install], and the
# `:env:` section that the environment variables are loaded into.
_PIP_SECTIONS = ("global", "install", ":env:")

# What a user-level or system uv.toml may hold: cache, link mode, concurrency,
# interpreter downloads and a few modes that change no source. Anything else is
# refused by name; `override-dependencies`, `no-build-isolation`, `index`,
# `extra-index-url` and `sources` are the ones that matter.
UV_USER_KEYS = frozenset({
    "cache-dir", "link-mode", "concurrent-downloads", "concurrent-builds", "concurrent-installs",
    "python-downloads", "python-preference", "native-tls", "offline", "compile-bytecode",
    "preview", "http-timeout", "no-progress", "no-cache", "system-certs",
})
UV_USER_PIP_KEYS = frozenset({"compile-bytecode", "link-mode"})

# What `uv run` itself puts in its child's environment (uv's `commands/project/run.rs`; checked with
# `uv run` 0.12.5 under the guard's own flags): a counter that stops `uv run` calling itself without end.
# The guard runs under `uv run` (run.sh, `pg`), so its own environment carries it. It selects no source,
# index, build or version, so it passes when it is a plain number; any other `UV_` name stays refused.
UV_RUN_CHILD_VARS = frozenset({"UV_RUN_RECURSION_DEPTH"})
UV_RESOLUTION_VARS = verbs.BENCH_RESOLUTION_VARS

# The name `bench new-app` accepts for the app it makes (bench_table's own rule).
NEW_APP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")

# uv skips a pyproject.toml that has no `[tool.uv]` table and looks in the parent
# directory (read from uv's source, not run: a live check item). If it stops
# there instead, set this False and `effective_uv` requires the bench root.
UV_SKIPS_PYPROJECT_WITHOUT_TOOL_UV = True


def _normalize_key(name) -> str:
    key = name.lower().replace("_", "-")
    return key[2:] if key.startswith("--") else key


def _split_dirs(value) -> list:
    return [d for d in (value or "").split(os.pathsep) if d.strip()]


def _pip_config_files(env_dir, home, environ, system_dirs=None) -> list:
    """[(kind, path)] pip may read, lowest precedence first (pip's `OVERRIDE_ORDER`:
    global, user, site, then the `PIP_CONFIG_FILE` file).

    The union over the platforms and the pip versions a bench can have, since the bench
    env's own pip decides and may not be the one the guard's machine has; a file that is
    not there is skipped, one that is there is read as pip would. From pip 26.2.1's source
    (`_internal/configuration.py` `get_configuration_files`, `utils/appdirs.py`, and the
    vendored platformdirs `_xdg.py`, `unix.py`, `macos.py`, `windows.py`; none imported):

    - global: Linux `$XDG_CONFIG_DIRS/pip` (default `/etc/xdg/pip`) and `/etc/pip.conf`;
      macOS `$XDG_DATA_DIRS/pip` or Homebrew's `<prefix>/share/pip` and
      `/Library/Application Support/pip`; Windows `%ALLUSERSPROFILE%\\pip\\pip.ini`;
    - user: the legacy `~/.pip/pip.conf` (`~\\pip\\pip.ini`), Linux
      `$XDG_CONFIG_HOME/pip` or `~/.config/pip`, macOS `$XDG_DATA_HOME/pip` or
      `~/Library/Application Support/pip` (else `~/.config/pip`), Windows `%APPDATA%\\pip`;
    - site: `<env>/pip.conf` (`pip.ini` on Windows), the guard's.

    `system_dirs`, when given, replaces the global directories (a test never reads the
    machine's own). Every other location comes from `home` and `environ`."""
    home = Path(home)
    if system_dirs is None:
        system_dirs = [Path(d) / "pip" for d in _split_dirs(environ.get("XDG_CONFIG_DIRS"))]
        system_dirs += [Path("/etc/xdg/pip"), Path("/etc")]
        system_dirs += [Path(d) / "pip" for d in _split_dirs(environ.get("XDG_DATA_DIRS"))]
        system_dirs += [Path("/Library/Application Support/pip"), Path("/opt/homebrew/share/pip"),
                        Path("/usr/local/share/pip")]
        for name in ("ALLUSERSPROFILE", "PROGRAMDATA"):
            if environ.get(name):
                system_dirs.append(Path(environ[name]) / "pip")
        system_dirs.append(Path("C:/ProgramData/pip"))
    names = ("pip.conf", "pip.ini")
    user_dirs = [home / ".pip", home / "pip"]
    if environ.get("XDG_CONFIG_HOME", "").strip():
        user_dirs.append(Path(environ["XDG_CONFIG_HOME"]) / "pip")
    user_dirs.append(home / ".config" / "pip")
    if environ.get("XDG_DATA_HOME", "").strip():
        user_dirs.append(Path(environ["XDG_DATA_HOME"]) / "pip")
    user_dirs.append(home / "Library" / "Application Support" / "pip")
    if environ.get("APPDATA"):
        user_dirs.append(Path(environ["APPDATA"]) / "pip")
    user_dirs.append(home / "AppData" / "Roaming" / "pip")
    files = [("global", Path(d) / n) for d in dict.fromkeys(system_dirs) for n in names]
    files += [("user", d / n) for d in dict.fromkeys(user_dirs) for n in names]
    files += [("site", Path(env_dir) / n) for n in names]
    extra = next((v for n, v in environ.items() if n.upper() == "PIP_CONFIG_FILE"), None)
    if extra:
        files.append(("env", Path(extra)))
    return files


def effective_pip(env_dir, *, home, environ=None, system_dirs=None) -> list:
    """Why `pip install` into the env at `env_dir` would not use only the guard's
    configuration; [] when it would.

    pip reads the global, user and site files (`<env>/pip.conf`, the guard's), later
    ones over earlier (`_pip_config_files`), and within them the `[global]` section, then
    `[install]`, then the environment's `:env:` (pip's `_get_ordered_configuration_items`):
    for one section and key the value of the last file that sets it is the one kept, and
    an empty value is dropped after that. So a guarded key in a user or system file is
    harmless where the guard's file sets the same key in the same section, because that
    file comes later; it is refused where nothing later overrides it (a key the guard
    does not write, `no-binary` when no build is allowed, or any key under `:env:`,
    which the guard's file never writes). Each refusal names the file and the section."""
    environ = os.environ if environ is None else environ
    problems = []
    if sys.platform == "win32":
        problems.append("pip on Windows reads `pip.ini`, and the guard writes `env/pip.conf`: a "
                        "Frappe bench on native Windows is not supported")
    guard = Path(env_dir) / "pip.conf"
    merged = {}
    for kind, path in _pip_config_files(env_dir, home, environ, system_dirs):
        if kind == "env":
            continue  # PIP_CONFIG_FILE is refused below, with the other variables
        try:
            if not path.is_file():
                continue
            text = read_text_lf(path)
        except OSError:
            continue
        except BenchConfigError as exc:
            problems.append(str(exc))
            continue
        parser = configparser.RawConfigParser()
        try:
            parser.read_string(text, source=str(path))
        except configparser.Error:
            problems.append(f"{path}: unreadable pip configuration")
            continue
        for section in parser.sections():
            if section.lower() not in _PIP_SECTIONS:
                continue
            for option, value in parser.items(section):
                merged[(section, _normalize_key(option))] = (value, path)
    for (section, key), (value, path) in sorted(merged.items()):
        if key in PIP_GUARDED_KEYS and value.strip() and path != guard:
            problems.append(f"{path}: [{section}] {key} would override the guard's pip "
                            "configuration")
    for name in sorted(environ):
        if not name.upper().startswith("PIP_"):
            continue
        category = verbs.classify_env("pip", name, shared=False)
        if category not in (None, "allow"):
            problems.append(f"environment: {name} {verbs.env_reason('pip', category, name)}")
    return problems


class _Unreadable(Exception):
    """A pyproject.toml uv's discovery would read that cannot be read (it may hold anything)."""

    def __init__(self, path):
        super().__init__(str(path))
        self.path = path


def _pyproject(directory):
    """The parsed pyproject.toml of `directory`, None when it has none."""
    path = Path(directory) / "pyproject.toml"
    if not path.is_file():
        return None
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError, RecursionError):
        raise _Unreadable(path) from None
    return data


def _tool_uv(data) -> dict:
    tool = data.get("tool") if isinstance(data, dict) else None
    uv = tool.get("uv") if isinstance(tool, dict) else None
    return uv if isinstance(uv, dict) else {}


def _in_workspace(root, member, uv) -> bool:
    """Whether `member` is a member of the workspace `uv` (the `[tool.uv]` table of the
    pyproject.toml in `root`) declares: matched by the `members` globs, anchored at `root`,
    and not by `exclude`. A table that cannot be read as globs counts as including it:
    refusing is the safe error."""
    workspace = uv.get("workspace")
    if not isinstance(workspace, dict) or "members" not in workspace:
        return False  # no `members`: uv's workspace has no members but the root

    def matches(patterns, malformed) -> bool:
        if not isinstance(patterns, list):
            return malformed
        for pattern in patterns:
            if not isinstance(pattern, str):
                return malformed
            for found in glob.glob(os.path.join(glob.escape(str(root)), pattern), recursive=True):
                if os.path.realpath(found) == os.path.realpath(member):
                    return True
        return False

    # a `members` that is not a list of globs counts as including it, an `exclude` that is
    # not as excluding nothing: either way the workspace root is taken for the search
    return matches(workspace.get("members"), True) and not (
        workspace.get("exclude") is not None and matches(workspace.get("exclude"), False))


def _uv_search_start(cwd):
    """The directory uv looks for its project configuration from, for a command run in
    `cwd` (uv 0.12.5, `crates/uv/src/lib.rs` and `crates/uv-workspace/src/workspace.rs`,
    read, not run). uv discovers a workspace first: the nearest directory from `cwd` up
    that has a pyproject.toml is the project (or an explicit workspace root, with a
    `[tool.uv.workspace]` table); for a project the first ancestor above it that has a
    pyproject.toml is its workspace root when its `[tool.uv.workspace]` includes the
    project, and the walk goes no further. The configuration is then looked for from the
    workspace root, not from `cwd`. A pyproject.toml with neither `[project]` nor
    `[tool.uv.workspace]` (an error to uv), an unmanaged project and no pyproject.toml at
    all leave `cwd` the start. Raises `_Unreadable` for a pyproject.toml uv would read
    that cannot be read."""
    cwd = Path(os.path.realpath(cwd))
    project = next((d for d in (cwd, *cwd.parents) if (d / "pyproject.toml").is_file()), None)
    if project is None:
        return cwd
    data = _pyproject(project)
    uv = _tool_uv(data)
    if isinstance(uv.get("workspace"), dict):
        return project
    if not isinstance(data.get("project"), dict) or uv.get("managed") is False:
        return cwd
    for ancestor in project.parents:
        parent = _pyproject(ancestor)
        if parent is None:
            continue
        if _in_workspace(ancestor, project, _tool_uv(parent)):
            return ancestor
        break
    return project


def _uv_project_config(cwd):
    """(file, start): the file uv reads for a command run in `cwd`, and the directory it
    looked from. The nearest directory, from the start `_uv_search_start` gives up, with a
    `uv.toml` (it wins in its directory) or a `pyproject.toml` that has a `[tool.uv]`
    table; None when there is none. A pyproject.toml that cannot be read is returned: it
    may hold anything."""
    try:
        start = _uv_search_start(cwd)
    except _Unreadable as exc:
        return exc.path, Path(os.path.realpath(cwd))
    for directory in (start, *start.parents):
        uv = directory / "uv.toml"
        if uv.is_file():
            return uv, start
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file():
            try:
                data = _pyproject(directory)
            except _Unreadable:
                return pyproject, start
            if "uv" in (data.get("tool") if isinstance(data.get("tool"), dict) else {}):
                return pyproject, start
            if not UV_SKIPS_PYPROJECT_WITHOUT_TOOL_UV:
                return pyproject, start
    return None, start


def _uv_user_files(home, environ, system_dirs=None) -> list:
    home = Path(home)
    xdg = environ.get("XDG_CONFIG_HOME")
    files = [Path(xdg) / "uv" / "uv.toml"] if xdg else []
    files += [home / ".config" / "uv" / "uv.toml",
              home / "Library" / "Application Support" / "uv" / "uv.toml"]
    appdata = environ.get("APPDATA")
    if appdata:
        files.append(Path(appdata) / "uv" / "uv.toml")
    if system_dirs is None:
        system_dirs = [Path("/etc/uv")]
        system_dirs += [Path(p) / "uv" for p in (environ.get("XDG_CONFIG_DIRS") or "").split(os.pathsep)
                        if p]
    files += [Path(d) / "uv.toml" for d in system_dirs]
    return list(dict.fromkeys(files))


def effective_uv(bench, cwd, *, home, environ=None, system_dirs=None) -> list:
    """Why `uv` run in `cwd` would not use only the guard's `<bench>/uv.toml`; [] when it
    would.

    uv reads one project file, the nearest from `cwd` up, so a command run inside
    `apps/<app>` finds that app's `uv.toml` or `[tool.uv]` first. The user-level and
    system files are merged under it and may hold only `UV_USER_KEYS`. Settings
    spelled as variables, `UV_NO_CONFIG` and `UV_CONFIG_FILE` included, are refused."""
    environ = os.environ if environ is None else environ
    problems = []
    guard = Path(os.path.realpath(Path(bench) / "uv.toml"))
    found, start = _uv_project_config(cwd)
    where = "" if os.path.realpath(start) == os.path.realpath(cwd) else (
        f" (uv looks from {start}, the root of the project or workspace it finds)")
    if found is None:
        problems.append(f"no uv.toml is found from {cwd}{where}: uv would not read the guard's "
                        f"{guard}; run the command from the bench root")
    elif Path(os.path.realpath(found)) != guard:
        problems.append(f"{found} is the configuration uv reads from {cwd}{where}, not the "
                        f"guard's {guard}")
    for path in _uv_user_files(home, environ, system_dirs):
        try:
            if not path.is_file():
                continue
            text = read_text_lf(path)
        except OSError:
            continue
        except BenchConfigError as exc:
            problems.append(str(exc))
            continue
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            problems.append(f"{path}: unreadable uv configuration")
            continue
        for key, value in data.items():
            if key == "pip" and isinstance(value, dict):
                problems += [f"{path}: [pip] {k} is not a setting a user-level uv.toml may hold "
                             "in a bench" for k in value if k not in UV_USER_PIP_KEYS]
            elif key not in UV_USER_KEYS:
                problems.append(f"{path}: {key} is not a setting a user-level uv.toml may hold "
                                "in a bench")
    for name in sorted(environ):
        if not name.upper().startswith("UV_"):
            continue
        if name.upper() in UV_RUN_CHILD_VARS and environ[name].strip().isdigit():
            continue
        if name.upper() in UV_RESOLUTION_VARS:
            problems.append(f"environment: {name} changes which release uv picks (a pre-release, the lowest, "
                            "one newer than the cool-down); the bench installs the releases that were approved")
            continue
        category = verbs.classify_env("uv", name, shared=False)
        if category not in (None, "allow", "locked", "path"):
            problems.append(f"environment: {name} {verbs.env_reason('uv', category, name)}")
    return problems


def _yarn_classic_config():
    """P2's effective Yarn Classic configuration, or None when this build has not got it."""
    return getattr(pm_config, "yarn_classic_config", None)


def effective_yarn(bench, *, home, environ=None, yarn_config=None) -> list:
    """Why `yarn install` in a directory of the bench would not run frozen with
    scripts off; [] when it would. The computation is `pm_config.yarn_classic_config`
    (the effective `.yarnrc` chain and the environment); this only asks it, once for
    each directory that carries the guard's `.yarnrc`, and refuses when it is missing."""
    environ = os.environ if environ is None else environ
    compute = yarn_config or _yarn_classic_config()
    if compute is None:
        return ["the effective Yarn Classic configuration cannot be computed in this build"]
    problems = []
    for directory in yarn_dirs(bench):
        config = compute(directory, home, environ, command="install")
        problems += list(config.problems)
        if not config.scripts_off:
            problems.append(f"{directory}: yarn would run dependency scripts "
                            f"({config.scripts_reason})")
        if not config.frozen:
            problems.append(f"{directory}: yarn would not freeze the lockfile "
                            f"({config.frozen_reason})")
    return problems


def file_problems(bench, root, config: ConfigInput) -> list:
    """Why a file the guard writes is missing, edited, or not the one the CLI wrote.

    The expected text is recomputed from `config`, never read back. A CRLF copy of
    `pip.conf`, `uv.toml` or a constraint file is the same file (those tools read
    it); a `.yarnrc` must be exact, because yarn keeps a carriage return in a value."""
    try:
        files = expected_files(bench, root, config)
        record = read_record(root)
    except BenchConfigError as exc:
        return [str(exc)]
    problems = []
    for path, text in files.items():
        if not path.is_file():
            problems.append(f"{path} is missing")
            continue
        entry = existing_name(path.parent, path.name)
        if entry != path.name:
            problems.append(f"{path.parent / (entry or path.name)} is not spelled {path.name}")
            continue
        try:
            raw = path.read_bytes().decode("utf-8")
            current = read_text_lf(path)
        except (OSError, UnicodeDecodeError, BenchConfigError) as exc:
            problems.append(str(exc))
            continue
        if current != text or (path.name == ".yarnrc" and raw != text):
            problems.append(f"{path} is not what the guard would write now")
        elif record.get(_key(root, path)) != _sha256(text):
            problems.append(f"{path} is not recorded as written by the guard")
    problems += [_stale_text(path) for path in stale_entries(bench, root, files)]
    return problems


def recorded_file_problems(bench, root) -> list:
    """Why a file the CLI recorded is missing or is no longer what it wrote: the check for a verb
    that installs nothing (a build), which needs the files to hold but has no baseline to
    recompute them from. An empty record is a problem: nothing was ever applied."""
    try:
        record = read_record(root)
    except BenchConfigError as exc:
        return [str(exc)]
    if not record:
        return ["the guard has written no installer files for this bench yet"]
    problems, bench = [], Path(os.path.abspath(bench))
    for name, digest in sorted(record.items()):
        path = Path(os.path.abspath(Path(root) / name))
        if bench not in path.parents and ".claude" not in path.parts:
            continue  # another bench's file
        entry = existing_name(path.parent, path.name)
        if entry != path.name:
            if entry is None and not path.parent.exists() and bench in path.parents:
                problems.append(_stale_text(path))  # the folder is gone: the app was removed
            else:
                problems.append(f"{path} is missing" if entry is None
                                else f"{path.parent / entry} is not spelled {path.name}")
            continue
        try:
            raw = path.read_bytes().decode("utf-8")
            text = read_text_lf(path)
        except (OSError, UnicodeDecodeError, BenchConfigError) as exc:
            problems.append(str(exc))
            continue
        if _sha256(text) != digest or (path.name == ".yarnrc" and "\r" in raw):
            problems.append(f"{path} is not what the guard wrote")
    return problems


def verify_recorded(bench, root, *, cwd=None, home=None, environ=None, yarn_config=None,
                    system_dirs=None) -> list:
    """`verify` for a verb with no baselines to recompute from: the recorded files hold, and
    nothing overrides them."""
    bench = Path(os.path.abspath(bench))
    cwd = bench if cwd is None else cwd
    home = Path.home() if home is None else home
    environ = os.environ if environ is None else environ
    problems = recorded_file_problems(bench, root)
    problems += effective_pip(bench / "env", home=home, environ=environ, system_dirs=system_dirs)
    problems += effective_uv(bench, cwd, home=home, environ=environ, system_dirs=system_dirs)
    problems += effective_yarn(bench, home=home, environ=environ, yarn_config=yarn_config)
    return list(dict.fromkeys(problems))


def verify(bench, root, config: ConfigInput, *, cwd=None, home=None, environ=None,
           yarn_config=None, system_dirs=None) -> list:
    """Every reason an install in `cwd` (default the bench root) would run without the
    guard's configuration; [] means none was found. Local reads only: no network, no
    subprocess. The hook adds its own prefix to a reason."""
    bench = Path(os.path.abspath(bench))
    cwd = bench if cwd is None else cwd
    home = Path.home() if home is None else home
    environ = os.environ if environ is None else environ
    problems = file_problems(bench, root, config)
    problems += effective_pip(bench / "env", home=home, environ=environ, system_dirs=system_dirs)
    problems += effective_uv(bench, cwd, home=home, environ=environ, system_dirs=system_dirs)
    problems += effective_yarn(bench, home=home, environ=environ, yarn_config=yarn_config)
    return list(dict.fromkeys(problems))


# -- the lock on the files the guard wrote ---------------------------------------

def fold_path(path) -> str:
    """`path` as NTFS compares it: absolute, case-folded, each component without
    trailing dots and spaces. Lexical: no link is followed."""
    parts = os.path.abspath(path).split(os.sep)
    return os.sep.join(part.rstrip(". ").casefold() for part in parts)


def config_paths(root) -> list:
    """The files the CLI wrote, folded, as they are and with their links resolved,
    for the lock on them: [] before the CLI has written any."""
    found = []
    for path in recorded_paths(root):
        found += [fold_path(path), fold_path(os.path.realpath(path))]
    return list(dict.fromkeys(found))


def is_config_path(path, root) -> bool:
    """True when `path` is a file the CLI recorded as one it wrote."""
    wanted = config_paths(root)
    return bool(wanted) and (fold_path(path) in wanted
                             or fold_path(os.path.realpath(path)) in wanted)
