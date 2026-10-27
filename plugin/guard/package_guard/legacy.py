"""What the old Frappe versions (v11, v12, v13) need that the current ones do not.

Many sites cannot move off them, so they are first-class, not trimmed. The guard's job
there is the same as everywhere: stop a WRONG package. Old but genuine packages with
known advisories are information (see `baseline.prompt_text`), never a gate.

  * the Python a baseline's markers are evaluated for, when the app declares none;
  * the dependency metadata uv cannot parse for one exact version (`legacy-overrides.json`);
  * the one command the person runs, once, to build node-sass;
  * the bench releases those versions are installed with.

Standard library only.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

OVERRIDES_FILE = Path(__file__).resolve().parent / "legacy-overrides.json"

# The Python a v11, v12 or v13 baseline is compiled for. Python 3.7 cannot be downloaded
# by uv, so the compile evaluates markers for it under another interpreter and nothing of
# that version runs; the baseline says so. v11 and v12 are Python 3.6/3.7 apps, v13 is 3.7+.
LEGACY_PYTHON_BY_MAJOR = {11: "3.7", 12: "3.7", 13: "3.8"}

_VERSION = re.compile(r"""^__version__\s*=\s*['"]([0-9]+)\.[^'"]*['"]""", re.MULTILINE)


def app_major_version(tree):
    """The major version in the app's `<package>/__init__.py` (the package that holds
    `hooks.py`), or None. Read as text; nothing is imported or run."""
    for path in tree.paths():
        parts = path.split("/")
        if len(parts) == 2 and parts[1] == "hooks.py":
            try:
                text = tree.read(f"{parts[0]}/__init__.py").decode("utf-8")
            except (OSError, UnicodeDecodeError, ValueError):
                continue
            match = _VERSION.search(text.replace("\r\n", "\n"))
            if match:
                return int(match.group(1))
    return None


def python_version_for_app(tree):
    """The legacy Python for an app with no `requires-python`, or None."""
    major = app_major_version(tree)
    return LEGACY_PYTHON_BY_MAJOR.get(major)


def metadata_overrides() -> list:
    """The shipped dependency-metadata overrides: [{name, version, requires-dist, reason, source}]."""
    data = json.loads(OVERRIDES_FILE.read_text(encoding="utf-8"))
    return list(data["dependency_metadata"])


def override_for(name, version, table=None):
    """The override for exactly this name (PEP 503 normalised) and version, or None."""
    wanted = re.sub(r"[-_.]+", "-", name).lower()
    for entry in table if table is not None else metadata_overrides():
        if re.sub(r"[-_.]+", "-", entry["name"]).lower() == wanted and entry["version"] == version:
            return entry
    return None


def uv_config_text(entries) -> str:
    """The uv.toml the plan passes with `--config-file` for the entries that applied."""
    rows = []
    for entry in entries:
        requires = ", ".join(json.dumps(r) for r in entry["requires-dist"])
        rows.append(f'  {{ name = {json.dumps(entry["name"])}, version = {json.dumps(entry["version"])}, '
                    f"requires-dist = [{requires}] }},")
    return "dependency-metadata = [\n" + "\n".join(rows) + "\n]\n"


# ---------------------------------------------------------------------------
# node-sass (v11 to v13)
# ---------------------------------------------------------------------------

NODE_SASS = "node-sass"


def node_sass_versions(doc) -> list:
    """The node-sass versions a baseline's locks list among the packages that carry an install script."""
    return sorted({s["version"] for lock in doc["js"]["locks"] for s in lock["scripts"] if s["name"] == NODE_SASS})


def node_sass_command(app_dir="apps/<app>") -> str:
    """The command the person runs, once, in their own terminal, after the install (which ran with
    scripts off). Scoped to node-sass: `YARN_IGNORE_SCRIPTS=false yarn install` would run the
    scripts of every locked package, and is not offered."""
    target = f"{app_dir}/node_modules/node-sass"
    target = target if "<" in target else shlex.quote(target)
    return f"cd {target} && node scripts/install.js && node scripts/build.js"


def node_sass_lines(doc, app_dir="apps/<app>") -> list:
    """The summary lines for a baseline that locks node-sass; [] otherwise."""
    versions = node_sass_versions(doc)
    if not versions:
        return []
    others = sorted({f"{s['name']}@{s['version']}" for lock in doc["js"]["locks"] for s in lock["scripts"]
                     if s["name"] != NODE_SASS})
    return [
        f"node-sass {', '.join(versions)} downloads a native binding (a compiled program that is loaded) with no "
        "checksum, so Claude never runs its install script and the guard does not allow it.",
        f"  After the install, in your own terminal, once: {node_sass_command(app_dir)}",
        "  This is scoped to node-sass"
        + (f"; the scripts of the other {len(others)} packages that carry one stay off" if others else "")
        + ". Do not use `YARN_IGNORE_SCRIPTS=false yarn install`: it runs every locked package's script.",
    ]


# ---------------------------------------------------------------------------
# The bench releases these versions are installed with
# ---------------------------------------------------------------------------

# (first tag, last tag, tag dates, how the bench installs an app's Python packages, how it
# installs JavaScript, which Frappe versions were current then). Read from frappe/bench at
# those tags (git grep), nothing run. "Current then" is by date, not an official support
# matrix, which the repository does not hold. Every release before 5.25.2 installs with
# the env's own pip.
BENCH_RELEASES = (
    {"tags": ("v4.1", "v5.0"), "dates": "2020-03-24", "python": "env pip install -U -e <app> (get-app, new-app); the bench's own requirements with pip -r",
     "javascript": "yarn install per app, npm install below Frappe 11", "frappe": (11, 12)},
    {"tags": ("v5.1", "v5.2", "v5.2.1"), "dates": "2020-05-22 to 2020-08-24", "python": "env pip install -U -e <app>",
     "javascript": "yarn install per app, npm install below Frappe 11", "frappe": (11, 12)},
    {"tags": ("v5.3.0", "v5.4.0", "v5.4.1"), "dates": "2021-02-04 to 2021-05-17", "python": "env python -m pip install -U -e <app>",
     "javascript": "yarn install per app", "frappe": (12, 13)},
    {"tags": ("v5.5.0", "v5.6.0"), "dates": "2021-07-29 to 2021-09-13", "python": "env python -m pip install -U -e <app>",
     "javascript": "yarn install per app", "frappe": (12, 13)},
    {"tags": ("v5.7.0", "v5.19.0"), "dates": "2021-12-01 to 2023-11-02", "python": "env python -m pip install --upgrade -e <app>; from 5.19 also pip and wheel upgraded",
     "javascript": "yarn install per app", "frappe": (13, 14, 15)},
)

# The releases whose verbs and installs were read from source for v11, v12 and v13. The range
# a bench is allowed in is set by the matrix run (the last stage); this is what the table covers.
LEGACY_BENCH_TAGS = tuple(tag for row in BENCH_RELEASES for tag in row["tags"])


def legacy_bench_row(version):
    """The BENCH_RELEASES row whose tags include `version` ("5.2.1" and "v5.2.1" alike), or None."""
    wanted = version if version.startswith("v") else "v" + version
    for row in BENCH_RELEASES:
        if wanted in row["tags"]:
            return row
    return None
