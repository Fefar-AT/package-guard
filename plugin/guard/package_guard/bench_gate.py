"""What the hook must know about a Frappe bench before it lets a bench verb run.

`bench_config` says where a bench is and writes and checks the installer files.
This module reads the rest, from disk and without running bench:

  * the installed `bench` package (its version, and its own `patches.txt`);
  * the apps of the bench and their local versions;
  * which distributions the bench's env holds as editable installs of its apps;
  * the one function that turns approved baselines into the `ConfigInput` both
    `apply` and the hook's recomputation use, so they cannot disagree;
  * every call into the baseline module, in one place.

Nothing here decides; each function answers with data or with reasons, and the
hook decides. Standard library, `bench_config` and (lazily) `baseline`.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import NamedTuple

import bench_config

# The `frappe-bench` releases whose verb semantics the design checked: v4.1 and v5.0 hand
# requirements files to `pip install -U`, v5.2.1 to `-e`, current ones to uv. Inclusive. A
# placeholder until the lab matrix has run on real benches: a version outside it is refused,
# so a release nobody looked at runs nothing.
BENCH_TESTED = ((4, 1, 0), (5, 31, 99))

# Frappe below this version installs its node packages through one `npm install` written at
# the bench root, which no gate here reads.
NODE_YARN_FROM = 11

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


# -- the installed bench package -----------------------------------------------------------

class BenchInstall(NamedTuple):
    executable: str
    version_text: str
    version: tuple | None
    patches_file: Path | None


def _site_packages(prefix) -> list:
    base = Path(prefix)
    found, seen = [], set()
    for lib in ("lib", "lib64", "Lib"):
        candidates = sorted((base / lib).glob("python*/site-packages"))
        if (base / lib / "site-packages").is_dir():
            candidates.append(base / lib / "site-packages")
        for candidate in candidates:
            try:
                info = os.stat(candidate)
            except OSError:
                continue
            key = (info.st_dev, info.st_ino)  # `Lib` and `lib` are one directory on a case-insensitive volume
            if key not in seen:
                seen.add(key)
                found.append(candidate)
    return found


def _shebang_prefix(script) -> Path | None:
    try:
        first = Path(script).read_bytes()[:300].split(b"\n", 1)[0].decode("utf-8", "replace")
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    words = first[2:].split()
    if not words:
        return None
    if os.path.basename(words[0]) == "env" and len(words) > 1:
        return None  # `#!/usr/bin/env python3` names no environment
    return Path(words[0]).parent.parent


def read_bench_install(path_env=None, which=shutil.which, executable=None, cwd=None) -> BenchInstall:
    """The `bench` the shell will run, read from disk: its version and patches file.

    `executable` is the word the command named: a path (`./env/bin/bench`) is that file, relative
    to `cwd`; a bare name, or none, is `bench` found on `path_env` (the hook's own PATH by default).
    The environment it runs in
    is found from its script's first line and its own directory, and the version is read from
    the `frappe_bench-*.dist-info` there. Raises BenchConfigError with the reason when any of it
    cannot be read: an unreadable bench is not a tested one. UNVERIFIED live: the hook's PATH
    may differ from the shell's."""
    if executable and ("/" in executable or "\\" in executable):
        named = Path(executable) if Path(executable).is_absolute() else Path(cwd or ".") / executable
        executable = str(named) if named.is_file() else None
    else:
        executable = which(executable or "bench", path=path_env)
    if not executable:
        raise bench_config.BenchConfigError("`bench` is not on the PATH the hook sees")
    script = Path(executable)
    prefixes = []
    for candidate in (_shebang_prefix(script), script.parent.parent,
                      Path(os.path.realpath(script)).parent.parent):
        if candidate is not None and candidate not in prefixes:
            prefixes.append(candidate)
    found = []
    for prefix in prefixes:
        for site in _site_packages(prefix):
            for dist in sorted(site.glob("frappe[_-]bench-*.dist-info")):
                found.append((site, dist))
        if found:
            break
    if not found:
        raise bench_config.BenchConfigError(
            f"no frappe_bench dist-info was found beside {executable}")
    if len({str(dist) for _site, dist in found}) > 1:
        raise bench_config.BenchConfigError(
            f"more than one frappe_bench install is visible beside {executable}")
    site, dist = found[0]
    try:
        metadata = (dist / "METADATA").read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise bench_config.BenchConfigError(f"{dist}/METADATA cannot be read ({exc.__class__.__name__})")
    match = re.search(r"^Version:\s*(\S+)", metadata, re.MULTILINE)
    if not match:
        raise bench_config.BenchConfigError(f"{dist}/METADATA names no version")
    text = match.group(1)
    parsed = _VERSION.match(text)
    version = tuple(int(part) for part in parsed.groups()) if parsed else None
    source = site / "bench" / "patches" / "patches.txt"
    try:
        direct = json.loads((dist / "direct_url.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        direct = None
    if isinstance(direct, dict) and (direct.get("dir_info") or {}).get("editable"):
        url = str(direct.get("url") or "")
        if url.startswith("file://"):
            source = Path(url[len("file://"):]) / "bench" / "patches" / "patches.txt"
    return BenchInstall(executable, text, version, source if source.is_file() else None)


def version_problem(install: BenchInstall, tested=BENCH_TESTED) -> str | None:
    """Why this bench release is not one the hook runs verbs for, or None."""
    if install.version is None:
        return f"the version of the bench at {install.executable} ({install.version_text!r}) cannot be read"
    low, high = tested
    if not low <= install.version <= high:
        shown = lambda t: ".".join(map(str, t))
        return (f"bench {install.version_text} is outside the releases Package Guard has checked "
                f"({shown(low)} to {shown(high)})")
    return None


def missing_patches(bench, install: BenchInstall) -> list:
    """The entries of the installed bench's patches.txt that `<bench>/patches.txt` lacks, as bench's
    `patches.run` compares them (the entry as written, against the raw lines of the bench's own file).
    `bench update` runs each one unseen, and one of them installs a package. Raises BenchConfigError
    when the installed list cannot be read: an unknown list may name anything."""
    if install.patches_file is None:
        raise bench_config.BenchConfigError("the installed bench's patches.txt cannot be found")
    try:
        wanted = [line.strip() for line in install.patches_file.read_text(encoding="utf-8").splitlines()
                  if line.strip() and not line.strip().startswith("#")]
    except OSError as exc:
        raise bench_config.BenchConfigError(f"{install.patches_file} cannot be read ({exc.__class__.__name__})")
    try:
        done = (Path(bench) / "patches.txt").read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        done = []
    except OSError as exc:
        raise bench_config.BenchConfigError(f"{Path(bench) / 'patches.txt'} cannot be read ({exc.__class__.__name__})")
    return [patch for patch in wanted if patch not in done]


# -- the apps ------------------------------------------------------------------------

def dist_name(app) -> str:
    """The distribution name of an app: its pyproject `[project].name`, else its directory's name."""
    project = bench_config._toml(Path(app) / "pyproject.toml").get("project")
    declared = project.get("name") if isinstance(project, dict) else None
    return bench_config._normalize(declared if isinstance(declared, str) and declared.strip()
                                   else Path(app).name)


def frappe_major(bench) -> int | None:
    """The major version of `apps/frappe`, or None when it is not written down plainly."""
    import baseline
    version, _why = baseline.local_app_version(Path(bench) / "apps" / "frappe")
    if version is None:
        return None
    return int(version.split(".")[0])


# -- the env -------------------------------------------------------------------------

def editable_installs(env) -> dict:
    """{normalised distribution name: directory} of the distributions in `env` that are editable
    installs of a directory (`direct_url.json` with `dir_info.editable`)."""
    found = {}
    for site in _site_packages(env):
        for dist in site.glob("*.dist-info"):
            try:
                direct = json.loads((dist / "direct_url.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not (isinstance(direct, dict) and (direct.get("dir_info") or {}).get("editable")):
                continue
            url = str(direct.get("url") or "")
            if url.startswith("file://"):
                name = re.sub(r"-[0-9][^-]*$", "", dist.name[:-len(".dist-info")])
                found[bench_config._normalize(name)] = Path(url[len("file://"):])
    return found


def interpreter_version(env) -> tuple | None:
    """The (major, minor) Python of `env`, from its pyvenv.cfg."""
    try:
        text = (Path(env) / "pyvenv.cfg").read_text(encoding="utf-8")
    except OSError:
        return None
    match = re.search(r"^version(?:_info)?\s*=\s*(\d+)\.(\d+)", text, re.MULTILINE)
    return (int(match.group(1)), int(match.group(2))) if match else None


def requires_python_problem(requires, env) -> str | None:
    """Why the Python of `env` is not inside a baseline's `requires_python` (`>=3.10,<3.15`), or None."""
    have = interpreter_version(env)
    if have is None:
        return f"the Python of {env} cannot be read from its pyvenv.cfg"
    for clause in (c.strip() for c in str(requires or "").split(",") if c.strip()):
        match = re.match(r"(>=|<=|==|!=|>|<)\s*(\d+)(?:\.(\d+))?", clause)
        if not match:
            return f"requires_python {requires!r} cannot be read"
        op, major, minor = match.group(1), int(match.group(2)), int(match.group(3) or 0)
        bound = (major, minor)
        ok = {">=": have >= bound, "<=": have <= bound, ">": have > bound, "<": have < bound,
              "==": have == bound, "!=": have != bound}[op]
        if not ok:
            return f"the env's Python {have[0]}.{have[1]} is outside {requires}"
    return None


# -- the baselines (every call into baseline.py) -----------------------------------------------

def local_names(bench, apps, docs=()) -> set:
    """Every name that is local in this bench: the apps that are in it (directory and distribution),
    and nothing else. A known Frappe app that is not in `apps/` is not local; it never comes from
    PyPI either (`baseline.declared_dependencies` refuses it). `docs` is kept for old callers."""
    names = set()
    for app in apps:
        names.add(bench_config._normalize(Path(app).name))
        names.add(dist_name(app))
    return names


def absent_excluded_names(docs, names) -> list:
    """[(baseline id, name)] for each local name a baseline left out of its pins that no app of this
    bench provides: the requirement was dropped as local code, and nothing local answers it."""
    return [(doc["id"], n) for doc in docs for n in doc["python"]["excluded_local_names"]
            if bench_config._normalize(n) not in names]


def load_baseline(root, baseline_id) -> dict:
    import baseline
    return baseline.load(root, baseline_id)


def covering_of(root, apps, names, now=None) -> dict:
    """{app directory: baseline.covering(...)} for each app."""
    import baseline
    return {Path(app): baseline.covering(root, app, tuple(sorted(names)), now) for app in apps}


def baseline_docs(coverings) -> list:
    """The approved baseline documents that cover the apps, once each, in a stable order."""
    seen, docs = set(), []
    for app in sorted(coverings):
        covering = coverings[app]
        if covering.get("kind") == "baseline" and covering["baseline"]["id"] not in seen:
            seen.add(covering["baseline"]["id"])
            docs.append(covering["baseline"])
    return docs


def _spec_name(spec) -> str:
    return bench_config._normalize(str(spec).split("@", 1)[0])


def allowed_build_names(docs) -> tuple:
    return tuple(sorted({_spec_name(spec) for doc in docs
                         for spec in ((doc.get("approval") or {}).get("allowed_builds") or [])}))


def unapproved_builds(docs) -> list:
    """[(baseline id, name)] of a baseline's `needs_build` entries that its approval did not allow."""
    found = []
    for doc in docs:
        allowed = {_spec_name(s) for s in (doc.get("approval") or {}).get("allowed_builds") or []}
        for entry in doc["python"]["needs_build"]:
            if bench_config._normalize(entry["name"]) not in allowed:
                found.append((doc["id"], entry["name"]))
    return found


def new_app_problem(config) -> str | None:
    """Why the apps named for `bench new-app` cannot be listed for uv to build: a requirement of the
    bench names a package of the same name (None when none does)."""
    clash = sorted(set(config.new_apps) & {bench_config._normalize(n) for n in config.requirement_names})
    if not clash:
        return None
    return (f"{', '.join(clash)} cannot be named as an app `bench new-app` is about to create: a requirement of "
            "this bench asks for a package of that name, and an app named like it would let uv build that "
            "package from source (running its setup code) instead of installing the reviewed wheel. Pick "
            "another name for the app")


def config_input(root, bench, now=None, new_apps=None) -> bench_config.ConfigInput:
    """The `ConfigInput` for a bench, from `baseline.config_input` and the choices `apply` recorded
    (the toolchain the person chose, whether symlinks are avoided): `apply` and the hook's
    recomputation both call this one function, so they cannot disagree. Raises BenchConfigError
    with the reason when it cannot be built (an upstream app no baseline covers, a local app whose
    version cannot be pinned, two baselines that disagree about a pin, an app name `apply --new-app`
    was given that a requirement of the bench names too). `new_apps`, when given, replaces the names
    the record holds: `apply` passes exactly the names of its own command line, so a name lasts until
    the next `apply`."""
    import baseline
    options = bench_config.read_options(root)
    toolchain = tuple((t["name"], t["version"]) for t in options.get("toolchain") or [])
    try:
        config = baseline.config_input(root, bench, toolchain, bool(options.get("no_symlinks")), now)
        # Apps the person named before `bench new-app`, until the app is there and is listed as any app.
        present = {bench_config._normalize(Path(app).name) for app in bench_config.bench_apps(bench)}
        present |= {bench_config._normalize(name) for name, _version in config.local_apps}
        named = options.get("new_apps") or [] if new_apps is None else new_apps
        new_apps = tuple(sorted({bench_config._normalize(n) for n in named} - present))
        config = dataclasses.replace(config, new_apps=new_apps)
        why = new_app_problem(config)
        if why:
            raise bench_config.BenchConfigError(why)
        return config
    except baseline.BaselineError as exc:
        error = bench_config.BenchConfigError(str(exc))
        error.baseline = True  # the hook answers with the baseline message, not the config one
        raise error from exc


# -- what the env holds, and who covers it -----------------------------------------------------

def _requires(dist) -> list:
    """The normalised names a distribution's METADATA requires, without the extras it only
    offers (`Requires-Dist: x ; extra == 'y'`)."""
    try:
        text = (Path(dist) / "METADATA").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    names = []
    for line in text.splitlines():
        if not line.startswith("Requires-Dist:"):
            continue
        spec = line.split(":", 1)[1]
        if re.search(r"extra\s*==", spec):
            continue
        name = bench_config.requirement_name(spec)
        if name:
            names.append(name)
    return names


def env_unreadable(env) -> list:
    """Why the env cannot be read in full: a site-packages that cannot be listed, a dist-info
    with no readable METADATA (half written). [] when everything can be read."""
    import inventory
    problems = []
    if not (Path(env) / "pyvenv.cfg").is_file():
        return [f"{env} has no pyvenv.cfg"]
    for site in inventory.site_packages_dirs(env):
        try:
            entries = list(os.scandir(site))
        except OSError as exc:
            problems.append(f"{site} cannot be listed ({exc.__class__.__name__})")
            continue
        for entry in entries:
            if entry.name.endswith(".dist-info"):
                try:
                    with open(Path(entry.path) / "METADATA", "rb") as handle:
                        handle.read(1)
                except OSError as exc:
                    problems.append(f"{entry.path}/METADATA cannot be read ({exc.__class__.__name__})")
    return problems


def approved_identities(root) -> tuple:
    """({(name, version)} the approved baselines and the recorded toolchain list, [reasons])."""
    import baseline
    docs, problems = baseline.load_approved(root)
    identities = set()
    for doc in docs:
        identities.update((name, version) for eco, name, version in baseline.covered_identities(doc)
                          if eco == "pypi")
    try:
        options = bench_config.read_options(root)
    except bench_config.BenchConfigError as exc:
        problems = list(problems) + [str(exc)]
        options = {}
    for tool in options.get("toolchain") or []:
        identities.add((bench_config._normalize(tool["name"]), tool["version"]))
    return identities, list(problems)


def env_residue(root, bench, installed, is_vetted) -> list:
    """The packages of `installed` (the env's distributions) that nothing covers: not an identity
    an approved baseline or the recorded toolchain lists, not vetted, not required (transitively,
    by METADATA, without extras) by one that is, and not an editable install of an app of the bench
    (`bench_config.bench_apps`). This is what turns "constrained" into "checked"."""
    identities, _problems = approved_identities(root)
    env = Path(bench) / "env"
    apps = {os.path.realpath(app) for app in bench_config.bench_apps(bench)}
    editable = {name for name, where in editable_installs(env).items()
                if os.path.realpath(where) in apps}
    seeds = [p for p in installed
             if (p.name, p.version) in identities or p.name in editable or is_vetted(p)]
    left = [p for p in installed if p not in seeds]
    if not left:
        return []
    # An editable app is exempt itself, but what its METADATA requires is not: a custom app's
    # direct dependencies are reviewed one by one (an upstream app's are the baseline's identities).
    reach, frontier = set(), [Path(p.path) for p in seeds if p.name not in editable]
    while frontier:
        dist = frontier.pop()
        for name in _requires(dist):
            if name not in reach:
                reach.add(name)
                frontier.extend(Path(p.path) for p in installed if p.name == name)
    return [p for p in left if p.name not in reach]


def _under(path, base) -> bool:
    path, base = os.path.realpath(path), os.path.realpath(base)
    return path == base or path.startswith(base + os.sep)


# -- problems the post-hook found, and what the last allowed command used ----------------------------------

PROBLEMS_FILE = "bench-problems.json"
ALLOWED_FILE = "bench-allowed.json"


def _state_file(root, name) -> Path:
    return bench_config._state_dir(root) / name


def read_problems(root) -> list:
    """The open problems: [{kind, text, detected_at}]. An unreadable file is a problem of its own
    (it is the record that something is wrong)."""
    path = _state_file(root, PROBLEMS_FILE)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        return [{"kind": "record", "text": f"{path} is unreadable", "detected_at": None}]
    found = data.get("problems") if isinstance(data, dict) else None
    return [p for p in found if isinstance(p, dict)] if isinstance(found, list) else [
        {"kind": "record", "text": f"{path} is not a problems record", "detected_at": None}]


def _write_json(root, name, data) -> None:
    import store
    store._atomic_write_json(_state_file(root, name), data)


def add_problems(root, found, now, command=None) -> None:
    """Record problems the post-hook found: [(kind, text, check)], `check` being what `still_holds`
    re-evaluates. They stay until `cli.py reconcile` finds that none holds."""
    current = [p for p in read_problems(root) if p.get("kind") != "record"]
    have = {(p.get("kind"), p.get("text")) for p in current}
    for kind, text, check in found:
        if (kind, text) not in have:
            current.append({"kind": kind, "text": text, "detected_at": now, "command": command,
                            "check": check})
    _write_json(root, PROBLEMS_FILE, {"schema_version": 1, "problems": current})


def clear_problems(root) -> None:
    try:
        _state_file(root, PROBLEMS_FILE).unlink()
    except FileNotFoundError:
        pass


def record_allowed(root, bench, apps, tool_use_id=None, command=None) -> None:
    """What the command the hook just allowed was covered by: [{app dir, baseline id}], so the
    post-hook compares each app with the digests THAT BASELINE recorded, not with what the
    pre-hook read. `tool_use_id` ties the record to the command that ran, so a command the rest of
    the gate went on to refuse leaves nothing that a later command is judged by. Records are kept
    per command and each is taken only by its own completion, so another command's post-hook, or
    a second command allowed before the first one ends, does not lose it."""
    now = time.time()
    kept = [r for r in _allowed_records(root) if now - float(r.get("at") or 0) < _ALLOWED_KEEP_SECONDS]
    kept = [r for r in kept if not allowed_matches(r, {"tool_use_id": tool_use_id,
                                                      "tool_input": {"command": command}})]
    kept.append({"bench": str(bench), "apps": apps, "tool_use_id": tool_use_id, "command": command,
                 "at": now})
    _write_json(root, ALLOWED_FILE, {"schema_version": 2, "records": kept[-_ALLOWED_KEEP_COUNT:]})


def local_name_problems(app, names, apps, editable) -> list:
    """Reasons an app's requirement lines name a local app that is present in the bench and is not
    installed in the env as an editable install from `apps/`. Such a line (Frappe v11 erpnext's
    first line is a bare `frappe`) is harmless only because the constraints pin the name and the
    editable install satisfies the pin; without the editable, an index could be asked."""
    app = Path(app)
    own = {dist_name(app), bench_config._normalize(app.name)}
    app_dir = {}
    for a in apps:
        app_dir[dist_name(a)] = a
        app_dir[bench_config._normalize(Path(a).name)] = a
    present = set(app_dir)
    lines = []
    for path in sorted(app.glob("requirements*.txt")) + sorted(app.glob("*requirements*.txt")):
        lines += [(f"{path.name}, line {n}", name) for n, name, _line in bench_config.requirements_file_names(path)]
    lines += [(f"pyproject.toml ({where})", name)
              for where, name in bench_config.pyproject_names(app / "pyproject.toml")]
    reasons = []
    for where, name in dict.fromkeys(lines):
        if name in own or name not in names or name not in present:
            continue
        # An editable install of THAT app: one of another directory leaves the name to the index.
        if name not in editable or os.path.realpath(editable[name]) != os.path.realpath(app_dir[name]):
            reasons.append(f"apps/{app.name}/{where} names the local app {name}, which is not installed "
                           "in the env as an editable install from apps/, so nothing but the constraints "
                           "would keep an index from answering it. Tell the user.")
    return list(dict.fromkeys(reasons))


_ALLOWED_KEEP_SECONDS = 24 * 3600
_ALLOWED_KEEP_COUNT = 64
_UNREADABLE = {"bench": None, "apps": [], "unreadable": True}


def _allowed_records(root) -> list:
    """The records of allowed commands still waiting for their completion; an unreadable file
    reads as one record that says so."""
    try:
        data = json.loads(_state_file(root, ALLOWED_FILE).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        return [dict(_UNREADABLE)]
    if isinstance(data, dict) and isinstance(data.get("records"), list):
        return [r for r in data["records"] if isinstance(r, dict)]
    return [data] if isinstance(data, dict) else [dict(_UNREADABLE)]


def take_allowed(root, event=None) -> dict | None:
    """The record of the command that just completed (`event`), removed; the others stay for their
    own completions. With no event, the oldest record."""
    records = _allowed_records(root)
    if not records:
        return None
    if any(r.get("unreadable") for r in records):
        try:
            _state_file(root, ALLOWED_FILE).unlink()
        except OSError:
            pass
        return dict(_UNREADABLE)
    taken = next((r for r in records if event is None or allowed_matches(r, event)), None)
    if taken is None:
        return None
    rest = [r for r in records if r is not taken]
    if rest:
        _write_json(root, ALLOWED_FILE, {"schema_version": 2, "records": rest})
    else:
        try:
            _state_file(root, ALLOWED_FILE).unlink()
        except OSError:
            pass
    return taken


def allowed_matches(allowed, event) -> bool:
    """Whether the record of an allowed command belongs to the command that just ran."""
    if not allowed:
        return False
    ids = (allowed.get("tool_use_id"), event.get("tool_use_id"))
    if all(ids):
        return ids[0] == ids[1]
    command = ((event.get("tool_input") or {}).get("command"))
    return bool(command) and command == allowed.get("command")


def after_problems(root, bench, allowed) -> list:
    """[(kind, text, check)] a command that ran under the gate left wrong: an app whose manifests
    are no longer the ones its baseline recorded (an earlier segment may have swapped a lock before
    the gate looked, and a frozen install leaves a swapped lock alone), a Yarn lock that is no
    longer a Classic one, the installer files changed, an env that cannot be read."""
    import baseline
    found = []
    if allowed and allowed.get("unreadable"):
        found.append(("record", "the record of what the last bench command was covered by is unreadable",
                      {"type": "record"}))
    for entry in (allowed or {}).get("apps") or []:
        app, bid = Path(entry["app"]), entry["baseline"]
        try:
            doc = baseline.load(root, bid)
        except baseline.BaselineError as exc:
            found.append(("baseline", f"{app.name}: baseline {bid} cannot be read ({exc})",
                          {"type": "lock", "app": str(app), "baseline": bid}))
            continue
        for why in baseline.tree_matches(doc, baseline.FsTree(app)):
            found.append(("lock", f"{app.name}: {why}", {"type": "lock", "app": str(app), "baseline": bid}))
    for why in env_unreadable(Path(bench) / "env"):
        found.append(("unread", why, {"type": "unread", "bench": str(bench)}))
    # The files are compared with what the CLI recorded, not recomputed: a verb that adds a local app
    # (`bench new-app`) legitimately changes what the baselines would now write, and staleness is the
    # next command's check, which names `bench-config apply`.
    for why in bench_config.recorded_file_problems(bench, root) if bench_config.read_record(root) else ():
        found.append(("config", why, {"type": "config", "bench": str(bench)}))
    return found


def still_holds(root, check) -> bool:
    """Whether a recorded problem is still true. `cli.py reconcile` asks."""
    import baseline
    kind = (check or {}).get("type")
    if kind == "lock":
        app = Path(check.get("app") or "")
        if not app.is_dir():
            return False  # the app is gone
        doc, _reasons = baseline.find_match(root, app)
        if doc is not None:
            return False  # an approved baseline covers the tree as it is now
        try:
            recorded = baseline.load(root, check["baseline"])
        except (baseline.BaselineError, KeyError):
            return True
        return bool(baseline.tree_matches(recorded, baseline.FsTree(app)))
    if kind == "unread":
        return bool(env_unreadable(Path(check["bench"]) / "env"))
    if kind == "config":
        try:
            return bool(bench_config.recorded_file_problems(Path(check["bench"]), root))
        except Exception:  # noqa: BLE001 - what cannot be read has not been repaired
            return True
    return False
