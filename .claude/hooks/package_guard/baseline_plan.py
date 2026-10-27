"""`baseline plan`: build the proposal for one upstream app at one commit (P4).

The CLI runs this, never the hook, so it may take minutes and use the network
. Everything it reaches outside itself goes through `Seams`, so a test
supplies a git remote, uv, the registries and OSV and runs offline.

What it does, in order:

  1. the owner of the app's URL must be in the git-owners allowlist;
  2. the commit is fetched FROM THAT URL, never from the local object store, and
     must be reachable from a branch or tag of it (a fork commit is served by
     GitHub under the parent's URL and is not upstream);
  3. the manifests and locks are read from the FETCHED tree; a working tree
     (`--app`) must have the same digests or the plan refuses;
  4. the Python pins come from `uv pip compile --no-build --no-config --universal`
     over static metadata only. What uv cannot read without building is detected,
     taken out, and recorded in `needs_build`: nothing is ever built or run;
  5. every yarn.lock is read in full (P1), its git entries are checked against the
     allowlist and for reachability, its sha1-only entries against the registry;
  6. OSV is asked about every pin and every locked package, in batches.

Standard library only.
"""
from __future__ import annotations

import configparser
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
import urllib.parse
from concurrent import futures
from datetime import datetime, timedelta, timezone
from pathlib import Path

import baseline as bl
import legacy
import store
import yarn_classic_lock
from lock_errors import LockReadError


class PlanError(Exception):
    """The plan is refused. The message says why and what to do."""


class BaseClash(PlanError):
    """The plan cannot agree with an approved baseline of the same bench."""


# ---------------------------------------------------------------------------
# The seams
# ---------------------------------------------------------------------------

class Seams:
    """Everything the plan reaches outside itself with. Defaults are the real
    thing; a test replaces each with a function.

      fetch(url)            -> a Fetched (see GitFetch) for the remote at `url`
      uv(args, cwd)         -> (returncode, stdout, stderr)
      uv_version()          -> "0.12.5"
      http_json(url)        -> parsed JSON, or None for a 404
      osv_batch(eco, pairs) -> {(name, version): [advisory ids]}
      osv_vuln(id)          -> {"id", "severity"} or None
      git(args, cwd)        -> (returncode, stdout) for a read of a LOCAL repository
      now()                 -> datetime (UTC)
    """

    def __init__(self, fetch=None, uv=None, uv_version=None, http_json=None, osv_batch=None,
                 osv_vuln=None, git=None, now=None, git_local_ok=False, uv_cache_dir=None):
        self.git_local_ok = git_local_ok
        self.uv_cache_dir = uv_cache_dir
        self.fetch = fetch or self._fetch
        self.uv = uv or self._uv
        self.uv_version = uv_version or self._uv_version
        self.http_json = http_json or self._http_json
        self.osv_batch = osv_batch or self._osv_batch
        self.osv_vuln = osv_vuln or self._osv_vuln
        self.git = git or run_git
        self.now = now or (lambda: datetime.now(timezone.utc))
        self._tmp = []

    # -- real implementations ------------------------------------------------

    def _fetch(self, url):
        directory = tempfile.mkdtemp(prefix="pg-baseline-")
        self._tmp.append(directory)
        return GitFetch(url, directory, self.git, allow_local=self.git_local_ok)

    def _uv(self, args, cwd):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("UV_", "PIP_"))}
        env["UV_NO_CONFIG"] = "1"
        # uv's default of 30 s per request fails a plan on a slow link (PyPI's index pages took 20-30 s
        # in the v14 x86 lab); a longer wait changes nothing about what is resolved.
        env["UV_HTTP_TIMEOUT"] = "120"
        if self.uv_cache_dir:
            env["UV_CACHE_DIR"] = str(self.uv_cache_dir)
        done = subprocess.run(["uv", *args], cwd=cwd, env=env, capture_output=True, text=True,
                              timeout=bl.BASELINE_PLAN_DEADLINE)
        return done.returncode, done.stdout, done.stderr

    def _uv_version(self):
        try:
            done = subprocess.run(["uv", "--version"], capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            return "unknown"
        match = re.search(r"\d+\.\d+\.\d+", done.stdout)
        return match.group(0) if match else "unknown"

    def _http_json(self, url):
        import vetting
        for attempt in range(4):
            try:
                return vetting._request_json(url)
            except vetting.ProviderError:
                # A registry answers 502 under load; a plan is hundreds of calls.
                if attempt == 3:
                    raise
                time.sleep(1.0 + attempt)

    def _osv_batch(self, ecosystem, pairs):
        import vetting
        return vetting.query_osv_batch(ecosystem, pairs)

    def _osv_vuln(self, vuln_id):
        import vetting
        data = vetting._request_json("https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vuln_id, safe=""))
        if not isinstance(data, dict):
            return None
        severity = (data.get("database_specific") or {}).get("severity") if isinstance(data.get("database_specific"), dict) else None
        return {"id": vuln_id, "severity": severity if isinstance(severity, str) else None}

    def cleanup(self):
        for directory in self._tmp:
            shutil.rmtree(directory, ignore_errors=True)
        self._tmp = []


def run_git(args, cwd=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    # The user's own git configuration must not shape the fetch: an `insteadOf`
    # rewrite would send https://github.com/... somewhere else.
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    try:
        done = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, timeout=bl.BASELINE_PLAN_DEADLINE)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"git did not run: {exc}".encode()
    return done.returncode, done.stdout if done.returncode == 0 else done.stderr


_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*\Z")


def utc_z(stamp: str) -> str:
    """An ISO-8601 timestamp (any offset) as UTC with a trailing Z."""
    parsed = datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class GitFetch:
    """The remote at `url`, as a partial bare clone (commits, no blobs): enough to
    ask which branches and tags contain a commit and to read its manifests.

    Only https is allowed to git; `allow_local` is for a test against a local
    repository standing in for the remote. Nothing is checked out and nothing is
    run: it is `git fetch` and `git cat-file`.
    """

    def __init__(self, url, directory, run, allow_local=False):
        self.url, self.directory, self.run, self.allow_local = url, directory, run, allow_local
        self._ready = False

    def _git(self, *args):
        protocol = ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
        if self.allow_local:
            protocol += ["-c", "protocol.file.allow=always"]
        return self.run([*protocol, *args], self.directory)

    def _ensure(self):
        if self._ready:
            return
        code, out = self._git("init", "--bare", "-q", self.directory)
        if code != 0:
            raise PlanError(f"git init failed: {out.decode(errors='replace').strip()}")
        for args in (("remote", "add", "origin", self.url),
                     ("config", "remote.origin.promisor", "true"),
                     ("config", "remote.origin.partialclonefilter", "tree:0"),
                     ("fetch", "--quiet", "--no-tags", "--filter=tree:0", "origin",
                      "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")):
            code, out = self._git(*args)
            if code != 0:
                raise PlanError(f"could not fetch {self.url}: {out.decode(errors='replace').strip()[:300]}")
        self._ready = True

    def resolve(self, ref):
        """The commit a branch, tag or full commit names in the REMOTE's refs."""
        self._ensure()
        if _HEX40.match(ref):
            return ref
        if not _REF.match(ref) or ".." in ref:
            raise PlanError(f"{ref!r} is not a branch, tag or commit name")
        for candidate in (f"refs/heads/{ref}", f"refs/tags/{ref}"):
            code, out = self._git("rev-parse", "--verify", "--quiet", candidate + "^{commit}")
            if code == 0 and _HEX40.match(out.decode().strip()):
                return out.decode().strip()
        raise PlanError(f"{self.url} has no branch or tag {ref!r}")

    def reachable_refs(self, commit):
        """The branches and tags of the remote that contain `commit`; [] when it is
        not in the remote's refs at all."""
        if not _HEX40.match(commit):
            return []
        self._ensure()
        code, _out = self._git("cat-file", "-e", commit + "^{commit}")
        if code != 0:
            return []
        code, out = self._git("for-each-ref", "--contains", commit, "--format=%(refname)",
                              "refs/heads", "refs/tags")
        return [line for line in out.decode().splitlines() if line] if code == 0 else []

    def tags_at(self, commit):
        """The tags of the remote that point exactly at `commit` (an annotated tag counts)."""
        if not _HEX40.match(commit):
            return []
        self._ensure()
        code, out = self._git("for-each-ref", "--points-at", commit, "--format=%(refname)", "refs/tags")
        return [line for line in out.decode().splitlines() if line] if code == 0 else []

    def commit_date(self, commit):
        self._ensure()
        code, out = self._git("show", "-s", "--format=%cI", commit)
        if code != 0:
            raise PlanError(f"cannot read the date of {commit}")
        return utc_z(out.decode().strip())

    def tree(self, commit):
        self._ensure()
        code, out = self._git("ls-tree", "-r", "-z", commit)
        if code != 0:
            raise PlanError(f"cannot list {commit}: {out.decode(errors='replace').strip()[:200]}")
        files, links = {}, set()
        for record in out.decode("utf-8", "surrogateescape").split("\0"):
            if not record:
                continue
            meta, _tab, path = record.partition("\t")
            mode = meta.split(" ")[0]
            files[path] = None
            if mode == "120000":
                links.add(path)
            elif mode == "160000":
                links.add(path)
        return _GitTree(self, commit, sorted(files), links)


class _GitTree:
    def __init__(self, fetched, commit, paths, links):
        self.fetched, self.commit, self._paths, self.links = fetched, commit, paths, links

    def paths(self):
        return self._paths

    def read(self, path):
        if path in self.links:
            raise bl.BaselineError(f"{path} is a symbolic link or a submodule")
        code, out = self.fetched._git("cat-file", "blob", f"{self.commit}:{path}")
        if code != 0:
            raise FileNotFoundError(path)
        return out


# ---------------------------------------------------------------------------
# Reading the app's declared Python dependencies, statically
# ---------------------------------------------------------------------------

_GIT_REF = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*git\+https://github\.com/"
    r"(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?@(?P<commit>[0-9a-f]{40})\s*(?:;.*)?$")
_REQ_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_DEV_FILE = re.compile(r"(?:^|[-_.])dev", re.IGNORECASE)


class Declared:
    """What an app's static metadata asks pip for."""

    def __init__(self):
        self.run, self.dev, self.build = [], [], []
        self.git = []                  # {name, owner, repo, commit, section, line}
        self.requires_python = None
        self.inputs = []
        self.local_extra = set()       # names from frappe-dependencies / required_apps
        self.constraints = []          # exact pins of `-c` files: they constrain, they do not install
        self.name = None
        self.dist_names = set()        # the distribution names its own metadata declares (normalized)
        self.version = None            # the static [project].version, when there is one
        self.setuptools_build = False  # the app is built by setuptools (see `editable_setuptools`)


def _lines_of(tree, path):
    return bl.requirement_lines(bl.normalized_bytes(tree.read(path), path).decode("utf-8"))


_SETUP_NAME = re.compile(r"""(?<![\w.])name\s*=\s*(['"])([A-Za-z0-9][A-Za-z0-9._-]*)\1""")


def _setup_cfg_names(text) -> set:
    """{the `[metadata] name` of a setup.cfg}, read as text; nothing runs."""
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
        name = parser.get("metadata", "name", fallback=None)
    except configparser.Error:
        return set()
    return {bl.normalize_py(name.strip())} if name and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name.strip()) else set()


def _setup_py_names(text) -> set:
    """{the literal `name="..."` keyword of the `setup(...)` call of a setup.py}, read as text; nothing runs."""
    start = re.search(r"\bsetup\s*\(", text)
    found = _SETUP_NAME.search(text, start.end()) if start else None
    return {bl.normalize_py(found.group(2))} if found else set()


def tree_version(tree, declared):
    """The version an app's own files declare at this commit, read as text (a static `[project].version`, or
    the `__version__` literal of the package that holds `hooks.py`), or None."""
    if declared.version:
        return declared.version
    for path in tree.paths():
        parts = path.split("/")
        if len(parts) == 2 and parts[1] == "hooks.py":
            try:
                text = bl.normalized_bytes(tree.read(f"{parts[0]}/__init__.py"), "__init__.py").decode("utf-8")
            except (OSError, UnicodeDecodeError, bl.BaselineError, ValueError):
                continue
            value, _why = bl.top_level_string(text, "__version__")
            if value:
                return value
    return None


def declared_python(tree, manifests) -> Declared:
    out = Declared()
    paths = set(manifests)

    def toml(path):
        try:
            return tomllib.loads(bl.normalized_bytes(tree.read(path), path).decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError, bl.BaselineError) as exc:
            raise PlanError(f"{path} cannot be read ({exc})") from None

    data = toml("pyproject.toml") if "pyproject.toml" in paths else {}
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    out.name = project.get("name") if isinstance(project.get("name"), str) else None
    if out.name:
        out.dist_names.add(bl.normalize_py(out.name))
    if isinstance(project.get("version"), str) and "version" not in (
            project.get("dynamic") if isinstance(project.get("dynamic"), list) else []):
        out.version = project["version"]
    out.requires_python = project.get("requires-python") if isinstance(project.get("requires-python"), str) else None
    dynamic = project.get("dynamic") if isinstance(project.get("dynamic"), list) else []
    for field in ("dependencies", "optional-dependencies"):
        if field in dynamic:
            raise PlanError(f"pyproject.toml declares {field} dynamically: the plan reads static metadata "
                            "only and never runs the app's build")
    deps = project.get("dependencies")
    if isinstance(deps, list):
        out.run += [d for d in deps if isinstance(d, str)]
        out.inputs.append("pyproject.toml#project.dependencies")
    tool = data.get("tool") if isinstance(data.get("tool"), dict) else {}
    bench = tool.get("bench") if isinstance(tool.get("bench"), dict) else {}
    dev = bench.get("dev-dependencies")
    if isinstance(dev, dict):
        for name, spec in dev.items():
            spec = str(spec)
            out.dev.append(f"{name}{spec}" if spec[:1] in "=~<>!" else f"{name}=={spec}")
        # development dependencies are resolved after the runtime set, as their own step (see `_plan`)
    fd = bench.get("frappe-dependencies")
    if isinstance(fd, dict):
        out.local_extra |= {bl.normalize_py(n) for n in fd}
    build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
    if isinstance(build.get("requires"), list):
        out.build += [r for r in build["requires"] if isinstance(r, str)]
        out.inputs.append("pyproject.toml#build-system.requires")
    # No [build-system], or one with no backend, is built by setuptools (uv's default is its legacy backend).
    backend = build.get("build-backend")
    out.setuptools_build = not build or backend is None or (
        isinstance(backend, str) and backend.strip().startswith("setuptools.build_meta"))
    # Every source the installer reads is read, and they are added together: a pyproject list, a
    # setup.cfg, a setup.py that reads requirements.txt, and every requirements file with whatever
    # it includes. One source never switches another off.
    requirement_files = sorted(p for p in paths if "/" not in p and bl._REQUIREMENTS_NAME.match(p))
    if "setup.cfg" in paths:
        cfg_lines, cfg_files, cfg_problems = bl.setup_cfg_requirements(
            bl.normalized_bytes(tree.read("setup.cfg"), "setup.cfg").decode("utf-8"), extras=False)
        if cfg_problems:
            raise PlanError("; ".join(cfg_problems))
        out.run += cfg_lines
        out.dist_names |= _setup_cfg_names(bl.normalized_bytes(tree.read("setup.cfg"), "setup.cfg").decode("utf-8"))
        if cfg_lines:
            out.inputs.append("setup.cfg#options.install_requires")
        requirement_files += [f for f in cfg_files if f not in requirement_files]
    if "setup.py" in paths:
        reads, why = bl.setup_py_problems(bl.normalized_bytes(tree.read("setup.py"), "setup.py").decode("utf-8"),
                                          allow_dependency_links=True)
        if why:
            raise PlanError("setup.py: " + "; ".join(why) + "; the plan reads static metadata only and never runs it")
        if reads and "requirements.txt" not in paths:
            raise PlanError("setup.py reads requirements.txt, which is not in the app")
        out.dist_names |= _setup_py_names(bl.normalized_bytes(tree.read("setup.py"), "setup.py").decode("utf-8"))
    walked, constraints = set(), []
    for path in requirement_files:
        stack = [path]
        while stack:
            current = stack.pop(0)
            if current in walked:
                continue
            walked.add(current)
            try:
                lines, includes, constrain, options = bl.requirement_parts(
                    bl.normalized_bytes(tree.read(current), current).decode("utf-8"))
            except (OSError, UnicodeDecodeError, bl.BaselineError) as exc:
                raise PlanError(f"{current} cannot be read ({exc})") from None
            if options:
                raise PlanError(f"{current}: the option line {options[0]!r} changes where or how packages are "
                                "fetched; the plan refuses it")
            (out.dev if _DEV_FILE.search(path) else out.run).extend(lines)
            if not _DEV_FILE.search(path):
                out.inputs.append(current)
            for include in includes + constrain:
                target = os.path.normpath(os.path.join(os.path.dirname(current), include)).replace(os.sep, "/")
                if target.startswith(("../", "/")) or target == "..":
                    raise PlanError(f"{current} includes {include!r}, outside the app")
                if target not in paths and target not in walked:
                    raise PlanError(f"{current} includes {include!r}, which is not in the app")
            for include in includes:
                stack.append(os.path.normpath(os.path.join(os.path.dirname(current), include)).replace(os.sep, "/"))
            for include in constrain:
                target = os.path.normpath(os.path.join(os.path.dirname(current), include)).replace(os.sep, "/")
                clines, _r, _c, copts = bl.requirement_parts(bl.normalized_bytes(tree.read(target), target).decode("utf-8"))
                if copts:
                    raise PlanError(f"{target}: the option line {copts[0]!r} changes where or how packages are fetched")
                constraints += [l for l in clines if re.match(r"[A-Za-z0-9._-]+\s*===?\s*[\w.!+-]+\s*(?:;.*)?$", l)]
                out.inputs.append(target)
    out.constraints = constraints
    if "hooks.py" in {p.rsplit("/", 1)[-1] for p in tree.paths()}:
        for path in tree.paths():
            if path.endswith("/hooks.py") and path.count("/") == 1:
                try:
                    text = bl.normalized_bytes(tree.read(path), path).decode("utf-8")
                except (OSError, UnicodeDecodeError, bl.BaselineError):
                    continue
                found = re.search(r"^required_apps\s*=\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL)
                if found:
                    out.local_extra |= {bl.normalize_py(n) for n in re.findall(r"[\"']([A-Za-z0-9_.-]+)[\"']", found.group(1))}
    return out


def split_requirements(lines, section, local_names, owners, excluded, out_git):
    """Lines with the bench's own apps and the git references taken out. A git
    reference is checked now (allowlisted owner, full commit, GitHub https only);
    any other direct reference refuses the plan."""
    kept = []
    for line in lines:
        text = line.strip()
        if not text:
            continue
        git = _GIT_REF.match(text)
        if git:
            owner = git.group("owner")
            if owner not in owners:
                raise PlanError(f"{git.group('name')}: the git owner {owner!r} is not in the git-owners allowlist")
            out_git.append({"name": bl.normalize_py(git.group("name")), "owner": owner, "repo": git.group("repo"),
                            "commit": git.group("commit"), "section": section, "line": text})
            continue
        if "@" in text.split(";")[0] and "://" in text or text.startswith((".", "/", "~")) or "git+" in text:
            raise PlanError(f"{text!r} is a source other than the registry or an allowlisted GitHub commit")
        match = _REQ_NAME.match(text)
        if not match:
            raise PlanError(f"{text!r} is not a requirement the plan can read")
        name = bl.normalize_py(match.group(1))
        if name in local_names:
            if name not in excluded:
                excluded.append(name)
            continue
        kept.append(text)
    return kept


# ---------------------------------------------------------------------------
# The compile: strip what uv cannot read without building, record it
# ---------------------------------------------------------------------------

_FAIL_VERSIONED = re.compile(r"Because ([A-Za-z0-9][A-Za-z0-9._-]*)([<>=!~][^\s]*) has no usable wheels")
_FAIL_METADATA = re.compile(
    r"Metadata for `([A-Za-z0-9][A-Za-z0-9._-]*)` \(v([^)\s]+)\) could not be parsed"
    r"|Because ([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+) has invalid metadata")
_FAIL_BUILD = re.compile(r"Failed to download and build `([A-Za-z0-9][A-Za-z0-9._-]*)")
_FAIL_WHEELS = re.compile(r"Wheels are required for `([A-Za-z0-9][A-Za-z0-9._-]*)`")
_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9.!+_-]+)\s*(?:;\s*(?P<markers>.+?))?\s*$")
_URL_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*@\s*(?P<url>\S+)")
MAX_STRIPS = 60


class Compiled:
    def __init__(self):
        self.pins = []           # (name, version, markers or None)
        self.git = []            # (name, owner, repo, commit) uv resolved itself
        self.stripped_git = []   # the {name, owner, repo, commit, ...} dicts taken out
        self.registry_builds = []  # {name, version, transitive}
        self.overrides = []
        self.stderr = []
        self.unchecked = []      # plain sentences: a range that could not be checked against a pinned sdist


_VIA = re.compile(r"\s+#\s+via\s+(?P<who>.+)$")


def _strip_annotation(line):
    """A compiled line without uv's trailing `# via ...` comment (present only in the annotated probe)."""
    match = _VIA.search(line)
    return line[:match.start()].rstrip() if match else line


def parse_dependents(stdout):
    """{package: [packages that ask for it]} from an annotated compile (`--annotation-style=line`)."""
    found = {}
    for raw in stdout.splitlines():
        match = _VIA.search(raw.strip())
        if not match:
            continue
        pin = _PIN.match(_strip_annotation(raw.strip()))
        if pin:
            found.setdefault(bl.normalize_py(pin.group("name")), []).extend(
                bl.normalize_py(w.strip()) for w in match.group("who").split(",")
                if w.strip() and not w.strip().startswith("-"))
    return found


def parse_compiled(stdout):
    pins, git = [], []
    for raw in stdout.splitlines():
        line = _strip_annotation(raw.strip())
        if not line or line.startswith("#"):
            continue
        match = _PIN.match(line)
        if match:
            pins.append((bl.normalize_py(match.group("name")), match.group("version"), match.group("markers")))
            continue
        url = _URL_PIN.match(line)
        ref = _GIT_REF.match(line.split(" ; ")[0]) if url else None
        if ref:
            git.append((bl.normalize_py(ref.group("name")), ref.group("owner"), ref.group("repo"), ref.group("commit")))
            continue
        raise PlanError(f"uv printed a line the plan cannot read: {line!r}")
    return pins, git


def compile_set(seams, lines, git_inputs, python_version, exclude_newer, constraint_text, tag, workdir, applied=None,
                newer=None):
    """Compile `lines` (and `git_inputs`, dicts with `line`) for one section. `newer` is {package: date}:
    those packages may be newer than `exclude_newer`, up to their own date (see `editable_setuptools`).

    uv fails the whole compile on a source it must build to read. On each failure
    the named package is taken out and recorded and the compile is retried:

      * a git input uv cannot read           -> stripped, recorded for needs_build;
      * a direct registry input with no wheel -> stripped, pinned at the version uv
        named, recorded for needs_build;
      * a transitive one                      -> removed from its dependents with an
        override (`name; python_version < "0"`), recorded the same way.

    uv also refuses a package whose own metadata it cannot parse (pandas 0.24.2). For
    exactly the name and version in the guard's shipped table (`legacy-overrides.json`) the
    corrected metadata is passed as a uv config file (`--config-file`, which uv does not
    allow beside `--no-config`) and the compile is retried; for any other package the
    plan refuses. `applied` (shared across the compiles of one plan) holds the entries used.

    An error that names no package is a failure of the plan, never a success.
    """
    applied = applied if applied is not None else []
    result = Compiled()
    lines, git_inputs = list(lines), list(git_inputs)
    overrides = []
    reconciled = set()      # direct pins already checked against what asks for the same package

    def run(annotate=False):
        inputs = lines + [g["line"] for g in git_inputs]
        input_path = Path(workdir) / f"{tag}.in"
        input_path.write_text("\n".join(inputs) + "\n", encoding="utf-8")
        args = ["pip", "compile", "--no-build", "--universal", "--python-version", python_version,
                "--exclude-newer", exclude_newer, "--no-header",
                "--annotation-style=line" if annotate else "--no-annotate"]
        for package, date in sorted((newer or {}).items()):
            args += ["--exclude-newer-package", f"{package}={date}"]
        if applied:
            config_path = Path(workdir) / "legacy.uv.toml"
            config_path.write_text(legacy.uv_config_text(applied), encoding="utf-8")
            args += ["--config-file", str(config_path)]
        else:
            args.append("--no-config")
        if seams.uv_cache_dir:
            args += ["--cache-dir", str(seams.uv_cache_dir)]
        if constraint_text:
            constraint_path = Path(workdir) / f"{tag}.constraints"
            constraint_path.write_text(constraint_text, encoding="utf-8")
            args += ["-c", str(constraint_path)]
        if overrides:
            override_path = Path(workdir) / f"{tag}.override"
            override_path.write_text("".join(f'{n}; python_version < "0"\n' for n in overrides), encoding="utf-8")
            args += ["--override", str(override_path)]
        args.append(str(input_path))
        return seams.uv(args, str(workdir))

    for _ in range(MAX_STRIPS):
        code, stdout, stderr = run()
        if code == 0:
            result.pins, result.git = parse_compiled(stdout)
            # A direct requirement that was set aside (no wheel) is pinned by itself. If something else in
            # the set asks for the same package, uv has just picked a release for that too: two pins for one
            # name. The set-aside pin is the app's own requirement and it stands; what asks for the package
            # must admit it, and the transitive pick is dropped by an override.
            direct = {b["name"]: b["version"] for b in result.registry_builds if not b["transitive"]}
            twice = sorted({n for n, _v, _m in result.pins if n in direct} - reconciled)
            if twice:
                result.unchecked += _reconcile_direct_pins(seams, twice, direct, result.pins,
                                                           parse_dependents(run(annotate=True)[1]))
                reconciled.update(twice)
                overrides += [n for n in twice if n not in overrides]
                continue
            result.overrides = list(overrides)
            return result
        result.stderr.append(stderr)
        if newer and "exclude-newer-package" in stderr and "unexpected argument" in stderr:
            raise PlanError("this uv does not know `--exclude-newer-package`, which the plan needs to pin a setuptools "
                            "newer than the baseline's date; update uv (`uv self update`) and plan again. Nothing "
                            "was written.")
        invalid = _FAIL_METADATA.search(stderr)
        if invalid:
            name, version = (invalid.group(1), invalid.group(2)) if invalid.group(1) else (invalid.group(3), invalid.group(4))
            entry = legacy.override_for(name, version)
            if entry is None or entry in applied:
                raise PlanError(f"uv cannot parse the metadata of {name} {version}, and Package Guard ships no "
                                "override for that exact version; the plan will not guess its dependencies")
            applied.append(entry)
            continue
        versioned = _FAIL_VERSIONED.search(stderr)
        built = _FAIL_BUILD.search(stderr)
        wheels = _FAIL_WHEELS.search(stderr)
        if built and not versioned:
            name = bl.normalize_py(built.group(1))
            stripped = [g for g in git_inputs if bl.normalize_py(g["name"]) == name]
            if not stripped:
                raise PlanError(f"uv could not read {name} without building it, and it is not a git input; "
                                "the plan will not build it")
            result.stripped_git += stripped
            git_inputs = [g for g in git_inputs if g not in stripped]
            continue
        found = versioned or wheels
        if not found:
            raise PlanError("uv pip compile failed and named no package the plan can set aside:\n"
                            + stderr.strip()[-1200:])
        name = bl.normalize_py(found.group(1))
        version = _highest_version(versioned.group(2)) if versioned else None
        direct = [l for l in lines if _line_name(l) == name]
        if version is None and direct:
            # An unpinned or ranged input (Frappe v11 lists `pyqrcode` bare): uv derived the failure
            # from several versions and names none. Pin the newest stable release the requirement
            # admits that existed at the cutoff, then let uv name that one exactly.
            pinned = pick_exact_version(seams, direct[0], exclude_newer)
            if pinned:
                lines = [pinned if l == direct[0] else l for l in lines]
                continue
        unconstrained = False
        if version is None and not direct and name not in overrides:
            # The release is already decided when a constraint pins the name (an approved baseline, or the
            # joint answer the app is held to) or the app itself pinned it and it was set aside: that is
            # the release to record, never a second pick of the newest one.
            decided = [b["version"] for b in result.registry_builds if b["name"] == name and not b["transitive"]]
            decided += [v for n, v in _exact_pins(constraint_text) if n == name]
            if decided:
                version = decided[0]
        if version is None and not direct and name not in overrides:
            # A transitive package with no wheel in any version (Frappe v11's googleapis-common-protos):
            # take the newest stable release of its time. The ranges its dependents ask for are not
            # evaluated, which the baseline's notes say; a pin they would refuse fails at install.
            picked = pick_exact_version(seams, name, exclude_newer)
            if picked:
                version, unconstrained = picked.split("==")[1], True
        if version is None:
            raise PlanError(f"uv names no version for the wheel-less {name}; plan it with the version pinned")
        if direct:
            lines = [l for l in lines if _line_name(l) != name]
            result.registry_builds.append({"name": name, "version": version, "transitive": False})
        elif name in overrides:
            raise PlanError(f"{name} is still unresolvable after it was set aside:\n" + stderr.strip()[-800:])
        else:
            overrides.append(name)
            result.registry_builds.append({"name": name, "version": version, "transitive": True,
                                           "unconstrained": unconstrained})
    raise PlanError(f"more than {MAX_STRIPS} packages needed setting aside; the plan stops")


def _reconcile_direct_pins(seams, names, direct, pins, dependents):
    """The app pins `name` itself (a package with no wheel, set aside from the compile at `direct[name]`),
    and something else in the set asks for it too. Both can be true only if what asks for it admits the
    pinned release. Each such requirement is read from PyPI's record of the pinned release of the package
    that asks (`dependents`: {package: [who asks]}); one that excludes the pinned release means the app's
    own requirements cannot be installed together, and the plan says so. Returns plain sentences for what
    could not be checked."""
    import vetting
    unchecked = []
    shown = {}
    for n, v, _m in pins:
        shown.setdefault(n, set()).add(v)
    for name in names:
        pinned = direct[name]
        asked_by = sorted(set(dependents.get(name, ())))
        if not asked_by:
            unchecked.append(f"{name} {pinned} is pinned by the app and also needed by another package; the plan "
                             "could not tell which, so the ranges of that other package were not checked")
        for dep in asked_by:
            for dep_version in sorted(shown.get(dep, ())):
                doc = seams.http_json(f"https://pypi.org/pypi/{urllib.parse.quote(dep, safe='')}/"
                                      f"{urllib.parse.quote(dep_version, safe='')}/json")
                requires = (doc.get("info") or {}).get("requires_dist") if isinstance(doc, dict) else None
                if not isinstance(requires, list):
                    unchecked.append(f"{name} {pinned} (pinned by the app) was not checked against {dep} {dep_version}: "
                                     "PyPI lists no requirements for it")
                    continue
                for text in requires:
                    if not isinstance(text, str) or "extra" in text.partition(";")[2]:
                        continue
                    if _line_name(text) != name:
                        continue
                    parsed = vetting.requirement_specifiers(text)
                    if parsed is None:
                        unchecked.append(f"{name} {pinned} (pinned by the app) was not checked against "
                                         f"{dep} {dep_version}: its requirement {text!r} is not one the plan can judge")
                        continue
                    if not all(vetting._specifier_allows(pinned, op, bound) for op, bound in parsed[0]):
                        raise PlanError(
                            f"the app's own requirements cannot be installed together: it pins {name}=={pinned}, but "
                            f"{dep} {dep_version}, which it also needs, requires {name} "
                            + ", ".join(f"{op}{bound}" for op, bound in parsed[0])
                            + ". Nothing was written. Change the app's requirements (a person decides that); "
                            "a baseline cannot approve a set that pip would refuse.")
    return sorted(set(unchecked))


def _exact_pins(text):
    """[(name, version)] of the `name==version` lines of a constraint file's text."""
    found = []
    for line in (text or "").splitlines():
        match = _PIN.match(line.strip())
        if match and not match.group("markers"):
            found.append((bl.normalize_py(match.group("name")), match.group("version")))
    return found


def _highest_version(spec):
    """The version uv names as having no wheel: `==2.0.0`, or the inclusive upper bound of a
    range of such versions (`>=5.0.5,<=5.0.6` is every version there is between them, and the
    highest is what an installer would take). Anything else is no version."""
    parts = spec.split(",")
    for part in parts:
        if part.startswith("=="):
            return part[2:]
    for part in parts:
        if part.startswith("<="):
            return part[2:]
    return None


def pick_exact_version(seams, line, cutoff):
    """`name==version` (with the line's marker kept) for the newest stable release that the
    direct requirement `line` admits and PyPI had at `cutoff`, or None when the line or PyPI's
    record cannot be read exactly. Read from the JSON of the project; nothing is downloaded."""
    import vetting
    requirement, _sep, marker = line.partition(";")
    match = vetting._BUILD_REQUIREMENT.match(requirement.strip())
    if not match:
        return None
    specs = []
    for part in [p for p in match.group("specs").split(",") if p.strip()]:
        found = vetting._SPECIFIER.match(part)
        if not found or found.group("version").endswith(".*") and found.group("op") not in ("==", "!="):
            return None
        specs.append((found.group("op"), found.group("version")))
    name = match.group("name")
    doc = seams.http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json")
    releases = doc.get("releases") if isinstance(doc, dict) else None
    if not isinstance(releases, dict):
        return None
    best, best_key = None, None
    for version, files in releases.items():
        key = vetting._stable_key("pypi", version)
        if key is None or not isinstance(files, list) or not files:
            continue
        stamps = [f.get("upload_time_iso_8601") for f in files if isinstance(f, dict) and not f.get("yanked")]
        if not stamps or min(s for s in stamps if isinstance(s, str)) > cutoff:
            continue
        if all(vetting._specifier_allows(version, op, bound) for op, bound in specs) and (best_key is None or key > best_key):
            best, best_key = version, key
    if best is None:
        return None
    return f"{name}=={best}" + (f" ;{marker}" if marker.strip() else "")


#: The first setuptools that can build an editable install (PEP 660, `build_editable`).
EDITABLE_SETUPTOOLS = "64"


def editable_setuptools(seams, python_version, cutoff, wanted=None):
    """(version, upload time) of the setuptools a bench app's build is pinned to.

    `bench setup requirements` installs each app with `uv pip install -e`, an editable install, which
    asks the build for `build_editable`; setuptools has that from 64 on. The newest setuptools of a
    Frappe v11 baseline's date (2020) is 47.1.1 and cannot do it, so the date does not decide here: the
    newest release at the cutoff when that is 64 or later, else the newest release there is that is 64
    or later and runs on the baseline's Python (68.0.0 for 3.7). `wanted` is a version an approved base
    baseline already pins: it is the answer if it can do the job. Read from PyPI's record; nothing is
    downloaded. Raises PlanError when no release can."""
    import vetting
    doc = seams.http_json("https://pypi.org/pypi/setuptools/json")
    releases = doc.get("releases") if isinstance(doc, dict) else None
    if not isinstance(releases, dict):
        raise PlanError("PyPI's record of setuptools cannot be read, so the plan cannot choose the setuptools that "
                        "builds the bench's apps. Nothing was written.")
    floor = vetting._stable_key("pypi", EDITABLE_SETUPTOOLS)
    found = []
    for version, files in releases.items():
        key = vetting._stable_key("pypi", version)
        if key is None or key < floor or not isinstance(files, list):
            continue
        live = [f for f in files if isinstance(f, dict) and not f.get("yanked")
                and isinstance(f.get("upload_time_iso_8601"), str)]
        if not live:
            continue
        needs = {f.get("requires_python") for f in live if f.get("requires_python")}
        ok = True
        for text in needs:
            parsed = vetting.requirement_specifiers("x " + text)
            ok = ok and parsed is not None and all(vetting._specifier_allows(python_version, op, bound)
                                                   for op, bound in parsed[0])
        if ok:
            found.append((key, version, min(f["upload_time_iso_8601"] for f in live)))
    found.sort()
    if wanted is not None:
        for _key_, version, uploaded in found:
            if version == wanted:
                return version, uploaded
        raise PlanError(f"an approved baseline pins setuptools {wanted} for building, which cannot build an editable "
                        f"install on Python {python_version} (that needs setuptools {EDITABLE_SETUPTOOLS} or later). "
                        "Nothing was written. That baseline was planned by an earlier release: plan its app again, "
                        "have it approved, and plan this one after it.")
    if not found:
        raise PlanError(f"no setuptools release is both {EDITABLE_SETUPTOOLS} or later (the first that can build an "
                        f"editable install, which `bench setup requirements` makes) and runs on Python {python_version}, "
                        "the Python this baseline is planned for. Nothing was written. The bench's Python is older than "
                        "the build tools it needs: use a newer Python for this bench.")
    at_cutoff = [item for item in found if item[2] <= cutoff]
    _key_, version, uploaded = (at_cutoff or found)[-1]
    return version, uploaded


def _after(stamp):
    """The second after an upload time, as the `uv --exclude-newer-package` date that still admits it."""
    base = datetime.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return (base + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _line_name(line):
    match = _REQ_NAME.match(line)
    return bl.normalize_py(match.group(1)) if match else None


def python_version_for(requires_python):
    """The Python the compile evaluates markers for: the lower bound of
    requires-python, or 3.11 when there is none."""
    match = re.search(r">=\s*(\d+)\.(\d+)", requires_python or "")
    return f"{match.group(1)}.{match.group(2)}" if match else "3.11"


# ---------------------------------------------------------------------------
# JS: every yarn.lock, in full
# ---------------------------------------------------------------------------

_RESOLVED_HOST = re.compile(r"https://(registry\.yarnpkg\.com|registry\.npmjs\.org)/")


def read_js_locks(tree, manifests, owners, fetch_for):
    """(locks, problems) for every yarn.lock in `manifests`."""
    locks = []
    for path in sorted(p for p in manifests if p.rsplit("/", 1)[-1] == "yarn.lock"):
        try:
            text = bl.normalized_bytes(tree.read(path), path).decode("utf-8")
            lock = yarn_classic_lock.build(yarn_classic_lock.parse_text(text))
        except (LockReadError, UnicodeDecodeError, bl.BaselineError, OSError) as exc:
            raise PlanError(f"{path} cannot be read ({exc})") from None
        packages, git, seen = [], [], {}
        for entry in lock.entries:
            if entry.kind == yarn_classic_lock.REGISTRY:
                if not entry.integrity:
                    raise PlanError(f"{path}: {entry.name}@{entry.version} has no integrity")
                key = (entry.name, entry.version)
                if key in seen:
                    if seen[key] != entry.integrity:
                        raise PlanError(f"{path}: {entry.name}@{entry.version} is locked twice with different "
                                        f"artifacts ({seen[key][:24]}... and {entry.integrity[:24]}...)")
                    continue
                seen[key] = entry.integrity
                host = _RESOLVED_HOST.match(entry.resolved or "")
                packages.append({"name": entry.name, "version": entry.version, "integrity": entry.integrity,
                                 "host": host.group(1)})
            elif entry.kind in (yarn_classic_lock.CODELOAD, yarn_classic_lock.GIT):
                if entry.owner not in owners:
                    raise PlanError(f"{path}: {entry.name} comes from {entry.owner}/{entry.repo}; the owner is "
                                    "not in the git-owners allowlist")
                refs = fetch_for(f"https://github.com/{entry.owner}/{entry.repo}").reachable_refs(entry.commit)
                if not refs:
                    raise PlanError(f"{path}: {entry.name} is pinned to {entry.commit} of "
                                    f"{entry.owner}/{entry.repo}, which no branch or tag of that repository "
                                    "contains (a fork's commit is not upstream)")
                git.append({"name": entry.name, "owner": entry.owner, "repo": entry.repo, "commit": entry.commit,
                            "form": "codeload" if entry.kind == yarn_classic_lock.CODELOAD else "git"})
            else:
                raise PlanError(f"{path}: {entry.name}@{entry.version} is fetched from {entry.resolved!r}, not "
                                "the registry or a GitHub commit")
        locks.append({"path": path, "format": "yarn-classic-v1", "entries": len(lock.entries),
                      "dangling": len(yarn_classic_lock.dangling(lock)), "packages": packages, "git": git,
                      "scripts": []})
    return locks


def registry_version_url(name, version):
    return "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@") + "/" + urllib.parse.quote(version, safe="")


def crosscheck_registry(seams, locks, deadline):
    """Fetch each locked package's version document: the sha1 of a sha1-only entry
    must equal `dist.shasum`, and `hasInstallScript` fills `scripts`.
    ({"checked": n, "mismatches": [..]}, notes)."""
    wanted = {}
    for lock in locks:
        for pkg in lock["packages"]:
            wanted.setdefault((pkg["name"], pkg["version"]), []).append(pkg)
    for (name, version), pkgs in wanted.items():
        by_algorithm = {}
        for pkg in pkgs:
            by_algorithm.setdefault(pkg["integrity"].split("-", 1)[0], set()).add(pkg["integrity"])
        for digests in by_algorithm.values():
            if len(digests) > 1:
                raise PlanError(f"{name}@{version} is locked with different artifacts in different places "
                                f"({', '.join(sorted(d[:24] + '...' for d in digests))}); one identity has one artifact")

    def one(key):
        if time.monotonic() > deadline:
            raise PlanError("the plan ran past its deadline while reading the registry; run it again")
        return key, seams.http_json(registry_version_url(*key))

    mismatches, checked = [], 0
    scripts = {}
    with futures.ThreadPoolExecutor(max_workers=bl.BASELINE_FETCH_CONCURRENCY) as pool:
        for key, doc in pool.map(one, sorted(wanted)):
            name, version = key
            # Every distinct artifact the locks name for this identity is compared, so the order of the
            # locks cannot decide whether a mismatch is seen.
            for integrity in sorted({pkg["integrity"] for pkg in wanted[key]}):
                dist = (doc or {}).get("dist") if isinstance(doc, dict) else None
                if integrity.startswith("sha1-"):
                    checked += 1
                    import base64
                    try:
                        want = base64.b64decode(integrity[5:]).hex()
                    except ValueError:
                        want = ""
                    shasum = dist.get("shasum") if isinstance(dist, dict) else None
                    if not isinstance(doc, dict):
                        mismatches.append(f"{name}@{version}: the registry has no record of it")
                    elif shasum != want:
                        mismatches.append(f"{name}@{version}: the lock's sha1 {want} is not the registry's {shasum}")
                elif isinstance(dist, dict) and isinstance(dist.get("integrity"), str) and dist["integrity"] != integrity \
                        and dist["integrity"].startswith(integrity.split("-", 1)[0] + "-"):
                    mismatches.append(f"{name}@{version}: the lock's {integrity[:24]}... is not the registry's "
                                      f"{dist['integrity'][:24]}...")
            if isinstance(doc, dict):
                lifecycle = [k for k in ("preinstall", "install", "postinstall") if (doc.get("scripts") or {}).get(k)]
                if doc.get("hasInstallScript") is True or lifecycle:
                    scripts[key] = True
    for lock in locks:
        lock["scripts"] = [{"name": p["name"], "version": p["version"]} for p in lock["packages"]
                           if (p["name"], p["version"]) in scripts]
    return {"checked": checked, "mismatches": sorted(mismatches)}


# ---------------------------------------------------------------------------
# Registry sdists and OSV
# ---------------------------------------------------------------------------

def sdist_info(seams, name, version):
    """(sha256 of the sdist, requires_dist) from PyPI's JSON; PlanError when the
    version has no sdist (and so cannot be installed at all)."""
    doc = seams.http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(version, safe='')}/json")
    if not isinstance(doc, dict):
        raise PlanError(f"PyPI has no {name}=={version}")
    for item in doc.get("urls") or []:
        if isinstance(item, dict) and item.get("packagetype") == "sdist":
            digest = (item.get("digests") or {}).get("sha256")
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
                requires = (doc.get("info") or {}).get("requires_dist")
                return digest, ([r for r in requires if isinstance(r, str)] if isinstance(requires, list) else None)
    raise PlanError(f"{name}=={version} has no wheel for this resolution and no sdist: it cannot be installed")


_SEV = bl._SEVERITY_RANK


def osv_evidence(seams, pins, npm_pairs, now_text):
    """The OSV block of `evidence`. Advisories are counted and the worst listed;
    MAL- ids are listed apart and make the proposal unapprovable."""
    import vetting
    answers = {"pypi": sorted(set(pins)), "npm": sorted(set(npm_pairs))}
    found, malware = {}, []
    for ecosystem, pairs in answers.items():
        for start in range(0, len(pairs), vetting.OSV_BATCH_SIZE):
            chunk = pairs[start:start + vetting.OSV_BATCH_SIZE]
            for pair, ids in seams.osv_batch(ecosystem, chunk).items():
                if ids:
                    found[(ecosystem, pair[0], pair[1])] = list(ids)
    advisories = set()
    for (ecosystem, name, version), ids in found.items():
        for vuln in ids:
            if vuln.startswith("MAL-"):
                malware.append(f"{ecosystem}:{name}@{version} {vuln}")
            else:
                advisories.add((vuln, ecosystem, name, version))
    ranked = []
    for vuln, ecosystem, name, version in sorted(advisories)[:300]:
        detail = seams.osv_vuln(vuln) or {}
        ranked.append({"ecosystem": ecosystem, "name": name, "version": version, "id": vuln,
                       "severity": detail.get("severity")})
    worst = bl.worst_advisories(ranked)
    return {"checked_at": now_text, "entries_checked": sum(len(p) for p in answers.values()),
            "malware": sorted(set(malware)), "advisory_count": len({a[0] for a in advisories}), "worst": worst}


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

def _remote_url(app_dir):
    for remote in ("upstream", "origin"):
        match = re.search(r'\[remote "%s"\][^\[]*?url\s*=\s*(\S+)' % remote,
                          (Path(app_dir) / ".git" / "config").read_text(encoding="utf-8")) \
            if (Path(app_dir) / ".git" / "config").is_file() else None
        if match:
            return match.group(1)
    return None


def plan(root, seams, app_dir=None, url=None, ref=None, base_ids=(), python_version=None, exclude_newer=None,
         dir_name=None, joint=None):
    """The proposal for the app at `app_dir` (its URL read from its remote) or at
    `url` + `ref`. Returns {"document", "notes"}; raises PlanError.

    A bench installs its upstream apps into one Python environment, so the plan resolves the app together
    with the declared requirements of every other upstream app of the bench (`app_dir` finds them; an
    import hands them as `joint`, the `{"git_url", "commit"}` the file recorded). Either planning order
    then gives the same answer, and the document records what it was resolved with."""
    deadline = time.monotonic() + bl.BASELINE_PLAN_DEADLINE
    try:
        owners, _hosts = bl.load_owners(root)
    except bl.BaselineError as exc:
        raise PlanError(str(exc)) from None
    import vetting
    try:
        return _plan(root, seams, owners, deadline, app_dir, url, ref, base_ids, python_version, exclude_newer, dir_name,
                     joint)
    except vetting.ProviderError as exc:
        raise PlanError(f"a registry or OSV did not answer ({exc}); nothing was written, run the plan again") from None
    finally:
        seams.cleanup()


def _plan(root, seams, owners, deadline, app_dir, url, ref, base_ids, python_version, exclude_newer=None,
          dir_name=None, joint=None):
    notes = []
    if app_dir is not None:
        app_dir = Path(app_dir)
        if not app_dir.is_dir():
            raise PlanError(f"{app_dir} is not a directory")
        url = _remote_url(app_dir)
        if url is None:
            raise PlanError(f"{app_dir} has no `upstream` or `origin` remote to take its URL from; give the URL "
                            "and a ref: `baseline plan <url> <ref>`")
        code, out = seams.git(["rev-parse", "HEAD"], str(app_dir))
        commit = out.decode().strip() if code == 0 else ""
        if not bl._COMMIT.match(commit):
            raise PlanError(f"{app_dir} is not a git checkout at a commit ({out.decode(errors='replace').strip()[:100]})")
    parts = bl.repo_parts(url)
    if parts is None:
        raise PlanError(f"{url!r} is not https://github.com/<owner>/<repo>; only a GitHub upstream is baselined")
    why = bl.owner_problem(url, owners)
    if why:
        raise PlanError(why)
    git_url = f"https://github.com/{parts[0]}/{parts[1]}"
    fetched = seams.fetch(git_url)
    if app_dir is None:
        commit = fetched.resolve(ref)
    refs = fetched.reachable_refs(commit)
    if not refs:
        raise PlanError(f"commit {commit} is not in any branch or tag of {git_url}: a local commit or another "
                        "repository's commit is not upstream, and has no baseline")
    tree = fetched.tree(commit)
    digests, problems = bl.discover_manifests(tree)
    if problems:
        raise PlanError("; ".join(problems))
    if app_dir is not None:
        local, local_problems = bl.discover_manifests(bl.FsTree(app_dir))
        if local_problems:
            raise PlanError("; ".join(local_problems))
        diffs = sorted(p for p in set(local) | set(digests) if local.get(p) != digests.get(p))
        if diffs:
            raise PlanError(f"the working tree differs from {git_url}@{commit[:12]} in {', '.join(diffs[:6])}: "
                            "a baseline names the commit, so the tree must be exactly it")
    commit_date = fetched.commit_date(commit)
    declared = declared_python(tree, digests)
    name = declared.name or parts[1]
    # The directory name is metadata (`apps/<dir>`), part of the id. An import is judged by the remote and
    # the commit, so it hands the name the file carries; it is a plain name, never a path.
    if dir_name is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", dir_name):
        raise PlanError(f"{dir_name!r} is not an app directory name")
    dir_name = dir_name or (Path(app_dir).name if app_dir is not None else parts[1])
    now = seams.now()
    now_text = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    joint_items = [dict(item) for item in joint or ()]
    if app_dir is not None:
        # A bench is one Python env: the approved baselines of its other apps are constraints of this plan,
        # and the declared requirements of every other upstream app are resolved together with this one's.
        siblings, _waiting = _bench_siblings(root, app_dir, dir_name, owners)
        base_ids = tuple(dict.fromkeys([*base_ids, *siblings]))
        joint_items = _bench_joint_apps(root, seams, app_dir, dir_name, owners)
    mates = [read_mate(seams, owners, item) for item in joint_items]
    notes += [f"Resolved together with the declared requirements of {m['label']}, so planning the apps in "
              "either order gives the same packages." for m in mates]
    notes += [f"{m['label']} is at {m['commit']}, version {m['version'] or 'unknown'}, which is neither on its release "
              "branch nor a release tag of " + m["git_url"] + ". Its requirements shaped the pins of this plan. "
              "Check that commit before approving (Package Guard cannot tell whether it is the release you run)."
              for m in mates if m["release"] == "none"]
    base_docs = []
    for base in base_ids:
        try:
            base_docs.append(bl.load(root, base))
        except bl.BaselineError:
            try:
                base_docs.append(bl.load(root, base, proposal=True))
            except bl.BaselineError as exc:
                raise PlanError(f"base {base}: {exc}") from None
    # The constraints of a base baseline are pins that exist as of ITS cutoff: an app dated earlier than
    # its base (erpnext before the frappe it runs on) would find them filtered out and be unsatisfiable.
    # So the cutoff is the later of the app's date and its bases', never later than now. The id records it.
    floor = max([commit_date] + [d["python"]["compile"]["exclude_newer"] for d in base_docs]
                + [m["date"] for m in mates])
    bound = min(floor, now_text)
    if exclude_newer is not None and (not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", exclude_newer)
                                      or exclude_newer > bound):
        raise PlanError(f"exclude-newer {exclude_newer} is later than the commit date or the plan time ({bound})")
    exclude_newer = exclude_newer or bound
    local_names = ({bl.normalize_py(n) for n in bl.FRAPPE_APP_NAMES} | declared.local_extra
                   | {bl.normalize_py(name), bl.normalize_py(dir_name)}
                   | {n for m in mates for n in m["names"]})
    excluded, git_found = [], []
    run = split_requirements(declared.run, "run", local_names, owners, excluded, git_found)
    # Development dependencies are read and checked like any other (a source other than the registry or an
    # allowlisted GitHub commit is refused). `bench` installs them whenever `developer_mode` is on, for every
    # app it installs, so they are resolved here, after the runtime set: together with it and with the
    # other upstream apps' development sets. If that resolves they are pinned like the rest; if it does not,
    # the baseline says so, and the hook refuses the installs while `developer_mode` is on.
    dev = split_requirements(declared.dev, "dev", local_names, owners, excluded, git_found)
    build = split_requirements(declared.build, "build", local_names, owners, excluded, git_found)
    dev_git = [g for g in git_found if g["section"] == "dev"]
    git_found = [g for g in git_found if g["section"] != "dev"]
    for item in git_found:
        check_git_source(seams, owners, item)
    # What the other upstream apps of the bench ask for, read from their trees: resolved with this app's.
    mate_run, mate_build, mate_git, mate_build_git, mate_constraints = [], [], [], [], ""
    mate_dev, mate_dev_git = [], []
    for m in mates:
        ignore, found = [], []
        mate_names = local_names | m["declared"].local_extra
        mate_run += split_requirements(m["declared"].run, "run", mate_names, owners, ignore, found)
        mate_dev += split_requirements(m["declared"].dev, "dev", mate_names, owners, ignore, found)
        mate_build += split_requirements(m["declared"].build, "build", mate_names, owners, ignore, found)
        for item in found:
            if item["section"] != "dev":
                check_git_source(seams, owners, item)
        mate_git += [g for g in found if g["section"] == "run"]
        mate_dev_git += [g for g in found if g["section"] == "dev"]
        mate_build_git += [g for g in found if g["section"] == "build"]
        mate_constraints += "".join(f"{c}\n" for c in m["declared"].constraints)
    pv = python_version or (python_version_for(declared.requires_python) if declared.requires_python
                            else legacy.python_version_for_app(tree) or python_version_for(None))
    applied = []
    below = tuple(int(x) for x in pv.split(".")) < (3, 10)
    workdir = tempfile.mkdtemp(prefix="pg-plan-")
    seams._tmp.append(workdir)
    base_run = "".join(f"{p['name']}=={p['version']}\n" for d in base_docs for p in d["python"]["pins"]
                       if p["section"] in ("run", "dev") and not p.get("markers"))
    base_build = "".join(f"{p['name']}=={p['version']}\n" for d in base_docs for p in d["python"]["pins"]
                         if p["section"] == "build" and not p.get("markers"))
    own = "".join(f"{c}\n" for c in declared.constraints)
    constraint = (base_run + own) or None
    mate_labels = ", ".join(m["label"] for m in mates)
    newer = {}     # packages the build section may take newer than the cutoff: {name: date} (see `editable_setuptools`)

    def resolve(lines, git_inputs, tag, with_bases, plain, section):
        """compile_set with the bases' pins as constraints; when that fails and the same set compiles
        without them, the failure is the bases' and the plan names the packages that clash."""
        later = newer if section == "build" else None
        try:
            return compile_set(seams, lines, git_inputs, pv, exclude_newer, with_bases, tag, workdir, applied, later)
        except PlanError as failure:
            if not base_docs:
                raise
            try:
                alone = compile_set(seams, lines, git_inputs, pv, exclude_newer, plain, tag, workdir, applied, later)
            except PlanError:
                raise failure from None
            clash = joint_clash(base_docs, [{"name": n, "version": v, "markers": m, "section": section}
                                            for n, v, m in alone.pins])
            if not clash:
                raise failure from None
            raise BaseClash(clash_text(base_docs, clash)) from None

    held_by_tag = {}

    def joint(lines, git_inputs, tag, with_bases, plain, section, mate_lines=(), mate_git_inputs=(), mate_own=""):
        """The app's set resolved together with the other upstream apps' (`mate_lines`): first the whole
        lot as one resolution, then the app's own set held to exactly what that gave, so the pins
        it records are its own closure and agree with the other apps on every package they share."""
        if not (mate_lines or mate_git_inputs):
            alone = resolve(lines, git_inputs, tag, with_bases, plain, section)
            held_by_tag[tag] = _held_text(alone)
            return alone
        try:
            whole = resolve(list(lines) + list(mate_lines), list(git_inputs) + list(mate_git_inputs),
                            tag + "-joint", (with_bases or "") + mate_own or None, (plain or "") + mate_own or None,
                            section)
        except PlanError as failure:
            if isinstance(failure, BaseClash):
                raise
            if _network_failure(str(failure)):
                raise PlanError(
                    f"a registry did not answer while resolving apps/{dir_name} with {mate_labels} "
                    f"({_tail(failure)}); nothing was written, run the plan again") from None
            try:
                resolve(lines, git_inputs, tag + "-alone", with_bases, plain, section)
            except PlanError:
                raise failure from None   # the app cannot be resolved on its own: that is the answer
            raise PlanError(
                f"apps/{dir_name} and {mate_labels} resolve alone, but not in one Python environment, and a "
                f"bench is one: {_tail(failure)} Nothing was written. This is a disagreement between "
                "the apps' own requirements (are they on matching releases?), which no baseline can fix.") from None
        held = _held_text(whole)
        held_by_tag[tag] = held
        return resolve(lines, git_inputs, tag, (with_bases or "") + held, (plain or "") + held, section)

    pins, all_git, needs, overrides = [], [], [], []
    run_result = joint(run, [g for g in git_found if g["section"] == "run"], "run", constraint, own or None, "run",
                       mate_run, mate_git, mate_constraints)
    sections = [("run", run_result)]
    # Build requirements of the app, and of every git source that was set aside (read statically,
    # to any depth): each goes through the same checks as a requirement the app wrote itself.
    build_lines, build_git, read = list(build), [g for g in git_found if g["section"] == "build"], set()
    build_result = None
    # The build requirements of the bench's own apps must be able to do what the bench runs: it installs
    # each app editable, which setuptools can build from 64 on. A baseline dated before that (Frappe v11,
    # 2020: setuptools 47.1.1) is given a pinned setuptools that can, instead of the one its date picks.
    editable_pin, editable_notes = None, []
    if declared.setuptools_build or any(m["declared"].setuptools_build for m in mates):
        import vetting
        floor_key = vetting._stable_key("pypi", EDITABLE_SETUPTOOLS)
        run_versions = [v for n, v, _m in run_result.pins if n == "setuptools"]
        base_versions = sorted({p["version"] for d in base_docs for p in d["python"]["pins"]
                                if p["name"] == "setuptools" and p["section"] == "build" and not p.get("markers")})
        if base_versions or any(vetting._stable_key("pypi", v) < floor_key for v in run_versions):
            version, uploaded = editable_setuptools(seams, pv, exclude_newer, base_versions[0] if base_versions else None)
            editable_pin = f"setuptools=={version}"
            build_lines.append(editable_pin)
            past = uploaded > exclude_newer
            if past:
                newer["setuptools"] = _after(uploaded)
            editable_notes.append(
                f"setuptools {version} is pinned for building the apps"
                + (f", newer than the baseline's date ({exclude_newer[:10]})" if past else "")
                + f": `bench setup requirements` installs each app editable, which needs setuptools {EDITABLE_SETUPTOOLS} "
                "or later" + (" and the newest release of that date cannot do it" if past else ""))
    for _round in range(MAX_BUILD_ROUNDS):
        pending = [g for g in [x for _s, r in sections for x in r.stripped_git]
                   + (build_result.stripped_git if build_result else []) if (g["name"], g["commit"]) not in read]
        for item in pending:
            read.add((item["name"], item["commit"]))
            fresh = []
            kept = split_requirements(static_build_requires(fetched_for(seams, item, want_tree=True), item), "build",
                                      local_names, owners, excluded, fresh)
            for g in fresh:
                check_git_source(seams, owners, g)
            build_git += fresh
            build_lines += [l for l in kept if l not in build_lines]
        if build_lines or build_git:
            try:
                build_result = joint(build_lines, build_git, "build", base_build or None, None, "build",
                                     mate_build, mate_build_git)
            except BaseClash:
                raise
            except PlanError as failure:
                if not editable_pin:
                    raise
                raise PlanError(f"the build requirements do not resolve with {editable_pin}, the setuptools the bench's "
                                f"editable installs need (setuptools {EDITABLE_SETUPTOOLS} or later, on Python {pv}): "
                                f"{_tail(failure)} Nothing was written.") from None
        if not pending:
            break
    else:
        raise PlanError("build requirements of git sources nest too deeply; the plan stops")
    if build_result:
        sections.append(("build", build_result))
    stripped_git = [g for _s, r in sections for g in r.stripped_git]
    registry = {}
    for section, result in sections:
        for item in result.registry_builds:
            item["sections"] = {section}
        for n, v, m in result.pins:
            pins.append({"name": n, "version": v, "section": section, "markers": m})
        for n, owner, repo, c in result.git:
            # A git reference uv itself printed is checked like one written in a manifest.
            check_git_source(seams, owners, {"name": n, "owner": owner, "repo": repo, "commit": c})
            all_git.append({"name": n, "owner": owner, "repo": repo, "commit": c})
        overrides += result.overrides
        for item in result.registry_builds:
            known = registry.setdefault((item["name"], item["version"]), item)
            known.setdefault("sections", set()).add(section)
    # requires_dist of the registry sdists that were set aside, compiled as extra inputs
    extra, no_metadata = [], []
    for (n, v), item in sorted(registry.items()):
        digest, requires = sdist_info(seams, n, v)
        item["sha256"] = digest
        if requires is None:
            no_metadata.append(n)
        extra += [r for r in requires or [] if "extra" not in r.split(";", 1)[-1] or ";" not in r]
        for section in sorted(item["sections"]):
            pins.append({"name": n, "version": v, "section": section, "markers": None})
    notes_unresolved = sorted({u for _s, r in sections for u in r.unchecked}) + editable_notes
    if extra:
        run_names = {(p["name"], p["version"]) for p in pins if p["section"] == "run"}
        run_only = {p["name"] for p in pins if p["section"] == "run"}
        more = compile_set(seams, extra, [], pv, exclude_newer,
                           base_run + "".join(f"{p['name']}=={p['version']}\n" for p in pins if not p["markers"]
                                              and not (p["section"] == "build" and p["name"] in run_only
                                                       and (p["name"], p["version"]) not in run_names)),
                           "deps", workdir, applied)
        have = {(p["name"], p["version"], p["section"], p["markers"]) for p in pins}
        for n, v, m in more.pins:
            if (n, v, "run", m) not in have:
                pins.append({"name": n, "version": v, "section": "run", "markers": m})
        for item in more.registry_builds:
            if (item["name"], item["version"]) not in registry:
                digest, requires = sdist_info(seams, item["name"], item["version"])
                if requires is None:
                    no_metadata.append(item["name"])
                item["sha256"] = digest
                item["sections"] = {"run"}
                registry[(item["name"], item["version"])] = item
                pins.append({"name": item["name"], "version": item["version"], "section": "run", "markers": None})
        overrides += more.overrides
    seen_git = set()
    for item in stripped_git:
        key = (item["name"], item["commit"])
        if key in seen_git:
            continue
        seen_git.add(key)
        all_git.append({k: item[k] for k in ("name", "owner", "repo", "commit")})
        needs.append({"name": item["name"], "commit": item["commit"],
                      "reason": "git source whose metadata uv cannot read without building it; built at install"})
    for (n, v), item in sorted(registry.items()):
        needs.append({"name": n, "version": v, "sdist_sha256": item["sha256"],
                      "reason": ("transitive dependency with no wheel, set aside with an override; its sdist is built at install"
                                 if item["transitive"] else "no wheel for this resolution; its sdist is built at install")})
    if stripped_git:
        notes_unresolved.append("the dependencies of " + ", ".join(sorted({g['name'] for g in stripped_git}))
                                + " (git sources built at install) are not resolved; reconciliation finds them")
    if registry:
        notes_unresolved.append("registry sdists set aside from the compile: " + ", ".join(sorted(n for n, _v in registry))
                                + "; their dependencies come from PyPI's metadata where it has any")
    guessed = sorted({n for (n, _v), item in registry.items() if item.get("unconstrained")})
    if guessed:
        notes_unresolved.append(", ".join(guessed) + ": no wheel in any version, so pinned to the newest stable release "
                                "of the baseline's date; the version ranges the packages that need it ask for were not evaluated")
    if no_metadata:
        notes_unresolved.append("PyPI's record has no dependency metadata for " + ", ".join(sorted(set(no_metadata)))
                                + ": their dependencies are unknown to the plan, and reconciliation finds them")
    own_conflicts = bl.pin_conflicts(pins)
    if own_conflicts:
        raise PlanError("this app's requirements do not resolve to one set of packages: " + conflict_text(own_conflicts)
                        + ". Nothing was written. A bench installs one release of each package, so no baseline can "
                        "approve both; the app's own requirements need to change (a person decides that).")
    clash = joint_clash(base_docs, pins)
    if clash:
        raise BaseClash(clash_text(base_docs, clash))
    # Development dependencies: one more resolution, held to the runtime pins just decided.
    dev_names = sorted({n for n in (_line_name(l) for l in dev) if n} | {bl.normalize_py(g["name"]) for g in dev_git})
    dev_info = {"pinned": True, "names": dev_names, "reason": ""}
    if dev_names:
        dev_pins, dev_pin_git, why = _resolve_dev(seams, owners, joint, held_by_tag.get("run", ""), constraint, own,
                                                  dev, dev_git, mate_dev, mate_dev_git, mate_constraints, pins,
                                                  base_docs)
        if why:
            dev_info = {"pinned": False, "names": dev_names, "reason": why}
            notes.append("The development dependencies (" + ", ".join(dev_names[:6]) + (", ..." if len(dev_names) > 6 else "")
                         + ") are NOT pinned by this baseline: " + why + " While developer_mode is on, Package Guard "
                         "refuses the bench commands that install apps.")
        else:
            pins += dev_pins
            all_git += dev_pin_git
    # JS
    locks = read_js_locks(tree, digests, owners, lambda u: seams.fetch(u))
    sha1 = crosscheck_registry(seams, locks, deadline)
    if sha1["mismatches"]:
        raise PlanError("the registry disagrees with the lock: " + "; ".join(sha1["mismatches"][:5]))
    # OSV
    npm_pairs = [(p["name"], p["version"]) for lock in locks for p in lock["packages"]]
    py_pairs = [(p["name"], p["version"]) for p in pins]
    osv = osv_evidence(seams, py_pairs, npm_pairs, now_text)
    reasons = list(notes_unresolved)
    for entry in applied:
        reasons.append(f"{entry['name']} {entry['version']}: uv cannot parse its metadata ({entry['reason'].split(';')[0]}); "
                       "Package Guard's shipped dependency-metadata override for exactly that version was applied")
    if below:
        reasons.append(f"Python {pv} is below 3.10: compiled with --python-version markers under another "
                       "interpreter; no interpreter of that version was used")
    doc = {
        "schema_version": bl.SCHEMA_VERSION, "kind": "upstream",
        "app": {"name": name, "dir_name": dir_name, "git_url": git_url, "commit": commit, "commit_date": commit_date},
        "base": sorted(d["id"] for d in base_docs),
        "manifests": bl.manifest_list(digests),
        "python": {
            "requires_python": declared.requires_python or "",
            "compile": {"uv": seams.uv_version(), "python_version": pv, "universal": True,
                        "exclude_newer": exclude_newer, "no_build": True, "inputs": sorted(set(declared.inputs)),
                        **({"overrides": sorted(set(overrides))} if overrides else {}),
                        **({"joint_with": [{"git_url": m["git_url"], "commit": m["commit"], "names": sorted(m["names"]),
                                            "version": m["version"], "release": m["release"]} for m in mates]}
                           if mates else {}),
                        **({"dependency_metadata_override": sorted({bl.normalize_py(e["name"]) for e in applied})}
                           if applied else {})},
            "pins": pins, "git": all_git, "excluded_local_names": sorted(excluded), "needs_build": needs,
            "dev": dev_info,
        },
        "js": {"locks": locks},
        "legacy": {"python_below_3_10": below, "reasons": sorted(reasons)},
        "evidence": {"osv": osv, "sha1_crosscheck": sha1},
    }
    if len(pins) + len(all_git) + sum(len(l["packages"]) + len(l["git"]) for l in locks) > bl.BASELINE_MAX_PACKAGES:
        raise PlanError(f"more than {bl.BASELINE_MAX_PACKAGES} packages: refused rather than truncated")
    sealed = bl.seal(doc)
    sealed["approvable"] = not osv["malware"]
    if osv["malware"]:
        notes.append("OSV lists malware in this set; the proposal cannot be approved: " + "; ".join(osv["malware"][:5]))
    problems = bl.verify(sealed)
    if problems:
        raise PlanError("the plan produced a document it cannot read back: " + "; ".join(problems))
    return {"document": sealed, "notes": notes}


def _held_text(result) -> str:
    """The pins of a resolution as constraint lines: what a later resolution is held to."""
    return "".join(f"{n}=={v}\n" for n, v, m in result.pins if not m) \
        + "".join(f"{b['name']}=={b['version']}\n" for b in result.registry_builds)


def _resolve_dev(seams, owners, joint, held_run, constraint, own, dev, dev_git, mate_dev, mate_dev_git,
                 mate_constraints, pins, base_docs):
    """(pins, git, why) for the development dependencies of the app: resolved together with the other upstream
    apps' development sets and held to the runtime pins already decided (`held_run`), because bench installs
    them with the same constraint files after the runtime set. `why` is empty when they resolve; otherwise it is
    a plain sentence for what stopped it, and nothing of the development set is pinned. A development package
    that would have to be built from source is not pinned either: a baseline records builds for the runtime
    set only."""
    try:
        for item in dev_git + mate_dev_git:
            check_git_source(seams, owners, item)
        result = joint(dev, dev_git, "dev", (constraint or "") + held_run or None, (own or "") + held_run or None,
                       "dev", mate_dev, mate_dev_git, mate_constraints)
        if result.registry_builds or result.stripped_git:
            names = sorted({b["name"] for b in result.registry_builds} | {g["name"] for g in result.stripped_git})
            return [], [], ("a development package has no wheel and would be built from source ("
                            + ", ".join(names) + "), and a baseline records source builds for the runtime set only.")
        have = {(p["name"], p["version"], p["markers"]) for p in pins if p["section"] == "run"}
        found = [{"name": n, "version": v, "section": "dev", "markers": m} for n, v, m in result.pins
                 if (n, v, m) not in have]
        conflicts = bl.pin_conflicts(pins + found)
        if conflicts:
            return [], [], ("they cannot be installed with the runtime packages: " + conflict_text(conflicts) + ".")
        clash = joint_clash(base_docs, found)
        if clash:
            return [], [], ("they disagree with an approved baseline of this bench: "
                            + "; ".join(f"{n} {mine} against {theirs} ({bid})" for n, mine, theirs, bid in clash[:4]) + ".")
        git = []
        for n, owner, repo, c in result.git:
            check_git_source(seams, owners, {"name": n, "owner": owner, "repo": repo, "commit": c})
            git.append({"name": n, "owner": owner, "repo": repo, "commit": c})
        return found, git, ""
    except PlanError as failure:
        detail = re.search(r"a bench is one: (.*?) Nothing was written", str(failure), re.DOTALL)
        text = " ".join(detail.group(1).split()) if detail else _tail(failure)
        text = re.sub(r"^uv pip compile failed and named no package the plan can set aside:\s*(?:error:\s*)?"
                      r"(?:No solution found when resolving dependencies\s*(?:cause:\s*)?)?", "", text)
        return [], [], "they cannot be installed together with the other upstream apps' development sets: " + text


def _bench_siblings(root, app_dir, dir_name, owners) -> tuple:
    """([ids of the approved baselines of the other apps of the bench `app_dir` is in], [names of its
    upstream apps that have none yet])."""
    import bench_config
    bench = bench_config.bench_root(Path(app_dir).resolve())
    if bench is None:
        return [], []
    covered, uncovered = bl.baselines_for_bench(root, bench)
    ids = sorted(doc["id"] for name, doc in covered.items() if name != dir_name and doc.get("kind") == "upstream")
    waiting = sorted(n for n in uncovered if n != dir_name and bl.app_origin_owner(Path(bench) / "apps" / n) in owners)
    return ids, waiting


def _tail(failure) -> str:
    lines = [l.strip() for l in str(failure).strip().splitlines() if l.strip()]
    return " ".join(lines[-6:])


# What uv and git print when the network, not the requirements, failed a resolution.
_NETWORK_MARKERS = ("request failed", "failed to fetch", "error sending request", "operation timed out",
                    "timed out", "network is unreachable", "dns error", "connection reset",
                    "connection refused", "gnutls recv error", "early eof", "temporary failure in name resolution")


def _network_failure(text) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _NETWORK_MARKERS)


def read_mate(seams, owners, item):
    """Another upstream app of the bench, read from its upstream repository at its commit (never from the
    working tree, which a plan cannot trust): {label, git_url, commit, date, declared, names}."""
    url, commit = item.get("git_url"), item.get("commit")
    parts = bl.repo_parts(url) if isinstance(url, str) else None
    if parts is None or not isinstance(commit, str) or not bl._COMMIT.match(commit):
        raise PlanError(f"{item!r} is not an upstream app at a full commit; it cannot be resolved together with")
    why = bl.owner_problem(url, owners)
    if why:
        raise PlanError(why)
    git_url = f"https://github.com/{parts[0]}/{parts[1]}"
    label = "apps/" + (item.get("dir_name") or parts[1])
    fetched = seams.fetch(git_url)
    if not fetched.reachable_refs(commit):
        raise PlanError(f"{label} is at {commit[:12]}, which no branch or tag of {git_url} contains: it is not "
                        "upstream, so this plan cannot take its requirements into account. Nothing was written. "
                        f"Put {label} on a released commit, or plan it first.")
    tree = fetched.tree(commit)
    digests, problems = bl.discover_manifests(tree)
    if problems:
        raise PlanError(f"{label}: " + "; ".join(problems))
    declared = declared_python(tree, digests)
    # The names this app is known by as a distribution are the ones its own metadata declares at this commit.
    # The directory it sits in (`apps/<dir>`) and the name of its repository are not read: a person (or
    # Claude) sets the first, and neither is metadata of the app, so neither may make a requirement of
    # another app "local" and take it out of the resolution.
    names = set(declared.dist_names)
    version = tree_version(tree, declared)
    return {"label": label, "git_url": git_url, "commit": commit, "date": fetched.commit_date(commit),
            "declared": declared, "names": names, "version": version or "",
            "release": release_of(fetched, commit, version)}


def release_of(fetched, commit, version) -> str:
    """Where `commit` stands among the releases of its repository: `branch version-NN` when the release branch
    for its major (read from its `__version__`) contains it, `tag <name>` when a tag points at it, else `none`."""
    major = (version or "").split(".")[0]
    if major.isdigit() and f"refs/heads/version-{int(major)}" in fetched.reachable_refs(commit):
        return f"branch version-{int(major)}"
    tags = sorted(t[len("refs/tags/"):] for t in (fetched.tags_at(commit) if hasattr(fetched, "tags_at") else [])
                  if t.startswith("refs/tags/") and _REF.match(t[len("refs/tags/"):]))
    return f"tag {tags[0]}" if tags else "none"


def _bench_joint_apps(root, seams, app_dir, dir_name, owners) -> list:
    """[{git_url, commit, dir_name}] for each other upstream app of the bench `app_dir` is in: the ones an
    approved baseline covers (the commit it names) and the ones with none (their checkout's commit)."""
    import bench_config
    bench = bench_config.bench_root(Path(app_dir).resolve())
    if bench is None:
        return []
    covered, uncovered = bl.baselines_for_bench(root, bench)
    found = [{"git_url": doc["app"]["git_url"], "commit": doc["app"]["commit"], "dir_name": name}
             for name, doc in sorted(covered.items()) if name != dir_name and doc.get("kind") == "upstream"]
    for name in sorted(uncovered):
        app = Path(bench) / "apps" / name
        if name == dir_name or bl.app_origin_owner(app) not in owners:
            continue
        url = _remote_url(app)
        code, out = seams.git(["rev-parse", "HEAD"], str(app))
        commit = out.decode().strip() if code == 0 else ""
        if url is None or not bl._COMMIT.match(commit):
            raise PlanError(f"apps/{name} is an upstream app of this bench, but its remote or its commit cannot be "
                            f"read ({out.decode(errors='replace').strip()[:100] if code != 0 else 'no remote'}), so "
                            "this plan cannot resolve the app together with it. Nothing was written.")
        found.append({"git_url": url, "commit": commit, "dir_name": name})
    return found


def conflict_text(conflicts) -> str:
    return "; ".join(f"{n} is pinned to {a} and to {b}" for n, a, b in conflicts[:8]) \
        + (f"; and {len(conflicts) - 8} more" if len(conflicts) > 8 else "")


def joint_clash(base_docs, pins) -> list:
    """[(name, own version, base version, base id)] for each pin of `pins` that an approved base pins
    differently where both can apply (run and dev share the runtime constraint file, build has its own;
    markers as `bench_config` unions them)."""
    runtime = lambda section: "build" if section == "build" else "runtime"
    found = []
    for pin in pins:
        for doc in base_docs:
            for other in doc["python"]["pins"]:
                if (bl.normalize_py(other["name"]) == bl.normalize_py(pin["name"])
                        and other["version"] != pin["version"]
                        and runtime(other["section"]) == runtime(pin["section"])
                        and (not other.get("markers") or not pin.get("markers")
                             or other["markers"] == pin["markers"])):
                    item = (bl.normalize_py(pin["name"]), pin["version"], other["version"], doc["id"])
                    if item not in found:
                        found.append(item)
    return sorted(found)


def clash_text(base_docs, clash) -> str:
    names = {doc["id"]: doc["app"]["dir_name"] for doc in base_docs}
    lines = [f"{n}: this app's requirements resolve it to {mine}, but {bid} (apps/{names[bid]}) pins {theirs}"
             for n, mine, theirs, bid in clash[:8]]
    ids = sorted({bid for _n, _m, _t, bid in clash})
    return ("no joint resolution with the approved baselines of this bench: " + "; ".join(lines)
            + (f"; and {len(clash) - 8} more" if len(clash) > 8 else "")
            + ". A bench is one Python environment, so its baselines must agree on every shared package. "
            "Nothing was written. " + ", ".join(ids) + (" was" if len(ids) == 1 else " were")
            + " resolved on its own or at another commit, before this app was taken into account. Ask the user to "
            "revoke " + ("it" if len(ids) == 1 else "them") + " (`baseline revoke`) and plan the apps again: a plan "
            "now resolves an app together with the declared requirements of every other upstream app in the bench, "
            "so the order does not matter. If a plan still fails after that, the apps' own requirements cannot be "
            "installed together, and the error says which packages.")


MAX_BUILD_ROUNDS = 6


def check_git_source(seams, owners, item):
    """A git reference, wherever it came from (a requirement, a build requirement read from another
    source, what uv printed): the owner must be on the allowlist now, and the commit must be in a
    branch or tag of that very repository."""
    if item["owner"] not in owners:
        raise PlanError(f"{item['name']} comes from {item['owner']}/{item['repo']}; the owner is not in the "
                        "git-owners allowlist")
    if not fetched_for(seams, item):
        raise PlanError(f"{item['name']} is pinned to {item['commit']} of {item['owner']}/{item['repo']}, which "
                        "no branch or tag of that repository contains")


def fetched_for(seams, item, want_tree=False):
    """True when a branch or tag of the git source's repository contains its commit
    (or, with `want_tree`, that commit's tree)."""
    fetched = seams.fetch(f"https://github.com/{item['owner']}/{item['repo']}")
    if want_tree:
        return fetched.tree(item["commit"])
    return bool(fetched.reachable_refs(item["commit"]))


def static_build_requires(tree, item):
    """`[build-system] requires` of a git source, read from its pyproject.toml;
    none when it has no pyproject (setuptools and wheel are the toolchain's)."""
    try:
        data = tomllib.loads(bl.normalized_bytes(tree.read("pyproject.toml"), "pyproject.toml").decode("utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError, bl.BaselineError):
        return []
    build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
    return [r for r in build.get("requires") or [] if isinstance(r, str)]
