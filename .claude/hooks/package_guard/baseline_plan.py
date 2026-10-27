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
from datetime import datetime, timezone
from pathlib import Path

import baseline as bl
import legacy
import store
import yarn_classic_lock
from lock_errors import LockReadError


class PlanError(Exception):
    """The plan is refused. The message says why and what to do."""


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


def _lines_of(tree, path):
    return bl.requirement_lines(bl.normalized_bytes(tree.read(path), path).decode("utf-8"))


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
        out.inputs.append("pyproject.toml#tool.bench.dev-dependencies")
    fd = bench.get("frappe-dependencies")
    if isinstance(fd, dict):
        out.local_extra |= {bl.normalize_py(n) for n in fd}
    build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
    if isinstance(build.get("requires"), list):
        out.build += [r for r in build["requires"] if isinstance(r, str)]
        out.inputs.append("pyproject.toml#build-system.requires")
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


def parse_compiled(stdout):
    pins, git = [], []
    for raw in stdout.splitlines():
        line = raw.strip()
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


def compile_set(seams, lines, git_inputs, python_version, exclude_newer, constraint_text, tag, workdir, applied=None):
    """Compile `lines` (and `git_inputs`, dicts with `line`) for one section.

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
    for _ in range(MAX_STRIPS):
        inputs = lines + [g["line"] for g in git_inputs]
        input_path = Path(workdir) / f"{tag}.in"
        input_path.write_text("\n".join(inputs) + "\n", encoding="utf-8")
        args = ["pip", "compile", "--no-build", "--universal", "--python-version", python_version,
                "--exclude-newer", exclude_newer, "--no-header", "--no-annotate"]
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
        code, stdout, stderr = seams.uv(args, str(workdir))
        if code == 0:
            result.pins, result.git = parse_compiled(stdout)
            result.overrides = list(overrides)
            return result
        result.stderr.append(stderr)
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
         dir_name=None):
    """The proposal for the app at `app_dir` (its URL read from its remote) or at
    `url` + `ref`. Returns {"document", "notes"}; raises PlanError."""
    deadline = time.monotonic() + bl.BASELINE_PLAN_DEADLINE
    try:
        owners, _hosts = bl.load_owners(root)
    except bl.BaselineError as exc:
        raise PlanError(str(exc)) from None
    import vetting
    try:
        return _plan(root, seams, owners, deadline, app_dir, url, ref, base_ids, python_version, exclude_newer, dir_name)
    except vetting.ProviderError as exc:
        raise PlanError(f"a registry or OSV did not answer ({exc}); nothing was written, run the plan again") from None
    finally:
        seams.cleanup()


def _plan(root, seams, owners, deadline, app_dir, url, ref, base_ids, python_version, exclude_newer=None,
          dir_name=None):
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
    if app_dir is not None:
        # A bench is one Python env: the approved baselines of its other apps are constraints of this plan.
        siblings, waiting = _bench_siblings(root, app_dir, dir_name, owners)
        base_ids = tuple(dict.fromkeys([*base_ids, *siblings]))
        notes += [f"apps/{n} is an upstream app with no approved baseline yet. This plan cannot take its "
                  "pins into account: if the two disagree about a shared package, `bench-config apply` "
                  "refuses and the later one is planned again." for n in waiting]
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
    floor = max([commit_date] + [d["python"]["compile"]["exclude_newer"] for d in base_docs])
    bound = min(floor, now_text)
    if exclude_newer is not None and (not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", exclude_newer)
                                      or exclude_newer > bound):
        raise PlanError(f"exclude-newer {exclude_newer} is later than the commit date or the plan time ({bound})")
    exclude_newer = exclude_newer or bound
    local_names = ({bl.normalize_py(n) for n in bl.FRAPPE_APP_NAMES} | declared.local_extra
                   | {bl.normalize_py(name), bl.normalize_py(dir_name)})
    excluded, git_found = [], []
    run = split_requirements(declared.run, "run", local_names, owners, excluded, git_found)
    dev = split_requirements(declared.dev, "dev", local_names, owners, excluded, git_found)
    build = split_requirements(declared.build, "build", local_names, owners, excluded, git_found)
    for item in git_found:
        check_git_source(seams, owners, item)
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

    def joint(lines, git_inputs, tag, with_bases, plain, section):
        """compile_set with the bases' pins as constraints; when that fails and the same set compiles
        without them, the failure is the bases' and the plan names the packages that clash."""
        try:
            return compile_set(seams, lines, git_inputs, pv, exclude_newer, with_bases, tag, workdir, applied)
        except PlanError as failure:
            if not base_docs:
                raise
            try:
                alone = compile_set(seams, lines, git_inputs, pv, exclude_newer, plain, tag, workdir, applied)
            except PlanError:
                raise failure from None
            clash = joint_clash(base_docs, [{"name": n, "version": v, "markers": m, "section": section}
                                            for n, v, m in alone.pins])
            if not clash:
                raise failure from None
            raise PlanError(clash_text(base_docs, clash)) from None

    pins, all_git, needs, overrides = [], [], [], []
    run_result = joint(run, [g for g in git_found if g["section"] == "run"], "run", constraint, own or None, "run")
    sections = [("run", run_result)]
    run_pins = "".join(f"{n}=={v}\n" for n, v, m in run_result.pins if not m)
    dev_result = joint(dev, [g for g in git_found if g["section"] == "dev"], "dev",
                       (constraint or "") + run_pins or None, own + run_pins or None, "dev") if dev or any(
        g["section"] == "dev" for g in git_found) else None
    if dev_result:
        sections.append(("dev", dev_result))
    # Build requirements of the app, and of every git source that was set aside (read statically,
    # to any depth): each goes through the same checks as a requirement the app wrote itself.
    build_lines, build_git, read = list(build), [g for g in git_found if g["section"] == "build"], set()
    build_result = None
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
            build_result = joint(build_lines, build_git, "build", base_build or None, None, "build")
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
    notes_unresolved = []
    if extra:
        more = compile_set(seams, extra, [], pv, exclude_newer,
                           base_run + "".join(f"{p['name']}=={p['version']}\n" for p in pins if not p["markers"]),
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
    clash = joint_clash(base_docs, pins)
    if clash:
        raise PlanError(clash_text(base_docs, clash))
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
                        **({"dependency_metadata_override": sorted({bl.normalize_py(e["name"]) for e in applied})}
                           if applied else {})},
            "pins": pins, "git": all_git, "excluded_local_names": sorted(excluded), "needs_build": needs,
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
            "Nothing was written. Plan the app that needs the older release first: ask the user to revoke "
            + ", ".join(ids) + " (`baseline revoke`), plan this app, then plan the other one again; it will be "
            "resolved against this one.")


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
