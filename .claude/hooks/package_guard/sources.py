"""Where the installer will actually fetch from. No policy beyond "the default".

A review vets `registry/name@version` against the default registry
(`parser.NPM_REGISTRY`, `parser.PYPI_REGISTRY`); an approval is only worth what
it says if the installer then fetches that identity from that registry. The
command line is checked by the parser. This module checks what the
command line cannot show:

  * configuration the installer reads on its own -- `.npmrc`, `pip.conf`,
    `uv.toml`, `[tool.uv]`, and the environment the hook shares with the shell;
  * the lockfile entries it will install -- npm `resolved` / alias `name`,
    uv.lock `source`, `sdist` and `wheels`;
  * manifest specs that name a non-registry source -- `npm:` aliases, git
    hosts, URLs, paths, PEP 508 direct references.

Each check answers with reasons, never a decision. The hook refuses when any
reason exists, the same way it refuses an `alternate-source` flag.

Every global location is a parameter with a default, like inventory.py's
roots, so the tests never read the developer's own configuration.

Standard library only.
"""
from __future__ import annotations

import configparser
import json
import os
import re
import shutil
import tomllib
from pathlib import Path

import bun_lock
import parser as pg_parser
import pm_config
import pnpm_lock
import protocols
import yarn_lock
from lock_errors import LockReadError

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_INDEX = "https://pypi.org/simple"
PYPI_FILES = "https://files.pythonhosted.org/"

HOME = Path.home()


def _same_url(value, default) -> bool:
    if not isinstance(value, str):
        return False
    # registry.yarnpkg.com is registry.npmjs.org under another name (D11).
    return protocols.canonical_registry(value) == protocols.canonical_registry(default)


_redact = protocols.redact


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

# A spec that names something other than a registry version. `owner/repo` is
# npm's GitHub shorthand; a range never contains a bare slash.
_NPM_NON_REGISTRY = re.compile(
    r"^(?:" + "|".join(re.escape(p) for p in protocols.NON_REGISTRY_PREFIXES)
    + r"|\.{0,2}/|~/|[^/@\s]+@[^:/\s]+:)", re.IGNORECASE)
_NPM_GITHUB_SHORTHAND = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.*)?$")
# npm reads `.tgz`, `.tar.gz` and `.tar` as a tarball file, in any case. The
# rest name no registry version either.
_ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".tar", ".tar.bz2", ".zip", ".whl")


def npm_spec_problem(name: str, spec) -> str | None:
    if not isinstance(spec, str):
        return None
    text = spec.strip()
    if _NPM_NON_REGISTRY.match(text) or _NPM_GITHUB_SHORTHAND.match(text):
        return f"package.json: {name!r} is {_redact(text)!r}, not a registry version"
    if text.lower().endswith(_ARCHIVE_SUFFIXES):
        return f"package.json: {name!r} is an archive file ({_redact(text)!r})"
    return None


def _npmrc_registry_keys(path: Path):
    """(key, value) for every registry setting in one .npmrc file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        # `registry` and `@scope:registry` redirect; `//host/:_authToken` is a
        # credential keyed by host and redirects nothing.
        if key == "registry" or key.endswith(":registry"):
            out.append((key, value.strip()))
    return out


def _npm_global_rc(environ):
    """$PREFIX/etc/npmrc. Under nvm or Homebrew it is user-writable."""
    path = environ.get("npm_config_globalconfig") or environ.get("NPM_CONFIG_GLOBALCONFIG")
    if path:
        return Path(path)
    prefix = environ.get("npm_config_prefix") or environ.get("NPM_CONFIG_PREFIX")
    if not prefix:
        node = shutil.which("node", path=environ.get("PATH"))
        if not node:
            return None
        prefix = Path(node).resolve().parent.parent
    return Path(prefix) / "etc" / "npmrc"


def npm_config_problems(directory, home=None, environ=None, prefixes=("npm_config_",)) -> list:
    home = Path(home) if home is not None else HOME
    environ = os.environ if environ is None else environ
    problems = []
    candidates = [Path(directory) / ".npmrc"]
    user = environ.get("npm_config_userconfig") or environ.get("NPM_CONFIG_USERCONFIG")
    candidates.append(Path(user) if user else home / ".npmrc")
    candidates.append(_npm_global_rc(environ))
    for path in candidates:
        if path is None:
            continue
        for key, value in _npmrc_registry_keys(path):
            if not _same_url(value, NPM_REGISTRY):
                problems.append(f"{path}: `{key}={_redact(value)}` redirects npm")
    for name, value in environ.items():
        lowered = name.lower()
        prefix = next((p for p in prefixes if lowered.startswith(p)), None)
        if prefix and (lowered == prefix + "registry" or lowered.endswith(":registry")):
            if not _same_url(value, NPM_REGISTRY):
                problems.append(f"environment: {name} redirects npm")
    return problems


def pm_config_problems(kind, directory, home=None, environ=None, require_linker=True) -> list:
    """`pm_config` for one pnpm, Bun or Yarn, with the npm spec rules for the
    `overrides` and `resolutions` it reads."""
    home = Path(home) if home is not None else HOME
    environ = os.environ if environ is None else environ
    return pm_config.pm_config_problems(kind, directory, home, environ,
                                        spec_problem=npm_spec_problem, require_linker=require_linker)


def npm_lock_problems(directory) -> list:
    """Lock entries npm would fetch from somewhere other than the registry,
    or under another package's name (an `npm:` alias)."""
    lock = Path(directory) / "package-lock.json"
    if not lock.is_file():
        return []
    try:
        data = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []  # the manifest reader reports an unreadable lock
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        # lockfileVersion 1: npm 7+ still installs from its `resolved` URLs,
        # which no reader here checks.
        return ["package-lock.json has no `packages` map (lockfileVersion 1); "
                "regenerate it with npm 7 or newer"] if isinstance(data, dict) else []
    problems = []
    for key, entry in packages.items():
        if not key or "node_modules/" not in key or not isinstance(entry, dict):
            continue
        name = key.rsplit("node_modules/", 1)[1]
        resolved = entry.get("resolved")
        if entry.get("link"):
            # A symlink to a directory npm installs as-is. Inside the project it
            # is the project's own code; outside it is someone else's, unreviewed.
            if not _inside(directory, resolved):
                problems.append(f"package-lock.json: {name} links outside the project "
                                f"({_redact(resolved)})")
            continue
        if entry.get("inBundle"):
            continue  # shipped inside its parent's tarball
        if isinstance(resolved, str) and not any(
                resolved.startswith(base + "/") for base in (NPM_REGISTRY, *protocols.NPM_REGISTRY_ALIASES)):
            problems.append(f"package-lock.json: {name} resolves to {_redact(resolved)}")
        alias = entry.get("name")
        if isinstance(alias, str) and alias != name:
            problems.append(f"package-lock.json: {name} is installed as {alias!r}")
    return problems


_PM_LOCK_MODULES = {"pnpm": ("pnpm-lock.yaml", pnpm_lock), "bun": ("bun.lock", bun_lock),
                    "yarn": ("yarn.lock", yarn_lock)}


def pm_lock_problems(kind, directory) -> list:
    """Lock entries a pnpm, Bun or Yarn install would fetch from somewhere other
    than the registry (git, URL, tarball, file, link, workspace, patch, exec,
    portal, jsr), and an unreadable lock, which is a problem and never an empty
    list. A missing lock is the hook's own check (`_pm_project_problem`)."""
    name, module = _PM_LOCK_MODULES[kind]
    path = Path(directory) / name
    if not path.is_file():
        return []
    try:
        problems = []
        for entry in module.non_registry_entries(path):
            source = entry.resolution if kind == "yarn" else entry.spec
            problems.append(f"{name}: {entry.name} is a {entry.kind} source ({_redact(source)})")
        if kind == "pnpm":
            problems += [f"{name}: patchedDependencies applies local code to {key}"
                         for key in pnpm_lock.patched_dependencies(path)]
        if kind == "bun":
            problems += [f"{name}: patchedDependencies applies local code to {key}"
                         for key in bun_lock.patched_dependencies(path)]
        return problems
    except LockReadError as exc:
        return [f"{name} cannot be read ({exc})"]


def _pm_lock_artifacts(kind, directory):
    name, module = _PM_LOCK_MODULES[kind]
    path = Path(directory) / name
    if kind == "yarn" or not path.is_file():
        return []  # Berry's checksum is a hash of its own cache zip, not npm's digest
    try:
        return [("npm", n, v, digests, missing) for n, v, digests, missing in module.artifacts(path)]
    except LockReadError:
        return []  # pm_lock_problems reports it


def npm_manifest_problems(directory) -> list:
    path = Path(directory) / "package.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    problems = []
    if isinstance(data, dict) and data.get("workspaces"):
        # Member manifests are never read, so nothing in them would be gated.
        problems.append("package.json: npm workspaces are not supported (members are not read)")
    # peerDependencies (installed by npm 7+) and overrides are not direct
    # dependencies, but npm fetches what they name all the same.
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        block = data.get(field) if isinstance(data, dict) else None
        if isinstance(block, dict):
            for name, spec in block.items():
                problem = npm_spec_problem(name, spec)
                if problem:
                    problems.append(problem)
    pending = [data.get("overrides")] if isinstance(data, dict) else []
    while pending:
        block = pending.pop()
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if isinstance(spec, dict):
                pending.append(spec)
                continue
            problem = npm_spec_problem(name, spec)
            if problem:
                problems.append(problem)
    return problems


# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------

_PIP_KEYS = ("index-url", "extra-index-url", "find-links", "no-index", "trusted-host")
_PIP_ENV = ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX",
            "PIP_TRUSTED_HOST", "PIP_CONFIG_FILE")


def _pip_conf_files(directory, home, environ, environments=None):
    """Every pip.conf pip may read. `environments` are the Python environments
    the install may use (the hook passes `disk_guard.environments`); without
    it, `<directory>/.venv`."""
    home = Path(home)
    files = [home / ".config" / "pip" / "pip.conf", home / ".pip" / "pip.conf",
             home / "Library" / "Application Support" / "pip" / "pip.conf"]
    if environments is None:
        environments = [Path(directory) / ".venv"]
    files += [Path(env) / "pip.conf" for env in environments]
    venv = environ.get("VIRTUAL_ENV")
    if venv:
        files.append(Path(venv) / "pip.conf")
    return list(dict.fromkeys(files))


def pip_config_problems(directory, home=None, environ=None, environments=None) -> list:
    home = HOME if home is None else home
    environ = os.environ if environ is None else environ
    problems = [f"environment: {name} changes where pip fetches from"
                for name in _PIP_ENV
                if environ.get(name) and not (name == "PIP_INDEX_URL"
                                              and _same_url(environ[name], PYPI_INDEX))]
    for path in _pip_conf_files(directory, home, environ, environments):
        if not path.is_file():
            continue
        # Raw, as pip reads it: a `%` in a URL is not interpolation.
        parser = configparser.RawConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except (configparser.Error, UnicodeDecodeError):
            problems.append(f"{path}: unreadable pip configuration")
            continue
        for section in parser.sections():
            for option, value in parser.items(section):
                # pip normalises names: lower case, `_` to `-`, leading `--` dropped.
                key = option.lower().replace("_", "-").lstrip("-")
                if key not in _PIP_KEYS:
                    continue
                if value and not (key == "index-url" and _same_url(value, PYPI_INDEX)):
                    problems.append(f"{path}: [{section}] {key} changes where pip fetches from")
    return problems


# ---------------------------------------------------------------------------
# uv
# ---------------------------------------------------------------------------

_UV_KEYS = ("index-url", "extra-index-url", "find-links", "index", "no-index", "default-index")
_UV_ENV = ("UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_DEFAULT_INDEX",
           "UV_FIND_LINKS", "UV_NO_INDEX", "UV_CONFIG_FILE")


def _load_toml(path: Path):
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def _uv_settings_problems(table, where, directory) -> list:
    problems = []
    if not isinstance(table, dict):
        return problems
    for key in _UV_KEYS:
        if table.get(key):
            problems.append(f"{where}: `{key}` changes where uv fetches from")
    sources = table.get("sources")
    if isinstance(sources, dict):
        for name, source in sources.items():
            entries = source if isinstance(source, list) else [source]
            for entry in entries:
                if isinstance(entry, dict) and (
                        entry.get("workspace") is True
                        or set(entry) <= {"path", "editable"} and _inside(directory, entry.get("path"))):
                    continue  # a workspace member: the project's own code
                problems.append(f"{where}: `sources.{name}` is not the registry")
    # `uv pip` reads its index settings from the [pip] subtable.
    if where and not where.endswith("[pip]"):
        problems += _uv_settings_problems(table.get("pip"), f"{where} [pip]", directory)
    return problems


# PEP 508 `name [extras] @ url`, spaces optional.
_DIRECT_REFERENCE = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\])?\s*@")


def _pyproject_requirements(pyproject):
    """Every requirement string uv may install from pyproject.toml."""
    project = pyproject.get("project") if isinstance(pyproject.get("project"), dict) else {}
    tool = pyproject.get("tool") if isinstance(pyproject.get("tool"), dict) else {}
    uv = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
    lists = [project.get("dependencies")]
    for table in (project.get("optional-dependencies"), pyproject.get("dependency-groups")):
        if isinstance(table, dict):
            lists += list(table.values())
    lists += [uv.get(k) for k in ("dev-dependencies", "override-dependencies",
                                  "constraint-dependencies")]
    return [d for block in lists if isinstance(block, list) for d in block if isinstance(d, str)]


def uv_config_problems(directory, home=None, environ=None) -> list:
    home = Path(HOME if home is None else home)
    environ = os.environ if environ is None else environ
    problems = [f"environment: {name} changes where uv fetches from"
                for name in _UV_ENV if environ.get(name)]
    pyproject = _load_toml(Path(directory) / "pyproject.toml")
    if isinstance(pyproject, dict):
        tool = pyproject.get("tool")
        if isinstance(tool, dict):
            problems += _uv_settings_problems(tool.get("uv"), "pyproject.toml [tool.uv]", directory)
        for dep in _pyproject_requirements(pyproject):
            if _DIRECT_REFERENCE.match(dep):
                problems.append(f"pyproject.toml: {dep!r} is a direct reference, not the registry")
    for path in (Path(directory) / "uv.toml", home / ".config" / "uv" / "uv.toml"):
        settings = _load_toml(path) if path.is_file() else None
        problems += _uv_settings_problems(settings, str(path), directory)
    # uv also finds project config in parent directories.
    for parent in Path(directory).resolve().parents:
        settings = _load_toml(parent / "uv.toml") if (parent / "uv.toml").is_file() else None
        problems += _uv_settings_problems(settings, str(parent / "uv.toml"), parent)
        outer = _load_toml(parent / "pyproject.toml") if (parent / "pyproject.toml").is_file() else None
        tool = outer.get("tool") if isinstance(outer, dict) else None
        if isinstance(tool, dict):
            problems += _uv_settings_problems(tool.get("uv"), f"{parent / 'pyproject.toml'} [tool.uv]",
                                              parent)
    return problems


def _inside(directory, relative) -> bool:
    if not isinstance(relative, str):
        return False
    base = Path(directory).resolve()
    target = (base / relative).resolve()
    return target == base or base in target.parents


def uv_lock_problems(directory) -> list:
    data = _load_toml(Path(directory) / "uv.lock")
    packages = data.get("package") if isinstance(data, dict) else None
    if not isinstance(packages, list):
        return []
    problems = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        source = entry.get("source")
        if not isinstance(source, dict):
            continue
        local = next((k for k in ("virtual", "editable", "directory") if k in source), None)
        if local:
            # The project and its workspace members. A path that leaves the
            # project is someone else's code installed unreviewed.
            if not _inside(directory, source[local]):
                problems.append(f"uv.lock: {name} is a local path outside the project ({source[local]})")
            continue
        if "registry" not in source:
            kind = next(iter(source), "?")
            problems.append(f"uv.lock: {name} comes from a {kind} source, not the registry")
            continue
        if not _same_url(source["registry"], PYPI_INDEX):
            problems.append(f"uv.lock: {name} comes from {_redact(source['registry'])}")
            continue
        files = [entry.get("sdist")] + list(entry.get("wheels") or [])
        for item in files:
            url = item.get("url") if isinstance(item, dict) else None
            if isinstance(url, str) and not url.startswith(PYPI_FILES):
                problems.append(f"uv.lock: {name} downloads {_redact(url)}")
                break
    return problems


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------

def _npm_lock_artifacts(directory):
    lock = Path(directory) / "package-lock.json"
    try:
        packages = json.loads(lock.read_text(encoding="utf-8")).get("packages")
    except (OSError, ValueError, AttributeError, RecursionError):
        return []
    out = []
    for key, entry in (packages or {}).items() if isinstance(packages, dict) else ():
        if key and "node_modules/" in key and isinstance(entry, dict) \
                and isinstance(entry.get("version"), str):
            if entry.get("link") or entry.get("inBundle"):
                continue
            integrity = entry.get("integrity")
            digests = [integrity] if isinstance(integrity, str) else []
            out.append(("npm", key.rsplit("node_modules/", 1)[1], entry["version"], digests,
                        not digests))
    return out


def _uv_lock_artifacts(directory):
    data = _load_toml(Path(directory) / "uv.lock")
    out = []
    for entry in (data or {}).get("package") or []:
        if not isinstance(entry, dict) or not isinstance(entry.get("version"), str):
            continue
        source = entry.get("source")
        if isinstance(source, dict) and "registry" not in source:
            continue  # the project's own code, or a source uv_lock_problems refuses
        hashes, missing = [], False
        for item in [entry.get("sdist")] + list(entry.get("wheels") or []):
            if not isinstance(item, dict):
                continue
            digest = item.get("hash")
            if isinstance(digest, str) and digest.startswith("sha256:"):
                hashes.append(digest[len("sha256:"):])
            else:
                missing = True
        if isinstance(entry.get("name"), str):
            name = re.sub(r"[-_.]+", "-", entry["name"]).lower()
            out.append(("pypi", name, entry["version"], hashes, missing or not hashes))
    return out


def artifact_problems(kinds, directory, artifacts_of, pm_kinds=()) -> list:
    """Lock files whose digest is not one an approval recorded: a file the
    registry gained after the review, or a lock edited to point elsewhere."""
    entries = []
    if "npm" in kinds:
        entries += _npm_lock_artifacts(directory)
    for kind in pm_kinds:
        entries += _pm_lock_artifacts(kind, directory)
    if "uv-project" in kinds:
        entries += _uv_lock_artifacts(directory)
    problems = []
    for ecosystem, name, version, digests, missing in entries:
        approved = artifacts_of(ecosystem, name, version)
        if approved is None:
            continue  # not approved here, or approved before artifacts were recorded
        if missing:
            # The approval recorded digests; a lock entry without one is
            # a file nobody compared against them.
            problems.append(f"{ecosystem}:{name}@{version} lock entry carries no digest for a "
                            "file it installs; restore the lock's integrity/hash and retry")
            continue
        stray = [d for d in digests if d not in approved]
        if stray:
            problems.append(f"{ecosystem}:{name}@{version} lock names a file the approval did not "
                            f"see ({stray[0][:24]}...); revoke and re-review it")
    return problems


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def problems_for(parsed, directory, home=None, environ=None, artifacts_of=None,
                 environments=None) -> list:
    """Every reason the installer `parsed` describes would fetch from somewhere
    other than the identity its review vetted. `environments` are the Python
    environments the install may use, whose pip.conf pip reads."""
    ecosystems = {r.ecosystem for r in parsed.requests}
    managers = {r.manager for r in parsed.requests}
    # pnpm, Bun and Yarn install from package.json and node_modules: every npm
    # source check applies to them as well.
    kinds = {"npm" if m.kind in ("npm", "pnpm", "bun", "yarn") else m.kind
             for m in parsed.manifests}
    problems = []
    if "npm" in ecosystems or "npm" in kinds:
        # pnpm reads `pnpm_config_*` by the same rules as `npm_config_*`.
        uses_pnpm = "pnpm" in pg_parser.pm_kinds(parsed)
        problems += npm_config_problems(
            directory, home, environ,
            prefixes=("npm_config_", "pnpm_config_") if uses_pnpm else ("npm_config_",))
    if "npm" in kinds:
        problems += npm_manifest_problems(directory) + npm_lock_problems(directory)
    pm_kinds = sorted({m.kind for m in parsed.manifests if m.kind in _PM_LOCK_MODULES})
    for kind in pm_kinds:
        problems += pm_lock_problems(kind, directory)
    # Configuration the manager reads itself, for every pnpm, Bun and Yarn the
    # command reaches, including the one-shot runners (`pnpm dlx`, `bunx`,
    # `yarn dlx`: Yarn copies .yarnrc.yml into its temp project).
    for kind, scoped in sorted(pg_parser.pm_kinds(parsed).items()):
        problems += pm_config_problems(kind, directory, home, environ, require_linker=scoped)
    # A local build fetches build-system.requires through pip or uv; the
    # scope does not say which, so both configurations are checked.
    pypi = "pypi" in ecosystems or kinds & {"requirements", "uv-project", "build-requires"}
    if pypi:
        uses_uv = any(m.startswith("uv") for m in managers) or kinds & {"uv-project", "build-requires"}
        uses_pip = (any(not m.startswith("uv") for m in managers if m)
                    or kinds & {"requirements", "build-requires"})
        if uses_pip:
            problems += pip_config_problems(directory, home, environ, environments)
        if uses_uv or "requirements" in kinds:
            problems += uv_config_problems(directory, home, environ)
    if "uv-project" in kinds:
        problems += uv_lock_problems(directory)
    if artifacts_of is not None:
        problems += artifact_problems(kinds, directory, artifacts_of, pm_kinds)
    seen = set()
    return [p for p in problems if not (p in seen or seen.add(p))]
