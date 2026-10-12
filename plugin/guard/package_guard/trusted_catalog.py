"""Per-user package identity evidence. Never writes installation approvals."""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

SEED_PATH = Path(__file__).with_name("trusted-packages.json")
REGISTRIES = {"npm": "https://registry.npmjs.org", "pypi": "https://pypi.org"}


def user_path() -> Path:
    # Deliberately independent of project configuration and Claude profiles.
    return Path.home() / ".config/package-guard/trusted-packages.json"


def normalize_name(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name


def repository_id(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.removeprefix("git+")
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value[len("git@github.com:"):]
    try:
        url = urlsplit(value)
        if (url.scheme not in ("https", "http", "git", "ssh") or url.hostname != "github.com"
                or url.password or url.port or url.query or url.fragment):
            return None
        path = url.path.rstrip("/").removesuffix(".git")
        if not re.fullmatch(r"/[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*", path):
            return None
        return "https://github.com" + path.lower()
    except ValueError:
        return None


def _select_path(path: Path | None) -> Path:
    selected = path if path is not None else user_path()
    # A broken symlink, unreadable file, or invalid replacement cannot silently
    # restore trust that the user may have removed from the bundled catalog.
    if path is None and not selected.exists() and not selected.is_symlink():
        selected = SEED_PATH
    return selected


def _load(selected: Path):
    """Parse and validate the catalog envelope; raise on any invalidity.

    The single parser for the file: `lookup` and `describe` both go through it,
    so a catalog that reads as trusted reads as active, and one that reads as
    unavailable is unavailable everywhere. Returns (document, entries by key,
    reviewed, expires).
    """
    document = json.loads(selected.read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or document.get("schema_version") != 1
            or not isinstance(document.get("catalog_version"), str)
            or not document["catalog_version"] or not isinstance(document.get("packages"), list)):
        raise ValueError("invalid catalog envelope")
    reviewed = date.fromisoformat(document["reviewed_at"])
    expires = date.fromisoformat(document["expires_at"])
    if reviewed >= expires:
        raise ValueError("invalid catalog validity interval")
    entries = {}
    for entry in document["packages"]:
        eco, package = entry["ecosystem"], entry["name"]
        if eco not in REGISTRIES or not isinstance(package, str) or not package:
            raise ValueError("invalid package identity")
        key = (eco, normalize_name(eco, package))
        repo = repository_id(entry["repository"])
        if (key in entries or entry["registry"] != REGISTRIES[eco] or repo is None
                or not isinstance(entry["source"], str) or not entry["source"].startswith("https://")):
            raise ValueError("duplicate or invalid catalog entry")
        entries[key] = entry
    return document, entries, reviewed, expires


def lookup(ecosystem: str, name: str, registry: str, repository,
           *, path: Path | None = None, today: date | None = None) -> dict:
    selected = _select_path(path)
    result = {"status": "unavailable", "catalog_version": None,
              "source": str(selected), "repository": None, "reason": None}
    try:
        document, entries, reviewed, expires = _load(selected)
        now = today or date.today()
        result["catalog_version"] = document["catalog_version"]
        if now < reviewed or now >= expires:
            result.update(status="expired", reason="catalog outside its review validity period")
            return result
        entry = entries.get((ecosystem, normalize_name(ecosystem, name)))
        if entry is None:
            result.update(status="not_listed", reason="not in the user's trusted identity catalog")
        elif registry != entry["registry"] or repository_id(repository) != repository_id(entry["repository"]):
            result.update(status="identity_mismatch", repository=entry["repository"],
                          reason="registry or repository differs from catalog")
        else:
            result.update(status="trusted", repository=entry["repository"])
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        result["reason"] = f"catalog unavailable ({type(exc).__name__})"
    return result


def describe(*, path: Path | None = None, today: date | None = None) -> dict:
    """The effective catalog's version and time to expiry.

    Read-only, no network, no per-package lookup: the freeze relies on this so a
    catalog nobody is watching announces its own expiry instead of dropping the
    established shortcut in silence. `status` is `active`, `expired`, or
    `unavailable`; `days_left` is signed (negative once past expiry).
    """
    result = {"status": "unavailable", "catalog_version": None, "source": None,
              "expires_at": None, "days_left": None, "reason": None}
    try:
        # Path.home() raises RuntimeError when HOME is unset (CI): describe must
        # not crash the audit it only advises, so the path resolves inside the try.
        selected = _select_path(path)
        result["source"] = str(selected)
        document, _entries, reviewed, expires = _load(selected)
        now = today or date.today()
        result.update(catalog_version=document["catalog_version"],
                      expires_at=document["expires_at"], days_left=(expires - now).days)
        if now < reviewed or now >= expires:
            result.update(status="expired", reason="catalog outside its review validity period")
        else:
            result["status"] = "active"
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        result["reason"] = f"catalog unavailable ({type(exc).__name__})"
    return result
