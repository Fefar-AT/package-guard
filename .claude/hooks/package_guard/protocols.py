"""Names every module shares about where a package comes from.

Two facts, kept in one place so the parser, the source checks and the three
lock readers cannot drift apart (v1.10.0, P3, decisions D11 and D13):

  * the spec protocols that name something other than a registry version;
  * the hosts that count as the default npm registry.

Standard library only; imports nothing from the package.
"""
from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

# A spec (or a lock reference) starting with one of these names a source a
# registry review cannot vet: an alias, a repository, a path, a patch, a
# protocol another ecosystem owns. Lower case; compare against lower-cased text.
NON_REGISTRY_PREFIXES = (
    "npm:", "jsr:", "crate:", "pypi:", "pkg:", "runtime:", "patch:", "exec:", "portal:",
    "link:", "file:", "workspace:", "catalog:", "git+", "git:", "github:", "gitlab:",
    "bitbucket:", "gist:", "ssh:", "http:", "https:",
)

# D11: Yarn's own default registry host is the same registry as npm's.
NPM_REGISTRY = "https://registry.npmjs.org"
NPM_REGISTRY_ALIASES = ("https://registry.yarnpkg.com",)
OFFICIAL_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com")


def names_other_source(spec) -> bool:
    return isinstance(spec, str) and spec.strip().lower().startswith(NON_REGISTRY_PREFIXES)


def canonical_registry(url) -> str:
    """`url` as a registry base for comparison: unquoted, no trailing slash,
    and the yarnpkg alias folded into the npm registry."""
    text = str(url).strip().strip("\"'").rstrip("/")
    return NPM_REGISTRY if text in NPM_REGISTRY_ALIASES else text


def is_official_registry(url) -> bool:
    return isinstance(url, str) and canonical_registry(url) == NPM_REGISTRY


def is_official_host(host) -> bool:
    return host in OFFICIAL_HOSTS


_USERINFO = re.compile(r"(?<=://)[^/@\s]*@")


def redact(value) -> str:
    """A URL as a reason may name it: the host, never the credentials before it."""
    return _USERINFO.sub("***@", str(value))


def is_registry_tarball(name, version, url) -> bool:
    """True only for the exact URL an official registry host serves
    `name@version` at (D11: registry.yarnpkg.com counts)."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    if (parts.scheme != "https" or not is_official_host(parts.hostname) or port
            or parts.username or parts.password or parts.query or parts.fragment):
        return False
    base = name.rsplit("/", 1)[-1]
    return parts.path == f"/{name}/-/{base}-{version}.tgz"


def archive_url_of(reference):
    """The URL in `1.2.3::__archiveUrl=<percent-encoded>` (Yarn's record of a
    tarball it fetched from a place other than the registry's own path), or None."""
    _, sep, tail = str(reference).partition("::__archiveUrl=")
    return unquote(tail) if sep and "&" not in tail and "::" not in tail else None
