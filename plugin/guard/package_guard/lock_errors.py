"""The one error every lockfile reader raises.

`bun_lock`, `pnpm_lock` and `yarn_lock` each refuse a file they cannot account
for. Their errors share this base so the hook can catch a single type and deny:
an unreadable lock is never read as an empty one.
"""
from __future__ import annotations


class LockReadError(ValueError):
    """A lockfile is unreadable, malformed, or in a shape its reader will not guess at."""
