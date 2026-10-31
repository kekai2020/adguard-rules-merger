"""Single source of truth for the AdGuard Rules Merger version (M0).

This is the ONLY place the version string is stored. All other version
points (pyproject metadata, README badge, CLI banner, rule-file titles,
CI cache key, User-Agent) are derived from this constant or guarded by
tests/test_version_consistency.py.

V8 notes:
- Product version: 8.0.0.
- The parsed-rule sidecar and cache-index format tags live with their modules
  (``cache.PARSED_CACHE_VERSION``); the audit JSON cache tag is
  ``AUDIT_CACHE_VERSION`` below.
"""

__version__ = "8.0.1"
__version_short__ = "8"

# Increment to invalidate the JSON whitelist-audit cache when the
# persisted field set changes. The JSON record is forward/backward tolerant,
# so a bumped version simply forces a one-time re-audit on upgrade.
AUDIT_CACHE_VERSION = 2


def user_agent() -> str:
    """HTTP User-Agent advertised when fetching remote lists."""
    return f"AdGuard-Rules-Merger/{__version_short__}"
