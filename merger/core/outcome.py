"""Outcome dataclasses and fetch-error helpers for the merge engine.

Moved verbatim from the legacy ``merger.core`` module during the P1-3 package
split; no algorithm, threshold or wording changed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from ..models import Rule


def _iter_parents(norm: str, min_labels: int = 2) -> Iterator[str]:
    """Yield strict parent domains, most-specific first.

    Stops as soon as a parent would have fewer than ``min_labels`` labels,
    so callers don't build (and then filter) the full parent list.
    """
    parts = norm.split(".")
    n = len(parts)
    for i in range(1, n):
        if n - i < min_labels:
            break
        yield ".".join(parts[i:])


@dataclass
class SourceFailure:
    url: str
    name: str
    error: str
    error_type: str = "unknown"


def classify_source_error(err: BaseException | str) -> str:
    """Map a fetch exception or error message to a coarse error_type."""
    msg = str(err).lower()
    if isinstance(err, asyncio.TimeoutError) or "timeout" in msg or "deadline" in msg:
        return "timeout"
    if "404" in msg:
        return "not_found"
    if "403" in msg or "401" in msg:
        return "auth"
    if (
        "name or service not known" in msg
        or "nodename nor servname" in msg
        or "getaddrinfo failed" in msg
        or "name resolution" in msg
    ):
        return "dns"
    if "connect" in msg or "connection" in msg:
        return "network"
    return "unknown"


@dataclass
class MergeOutcome:
    """Result of a merge run — all counts and rule lists produced by the engine.

    ``blocks``/``allows`` are the final deduplicated, aggregated, sorted rule
    lists ready for export.  ``regex_*`` hold regex rules (kept separate because
    they are not subject to domain aggregation).  The ``*_merged``/``*_dropped``
    counters feed the stats report.  ``added``/``removed`` (and ``added_allows``/
    ``removed_allows``, V5.3 C10) are diff lines against the previous output
    directory, used by the CLI summary table.  ``content_version`` is the
    short version stamp written into ``stats.json``.
    """

    blocks: list[Rule] = field(default_factory=list)
    allows: list[Rule] = field(default_factory=list)
    regex_blocks: list[Rule] = field(default_factory=list)
    regex_allows: list[Rule] = field(default_factory=list)
    raw_count: int = 0
    sources_ok: int = 0
    sources_total: int = 0
    sources_cached: int = 0
    exact_merged: int = 0
    normalized_merged: int = 0
    regex_merged: int = 0
    aggregated: int = 0
    wildcard_aggregated: int = 0
    wildcard_promoted: int = 0  # exact children absorbed into a new wildcard parent
    # Number of wildcard-parent rules created by promotion. The report funnel
    # uses ``wildcard_promoted - wildcard_promoted_groups`` as the NET
    # aggregation reduction (children removed minus the parent added per group).
    wildcard_promoted_groups: int = 0
    conflict_resolved: int = 0
    whitelist_blocked: int = 0
    pattern_dropped: int = 0
    quality_dropped: int = 0
    css_dropped: int = 0
    comment_dropped: int = 0
    modifier_stripped: int = 0
    unrecognized_dropped: int = 0
    unsupported_modifier: int = 0
    badfilter_removed: int = 0
    # Block rules moved to a different bucket by offline high-confidence
    # reclassification (0 when classification.enabled=false).
    reclassified: int = 0
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    failed_sources: list[dict[str, str]] = field(default_factory=list)
    contributions: list[dict[str, Any]] = field(default_factory=list)
    source_overlap: dict[str, Any] = field(default_factory=dict)
    modifier_stats: dict[str, int] = field(default_factory=dict)
    whitelist_audit: dict[str, Any] = field(default_factory=dict)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    added_allows: list[str] = field(default_factory=list)
    removed_allows: list[str] = field(default_factory=list)
    elapsed: float = 0.0
    stage_timings: dict[str, float] = field(default_factory=dict)
    content_version: str = ""
