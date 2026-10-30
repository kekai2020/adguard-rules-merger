"""``merger.core`` package: async rule engine, aggregation, conflicts, stats.

Backwards-compatible facade: every import path that worked against the old
flat ``merger/core.py`` keeps working.
"""

from .aggregation import AggregationMixin
from .conflicts import ConflictMixin
from .engine import AsyncRuleEngine
from .fetch import FetchMixin
from .outcome import (
    MergeOutcome,
    SourceContribution,
    SourceFailure,
    _iter_parents,
    classify_source_error,
)
from .stats import StatsMixin

__all__ = [
    "AsyncRuleEngine",
    "MergeOutcome",
    "SourceFailure",
    "SourceContribution",
    "classify_source_error",
    "_iter_parents",
    "FetchMixin",
    "AggregationMixin",
    "ConflictMixin",
    "StatsMixin",
]
