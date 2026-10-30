"""AdGuard Rules Merger V7 — DNS-layer rule compiler.

Pipeline: multi-source fetch -> parse -> dedup (exact/normalized/regex)
-> upward aggregation (exact + wildcard children + optional promotion)
-> whitelist split -> conflict resolution -> stable sort
-> multi-format export + tiered files + HTML report.

Committed artifacts are byte-stable for a given rule set (see
``output.report_timestamp``); the V7 CLI is installed as the
``adguard-rules-merger`` console script and via ``python -m merger``.
"""

from .cache import CacheEntry, SourceCache
from .core import AsyncRuleEngine, MergeOutcome
from .exporter import Exporter
from .models import (
    CATEGORY_ADS,
    CATEGORY_COMMENT,
    CATEGORY_MALWARE,
    CATEGORY_MINING,
    CATEGORY_OTHER,
    CATEGORY_PHISHING,
    CATEGORY_TRACKING,
    Rule,
    SourceMeta,
    merge_category,
)
from .parser import RuleParser
from .version import __version__, __version_short__, user_agent

__all__ = [
    "AsyncRuleEngine",
    "MergeOutcome",
    "Exporter",
    "Rule",
    "SourceMeta",
    "RuleParser",
    "SourceCache",
    "CacheEntry",
    "CATEGORY_ADS",
    "CATEGORY_MALWARE",
    "CATEGORY_TRACKING",
    "CATEGORY_PHISHING",
    "CATEGORY_MINING",
    "CATEGORY_OTHER",
    "CATEGORY_COMMENT",
    "merge_category",
    "__version__",
    "__version_short__",
    "user_agent",
]
