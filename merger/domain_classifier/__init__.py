"""V5 domain classifier — categorize whitelist domains by purpose.

This is a compatibility shim: the implementation lives in submodules
(``rules``, ``seeds``, ``ruleset``, ``api``). All public names are re-exported
here so existing ``from merger.domain_classifier import X`` imports keep working.
"""

from __future__ import annotations

from .api import (
    block_bucket_for,
    category_counts,
    classify_batch,
    classify_domain,
    classify_domain_with_confidence,
)
from .rules import (
    BLOCK_BUCKET_MAP,
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    CONFIDENCE_NONE,
    CONFIDENCE_REGISTERED,
    CONFIDENCE_SUBDOMAIN,
    EXTERNAL_CATEGORY_MAP,
    REGISTERED_DOMAIN_RULES,
    SUBDOMAIN_PREFIX_RULES,
    _extract,
)
from .ruleset import (
    ClassifierRuleSet,
    _DEFAULT_RULESET,
    _PREFIX_LOOKUP,
    _REGISTERED_LOOKUP,
    registered_domain,
)
from .seeds import _load_builtin_seeds, load_seed_file, merge_seed_map

__all__ = [
    "ClassifierRuleSet",
    "load_seed_file",
    "merge_seed_map",
    "block_bucket_for",
    "registered_domain",
    "classify_domain",
    "classify_domain_with_confidence",
    "classify_batch",
    "category_counts",
    "REGISTERED_DOMAIN_RULES",
    "SUBDOMAIN_PREFIX_RULES",
    "CATEGORY_LABELS",
    "CATEGORY_ORDER",
    "EXTERNAL_CATEGORY_MAP",
    "BLOCK_BUCKET_MAP",
]
