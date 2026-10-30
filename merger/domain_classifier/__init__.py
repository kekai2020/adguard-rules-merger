"""V5 domain classifier — categorize whitelist domains by purpose.

This is a compatibility shim: the implementation lives in submodules
(``rules``, ``seeds``, ``ruleset``, ``api``). All public names are re-exported
here so existing ``from merger.domain_classifier import X`` imports keep working.
"""

from __future__ import annotations

from .api import (
    category_counts,
    classify_batch,
    classify_domain,
    classify_domain_with_confidence,
)
from .rules import (
    BLOCK_BUCKET_MAP,
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    EXTERNAL_CATEGORY_MAP,
    REGISTERED_DOMAIN_RULES,
    SUBDOMAIN_PREFIX_RULES,
    block_bucket_for,
)
from .rules import CONFIDENCE_NONE as CONFIDENCE_NONE
from .rules import CONFIDENCE_REGISTERED as CONFIDENCE_REGISTERED
from .rules import CONFIDENCE_SUBDOMAIN as CONFIDENCE_SUBDOMAIN
from .rules import _extract as _extract
from .ruleset import _DEFAULT_RULESET as _DEFAULT_RULESET
from .ruleset import _PREFIX_LOOKUP as _PREFIX_LOOKUP
from .ruleset import _REGISTERED_LOOKUP as _REGISTERED_LOOKUP
from .ruleset import ClassifierRuleSet, registered_domain
from .seeds import _load_builtin_seeds as _load_builtin_seeds
from .seeds import load_seed_file, merge_seed_map

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
