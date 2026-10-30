"""Public classification API."""

from __future__ import annotations

import logging
from typing import Any

from .rules import BLOCK_BUCKET_MAP, CATEGORY_ORDER, EXTERNAL_CATEGORY_MAP, block_bucket_for
from .ruleset import (
    ClassifierRuleSet,
    _DEFAULT_RULESET,
    registered_domain,
)

logger = logging.getLogger(__name__)

def _resolve_ruleset(ruleset: ClassifierRuleSet | None) -> ClassifierRuleSet:
    """Return the given ruleset, or the default singleton when omitted."""
    return _DEFAULT_RULESET if ruleset is None else ruleset


def classify_domain(
    domain: str,
    cname_hints: list[str] | None = None,
    ruleset: ClassifierRuleSet | None = None,
) -> str:
    """Classify a domain by purpose. Returns category string.

    Matching priority:
      1. Registered-domain exact/suffix match (high confidence)
      2. Subdomain first-label prefix match (medium confidence)
      3. CNAME hints (if provided)
      4. Fallback to "other"

    ``ruleset`` selects the lookup tables; omitted uses the default singleton.
    """
    return _resolve_ruleset(ruleset).classify(domain, cname_hints)


def classify_domain_with_confidence(
    domain: str,
    cname_hints: list[str] | None = None,
    ruleset: ClassifierRuleSet | None = None,
) -> tuple[str, float, str]:
    """Classify with confidence score and match reason.

    Returns (category, confidence, reason). ``ruleset`` selects the lookup
    tables; omitted uses the default singleton. CNAME recursion transparently
    reuses the same ruleset.
    """
    return _resolve_ruleset(ruleset).classify_with_confidence(domain, cname_hints)


def classify_batch(
    domains: list[str],
    cname_map: dict[str, list[str]] | None = None,
    ruleset: ClassifierRuleSet | None = None,
) -> dict[str, str]:
    """Classify many domains at once. Returns {domain: category}."""
    return _resolve_ruleset(ruleset).classify_batch(domains, cname_map)


def category_counts(categories: list[str]) -> dict[str, int]:
    """Count occurrences per category, including zero-count categories."""
    counts = {c: 0 for c in CATEGORY_ORDER}
    for c in categories:
        counts[c] = counts.get(c, 0) + 1
    return counts
