"""ClassifierRuleSet: compiled lookup tables for the domain classifier."""

from __future__ import annotations

import logging

from .seeds import _load_builtin_seeds
from .rules import (
    BLOCK_BUCKET_MAP,
    CONFIDENCE_NONE,
    CONFIDENCE_REGISTERED,
    CONFIDENCE_SUBDOMAIN,
    REGISTERED_DOMAIN_RULES,
    SUBDOMAIN_PREFIX_RULES,
    _extract,
)

logger = logging.getLogger(__name__)

def registered_domain(domain: str) -> str:
    """Extract registered domain (eTLD+1) using PSL (public API)."""
    ext = _extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain.lower().strip(".")


class ClassifierRuleSet:
    """Constructible offline classification rule set (R3).

    An instance carries its own registered-domain and subdomain-prefix lookup
    tables, so classification no longer depends on module-level mutable
    globals.  The process-wide default singleton (``default()``) reproduces
    the legacy built-in tables exactly; a fresh instance built for one merge
    run stays independent — external seeds merged into it never leak into
    another run or into the default singleton.

    Immutable policy data (``BLOCK_BUCKET_MAP``, confidence thresholds) stays
    a shared module constant; only the mutable lookup tables live per
    instance.
    """

    def __init__(self) -> None:
        # Built-in hand-written table: first-listed category wins on a
        # duplicate pattern (setdefault).
        self.registered: dict[str, str] = {}
        for cat, pats in REGISTERED_DOMAIN_RULES:
            for pat in pats:
                self.registered.setdefault(pat, cat)
        self.prefix: dict[str, str] = {}
        for cat, prefs in SUBDOMAIN_PREFIX_RULES:
            for pref in prefs:
                self.prefix.setdefault(pref, cat)
        # Curated built-in seed file fills gaps; hand-written entries win.
        for dom, cat in _load_builtin_seeds().items():
            self.registered.setdefault(dom.lower(), cat)
        # V8: result cache keyed by (normalized domain, cname-hint tuple);
        # cleared whenever seeds are merged (tables mutate).
        self._cache: dict[tuple[str, tuple[str, ...] | None], tuple[str, float, str]] = {}

    @classmethod
    def default(cls) -> ClassifierRuleSet:
        """Return the process-wide default singleton (legacy globals)."""
        return _DEFAULT_RULESET

    def merge_seeds(self, mapping: dict[str, str]) -> int:
        """Merge external ``{domain: 9-class}`` into this set (setdefault).

        Hand-written and built-in entries always win; returns the number of
        newly added domains.
        """
        added = 0
        for dom, cat in mapping.items():
            key = dom.lower()
            if key and cat and key not in self.registered:
                self.registered[key] = cat
                added += 1
        self._cache.clear()
        return added

    def with_seeds(self, mapping: dict[str, str]) -> ClassifierRuleSet:
        """Return a copy with external seeds merged (setdefault); self untouched."""
        new = ClassifierRuleSet()
        new.registered = dict(self.registered)
        new.prefix = dict(self.prefix)
        new.merge_seeds(mapping)
        return new

    # ── classification ─────────────────────────────────────────────

    def classify_with_confidence(
        self, domain: str, cname_hints: list[str] | None = None
    ) -> tuple[str, float, str]:
        """Cached classification; see _classify_with_confidence_uncached."""
        norm = domain.lower().strip(".")
        cache_key = (norm, tuple(cname_hints) if cname_hints else None)
        hit = self._cache.get(cache_key)
        if hit is not None:
            return hit
        result = self._classify_with_confidence_uncached(domain, cname_hints)
        if len(self._cache) < 8192:
            self._cache[cache_key] = result
        return result

    def _classify_with_confidence_uncached(
        self, domain: str, cname_hints: list[str] | None = None
    ) -> tuple[str, float, str]:
        """Classify with confidence score and match reason.

        Returns (category, confidence, reason). CNAME hints recurse through
        this same instance, so a custom ruleset stays consistent.
        """
        domain = domain.lower().strip(".")
        if not domain:
            return "other", CONFIDENCE_NONE, "empty domain"

        # Single PSL extraction shared by both the registered-domain and the
        # first-subdomain-label lookups (previously parsed twice).
        ext = _extract(domain)
        registered = f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else domain

        # 1. Registered-domain match (exact, then parent labels — O(labels))
        d = registered
        while d:
            cat = self.registered.get(d)
            if cat:
                return (cat, CONFIDENCE_REGISTERED, f"registered domain match: {d}")
            if "." not in d:
                break
            d = d.split(".", 1)[1]

        # 2. Subdomain prefix match — check EVERY subdomain label, deepest
        # first. Previously only the first (deepest) label was inspected, so
        # ``api.tracking.example.com`` (where ``tracking`` is the signal but
        # ``api`` is not) fell through to "other". Iterating all labels is a
        # strict superset: single-label cases keep their existing verdict and
        # precedence (leftmost/deepest label wins on a tie).
        if ext.subdomain:
            for lab in ext.subdomain.split("."):
                cat = self.prefix.get(lab.lower())
                if cat:
                    return (cat, CONFIDENCE_SUBDOMAIN, f"subdomain prefix: {lab.lower()}")

        # 3. CNAME hints (e.g. domain CNAMEs to cloudfront)
        if cname_hints:
            for hint in cname_hints:
                cat, conf, _ = self.classify_with_confidence(hint)
                if cat != "other" and conf >= CONFIDENCE_SUBDOMAIN:
                    return (cat, conf * 0.8, f"cname hint: {hint}")

        return "other", CONFIDENCE_NONE, "no match"

    def classify(self, domain: str, cname_hints: list[str] | None = None) -> str:
        """Classify a domain by purpose. Returns category string."""
        return self.classify_with_confidence(domain, cname_hints)[0]

    def classify_batch(
        self, domains: list[str], cname_map: dict[str, list[str]] | None = None
    ) -> dict[str, str]:
        """Classify many domains at once. Returns {domain: category}."""
        cname_map = cname_map or {}
        return {d: self.classify(d, cname_map.get(d)) for d in domains}

    def block_bucket_for(self, category: str, confidence: float) -> str | None:
        """Map a 9-way verdict to a block bucket; None keeps the source bucket."""
        if confidence < CONFIDENCE_REGISTERED:
            return None
        return BLOCK_BUCKET_MAP.get(category)


# Process-wide default singleton: reproduces the legacy module globals so
# callers/tests that read ``_REGISTERED_LOOKUP`` / ``_PREFIX_LOOKUP`` or call
# ``merge_seed_map`` keep working; new code constructs its own instance.
_DEFAULT_RULESET = ClassifierRuleSet()
_REGISTERED_LOOKUP: dict[str, str] = _DEFAULT_RULESET.registered
_PREFIX_LOOKUP: dict[str, str] = _DEFAULT_RULESET.prefix


