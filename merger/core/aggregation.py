"""Badfilter cancellation and upward aggregation (exact/wildcard/promotion).

Moved verbatim during the P1-3 package split; promotion thresholds, patterns
and the whitelist-child exclusion are unchanged.
"""

from __future__ import annotations

import re

from ..models import Rule
from ..parser import canonicalize_modifiers
from .outcome import _iter_parents


def _aggregation_sort_key(r: Rule) -> tuple[int, str]:
    """Deterministic aggregation order: most-specific (most labels) first,
    then lexicographic domain.

    ``sorted(key=...)`` memoizes the key (one call per element), so the two
    sorts below do not re-count ``.`` per element; this shared key function
    also documents that the tie-break must stay identical across both passes.
    """
    return (-r.normalized_domain.count("."), r.normalized_domain)


class AggregationMixin:
    min_aggregator_labels: int
    wildcard_child_aggregation: bool
    wildcard_promotion_threshold: int
    psl_guard: bool
    promotion_mode: str
    promotion_pattern_min_ratio: float

    # ── badfilter cancellation ───────────────────────────────────

    def _apply_badfilter(self, block_map: dict, allow_map: dict) -> int:
        """Cancel $badfilter rules and their targets.

        Records cancelled (domain, wildcard) pairs on ``_badfilter_cancelled``
        so wildcard promotion cannot recreate a parent that was just voided.
        """

        def _modset(mods: str) -> set:
            return {m.strip() for m in mods.split(",") if m.strip()}

        cancelled: set[tuple[str, bool]] = set()
        removed = 0
        for m in (block_map, allow_map):
            # O-5: split each rule's modifiers ONCE and reuse the token set
            # for both the badfilter check and the remaining-modifiers join
            # (was 3 splits per badfilter rule: bad_keys listcomp, line 39,
            # and canonicalize_modifiers again).
            bad: list[tuple[tuple[str, bool, str], Rule, set[str]]] = []
            for k, r in m.items():
                if not r.modifiers:
                    continue
                toks = _modset(r.modifiers)
                if "badfilter" in toks:
                    bad.append((k, r, toks))
            for bk, bf, toks in bad:
                m.pop(bk)
                removed += 1
                cancelled.add((bf.normalized_domain, bf.wildcard))
                remaining = ",".join(toks - {"badfilter"})
                # Use the SAME canonical order as the parser emits, so the
                # target key matches regardless of token order in source
                # (single source of truth: parser.canonicalize_modifiers).
                tgt_mods = canonicalize_modifiers(remaining)
                tgt_key = (bf.normalized_domain, bf.wildcard, tgt_mods)
                if tgt_key in m:
                    m.pop(tgt_key)
                    removed += 1
        self._badfilter_cancelled = cancelled
        return removed

    # ── upward aggregation ──────────────────────────────────────

    # V5.3 — pattern-aware wildcard promotion helpers
    _PROMO_PATTERNS = (
        re.compile(r"^cdn\d+$"),
        re.compile(r"^ads?\d*$"),
        re.compile(r"^img\d+$"),
        re.compile(r"^static\d+$"),
        re.compile(r"^s\d+$"),
        re.compile(r"^ns\d+$"),
        re.compile(r"^\d+$"),
        re.compile(r"^server\d+$"),
    )

    @classmethod
    def _variant_label(
        cls, child: str, parent: str, counters: dict[str, int] | None = None
    ) -> str | None:
        """First label of *child* relative to *parent* if it matches a promo pattern.

        Returns None when the child differs from the parent in more than the
        first label (multi-level change); in that case, if *counters* is
        provided, ``promotion_multi_level_skipped`` is incremented.
        """
        child_parts = child.split(".")
        parent_parts = parent.split(".")
        if len(child_parts) != len(parent_parts) + 1:
            if counters is not None:
                counters["promotion_multi_level_skipped"] = (
                    counters.get("promotion_multi_level_skipped", 0) + 1
                )
            return None
        if child_parts[1:] != parent_parts:
            if counters is not None:
                counters["promotion_multi_level_skipped"] = (
                    counters.get("promotion_multi_level_skipped", 0) + 1
                )
            return None
        label = child_parts[0]
        for pat in cls._PROMO_PATTERNS:
            if pat.match(label):
                return label
        return None

    @classmethod
    def _pattern_consistency(
        cls, children: list[str], parent: str, counters: dict[str, int] | None = None
    ) -> float:
        """Fraction of children whose first label matches a promo pattern."""
        if not children:
            return 0.0
        matched = sum(1 for c in children if cls._variant_label(c, parent, counters) is not None)
        return matched / len(children)

    def _aggregate(
        self,
        block_map: dict[tuple[str, bool, str], Rule],
        allow_domains: set[str] | None = None,
        counters: dict[str, int] | None = None,
    ) -> tuple[list[Rule], int, int, int]:
        """Aggregate child rules under surviving parents.

        V5.3 C10: when *allow_domains* is provided, exact/wildcard children
        that are themselves whitelist exceptions are NOT folded into a parent
        — folding would let the parent's block widen the allow's scope.
        """
        wild_map: dict[str, Rule] = {}
        exact_map: dict[str, Rule] = {}
        for r in block_map.values():
            if r.modifiers:
                continue
            if r.wildcard:
                wild_map[r.normalized_domain] = r
            else:
                exact_map[r.normalized_domain] = r

        min_labels = self.min_aggregator_labels
        removed: set[int] = set()
        exact_agg = 0
        wild_agg = 0
        promoted = 0
        promoted_groups = 0  # wildcard parents actually created (one per group)

        if self.wildcard_promotion_threshold > 0:
            _tld = None
            if self.psl_guard:
                try:
                    import tldextract

                    _tld = tldextract.extract
                except ImportError:
                    pass
            sibling_groups: dict[str, list[str]] = {}
            for norm in exact_map:
                parts = norm.split(".")
                if len(parts) >= min_labels + 1:
                    parent = ".".join(parts[1:])
                    sibling_groups.setdefault(parent, []).append(norm)
            for parent, children in sibling_groups.items():
                if parent.count(".") + 1 < min_labels:
                    continue
                if parent in wild_map or parent in exact_map:
                    continue
                # Never recreate a wildcard parent that $badfilter just voided.
                if (parent, True) in self._badfilter_cancelled:
                    continue
                # V5.3 C6: PSL guard — skip if parent is a public suffix itself.
                if _tld is not None and _tld(parent).domain == "":
                    continue
                # D1: a child that is itself a whitelist exception must neither
                # count toward the sibling threshold nor be merged into the
                # promoted wildcard — it survives as an exact rule. Filter it
                # out BEFORE the pattern-consistency / threshold checks, since
                # _pattern_consistency has a side effect (promotion_multi_level_skipped)
                # and must run on the candidate list only.
                candidates = [c for c in children if not (allow_domains and c in allow_domains)]
                if not candidates:
                    continue
                # V5.3 C7: pattern mode requires variant-label consistency.
                if self.promotion_mode == "pattern":
                    if (
                        self._pattern_consistency(candidates, parent, counters)
                        < self.promotion_pattern_min_ratio
                    ):
                        continue
                if len(candidates) >= self.wildcard_promotion_threshold:
                    template = exact_map[candidates[0]]
                    wc = Rule(
                        raw=f"||*.{parent}^",
                        domain=parent,
                        rule_type="block",
                        wildcard=True,
                        sources=template.source_mask,
                        category=template.category,
                    )
                    wild_map[parent] = wc
                    block_map[(parent, True, "")] = wc
                    promoted_groups += 1
                    keeper = wc
                    for child_norm in candidates:
                        child = exact_map.get(child_norm)
                        if child is not None and id(child) not in removed:
                            keeper.merge_from(child)
                            removed.add(id(child))
                            promoted += 1

        exact_children = sorted(
            (
                r
                for r in block_map.values()
                if not r.wildcard and not r.modifiers and id(r) not in removed
            ),
            key=_aggregation_sort_key,
        )
        for child in exact_children:
            if allow_domains and child.normalized_domain in allow_domains:
                continue
            for parent in _iter_parents(child.normalized_domain, min_labels):
                cand_exact: Rule | None = wild_map.get(parent) or exact_map.get(parent)
                if cand_exact is not None and id(cand_exact) != id(child):
                    cand_exact.merge_from(child)
                    removed.add(id(child))
                    exact_agg += 1
                    break

        if self.wildcard_child_aggregation:
            wild_children = sorted(
                (
                    r
                    for r in block_map.values()
                    if r.wildcard and not r.modifiers and id(r) not in removed
                ),
                key=_aggregation_sort_key,
            )
            for child in wild_children:
                child_norm = child.normalized_domain
                if allow_domains and child_norm in allow_domains:
                    continue
                same_exact = exact_map.get(child_norm)
                if same_exact is not None and id(same_exact) not in removed:
                    same_exact.merge_from(child)
                    removed.add(id(child))
                    wild_agg += 1
                    continue
                for parent in _iter_parents(child_norm, min_labels):
                    cand_wild: Rule | None = wild_map.get(parent) or exact_map.get(parent)
                    if cand_wild is not None and id(cand_wild) != id(child):
                        cand_wild.merge_from(child)
                        removed.add(id(child))
                        wild_agg += 1
                        break

        survivors = [r for r in block_map.values() if id(r) not in removed]
        # Report the number of wildcard parents created so the funnel can show
        # the NET promotion reduction; ride on the existing counters dict rather
        # than widening the public 4-tuple return.
        if counters is not None and promoted_groups:
            counters["wildcard_promoted_groups"] = promoted_groups
        return survivors, exact_agg, wild_agg, promoted
