"""Per-source contribution/overlap stats, modifier stats, offline re-judge.

Moved verbatim during the P1-3 package split; coverage rates, tie-breaks and
the security-bucket protection are unchanged.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from ..domain_classifier import (
    BLOCK_BUCKET_MAP,
    CONFIDENCE_REGISTERED,
    CONFIDENCE_SUBDOMAIN,
    block_bucket_for,
    classify_domain_with_confidence,
)
from ..models import (
    CATEGORY_MALWARE,
    CATEGORY_MINING,
    CATEGORY_PHISHING,
    Rule,
    iter_source_keys,
    normalize_domain,
)
from ..ports import DnspythonDnsPort


class StatsMixin:
    classification_enabled: bool
    classification_registered_only: bool
    classification_use_cname_hints: bool

    # ── per-source contribution stats ───────────────────────────

    @staticmethod
    def _rule_key(r: Rule) -> str:
        """Identity key for coverage stats: domain rules by normalized domain,
        regex rules by raw body (V5.2: regex rules used to be invisible here,
        which made e.g. DNS Rebind Protection show 3/16 rules and a bogus
        100% unique ratio)."""
        return r.normalized_domain or r.raw

    @classmethod
    def _compute_stats(
        cls,
        blocks: list[Rule],
        allows: list[Rule],
        source_names: dict[str, str],
        source_raw_counts: dict[str, int],
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Fused two-pass contributions + source_overlap (V5.3 C9, R-2 pass form).

        Two traversals over chain(blocks, allows): the first accumulates
        per-key coverage, per-source effective counts and pairwise overlap;
        the second (re-walking the same rules — the lists are already in
        memory, so no per-rule staging rows are materialized) attributes
        unique/shared/category counts once coverage is final. Provenance bits
        are walked lazily via ``iter_source_keys``; dropping the old per-rule
        ``rows`` staging list removes a multi-hundred-MB transient at
        million-rule scale.
        """
        from collections import Counter
        from itertools import chain

        coverage: dict[str, int] = {}
        effective: Counter = Counter()
        pair_overlap: Counter = Counter()

        for r in chain(blocks, allows):
            key = cls._rule_key(r)
            if key:
                # O-1: ACCUMULATE the source mask, do not overwrite. A key
                # (normalized_domain, or raw for regex) can appear in several
                # rules — a block and an allow of the same domain, or modifier
                # variants — and every contributing source must be counted or
                # unique/shared attribution is wrong.
                coverage[key] = coverage.get(key, 0) | r.source_mask
            mask = r.source_mask
            if not mask or not key:
                continue
            if mask.bit_count() == 1:
                s = next(iter_source_keys(mask))
                effective[s] += 1
                continue
            srcs = list(iter_source_keys(mask))
            for s in srcs:
                effective[s] += 1
            n = len(srcs)
            for i in range(n):
                for j in range(i + 1, n):
                    # O2: canonical ordered tuple key instead of a frozenset
                    # (cheaper to allocate; counts/insertion order unchanged).
                    lo, hi = (srcs[i], srcs[j]) if srcs[i] <= srcs[j] else (srcs[j], srcs[i])
                    pair_overlap[(lo, hi)] += 1

        unique_count: dict[str, int] = {}
        shared_count: dict[str, int] = {}
        cat_by_src: dict[str, Counter] = {}
        for r in chain(blocks, allows):
            key = cls._rule_key(r)
            mask = r.source_mask
            if not mask or not key:
                continue
            # O-1: coverage is now final; unique means the mask has exactly
            # one bit set (single contributing source). Re-walking in the same
            # chain order keeps dict insertion order (and thus output bytes)
            # identical to the previous staged-rows form.
            unique = coverage.get(key, 0).bit_count() == 1
            for src in iter_source_keys(mask):
                if unique:
                    unique_count[src] = unique_count.get(src, 0) + 1
                else:
                    shared_count[src] = shared_count.get(src, 0) + 1
                cat_by_src.setdefault(src, Counter())[r.category] += 1

        contributions: list[dict[str, Any]] = []
        for url, name in source_names.items():
            uniq = unique_count.get(url, 0)
            shrd = shared_count.get(url, 0)
            raw = source_raw_counts.get(url, 0)
            eff = uniq + shrd
            contributions.append(
                {
                    "name": name,
                    "url": url,
                    "raw_rules": raw,
                    "unique_rules": uniq,
                    "shared_rules": shrd,
                    "effective_rules": eff,
                    "coverage_rate": round(eff / raw * 100, 1) if raw else 0.0,
                    "unique_rate": round(uniq / eff * 100, 1) if eff else 0.0,
                    "rule_categories": dict(cat_by_src.get(url, {})),
                }
            )
        contributions.sort(key=lambda c: (-c["unique_rules"], -c["effective_rules"], c["name"]))

        pairs = []
        # Deterministic tie-break: equal overlap counts sort by the canonical
        # pair tuple instead of async completion/insertion order.
        for pair, count in sorted(pair_overlap.items(), key=lambda kv: (-kv[1], kv[0])):
            a, b = pair
            ea, eb = effective[a], effective[b]
            union = ea + eb - count
            pairs.append(
                {
                    "source_a": source_names.get(a, a),
                    "source_b": source_names.get(b, b),
                    "overlap": count,
                    "rate_a": round(count / ea * 100, 1) if ea else 0.0,
                    "rate_b": round(count / eb * 100, 1) if eb else 0.0,
                    "jaccard": round(count / union * 100, 1) if union else 0.0,
                }
            )
        # Deterministic tie-break: equal effective counts sort by source name
        # instead of completion/insertion order.
        source_effective = {
            source_names.get(k, k): v
            for k, v in sorted(effective.items(), key=lambda kv: (-kv[1], kv[0]))
        }
        order = list(source_effective.keys())
        pos = {name: i for i, name in enumerate(order)}
        cells: dict[str, dict[str, Any]] = {}
        for p in pairs:
            a, b = p["source_a"], p["source_b"]
            if pos.get(a, -1) > pos.get(b, -1):
                a, b = b, a
            cells.setdefault(a, {})[b] = {
                "overlap": p["overlap"],
                "jaccard": p["jaccard"],
                "rate_a": p["rate_a"] if p["source_a"] == a else p["rate_b"],
                "rate_b": p["rate_b"] if p["source_a"] == a else p["rate_a"],
            }
        matrix = {"order": order, "effective": source_effective, "cells": cells}
        source_overlap = {"pairs": pairs, "source_effective": source_effective, "matrix": matrix}
        return contributions, source_overlap

    @staticmethod
    def _compute_modifier_stats(blocks: list[Rule], allows: list[Rule]) -> dict[str, int]:
        from collections import Counter
        from itertools import chain

        c: Counter = Counter()
        for r in chain(blocks, allows):
            if r.modifiers:
                for m in r.modifiers.split(","):
                    m = m.strip()
                    if m:
                        c[m] += 1
        # Deterministic tie-break: equal modifier counts sort by modifier name.
        return dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))

    # Source-declared security buckets are protected: an offline advertising /
    # analytics verdict can never downgrade malware/phishing/mining to
    # ads/tracking/other.
    _SECURITY_BUCKETS = frozenset({CATEGORY_MALWARE, CATEGORY_PHISHING, CATEGORY_MINING})

    # Short CNAME lookup budget (seconds); DNS is optional and must never stall
    # the merge on a slow resolver.
    _CNAME_TIMEOUT = 2.0

    def _resolve_cname_hints_sync(self, domain: str) -> list[str]:
        """Blocking CNAME-chain lookup; ``[]`` on any failure (never raises).

        Production resolves through the injected DnsPort (default: dnspython's
        system resolver); tests monkeypatch this seam. The 5-hop budget,
        seen-set loop guard and NXDOMAIN / timeout / missing-library collapse
        to ``[]`` are preserved; the single-hop resolve itself goes through
        ``self.dns_port`` instead of an inline ``import dns.resolver``.
        """
        port = getattr(self, "dns_port", None) or DnspythonDnsPort(timeout=self._CNAME_TIMEOUT)
        targets: list[str] = []
        seen: set[str] = set()
        current = domain.lower().strip(".")
        for _ in range(5):
            if not current or current in seen:
                break
            seen.add(current)
            try:
                chain = port.resolve_cname(current)
            except Exception:
                break
            if not chain:
                break
            targets.extend(chain)
            current = chain[0]
        return targets

    async def _resolve_cname_hints(self, domain: str) -> list[str]:
        """Run the blocking CNAME lookup in an executor; ``[]`` on any error."""
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, self._resolve_cname_hints_sync, domain)
        except Exception:
            return []

    async def _rejudge_block_categories(self, blocks: list[Rule]) -> int:
        """Reclassify block rules offline; return how many moved bucket.

        No-op when ``classification_enabled`` is False (default), so the
        source-declared buckets and every committed artifact stay byte-
        identical.  At registered-only mode (default) a rule moves only on a
        high-confidence (0.9) registered-domain exact match; CDN/payment/
        privacy/other verdicts and every medium/low-confidence verdict keep
        the source bucket; security buckets are never downgraded.  When
        ``classification_use_cname_hints`` is on, a missed registered match
        may be rescued by a CNAME target that itself hits a registered domain
        at 0.9; weaker CNAME conclusions keep the source bucket.
        """
        if not self.classification_enabled:
            return 0
        # R3: the engine owns the rule set instance; fall back to the module
        # default singleton when a mixin is used standalone.
        ruleset = getattr(self, "classification_ruleset", None)
        reclassified = 0
        # Perf (release-package alignment): classify each unique registered
        # domain once, then apply the same verdict to every rule sharing it
        # (was O(n) classifier calls).
        verdict_cache: dict[str, tuple[str, float]] = {}
        for r in blocks:
            domain = r.normalized_domain
            if not domain or r.category in self._SECURITY_BUCKETS:
                continue
            if domain in verdict_cache:
                offline_cat, confidence = verdict_cache[domain]
            else:
                offline_cat, confidence, _ = classify_domain_with_confidence(
                    domain, ruleset=ruleset
                )
                # CNAME rescue: accept only a target's own 0.9 registered match;
                # the classifier's 0.8 CNAME discount (0.72) stays rejected.
                if confidence < CONFIDENCE_REGISTERED and self.classification_use_cname_hints:
                    for hint in await self._resolve_cname_hints(domain):
                        ccat, cconf, _ = classify_domain_with_confidence(hint, ruleset=ruleset)
                        if cconf >= CONFIDENCE_REGISTERED:
                            offline_cat, confidence = ccat, cconf
                            break
                verdict_cache[domain] = (offline_cat, confidence)
            if self.classification_registered_only:
                new_bucket = block_bucket_for(offline_cat, confidence)
            elif confidence >= CONFIDENCE_SUBDOMAIN:
                new_bucket = BLOCK_BUCKET_MAP.get(offline_cat)
            else:
                new_bucket = None
            if new_bucket and new_bucket != r.category:
                r.category = new_bucket
                reclassified += 1
        return reclassified

    @staticmethod
    def _normalize_prev_line(line: str) -> str:
        """Reduce a previous-output rule line to the bare normalized domain.

        Warm-start diff compares the previous ``merged_rules.txt`` /
        ``whitelist.txt`` lines against the engine's ``Rule.normalized_domain``
        set.  Raw lines carry AdGuard syntax (``@@`` allow marker, ``||``
        anchor prefix, ``^`` end anchor, ``$modifiers``) which the new set does
        not — without this reduction the two sets never overlap and every warm
        run reports "everything added + everything removed".  We strip the
        allow/anchor prefixes, cut at the first ``$`` modifier, drop the
        trailing ``^`` and finally fold through ``models.normalize_domain``.
        ``*.example.com`` wildcard lines fold to ``example.com``, matching the
        normalized key both block and allow rules share.
        """
        s = line.strip()
        if not s or s.startswith(("#", "!")):
            return ""
        if s.startswith("@@"):
            s = s[2:]
        if s.startswith("||"):
            s = s[2:]
        # Keep only the part before any $modifiers (e.g. $important, $badfilter).
        s = s.split("$", 1)[0]
        # Drop the trailing end-of-rule anchor (it precedes any $ modifiers).
        s = s.removesuffix("^")
        return normalize_domain(s)

    @staticmethod
    def _load_previous_domains(path: str) -> set[str]:
        p = Path(path)
        if not p.exists():
            return set()
        try:
            return {
                dom
                for line in p.read_text(encoding="utf-8").splitlines()
                if (dom := StatsMixin._normalize_prev_line(line))
            }
        except OSError:
            return set()
