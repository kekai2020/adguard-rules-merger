"""Conflict recording: exact match, wildcard parent, cascade suffix cover.

Policy (v7): when a whitelist allow overlaps a block rule, the block rule is
**kept, not removed**. Overlaps are recorded for reporting/audit; both rules
survive — block rules stay in the merged list and allows go to the whitelist.
Aligned with the release-package ``blocks-preserved`` policy, including
``$important`` blocks (they survive and the overlap is still recorded).
"""

from __future__ import annotations

from typing import Any

from ..models import Rule
from .outcome import _iter_parents


class ConflictMixin:
    cascade_subdomains: bool

    # ── conflict recording (blocks preserved) ─────────────────

    def _resolve_conflicts(
        self,
        blocks: list[Rule],
        allows: list[Rule],
        source_names: dict[str, str] | None = None,
    ) -> tuple[list[Rule], int, list[dict[str, Any]]]:
        source_names = source_names or {}

        def _src_names(rule: Rule) -> list[str]:
            return [source_names.get(s, s) for s in rule.source_ids]

        exact_allow: dict[str, Rule] = {}
        wild_allow: dict[str, Rule] = {}
        suffix_allow: dict[str, Rule] = {}
        for a in allows:
            n = a.normalized_domain
            if not n:
                continue
            if a.wildcard:
                wild_allow[n] = a
            else:
                exact_allow[n] = a
            if self.cascade_subdomains:
                suffix_allow[n] = a

        conflicts: list[dict[str, Any]] = []

        for b in blocks:
            n = b.normalized_domain
            if not n:
                continue
            by = None
            conflict_type = "exact"
            if n in exact_allow:
                by = exact_allow[n]
            else:
                # O-8: reuse the shared parent-domain iterator (min_labels=1
                # keeps the TLD, matching the previous inline suffix chain).
                for parent in _iter_parents(n, min_labels=1):
                    if parent in wild_allow:
                        by = wild_allow[parent]
                        conflict_type = "wildcard"
                        break
                    if self.cascade_subdomains and parent in suffix_allow:
                        by = suffix_allow[parent]
                        conflict_type = "cascade"
                        break
            if by is not None:
                # Block rule is intentionally KEPT (not suppressed).
                conflicts.append(
                    {
                        "domain": n,
                        "blocked_rule": b.output_raw,
                        "blocked_category": b.category,
                        "blocked_sources": _src_names(b),
                        "whitelist_rule": by.output_raw,
                        "whitelist_sources": _src_names(by),
                        "conflict_type": conflict_type,
                        "action": "kept_block",
                    }
                )

        # No removals: all blocks survive.
        return list(blocks), 0, conflicts
