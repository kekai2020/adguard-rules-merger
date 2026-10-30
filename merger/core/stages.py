"""R1 pure stage kernels extracted from ``AsyncRuleEngine.run``.

Only self-contained, IO-free logic moved here: stable merge sorting, the
sha-256 content version, and thin module-level delegates for the contribution
/ modifier stats class/static methods. Stateful stages (badfilter
cancellation, upward aggregation, conflict resolution) stay bound Mixin
calls inside ``run``; fetch, seed-file IO, async re-judgement, whitelist
audit, diff and ``MergeOutcome`` construction are deliberately NOT moved
(they are IO / async / global or belong to later review rounds).

Algorithms, deterministic tie-breaks, counts and ordering are byte-for-byte
unchanged; every helper here is pure (no ``self``, no IO, no module globals).
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from itertools import chain
from typing import Any

from ..models import Rule
from .stats import StatsMixin


def sort_merged(
    blocks: Iterable[Rule],
    regex_blocks: Iterable[Rule],
    allows: Iterable[Rule],
    regex_allows: Iterable[Rule],
) -> tuple[list[Rule], list[Rule]]:
    """Concatenate exact/aggregated blocks with regex blocks and sort both the
    blocks and the allows by ``Rule.sort_key``.

    ``sorted`` is stable: domain rules (unique on the first four key fields)
    keep input order among equals, and regex rules share an empty normalized
    domain so their raw-string tiebreak decides. Pure.
    """
    final_blocks = sorted(chain(blocks, regex_blocks), key=Rule.sort_key)
    final_allows = sorted(chain(allows, regex_allows), key=Rule.sort_key)
    return final_blocks, final_allows


def compute_content_version(blocks: Iterable[Rule], allows: Iterable[Rule]) -> str:
    """SHA-256 over every rule's canonical ``output_raw`` (utf-8,
    ``errors="replace"``) each followed by a newline; first 12 hex chars.

    Unchanged rules must keep producing the same 12-char version, so this
    loop walks blocks then allows in the given order. Pure.
    """
    h = hashlib.sha256()
    for r in chain(blocks, allows):
        h.update(r.output_raw.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()[:12]


def compute_contributions(
    blocks: list[Rule],
    allows: list[Rule],
    source_names: dict[str, str],
    source_raw_counts: dict[str, int],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Thin delegate to ``StatsMixin._compute_stats`` (classmethod).

    Coverage counts, pairwise overlap, per-source category buckets and the
    deterministic tie-breaks are unchanged; the class method itself is not
    rewritten.
    """
    return StatsMixin._compute_stats(blocks, allows, source_names, source_raw_counts)


def compute_modifier_stats(blocks: list[Rule], allows: list[Rule]) -> dict[str, int]:
    """Thin delegate to ``StatsMixin._compute_modifier_stats`` (staticmethod).

    Per-modifier counts and the equal-count name tie-break are unchanged; the
    static method itself is not rewritten.
    """
    return StatsMixin._compute_modifier_stats(blocks, allows)
