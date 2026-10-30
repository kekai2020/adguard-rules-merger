"""V5.1 Data models for AdGuard DNS filter rules.

V5.1 vs V5:
  - Source provenance is an integer bitmask (OR-merge, no per-rule URL tuples).
  - Category / modifiers / rule_type interned.
  - ``source_ids`` property stays as a tuple of keys for stats/tests.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Iterable
from functools import total_ordering

# ── categories ─────────────────────────────────────────────────────
CATEGORY_ADS = "ads"
CATEGORY_MALWARE = "malware"
CATEGORY_TRACKING = "tracking"
CATEGORY_PHISHING = "phishing"
CATEGORY_MINING = "mining"
CATEGORY_OTHER = "other"
CATEGORY_COMMENT = "comment"

TIERED_CATEGORIES = (
    CATEGORY_ADS,
    CATEGORY_MALWARE,
    CATEGORY_TRACKING,
    CATEGORY_PHISHING,
    CATEGORY_MINING,
    CATEGORY_OTHER,
)

# When the same domain appears in sources with different categories, the
# category with the *lower* number wins (security categories outrank ads).
CATEGORY_PRIORITY = {
    CATEGORY_MALWARE: 0,
    CATEGORY_PHISHING: 1,
    CATEGORY_MINING: 2,
    CATEGORY_TRACKING: 3,
    CATEGORY_ADS: 4,
    CATEGORY_OTHER: 99,
}


def merge_category(existing: str, incoming: str) -> str:
    """Return the higher-priority category (security beats ads)."""
    if existing == incoming:
        return sys.intern(existing)
    winner = (
        existing
        if CATEGORY_PRIORITY.get(existing, 99) <= CATEGORY_PRIORITY.get(incoming, 99)
        else incoming
    )
    return sys.intern(winner)


# ASCII whitespace trimmed from label edges. DNS labels never contain
# whitespace legitimately; this only cleans literal noise handed to
# ``normalize_domain`` by direct callers / cached records — the parser regexes
# never emit it, so production output bytes are unaffected.
_LABEL_WS = " \t\r\n\f\v"


def normalize_domain(domain: str, strip_www: bool = False) -> str:
    """Fold literal-equivalent domain shapes onto one normalized key.

    Folds ASCII case, edge/inter-label whitespace, leading/trailing/consecutive
    dots, and a single literal ``*.`` prefix; ``www.`` is removed only when
    ``strip_www`` is set. This is *literal* equivalence only: no PSL parsing,
    no network, no IDN decode — ``xn--`` punycode labels keep their ASCII form
    (homograph folding belongs to the whitelist audit layer). Wildcard
    semantics live on ``Rule.wildcard``, never on the normalized key.
    """
    d = domain.lower()
    # Trim edge whitespace per label and drop empty labels (leading/trailing/
    # consecutive dots are literal noise, not DNS labels) before recognizing
    # the ``*.`` literal prefix, so whitespace around the marker still folds.
    labels = [part.strip(_LABEL_WS) for part in d.split(".")]
    labels = [part for part in labels if part]
    d = ".".join(labels)
    if d.startswith("*."):
        d = d[2:].strip(".")
    if strip_www and d.startswith("www."):
        d = d[4:]
    return d


# ── source bitmask registry ────────────────────────────────────────
# Maps provenance keys (URL or test label) to a bit index. Python ints are
# unbounded so this scales past 64 sources. Merge is a single |= on Rule.
# D-7: the registry is process-global and grows with every distinct source
# key. A long-lived process or a test suite that keeps minting new source
# labels would accumulate entries forever; call reset_source_registry()
# between independent runs/tests when a clean bit space is wanted. This is a
# single-run CLI in practice, so the growth is bounded per invocation.


_SOURCE_TO_BIT: dict[str, int] = {}
_BIT_TO_SOURCE: dict[int, str] = {}
# O-3: the registry is process-global and interned from concurrent parser
# threads (via run_in_executor); a plain get→len→assign race can hand two
# keys the same bit and corrupt _BIT_TO_SOURCE / stats provenance.
_SOURCE_LOCK = threading.Lock()


def reset_source_registry() -> None:
    """Clear the source bit registry (D-7).

    Safe to call between independent runs: the engine re-interns source keys
    on demand, so the next run gets a clean bit space. Intended for tests and
    long-lived processes that would otherwise accumulate registry entries.
    """
    with _SOURCE_LOCK:
        _SOURCE_TO_BIT.clear()
        _BIT_TO_SOURCE.clear()


def intern_source(key: str) -> int:
    """Return the bit index for a source key, allocating on first sight.

    O-3: uses double-checked locking so concurrent parser threads cannot
    allocate the same bit for two different source keys.
    """
    bit = _SOURCE_TO_BIT.get(key)
    if bit is not None:
        return bit
    with _SOURCE_LOCK:
        bit = _SOURCE_TO_BIT.get(key)
        if bit is not None:
            return bit
        bit = len(_SOURCE_TO_BIT)
        _SOURCE_TO_BIT[key] = bit
        _BIT_TO_SOURCE[bit] = key
        return bit


def sources_to_mask(value: None | str | int | Iterable = None) -> int:
    """Convert a source key / iterable of keys into a bitmask.

    * ``None`` / empty → 0
    * ``str`` → intern and shift
    * ``int`` → treated as an already-built mask (engine hot path)
    * iterable of ``str`` → OR of interned bits
    """
    if value is None:
        return 0
    if isinstance(value, str):
        return 1 << intern_source(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    mask = 0
    for item in value:  # type: ignore[union-attr]
        if isinstance(item, str):
            mask |= 1 << intern_source(item)
        elif isinstance(item, int) and not isinstance(item, bool):
            mask |= item
        else:
            mask |= 1 << intern_source(str(item))
    return mask


def iter_source_keys(mask: int):
    """Yield source keys of a bitmask, lowest bit first (lazy).

    Identical ordering to ``mask_to_sources`` but generator-based, so hot
    paths (stats) can walk provenance bits without allocating a tuple per
    rule.
    """
    m = mask
    while m:
        low = m & -m
        i = low.bit_length() - 1
        src = _BIT_TO_SOURCE.get(i)
        if src is not None:
            yield src
        m ^= low


def mask_to_sources(mask: int) -> tuple[str, ...]:
    return tuple(iter_source_keys(mask))


# ── sort helpers ────────────────────────────────────────────────────
_TYPE_ORDER = {"block": 0, "allow": 1, "comment": 2}


@total_ordering
class Rule:
    """A single DNS-layer filter rule with provenance.

    Stored slots: ``raw``, ``rule_type``, ``wildcard``, ``modifiers``,
    ``source_mask``, ``category``, ``_norm``, ``_sort_type``, ``_out``.

    ``modifiers`` holds the part after ``$`` (e.g. ``important``,
    ``badfilter``) normalised to lowercase with spaces removed.  It is part
    of the dedup key because ``||x.com^`` and ``||x.com^$important`` have
    different semantics and must NOT be merged.

    ``source_mask`` is an integer bitmask; ``source_ids`` is a compatibility
    view as a tuple of source keys.
    """

    __slots__ = (
        "raw",
        "rule_type",
        "wildcard",
        "modifiers",
        "source_mask",
        "category",
        "_norm",
        "_sort_type",
        "_out",
    )

    def __init__(
        self,
        raw: str,
        domain: str,
        rule_type: str,
        wildcard: bool,
        sources=None,
        source_ids=None,
        category: str = CATEGORY_OTHER,
        strip_www: bool = False,
        modifiers: str = "",
    ) -> None:
        self.raw = raw
        self.rule_type = sys.intern(rule_type) if rule_type else rule_type
        self.wildcard = bool(wildcard)
        if modifiers:
            if not isinstance(modifiers, str):
                modifiers = ",".join(str(m) for m in modifiers) if modifiers else ""
            self.modifiers = sys.intern(modifiers.strip())
        else:
            self.modifiers = ""
        if source_ids is not None:
            self.source_mask = sources_to_mask(source_ids)
        elif sources is not None:
            self.source_mask = sources_to_mask(sources)
        else:
            self.source_mask = 0
        self.category = sys.intern(category) if category else CATEGORY_OTHER
        # Regex rules pass domain="" and skip normalization entirely (hot path).
        self._norm = sys.intern(normalize_domain(domain, strip_www=strip_www)) if domain else ""
        self._sort_type = _TYPE_ORDER.get(rule_type, 9)
        self._out = ""  # memoised output_raw

    def merge_from(self, other: Rule) -> None:
        """OR provenance and keep the higher-priority category. O(1)."""
        self.source_mask |= other.source_mask
        if other.category != self.category:
            self.category = merge_category(self.category, other.category)

    # ── backwards-compatible accessors ────────────────────────────

    @property
    def source_ids(self):
        """Tuple of source keys (URLs or labels) derived from the bitmask."""
        return mask_to_sources(self.source_mask)

    @source_ids.setter
    def source_ids(self, value):
        self.source_mask = sources_to_mask(value)

    @property
    def sources(self):
        """Alias for source_ids (may hold URLs during parsing or IDs later)."""
        return self.source_ids

    @sources.setter
    def sources(self, value):
        self.source_ids = value

    # ── properties ────────────────────────────────────────────────

    @property
    def domain(self) -> str:
        return f"*.{self._norm}" if self.wildcard else self._norm

    @property
    def normalized_domain(self) -> str:
        return self._norm

    @property
    def output_raw(self) -> str:
        """Canonical AdGuard line for output (preserves $ modifiers).

        Memoised: hashing + multi-format export render each rule several
        times; caching the canonical string makes every pass after the
        first a plain attribute read.
        """
        out = self._out
        if out:
            return out
        if self.rule_type == "comment":
            self._out = self.raw
            return self.raw
        if self._norm == "":
            self._out = self.raw  # regex rules keep original form
            return self.raw
        prefix = "@@||" if self.rule_type == "allow" else "||"
        suffix = f"${self.modifiers}" if self.modifiers else ""
        out = f"{prefix}{self.domain}^{suffix}"
        self._out = out
        return out

    # ── equality / hashing (explicit 4-tuple key incl. modifiers) ──

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        return (
            self._norm == other._norm
            and self.rule_type == other.rule_type
            and self.wildcard == other.wildcard
            and self.modifiers == other.modifiers
        )

    def __hash__(self) -> int:
        return hash((self._norm, self.rule_type, self.wildcard, self.modifiers))

    # ── total ordering (pre-computed integer key) ─────────────────

    def __lt__(self, other: Rule) -> bool:
        if not isinstance(other, Rule):
            return NotImplemented
        if self._sort_type != other._sort_type:
            return self._sort_type < other._sort_type
        if self._norm != other._norm:
            return self._norm < other._norm
        if self.wildcard != other.wildcard:
            return self.wildcard and not other.wildcard
        if self.modifiers != other.modifiers:
            return (self.modifiers or "") < (other.modifiers or "")
        # V5.2: deterministic tiebreak (regex rules share an empty key,
        # their order used to depend on network completion order).
        return self.raw < other.raw

    def sort_key(self) -> tuple:
        """Tuple key for ``list.sort(key=...)`` — faster than rich comparisons.

        The trailing ``raw`` element is a deterministic tiebreak: domain rules
        are already unique on the first four fields, so it only orders regex
        rules (which share an empty normalized domain) — identical inputs now
        produce byte-identical output regardless of fetch completion order.
        """
        return (self._sort_type, self._norm, 0 if self.wildcard else 1, self.modifiers, self.raw)

    def __str__(self) -> str:
        return self.output_raw

    def __repr__(self) -> str:
        return f"Rule({self.rule_type} {self.domain!r} cat={self.category})"


class SourceMeta:
    """Metadata for a rule source."""

    __slots__ = ("name", "url", "category", "enabled", "reputation", "timeout", "id")

    def __init__(
        self,
        name: str,
        url: str,
        category: str = CATEGORY_OTHER,
        enabled: bool = True,
        reputation: float = 0.5,
        timeout: int | None = None,
        id: int | None = None,
    ) -> None:
        self.name = name
        self.url = url
        self.category = sys.intern(category) if category else CATEGORY_OTHER
        self.enabled = enabled
        self.reputation = max(0.0, min(1.0, reputation))
        self.timeout = timeout
        self.id = id
