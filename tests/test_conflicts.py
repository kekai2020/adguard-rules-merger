"""Tests for V7 conflict policy: overlaps are RECORDED, block rules are KEPT.

Whitelist allow never suppresses a block rule anymore; both survive.
"""

from merger.core import AsyncRuleEngine
from merger.models import Rule


def block(domain, wildcard=False, modifiers=""):
    return Rule(
        raw=f"||{'*.' if wildcard else ''}{domain}^{'$' + modifiers if modifiers else ''}",
        domain=domain,
        rule_type="block",
        wildcard=wildcard,
        sources="block-src",
        modifiers=modifiers,
    )


def allow(domain, wildcard=False):
    return Rule(
        raw=f"@@||{'*.' if wildcard else ''}{domain}^",
        domain=domain,
        rule_type="allow",
        wildcard=wildcard,
        sources="allow-src",
    )


def engine(**kwargs):
    defaults = dict(conflict_resolution_enabled=True, cascade_subdomains=True)
    defaults.update(kwargs)
    return AsyncRuleEngine(cache_dir=None, **defaults)


def test_exact_allow_keeps_exact_block():
    blocks = [block("example.com")]
    allows = [allow("example.com")]
    survivors, removed, conflicts = engine()._resolve_conflicts(blocks, allows)
    assert survivors == blocks  # block rule KEPT, not removed
    assert removed == 0
    assert len(conflicts) == 1
    assert conflicts[0]["action"] == "kept_block"


def test_allow_cascade_records_subdomains_but_keeps_blocks():
    blocks = [block("ads.example.com"), block("track.example.com")]
    allows = [allow("example.com")]
    survivors, removed, conflicts = engine(cascade_subdomains=True)._resolve_conflicts(
        blocks, allows
    )
    assert survivors == blocks  # both blocks survive
    assert removed == 0
    assert len(conflicts) == 2


def test_cascade_disable_no_record_for_subdomain():
    blocks = [block("ads.example.com")]
    allows = [allow("example.com")]
    survivors, removed, conflicts = engine(cascade_subdomains=False)._resolve_conflicts(
        blocks, allows
    )
    assert survivors == blocks
    assert removed == 0
    assert len(conflicts) == 0  # exact allow on parent does not cover child


def test_wildcard_allow_keeps_both_blocks():
    blocks = [block("example.com"), block("ads.example.com")]
    allows = [allow("example.com", wildcard=True)]
    survivors, removed, conflicts = engine()._resolve_conflicts(blocks, allows)
    assert survivors == blocks
    assert removed == 0
    # wildcard covers subdomain only; root not covered
    assert len(conflicts) == 1


def test_unrelated_allow_no_conflict():
    blocks = [block("evil.com")]
    allows = [allow("example.com")]
    survivors, removed, conflicts = engine()._resolve_conflicts(blocks, allows)
    assert survivors == blocks
    assert removed == 0
    assert len(conflicts) == 0


def test_regex_blocks_kept_and_no_record():
    regex = Rule(raw="/^192\\.168\\./", domain="", rule_type="block", wildcard=False)
    allows = [allow("168.com")]
    survivors, removed, conflicts = engine()._resolve_conflicts([regex], allows)
    assert survivors == [regex]
    assert removed == 0
    assert len(conflicts) == 0


def test_important_block_kept_and_recorded():
    # $important block survives; overlap is still recorded.
    blocks = [block("pixel.wp.pl", modifiers="important")]
    allows = [allow("pixel.wp.pl")]
    survivors, removed, conflicts = engine()._resolve_conflicts(blocks, allows)
    assert survivors == blocks
    assert removed == 0
    assert survivors[0].modifiers == "important"
    assert len(conflicts) == 1


def test_conflict_record_has_multi_source_info():
    """Conflict records include both sides' sources, domain, type, action."""
    b = block("ads.example.com")
    b.source_ids = ("src-a", "src-b")
    a = allow("example.com")
    a.source_ids = ("src-c",)
    source_names = {"src-a": "ListA", "src-b": "ListB", "src-c": "ListC"}
    survivors, removed, conflicts = engine()._resolve_conflicts([b], [a], source_names)
    assert survivors == [b]  # block kept
    assert removed == 0
    assert len(conflicts) == 1
    c = conflicts[0]
    assert c["domain"] == "ads.example.com"
    assert c["blocked_sources"] == ["ListA", "ListB"]
    assert c["whitelist_sources"] == ["ListC"]
    assert c["conflict_type"] == "cascade"
    assert c["action"] == "kept_block"
    assert "blocked_rule" in c
    assert "whitelist_rule" in c


# ── V5.3 C10: whitelist-aware aggregation + diff ──────────────────


def test_allow_exception_not_folded_into_parent():
    """A child that is a whitelist exception must not be folded into its parent."""
    e = AsyncRuleEngine(cache_dir=None, aggregation_enabled=True, min_aggregator_labels=2)
    blocks = {
        ("example.com", False, ""): block("example.com"),
        ("sub.example.com", False, ""): block("sub.example.com"),
    }
    allow_domains = {"sub.example.com"}
    survivors, exact_agg, _, _ = e._aggregate(blocks, allow_domains=allow_domains)
    norms = [r.normalized_domain for r in survivors]
    assert "sub.example.com" in norms


def test_allow_exception_folded_when_not_in_allow_set():
    """Without allow_domains, sub.example.com IS folded (legacy behavior)."""
    e = AsyncRuleEngine(cache_dir=None, aggregation_enabled=True, min_aggregator_labels=2)
    blocks = {
        ("example.com", False, ""): block("example.com"),
        ("sub.example.com", False, ""): block("sub.example.com"),
    }
    survivors, exact_agg, _, _ = e._aggregate(blocks)
    assert exact_agg == 1
    norms = [r.normalized_domain for r in survivors]
    assert "sub.example.com" not in norms


def test_merge_outcome_has_allow_diff_fields():
    from merger.core import MergeOutcome

    o = MergeOutcome()
    assert o.added_allows == []
    assert o.removed_allows == []
