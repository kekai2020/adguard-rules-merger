"""Tests for V5 upward aggregation (including new wildcard aggregation)."""

from merger.core import AsyncRuleEngine
from merger.models import Rule


def make_block(domain, wildcard=False, modifiers=""):
    raw = f"||{'*.' if wildcard else ''}{domain}^{'$' + modifiers if modifiers else ''}"
    return Rule(
        raw=raw,
        domain=domain,
        rule_type="block",
        wildcard=wildcard,
        sources="test",
        modifiers=modifiers,
    )


def build_map(rules):
    return {(r.normalized_domain, r.wildcard, r.modifiers): r for r in rules}


def engine(**kwargs):
    defaults = dict(
        aggregation_enabled=True,
        min_aggregator_labels=2,
        wildcard_child_aggregation=True,
        wildcard_promotion_threshold=0,
    )
    defaults.update(kwargs)
    return AsyncRuleEngine(cache_dir=None, **defaults)


def domains_of(survivors):
    return sorted((r.normalized_domain, r.wildcard) for r in survivors)


# ── V4-compatible behavior ─────────────────────────────────────────


def test_exact_child_under_wildcard_parent():
    rules = [
        make_block("example.com", wildcard=True),  # ||*.example.com^
        make_block("ads.example.com"),  # ||ads.example.com^
    ]
    survivors, exact_agg, wild_agg, promoted = engine()._aggregate(build_map(rules))
    norms = [r.normalized_domain for r in survivors]
    assert "example.com" in norms
    assert "ads.example.com" not in norms
    assert exact_agg == 1


def test_exact_child_under_exact_parent():
    # DNS layer: ||example.com^ covers subdomains too
    rules = [
        make_block("example.com"),
        make_block("ads.example.com"),
    ]
    survivors, exact_agg, _, _ = engine()._aggregate(build_map(rules))
    norms = [r.normalized_domain for r in survivors]
    assert norms == ["example.com"]
    assert exact_agg == 1


def test_root_exact_not_removed_by_wildcard():
    # The exact root rule ||example.com^ must survive ||*.example.com^
    # (wildcard only covers subdomains, not the root itself). V5 additionally
    # drops the now-redundant wildcard because exact strictly covers it.
    rules = [
        make_block("example.com", wildcard=True),
        make_block("example.com"),
    ]
    survivors, exact_agg, wild_agg, _ = engine()._aggregate(build_map(rules))
    exact_norms = [r.normalized_domain for r in survivors if not r.wildcard]
    assert "example.com" in exact_norms  # root exact survives
    assert exact_agg == 0  # exact was NOT folded by wildcard
    assert wild_agg == 1  # redundant wildcard removed by exact


def test_min_labels_protection():
    # no aggregation up to a bare TLD parent
    rules = [
        make_block("com"),
        make_block("example.com"),
    ]
    survivors, exact_agg, _, _ = engine(min_aggregator_labels=2)._aggregate(build_map(rules))
    # example.com's parent "com" has 1 label -> protected
    assert exact_agg == 0


# ── V5 new: wildcard child aggregation ─────────────────────────────


def test_wildcard_child_under_wildcard_parent():
    # ||*.sub.example.com^ covered by ||*.example.com^
    rules = [
        make_block("example.com", wildcard=True),
        make_block("sub.example.com", wildcard=True),
    ]
    survivors, _, wild_agg, _ = engine()._aggregate(build_map(rules))
    norms = [r.normalized_domain for r in survivors if r.wildcard]
    assert norms == ["example.com"]
    assert wild_agg == 1


def test_wildcard_child_under_exact_parent():
    # ||*.sub.example.com^ covered by ||example.com^ (DNS layer exact covers subs)
    rules = [
        make_block("example.com", wildcard=False),
        make_block("sub.example.com", wildcard=True),
    ]
    survivors, _, wild_agg, _ = engine()._aggregate(build_map(rules))
    wild_norms = [r.normalized_domain for r in survivors if r.wildcard]
    assert wild_norms == []
    assert wild_agg == 1


def test_same_domain_wildcard_covered_by_exact():
    # ||example.com^ strictly covers ||*.example.com^ -> wildcard is redundant
    rules = [
        make_block("example.com", wildcard=False),
        make_block("example.com", wildcard=True),
    ]
    survivors, _, wild_agg, _ = engine()._aggregate(build_map(rules))
    wild = [r for r in survivors if r.wildcard]
    assert wild == []
    assert wild_agg == 1


def test_wildcard_aggregation_disabled():
    rules = [
        make_block("example.com", wildcard=True),
        make_block("sub.example.com", wildcard=True),
    ]
    survivors, _, wild_agg, _ = engine(wildcard_child_aggregation=False)._aggregate(
        build_map(rules)
    )
    assert wild_agg == 0
    assert len(survivors) == 2


# ── V5 new: wildcard promotion ─────────────────────────────────────


def test_wildcard_promotion():
    # 3 exact siblings with threshold 3 -> promote to ||*.example.com^
    rules = [make_block(f"{n}.example.com") for n in ("a", "b", "c")]
    eng = engine(wildcard_promotion_threshold=3)
    survivors, _, _, promoted = eng._aggregate(build_map(rules))
    assert promoted == 3
    wild = [r for r in survivors if r.wildcard and r.normalized_domain == "example.com"]
    assert len(wild) == 1


def test_wildcard_promotion_below_threshold():
    rules = [make_block(f"{n}.example.com") for n in ("a", "b")]
    eng = engine(wildcard_promotion_threshold=3)
    survivors, _, _, promoted = eng._aggregate(build_map(rules))
    assert promoted == 0
    assert len(survivors) == 2


# ── D1: a whitelisted sibling must not count toward promotion ──────


def test_promotion_excludes_whitelisted_sibling():
    """D1: with b.example.com whitelisted, it neither counts toward the
    threshold nor is merged; below threshold -> no wildcard parent at all."""
    rules = [make_block(f"{n}.example.com") for n in ("a", "b", "c")]
    eng = engine(wildcard_promotion_threshold=3)
    survivors, _, _, promoted = eng._aggregate(build_map(rules), allow_domains={"b.example.com"})
    assert promoted == 0
    norms = {r.normalized_domain for r in survivors}
    assert "b.example.com" in norms
    assert not any(r.wildcard and r.normalized_domain == "example.com" for r in survivors)


def test_promotion_partial_after_excluding_whitelisted():
    """D1: threshold 2 -> only non-whitelisted a,c are promoted; b survives."""
    rules = [make_block(f"{n}.example.com") for n in ("a", "b", "c")]
    eng = engine(wildcard_promotion_threshold=2)
    survivors, _, _, promoted = eng._aggregate(build_map(rules), allow_domains={"b.example.com"})
    assert promoted == 2
    norms = {r.normalized_domain for r in survivors}
    assert "b.example.com" in norms
    wild = [r for r in survivors if r.wildcard and r.normalized_domain == "example.com"]
    assert len(wild) == 1


def test_promotion_unchanged_without_whitelist():
    """D1 regression: no allow_domains -> legacy count promotion unchanged."""
    rules = [make_block(f"{n}.example.com") for n in ("a", "b", "c")]
    eng = engine(wildcard_promotion_threshold=3)
    survivors, _, _, promoted = eng._aggregate(build_map(rules))
    assert promoted == 3
    wild = [r for r in survivors if r.wildcard and r.normalized_domain == "example.com"]
    assert len(wild) == 1


# ── V5: rules with $ modifiers skip aggregation ────────────────────


def test_modified_child_not_aggregated():
    # ||ads.example.com^$important must NOT be folded into ||*.example.com^
    rules = [
        make_block("example.com", wildcard=True),
        make_block("ads.example.com", modifiers="important"),
    ]
    survivors, exact_agg, _, _ = engine()._aggregate(build_map(rules))
    norms = [r.normalized_domain for r in survivors]
    assert "ads.example.com" in norms
    assert exact_agg == 0


def test_modified_and_plain_coexist():
    # ||x.com^ and ||x.com^$badfilter are different rules — both survive
    rules = [
        make_block("example.com"),
        make_block("example.com", modifiers="badfilter"),
    ]
    survivors, _, _, _ = engine()._aggregate(build_map(rules))
    assert len(survivors) == 2


# ── _iter_parents generator boundaries ──


def test_iter_parents_min_labels_1():
    from merger.core import _iter_parents

    assert list(_iter_parents("a.b.com", 1)) == ["b.com", "com"]


def test_iter_parents_min_labels_2_default():
    from merger.core import _iter_parents

    assert list(_iter_parents("a.b.c.com")) == ["b.c.com", "c.com"]


def test_iter_parents_min_labels_3():
    from merger.core import _iter_parents

    # "d.com" has only 2 labels and is excluded by min_labels=3
    assert list(_iter_parents("a.b.c.d.com", 3)) == ["b.c.d.com", "c.d.com"]


def test_iter_parents_single_label_no_parents():
    from merger.core import _iter_parents

    assert list(_iter_parents("localhost", 2)) == []


def test_iter_parents_min_labels_larger_than_depth():
    from merger.core import _iter_parents

    assert list(_iter_parents("a.b.com", 5)) == []


# ── V5.3 C6: PSL guard ─────────────────────────────────────────────


def test_promotion_blocked_on_public_suffix():
    """Public-suffix bodies (co.uk) must not be promoted to wildcard."""
    rules = [
        make_block("a.co.uk"),
        make_block("b.co.uk"),
        make_block("c.co.uk"),
    ]
    e = engine(wildcard_promotion_threshold=2, psl_guard=True)
    survivors, _, _, promoted = e._aggregate(build_map(rules))
    assert promoted == 0
    norms = [r.normalized_domain for r in survivors]
    assert "co.uk" not in norms


def test_promotion_allowed_when_psl_guard_disabled():
    """With psl_guard=False, public-suffix bodies can be promoted."""
    rules = [
        make_block("a.co.uk"),
        make_block("b.co.uk"),
        make_block("c.co.uk"),
    ]
    e = engine(wildcard_promotion_threshold=2, psl_guard=False)
    survivors, _, _, promoted = e._aggregate(build_map(rules))
    assert promoted == 3


def test_psl_guard_does_not_block_normal_domains():
    """Normal parent domains (example.com) are unaffected by psl_guard."""
    rules = [
        make_block("a.example.com"),
        make_block("b.example.com"),
    ]
    e = engine(wildcard_promotion_threshold=2, psl_guard=True)
    survivors, _, _, promoted = e._aggregate(build_map(rules))
    assert promoted == 2


# ── V5.3 C7: pattern-aware promotion ───────────────────────────────


def test_count_mode_promotes_by_threshold():
    """count mode (default) promotes purely by sibling count."""
    rules = [
        make_block("cdn1.example.com"),
        make_block("cdn2.example.com"),
        make_block("foo.example.com"),
    ]
    e = engine(wildcard_promotion_threshold=2, promotion_mode="count")
    _, _, _, promoted = e._aggregate(build_map(rules))
    assert promoted == 3


def test_pattern_mode_promotes_consistent_variants():
    """pattern mode promotes when variant labels match promo patterns."""
    rules = [
        make_block("cdn1.example.com"),
        make_block("cdn2.example.com"),
        make_block("cdn3.example.com"),
    ]
    e = engine(
        wildcard_promotion_threshold=2, promotion_mode="pattern", promotion_pattern_min_ratio=0.8
    )
    _, _, _, promoted = e._aggregate(build_map(rules))
    assert promoted == 3


def test_pattern_mode_skips_inconsistent_variants():
    """pattern mode skips when variant consistency < min_ratio."""
    rules = [
        make_block("cdn1.example.com"),
        make_block("foo.example.com"),
        make_block("bar.example.com"),
    ]
    e = engine(
        wildcard_promotion_threshold=2, promotion_mode="pattern", promotion_pattern_min_ratio=0.8
    )
    _, _, _, promoted = e._aggregate(build_map(rules))
    assert promoted == 0


def test_pattern_mode_partial_consistency():
    """2/3 match (0.67 < 0.8) → skipped; 2/2 match (1.0 >= 0.8) → promoted."""
    rules = [
        make_block("cdn1.example.com"),
        make_block("cdn2.example.com"),
        make_block("random.example.com"),
    ]
    e = engine(
        wildcard_promotion_threshold=2, promotion_mode="pattern", promotion_pattern_min_ratio=0.8
    )
    _, _, _, promoted = e._aggregate(build_map(rules))
    assert promoted == 0


def test_variant_label_patterns():
    """Verify _variant_label recognizes known promo patterns."""
    vl = AsyncRuleEngine._variant_label
    assert vl("cdn1.example.com", "example.com") == "cdn1"
    assert vl("ads2.example.com", "example.com") == "ads2"
    assert vl("img3.example.com", "example.com") == "img3"
    assert vl("static1.example.com", "example.com") == "static1"
    assert vl("s1.example.com", "example.com") == "s1"
    assert vl("ns1.example.com", "example.com") == "ns1"
    assert vl("server1.example.com", "example.com") == "server1"
    assert vl("42.example.com", "example.com") == "42"
    assert vl("random.example.com", "example.com") is None
    assert vl("example.com", "com") is None


def test_variant_label_multi_level_skipped():
    """Multi-level label change returns None and increments counter."""
    counters: dict = {}
    result = AsyncRuleEngine._variant_label("cdn1.x.example.com", "example.com", counters)
    assert result is None
    assert counters.get("promotion_multi_level_skipped") == 1


def test_variant_label_single_label():
    """Single-label variant relative to parent returns the label."""
    result = AsyncRuleEngine._variant_label("cdn1.example.com", "example.com")
    assert result == "cdn1"
