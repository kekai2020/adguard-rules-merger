"""Tests for $badfilter cancellation and source bitmask merge."""

from merger.core import AsyncRuleEngine
from merger.models import Rule, intern_source, mask_to_sources, sources_to_mask


def make(domain, modifiers="", rule_type="block"):
    return Rule(
        raw=f"||{domain}^${modifiers}" if modifiers else f"||{domain}^",
        domain=domain,
        rule_type=rule_type,
        wildcard=False,
        sources="src",
        modifiers=modifiers,
    )


def test_badfilter_removes_self_and_target():
    rules = [make("pl.ua"), make("pl.ua", "badfilter")]
    m = {(r.normalized_domain, r.wildcard, r.modifiers): r for r in rules}
    n = AsyncRuleEngine(cache_dir=None)._apply_badfilter(m, {})
    assert n == 2
    assert m == {}


def test_badfilter_without_target_still_dropped():
    rules = [make("orphan.com", "badfilter")]
    m = {(r.normalized_domain, r.wildcard, r.modifiers): r for r in rules}
    n = AsyncRuleEngine(cache_dir=None)._apply_badfilter(m, {})
    assert n == 1
    assert m == {}


def test_badfilter_with_important_only_cancels_important():
    rules = [
        make("x.com"),
        make("x.com", "important"),
        make("x.com", "badfilter,important"),
    ]
    m = {(r.normalized_domain, r.wildcard, r.modifiers): r for r in rules}
    AsyncRuleEngine(cache_dir=None)._apply_badfilter(m, {})
    assert ("x.com", False, "") in m
    assert ("x.com", False, "important") not in m


def test_source_mask_or_merge():
    a = Rule(raw="||a.com^", domain="a.com", rule_type="block", wildcard=False, sources="one")
    b = Rule(raw="||a.com^", domain="a.com", rule_type="block", wildcard=False, sources="two")
    a.merge_from(b)
    ids = set(a.source_ids)
    assert "one" in ids and "two" in ids
    assert a.source_mask == sources_to_mask("one") | sources_to_mask("two")


def test_empty_source_ids_clears_mask():
    r = Rule(raw="||a.com^", domain="a.com", rule_type="block", wildcard=False, sources="one")
    r.source_ids = ()
    assert r.source_mask == 0
    assert r.source_ids == ()


def test_intern_source_stable():
    i1 = intern_source("https://example.com/x.txt")
    i2 = intern_source("https://example.com/x.txt")
    assert i1 == i2
    assert mask_to_sources(1 << i1) == ("https://example.com/x.txt",)


# ── full-run integration: badfilter must block wildcard promotion ──


def test_badfilter_then_promotion_full_run(tmp_path):
    """A voided ||*.example.com^ must not be recreated by sibling promotion."""
    src = tmp_path / "list.txt"
    src.write_text(
        "||*.example.com^$badfilter\n||a.example.com^\n||b.example.com^\n||c.example.com^\n"
    )
    from merger.models import SourceMeta

    engine = AsyncRuleEngine(
        cache_dir=None,
        wildcard_promotion_threshold=3,
        whitelist_audit_enabled=False,
        quality_filter_enabled=False,
    )
    out = engine.run_sync([SourceMeta(name="T", url=str(src), category="ads")])
    # promotion would otherwise hit the 3 siblings and recreate *.example.com
    assert out.wildcard_promoted == 0
    wildcard_domains = {r.normalized_domain for r in out.blocks if r.wildcard}
    assert "example.com" not in wildcard_domains


def test_promotion_still_works_without_badfilter(tmp_path):
    """Sanity check: promotion fires normally for an un-cancelled parent."""
    src = tmp_path / "list.txt"
    src.write_text("||a.example.org^\n||b.example.org^\n||c.example.org^\n")
    from merger.models import SourceMeta

    engine = AsyncRuleEngine(
        cache_dir=None,
        wildcard_promotion_threshold=3,
        whitelist_audit_enabled=False,
        quality_filter_enabled=False,
    )
    out = engine.run_sync([SourceMeta(name="T", url=str(src), category="ads")])
    assert out.wildcard_promoted >= 1
