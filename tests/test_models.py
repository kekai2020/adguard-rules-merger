"""Tests for V5 models: normalization and category priority."""

from merger.models import (
    CATEGORY_ADS,
    CATEGORY_MALWARE,
    CATEGORY_MINING,
    CATEGORY_OTHER,
    CATEGORY_PHISHING,
    CATEGORY_TRACKING,
    Rule,
    merge_category,
    normalize_domain,
)


def test_normalize_basic():
    assert normalize_domain("EXAMPLE.COM.") == "example.com"


def test_normalize_wildcard_prefix():
    assert normalize_domain("*.example.com") == "example.com"


def test_normalize_leading_dot():
    assert normalize_domain(".example.com") == "example.com"


def test_normalize_www_optional():
    assert normalize_domain("www.example.com", strip_www=True) == "example.com"
    assert normalize_domain("www.example.com", strip_www=False) == "www.example.com"


def test_rule_dedup_key():
    a = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    b = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    assert a == b
    assert hash(a) == hash(b)


def test_wildcard_not_equal_exact():
    exact = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    wild = Rule(raw="||*.example.com^", domain="example.com", rule_type="block", wildcard=True)
    assert exact != wild


def test_block_not_equal_allow():
    block = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    allow = Rule(raw="@@||example.com^", domain="example.com", rule_type="allow", wildcard=False)
    assert block != allow


def test_category_priority_malware_beats_ads():
    assert merge_category(CATEGORY_ADS, CATEGORY_MALWARE) == CATEGORY_MALWARE
    assert merge_category(CATEGORY_MALWARE, CATEGORY_ADS) == CATEGORY_MALWARE


def test_category_priority_phishing_beats_tracking():
    assert merge_category(CATEGORY_TRACKING, CATEGORY_PHISHING) == CATEGORY_PHISHING


def test_category_priority_mining_beats_ads():
    assert merge_category(CATEGORY_ADS, CATEGORY_MINING) == CATEGORY_MINING


def test_category_priority_same():
    assert merge_category(CATEGORY_ADS, CATEGORY_ADS) == CATEGORY_ADS


def test_category_other_loses():
    assert merge_category(CATEGORY_OTHER, CATEGORY_ADS) == CATEGORY_ADS
    assert merge_category(CATEGORY_ADS, CATEGORY_OTHER) == CATEGORY_ADS


def test_sort_order():
    rules = [
        Rule(raw="||b.com^", domain="b.com", rule_type="block", wildcard=False),
        Rule(raw="||a.com^", domain="a.com", rule_type="block", wildcard=False),
    ]
    rules.sort()
    assert rules[0].normalized_domain == "a.com"


def test_sort_wildcard_before_exact_same_domain():
    exact = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    wild = Rule(raw="||*.example.com^", domain="example.com", rule_type="block", wildcard=True)
    ordered = sorted([exact, wild])
    # wildcard sorts first within same normalized domain
    assert ordered[0].wildcard is True


def test_modifier_changes_identity():
    """||x.com^ and ||x.com^$important must NOT dedup-merge."""
    plain = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    important = Rule(
        raw="||example.com^$important",
        domain="example.com",
        rule_type="block",
        wildcard=False,
        modifiers="important",
    )
    assert plain != important
    assert hash(plain) != hash(important)


def test_modifier_output_raw():
    r = Rule(
        raw="||x.com^$badfilter",
        domain="x.com",
        rule_type="block",
        wildcard=False,
        modifiers="badfilter",
    )
    assert r.output_raw == "||x.com^$badfilter"
