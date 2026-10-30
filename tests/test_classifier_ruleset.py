"""R3: ``ClassifierRuleSet`` offline unit tests.

The default singleton must reproduce the legacy built-in registered/prefix
tables exactly (key set, per-key category, setdefault hand-written priority,
builtin seed gap-fill); fresh instances are independent, external seeds merge
with setdefault semantics into the selected instance only, and the optional
``ruleset`` parameter transparently threads through classification — including
CNAME recursion.  Fully offline: no network, no DNS, no module-global mutation
outside the documented compat singleton.
"""

from __future__ import annotations

from merger.domain_classifier import (
    _PREFIX_LOOKUP,
    _REGISTERED_LOOKUP,
    BLOCK_BUCKET_MAP,
    CONFIDENCE_REGISTERED,
    CONFIDENCE_SUBDOMAIN,
    REGISTERED_DOMAIN_RULES,
    SUBDOMAIN_PREFIX_RULES,
    ClassifierRuleSet,
    _load_builtin_seeds,
    block_bucket_for,
    classify_batch,
    classify_domain,
    classify_domain_with_confidence,
)

# ── independent rebuild of the legacy tables (对拍 oracle) ──────────────


def _legacy_registered() -> dict[str, str]:
    """Rebuild the old module ``_REGISTERED_LOOKUP`` by hand (setdefault)."""
    table: dict[str, str] = {}
    for cat, pats in REGISTERED_DOMAIN_RULES:
        for pat in pats:
            table.setdefault(pat, cat)
    for dom, cat in _load_builtin_seeds().items():
        table.setdefault(dom.lower(), cat)
    return table


def _legacy_prefix() -> dict[str, str]:
    """Rebuild the old module ``_PREFIX_LOOKUP`` by hand (setdefault)."""
    table: dict[str, str] = {}
    for cat, prefs in SUBDOMAIN_PREFIX_RULES:
        for pref in prefs:
            table.setdefault(pref, cat)
    return table


# ── default consistency: default instance == legacy built-in tables ────


def test_default_ruleset_matches_legacy_registered_table():
    expected = _legacy_registered()
    rs = ClassifierRuleSet.default()
    # key set identical
    assert set(rs.registered) == set(expected)
    # every key maps to the same category
    for key, cat in expected.items():
        assert rs.registered[key] == cat, key


def test_default_ruleset_matches_legacy_prefix_table():
    expected = _legacy_prefix()
    rs = ClassifierRuleSet.default()
    assert set(rs.prefix) == set(expected)
    for key, cat in expected.items():
        assert rs.prefix[key] == cat, key


def test_default_singleton_aliases_legacy_globals():
    # Backwards-compat underscore globals ARE the singleton's tables.
    rs = ClassifierRuleSet.default()
    assert _REGISTERED_LOOKUP is rs.registered
    assert _PREFIX_LOOKUP is rs.prefix
    assert _REGISTERED_LOOKUP == _legacy_registered()
    assert _PREFIX_LOOKUP == _legacy_prefix()


def test_setdefault_handwritten_wins_on_duplicate_patterns():
    # Patterns listed in two buckets keep the FIRST-listed category.
    rs = ClassifierRuleSet.default()
    # msecnd.net: cdn listed before microsoft_telemetry
    assert rs.registered["msecnd.net"] == "cdn"
    # cloudflare.com: cdn listed before privacy_security
    assert rs.registered["cloudflare.com"] == "cdn"
    # fb.me: affiliate listed before social
    assert rs.registered["fb.me"] == "affiliate"
    # youtu.be: affiliate listed before social
    assert rs.registered["youtu.be"] == "affiliate"


def test_builtin_seeds_fill_gaps_not_overwrite_handwritten():
    seeds = _load_builtin_seeds()
    rs = ClassifierRuleSet.default()
    # Every curated seed present; hand-written duplicates keep their category.
    for dom, cat in seeds.items():
        assert dom.lower() in rs.registered
    # ads-twitter.com is seed-only (not hand-written) and hits at 0.9.
    c, conf, reason = classify_domain_with_confidence("ads-twitter.com")
    assert c == "advertising"
    assert conf == CONFIDENCE_REGISTERED
    assert "registered domain match" in reason


def test_fresh_instance_builtin_tables_equal_default():
    fresh = ClassifierRuleSet()
    rs = ClassifierRuleSet.default()
    assert fresh.registered == rs.registered
    assert fresh.prefix == rs.prefix
    # but they are independent copies, not shared dicts
    assert fresh.registered is not rs.registered
    assert fresh.prefix is not rs.prefix


# ── with_seeds: setdefault priority / gap-fill / count ────────────────


def test_with_seeds_does_not_overwrite_handwritten():
    rs = ClassifierRuleSet()
    grown = rs.with_seeds({"doubleclick.net": "cdn"})
    # hand-written entry wins; original instance untouched
    assert grown.registered["doubleclick.net"] == "advertising"
    assert rs.registered["doubleclick.net"] == "advertising"
    # default singleton untouched too
    assert ClassifierRuleSet.default().registered["doubleclick.net"] == "advertising"


def test_merge_seeds_counts_added_and_absent_only():
    rs = ClassifierRuleSet()
    marker = "zzqk-ruleset-new-marker.example"
    assert rs.merge_seeds({marker: "advertising"}) == 1
    assert rs.registered[marker] == "advertising"
    # re-adding an existing hand-written entry contributes nothing
    assert rs.merge_seeds({"doubleclick.net": "cdn"}) == 0
    assert rs.registered["doubleclick.net"] == "advertising"
    # falsy category / empty key are skipped
    assert rs.merge_seeds({"": "advertising", "empty-cat.example": ""}) == 0


def test_with_seeds_gap_fill_classifies_at_high_confidence():
    marker = "zzqk-ruleset-gap.example"
    grown = ClassifierRuleSet().with_seeds({marker: "analytics"})
    cat, conf, _ = grown.classify_with_confidence(marker)
    assert cat == "analytics"
    assert conf == CONFIDENCE_REGISTERED


# ── instance isolation: no per-run / cross-test accumulation ───────────


def test_instances_do_not_pollute_each_other_or_default():
    marker = "zzqk-ruleset-isolate.example"
    grown = ClassifierRuleSet().with_seeds({marker: "advertising"})

    # sibling fresh instance and default singleton never see the seed
    assert marker not in ClassifierRuleSet().registered
    assert marker not in ClassifierRuleSet.default().registered
    # the source instance was not mutated by the pure with_seeds copy
    assert marker not in ClassifierRuleSet().registered
    # only the returned copy carries it
    assert grown.registered[marker] == "advertising"


# ── optional ruleset passthrough (classify / batch / domain) ──────────


def test_optional_ruleset_passthrough_classify():
    marker = "zzqk-ruleset-passthrough.example"
    rs = ClassifierRuleSet().with_seeds({marker: "advertising"})

    cat, conf, _ = classify_domain_with_confidence(marker, ruleset=rs)
    assert cat == "advertising"
    assert conf == CONFIDENCE_REGISTERED
    # default singleton does not know the marker
    default_cat, default_conf, _ = classify_domain_with_confidence(marker)
    assert default_cat == "other"
    assert default_conf < CONFIDENCE_REGISTERED

    assert classify_domain(marker, ruleset=rs) == "advertising"
    assert classify_domain(marker) == "other"


def test_optional_ruleset_passthrough_batch():
    marker = "zzqk-ruleset-batch.example"
    rs = ClassifierRuleSet().with_seeds({marker: "tracking"})
    # batch signature accepts ruleset as third optional argument
    out = classify_batch([marker, "doubleclick.net"], ruleset=rs)
    assert out[marker] == "tracking"
    assert out["doubleclick.net"] == "advertising"
    default_out = classify_batch([marker])
    assert default_out[marker] == "other"


# ── CNAME recursion threads the same ruleset; 0.72 discount still rejected ──


def test_cname_recursion_uses_same_ruleset():
    # A target known ONLY to the custom ruleset must be reached via that
    # instance; the default singleton never sees it.
    target = "zzqk-ruleset-cname-target.test"
    rs = ClassifierRuleSet().with_seeds({target: "advertising"})

    cat, conf, reason = classify_domain_with_confidence(
        "miss-zone.example", cname_hints=[target], ruleset=rs
    )
    assert cat == "advertising"
    # 0.9 registered match discounted by 0.8 → 0.72
    assert conf == 0.9 * 0.8
    assert "cname hint" in reason

    # default singleton: unknown target → no CNAME rescue
    default_cat, default_conf, _ = classify_domain_with_confidence(
        "miss-zone.example", cname_hints=[target]
    )
    assert default_cat == "other"
    assert default_conf == 0.0


def test_cname_discount_072_rejected_for_bucket():
    cat, conf, _ = classify_domain_with_confidence("miss.example", cname_hints=["doubleclick.net"])
    assert cat == "advertising"
    assert conf == 0.9 * 0.8
    assert block_bucket_for("advertising", conf) is None


# ── safety buckets never downgraded; neutral categories keep source ────


def test_security_buckets_absent_from_block_map():
    for safe in ("malware", "phishing", "mining"):
        assert safe not in BLOCK_BUCKET_MAP
        assert block_bucket_for(safe, CONFIDENCE_REGISTERED) is None


def test_neutral_categories_keep_source_bucket():
    for cat in ("cdn", "ecommerce_payment", "privacy_security", "other"):
        assert block_bucket_for(cat, CONFIDENCE_REGISTERED) is None, cat


def test_medium_confidence_keeps_source_bucket():
    assert block_bucket_for("advertising", CONFIDENCE_SUBDOMAIN) is None
    assert block_bucket_for("analytics", 0.0) is None
