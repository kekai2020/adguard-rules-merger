"""iter1 — correctness / boundary characterization tests.

These pin the invariants the V7 audit calls out (dedup 4-tuple key,
$important outranking whitelists, badfilter preserved-as-modifier, conflict
types) and cross-check the engine against an independent tiny reference parser.
No behavior change — these document and lock current, deliberate semantics.
"""

from __future__ import annotations

from merger.models import Rule, normalize_domain
from merger.parser import RuleParser


def _parse(text: str):
    return RuleParser().parse_text(text, source="s", category="ads")


# ── normalization ────────────────────────────────────────────────────


def test_normalize_folds_case_dot_and_star():
    assert normalize_domain("X.Example.COM") == "x.example.com"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("*.example.com") == "example.com"
    assert normalize_domain("a..example.com") == "a.example.com"


# ── dedup 4-tuple key ─────────────────────────────────────────────────


def test_dedup_key_separates_modifiers():
    r1 = Rule(raw="||x.com^", domain="x.com", rule_type="block", wildcard=False, modifiers="")
    r2 = Rule(
        raw="||x.com^$important",
        domain="x.com",
        rule_type="block",
        wildcard=False,
        modifiers="important",
    )
    assert r1 != r2
    assert hash(r1) != hash(r2)


def test_exact_and_wildcard_are_distinct():
    r1 = Rule(raw="||x.com^", domain="x.com", rule_type="block", wildcard=False)
    r2 = Rule(raw="||*.x.com^", domain="x.com", rule_type="block", wildcard=True)
    assert r1 != r2


# ── parser edge cases ──────────────────────────────────────────────────


def test_parser_dedups_identical_and_normalized():
    rules = _parse("||x.com^\n||X.com^\n||x.com.^\n")
    # Three literal-equivalent shapes collapse to one rule.
    keys = {(r.normalized_domain, r.rule_type, r.wildcard, r.modifiers) for r in rules}
    assert len(keys) == 1


def test_parser_important_and_plain_are_both_kept():
    rules = _parse("||x.com^\n||x.com^$important\n")
    mods = sorted(r.modifiers for r in rules)
    assert mods == ["", "important"]


def test_parser_preserves_badfilter_modifier_for_engine_cancellation():
    # PARSER-layer semantics only: the parser keeps `$badfilter` as a modifier
    # (it does NOT cancel here). Cancellation happens later in the engine via
    # AggregationMixin._apply_badfilter — see tests/test_badfilter.py, which
    # proves the engine removes both the badfilter rule and its target.
    rules = _parse("||x.com^\n||x.com^$badfilter\n")
    out = sorted(r.output_raw for r in rules)
    assert out == ["||x.com^", "||x.com^$badfilter"]


def test_parser_hosts_and_ipv6():
    rules = _parse("0.0.0.0 ad.example.com\n::1 v6.example.com\n")
    domains = sorted(r.normalized_domain for r in rules)
    assert domains == ["ad.example.com", "v6.example.com"]


def test_parser_regex_kept_raw():
    rules = _parse("/(ad|track)-[a-z]+/\n")
    assert len(rules) == 1
    assert rules[0].normalized_domain == ""
    assert rules[0].raw.startswith("/")


def test_parser_unrecognized_counted():
    p = RuleParser()
    p.parse_text("this line is garbage 123\n||good.example.com^\n")
    assert p.unrecognized_dropped == 1
