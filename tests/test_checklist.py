"""Checklist items: M-4 preserve, IDN, CIDR/dnscrypt preserve, offline report."""

from types import SimpleNamespace

from merger.parser import RuleParser
from merger.report.analysis import analyze_rules
from merger.report.html import generate_html_report


def _outcome():
    return SimpleNamespace(
        raw_count=100,
        exact_merged=10,
        normalized_merged=5,
        regex_merged=2,
        aggregated=8,
        wildcard_aggregated=3,
        wildcard_promoted=1,
        conflict_resolved=4,
        sources_ok=18,
        sources_total=18,
        sources_cached=0,
        css_dropped=0,
        quality_dropped=0,
        pattern_dropped=0,
        added=[],
        removed=[],
        failed_sources=[],
        contributions=[],
        modifier_stats={},
        source_overlap={},
        conflicts=[],
        whitelist_audit={},
        content_version="x",
        elapsed=1.0,
        badfilter_removed=0,
        wildcard_promoted_groups=0,
    )


def test_infix_preserved():
    p = RuleParser()
    r = p.parse_text("||ad*.example.com^", source="s", category="ads")
    assert len(r) == 1 and r[0].raw == "||ad*.example.com^"


def test_idn_kept_as_is():
    # v8 intentionally removed the forced IDN->punycode decode (the old decode
    # mangled non-ASCII hosts); the unicode domain is now preserved verbatim.
    p = RuleParser()
    r = p.parse_text("||пример.рф^", source="s", category="ads")
    assert r and r[0].normalized_domain == "пример.рф"


def test_cidr_preserved():
    p = RuleParser()
    r = p.parse_text("1.2.3.0/24", source="s", category="ads")
    assert len(r) == 1 and r[0].raw == "1.2.3.0/24"


def test_sdns_preserved():
    p = RuleParser()
    r = p.parse_text("sdns://abc", source="s", category="ads")
    assert len(r) == 1 and r[0].raw.startswith("sdns://")


def test_report_no_cdn():
    outcome = _outcome()
    analysis = analyze_rules([], [])
    html = generate_html_report([], [], outcome, analysis)
    assert "cdn.jsdelivr" not in html
    assert "echarts" not in html
