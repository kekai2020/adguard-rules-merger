"""P1 regression tests: fusion-weight reconciliation, empty-UA fallback,
two-layer switch defaults, and the audit disk-cache fingerprint.
"""

from __future__ import annotations

from merger.config import DEFAULT_FUSION_WEIGHTS, MergeConfig
from merger.core import AsyncRuleEngine
from merger.version import user_agent as versioned_ua
from merger.whitelist_audit import AuditConfig
from merger.whitelist_audit.disk_cache import _cfg_fingerprint

# ── P1-2: fusion weights reconciled ──────────────────────────────────

# Keys fusion.py actually reads (the only knobs that may exist).
_LIVE_KEYS = {
    "threat_intel",
    "dnsbl_malicious",
    "scam_confirmed",
    "dns_private_ip",
    "scam_suspicious",
    "dnsbl_listed",
    "dns_nxdomain",
    "rdap_new_domain",
    "heuristics",
    "homograph",
    "dns_mx_missing",
    "gsb_malicious",
    "phishtank_malicious",
    "urlscan_suspicious",
}

_DEAD_KEYS = {"age_young", "dnsbl", "dnsbl_spam", "virustotal", "ai", "safe_signal"}


def test_default_fusion_weights_match_audit_config_exactly():
    assert set(DEFAULT_FUSION_WEIGHTS) == _LIVE_KEYS
    assert DEFAULT_FUSION_WEIGHTS == AuditConfig().fusion_weights


def test_default_fusion_weights_have_no_dead_keys():
    assert not (_DEAD_KEYS & set(DEFAULT_FUSION_WEIGHTS))


def test_default_fusion_weights_values_align_fusion_fallbacks():
    # The three values that used to mismatch the fusion.py fallbacks.
    assert DEFAULT_FUSION_WEIGHTS["threat_intel"] == 40
    assert DEFAULT_FUSION_WEIGHTS["scam_suspicious"] == 20
    assert DEFAULT_FUSION_WEIGHTS["dns_nxdomain"] == 15


def test_shallow_merge_keeps_unmentioned_layers():
    user = {"threat_intel": 77}
    merged = {**AuditConfig().fusion_weights, **user}
    assert merged["threat_intel"] == 77
    # Unmentioned layers keep their built-in weight (no whole-table drop).
    assert merged["dnsbl_malicious"] == AuditConfig().fusion_weights["dnsbl_malicious"]
    assert merged["heuristics"] == AuditConfig().fusion_weights["heuristics"]


# ── P1-3: empty User-Agent falls back to the versioned UA ───────────


def test_empty_user_agent_falls_back_to_versioned_ua():
    eng = AsyncRuleEngine(cache_dir=None, user_agent="")
    assert eng.user_agent == versioned_ua()
    assert eng.user_agent.startswith("AdGuard-Rules-Merger/")


def test_explicit_user_agent_is_preserved():
    eng = AsyncRuleEngine(cache_dir=None, user_agent="custom/1.0")
    assert eng.user_agent == "custom/1.0"


# ── P1-4: two-layer switch defaults unified to False (offline by default) ──


def test_pydantic_audit_switches_default_off():
    wa = MergeConfig().whitelist_audit
    assert wa.use_dnsbl is False
    assert wa.cache_results is False
    # And they match the AuditConfig dataclass defaults.
    ac = AuditConfig()
    assert wa.use_dnsbl == ac.use_dnsbl
    assert wa.cache_results == ac.cache_results


# ── P1-5: disk-cache fingerprint covers result-affecting dimensions ──


def test_fingerprint_changes_when_layers_or_keys_change():
    base = _cfg_fingerprint(AuditConfig())
    # use_dns_mx flips scoring -> must invalidate.
    assert _cfg_fingerprint(AuditConfig(use_dns_mx=True)) != base
    # Swapping an online key from absent->present switches the effective layer
    # on and must invalidate (the layer on/off flag alone is not enough).
    assert _cfg_fingerprint(AuditConfig(gsb_api_key="k1")) != base
    assert _cfg_fingerprint(AuditConfig(ai_api_key="k1")) != base
    # ai_min_confidence / ti_mode / feed_ttl alter the verdict.
    assert _cfg_fingerprint(AuditConfig(ai_min_confidence=0.9)) != base
    assert _cfg_fingerprint(AuditConfig(ti_mode="auto")) != base
    assert _cfg_fingerprint(AuditConfig(feed_ttl_seconds=7200)) != base


# ── P1-8: conflict type wildcard renders as 通配符 ───────────────────


def _outcome_with_wildcard_conflict():
    from types import SimpleNamespace

    return SimpleNamespace(
        raw_count=10,
        exact_merged=0,
        normalized_merged=0,
        regex_merged=0,
        aggregated=0,
        wildcard_aggregated=0,
        wildcard_promoted=0,
        conflict_resolved=1,
        sources_ok=1,
        sources_total=1,
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
        conflicts=[
            {
                "domain": "sub.example.com",
                "blocked_rule": "||sub.example.com^",
                "blocked_sources": ["src"],
                "whitelist_rule": "@@||*.example.com^",
                "whitelist_sources": ["wl"],
                "conflict_type": "wildcard",
            },
            {
                "domain": "exact.example.com",
                "blocked_rule": "||exact.example.com^",
                "blocked_sources": ["src"],
                "whitelist_rule": "@@||exact.example.com^",
                "whitelist_sources": ["wl"],
                "conflict_type": "exact",
            },
        ],
        whitelist_audit={},
        content_version="t",
        elapsed=0.0,
    )


def test_wildcard_conflict_rendered_as_tongpeifu():
    from merger.report import analyze_rules, generate_html_report, generate_markdown_report

    oc = _outcome_with_wildcard_conflict()
    analysis = analyze_rules([], [])
    html = generate_html_report([], [], oc, analysis, include_time=False)
    md = generate_markdown_report([], [], oc, analysis, include_time=False)
    # The wildcard row carries 通配符, and the exact row still says 精确.
    assert "通配符" in html
    assert "通配符" in md
    # exact must NOT be relabelled 通配符.
    sub_html = html[html.index("exact.example.com") : html.index("exact.example.com") + 400]
    sub_md = md[md.index("exact.example.com") : md.index("exact.example.com") + 200]
    assert "精确" in sub_html
    assert "精确" in sub_md


# ── P1-9: funnel numbers close (Raw − steps == final) ─────────────────


def _funnel_counts(report_text: str, html: bool):
    """Pull the ordered (count, step-diff) pairs out of the funnel section."""
    import re

    if html:
        nums = re.findall(
            r'step-count">([\d,]+)</div><div class="step-diff">(-?[\d,-]*)',
            report_text,
        )
        return [(int(c.replace(",", "")), d.replace(",", "")) for c, d in nums]
    # markdown: | stage | count | diff |
    rows = []
    in_table = False
    for line in report_text.splitlines():
        if line.startswith("| 阶段"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            if line.startswith("|------"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            count = int(cells[1].replace(",", ""))
            diff = cells[2]
            rows.append((count, diff))
    return rows


def test_funnel_numbers_close_with_badfilter_and_promotion(tmp_path):
    from merger.core import AsyncRuleEngine
    from merger.models import SourceMeta
    from merger.report import analyze_rules, generate_html_report, generate_markdown_report

    # raw: 3 siblings (promoted into one new wildcard parent -> net -2), one
    # exact kept, a badfilter cancellation (2 removed), one block vs allow.
    src = tmp_path / "s.txt"
    src.write_text(
        "||s1.example.net^\n"
        "||s2.example.net^\n"
        "||s3.example.net^\n"
        "||keep.example.com^\n"
        "||gone.example.com^\n"
        "||gone.example.com^$badfilter\n"
        "@@||allow.example.com^\n"
        "||allow.example.com^\n",
        encoding="utf-8",
    )
    eng = AsyncRuleEngine(
        cache_dir=None,
        wildcard_promotion_threshold=2,
        conflict_resolution_enabled=True,
    )
    out = eng.run_sync([SourceMeta(name="s1", url=str(src), category="ads")])
    analysis = analyze_rules(out.blocks, out.allows)
    html = generate_html_report(out.blocks, out.allows, out, analysis, include_time=False)
    md = generate_markdown_report(out.blocks, out.allows, out, analysis, include_time=False)

    final = len(out.blocks) + len(out.allows)
    for text, is_html in ((html, True), (md, False)):
        rows = _funnel_counts(text, is_html)
        assert rows, "funnel rows not found"
        counts = [c for c, _ in rows]
        # monotonic non-increasing, ends at the real final count.
        assert counts[-1] == final, (counts, final)
        assert counts == sorted(counts, reverse=True)
        # Raw − every step reduction == final.
        reductions = sum(-int(d) for _, d in rows[1:] if d not in ("-", ""))
        assert counts[0] - reductions == final, (counts, rows, reductions)
