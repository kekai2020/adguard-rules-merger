"""Offline tests for the DoH config wiring and the aligned defense-layer report.

No network: the real ``config/sources.yaml`` is read from disk only, and the
report is rendered from a fabricated ``outcome`` / ``analysis`` carrying fake
``layers_enabled`` / ``layer_hits`` data.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from merger.config import MergeConfig, WhitelistAuditConfig, load_config
from merger.report import (
    DEFENSE_LAYERS,
    analyze_rules,
    generate_html_report,
    generate_markdown_report,
)
from merger.whitelist_audit import AuditConfig

REPO_ROOT = Path(__file__).resolve().parent.parent
NEXTDNS = "https://dns.nextdns.io/3fef68"


# ── DoH config parsing (programmatic + dict, no network) ──────────────


def test_doh_config_accepts_nextdns_endpoint_kwarg():
    cfg = WhitelistAuditConfig(doh_endpoint=NEXTDNS)
    assert cfg.doh_endpoint == NEXTDNS


def test_doh_config_accepts_endpoint_from_dict():
    cfg = WhitelistAuditConfig(**{"doh_endpoint": NEXTDNS})
    assert cfg.doh_endpoint == NEXTDNS


def test_doh_defaults_to_empty_and_rejects_non_http():
    assert WhitelistAuditConfig().doh_endpoint == ""
    assert WhitelistAuditConfig(**{"doh_endpoint": ""}).doh_endpoint == ""
    with pytest.raises(Exception, match="http"):
        WhitelistAuditConfig(doh_endpoint="dns.nextdns.io/3fef68")


def test_audit_dataclass_accepts_doh_endpoint():
    cfg = AuditConfig(doh_endpoint=NEXTDNS)
    assert cfg.doh_endpoint == NEXTDNS


def test_real_sources_yaml_sets_doh_and_keeps_other_switches():
    cfg: MergeConfig = load_config(str(REPO_ROOT / "config" / "sources.yaml"))
    wa = cfg.whitelist_audit
    # The single permitted change: DoH endpoint populated.
    assert wa.doh_endpoint == NEXTDNS
    # Every other switch keeps its shipped default (default-off / keyed layers
    # must not be flipped by this edit).
    assert wa.use_dns is True
    assert wa.use_urlhaus is True
    assert wa.use_threatfox is True
    assert wa.use_rdap is True
    assert wa.use_scam_check is True
    assert wa.use_dnsbl is True
    assert wa.use_heuristics is True
    assert wa.use_homograph is True
    assert wa.use_virustotal is False
    assert wa.ai.enabled is False
    assert wa.use_gsb is False
    assert wa.use_phishtank is False
    assert wa.use_urlscan is False
    assert wa.use_crtsh is False
    assert wa.use_dns_mx is False


# ── fabricated outcome / analysis ─────────────────────────────────────


def _fake_outcome() -> SimpleNamespace:
    summary = {
        "malicious": 1,
        "suspicious": 2,
        "safe": 3,
        "unknown": 0,
        "layers_enabled": {
            "dns": True,
            "doh": True,
            "urlhaus": True,
            "threatfox": True,
            "rdap": True,
            "scam_check": True,
            "dnsbl": True,
            "virustotal": False,
            "ai": False,
            "homograph": True,
            "dns_mx": False,
            "gsb": False,
            "phishtank": False,
            "urlscan": False,
            "crtsh": False,
        },
        "layer_hits": {
            "dns_nxdomain": 4,
            "dns_private_ip": 1,
            "urlhaus": 2,
            "threatfox": 1,
            "rdap_new_domain": 3,
            "scam_check": 2,
            "virustotal": 0,
            "ai_classified": 0,
            "heuristics": 5,
            "dnsbl_malicious": 2,
            "dnsbl_listed": 3,
            "homograph": 1,
            "dns_mx_missing": 0,
            "gsb": 0,
            "phishtank": 0,
            "urlscan": 0,
        },
    }
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
        whitelist_audit={"summary": summary, "rules": []},
        content_version="test1234",
        elapsed=1.0,
    )


def _render():
    outcome = _fake_outcome()
    analysis = analyze_rules([], [])
    html = generate_html_report([], [], outcome, analysis, include_time=False)
    md = generate_markdown_report([], [], outcome, analysis, include_time=False)
    return html, md


# ── layer presence / order / aggregation ──────────────────────────────


def _layer_regions():
    """Slice out just the defense-layer table from both reports so names that
    also appear in the audit intro paragraph do not skew row/order matching."""
    html, md = _render()
    h_start = html.index("防御层概览")
    h_region = html[h_start : html.index("</table>", h_start)]
    m_block: list[str] = []
    for line in md[md.index("### 防御层概览") :].splitlines():
        if line.startswith("|"):
            m_block.append(line)
        elif m_block:
            break
    m_region = "\n".join(m_block)
    return h_region, m_region


def test_all_layer_names_present_in_html_and_md():
    h_region, m_region = _layer_regions()
    for _key, name, _desc, _cost, _hits, _always, _no_count in DEFENSE_LAYERS:
        assert name in h_region, f"HTML missing layer: {name}"
        assert name in m_region, f"MD missing layer: {name}"


def test_html_and_md_share_layer_order():
    h_region, m_region = _layer_regions()
    positions_h: list[int] = []
    positions_m: list[int] = []
    for _key, name, _desc, _cost, _hits, _always, _no_count in DEFENSE_LAYERS:
        positions_h.append(h_region.index(name))
        positions_m.append(m_region.index(name))
    assert positions_h == sorted(positions_h)
    assert positions_m == sorted(positions_m)


def _html_row(h_region: str, name: str) -> str:
    for row in h_region.split("<tr>"):
        if name in row:
            return row
    raise AssertionError(f"HTML row not found: {name}")


def _md_row(m_region: str, name: str) -> str:
    for line in m_region.splitlines():
        if line.startswith("|") and name in line:
            return line
    raise AssertionError(f"MD row not found: {name}")


def test_dns_and_dnsbl_hits_are_aggregated():
    h_region, m_region = _layer_regions()
    # dns = dns_nxdomain(4) + dns_private_ip(1) = 5
    assert ">5<" in _html_row(h_region, "DNS 解析")
    assert "| 5 |" in _md_row(m_region, "DNS 解析")
    # dnsbl = dnsbl_malicious(2) + dnsbl_listed(3) = 5
    assert ">5<" in _html_row(h_region, "DNSBL 黑名单")
    assert "| 5 |" in _md_row(m_region, "DNSBL 黑名单")
    # heuristics always-on, direct counter
    assert ">5<" in _html_row(h_region, "内置离线启发式")
    assert "| 5 |" in _md_row(m_region, "内置离线启发式")
    # homograph direct counter
    assert ">1<" in _html_row(h_region, "同形字/拼写劫持")
    assert "| 1 |" in _md_row(m_region, "同形字/拼写劫持")


def test_disabled_layers_show_dash_and_countless_layers_show_em_dash():
    h_region, m_region = _layer_regions()
    # Default-off / keyed layers: status 未启用, hit cell "-"
    for name in (
        "VirusTotal",
        "AI/LLM 分类",
        "MX/SPF 缺失线索",
        "Google Safe Browsing",
        "PhishTank",
        "urlscan 沙箱",
    ):
        hrow = _html_row(h_region, name)
        mrow = _md_row(m_region, name)
        assert "⬜ 未启用" in hrow
        assert "⬜ 未启用" in mrow
        assert "class='num'>-</td>" in hrow
        assert mrow.rstrip().endswith("| - |")
    # doh / crtsh have no independent counter → "—"
    for name in ("DoH 加密解析", "证书透明度 CT"):
        assert "—" in _html_row(h_region, name)
        assert "—" in _md_row(m_region, name)


def test_report_byte_stable_without_timestamp():
    (h1, m1), (h2, m2) = _render(), _render()
    assert h1 == h2
    assert m1 == m2
    # Deterministic mode must not embed a calendar date.
    assert not re.search(r"\d{4}-\d{2}-\d{2}", h1)
    assert not re.search(r"\d{4}-\d{2}-\d{2}", m1)


def test_html_has_static_toc_and_section_numbers():
    html, _md = _render()
    assert 'class="toc"' in html
    assert "报告目录" in html
    # Section kickers 02..13 are static markers.
    for n in ("02", "05", "11", "13"):
        assert f'sec-no">{n}<' in html
