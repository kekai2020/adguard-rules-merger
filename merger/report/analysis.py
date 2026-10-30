"""Data preparation (``analyze_rules``) and shared report helpers.

Byte-stable helpers, the defense-layer catalog and the source-overlap matrix
builder are shared by the HTML and Markdown renderers. Moved verbatim during
the P1-3 package split; colors, thresholds and catalog wording are unchanged.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from ..models import Rule

# User-facing Chinese labels for the §三 rule-type / category tables. Machine
# keys come from sources.yaml (block categories: ads/malware/...) and from
# ``_classify_rule`` (domain/wildcard/regex/ip). Unmapped keys fall back to the
# raw machine key so custom categories still render.
REPORT_CATEGORY_LABELS = {
    "ads": "广告",
    "malware": "恶意",
    "tracking": "追踪",
    "phishing": "钓鱼",
    "mining": "挖矿",
    "other": "其他",
}
REPORT_RULETYPE_LABELS = {
    "domain": "普通域名",
    "wildcard": "通配符",
    "regex": "正则",
    "ip": "IP 地址",
}


def _cat_label(cat: str) -> str:
    return REPORT_CATEGORY_LABELS.get(cat, cat)


def _ruletype_label(t: str) -> str:
    return REPORT_RULETYPE_LABELS.get(t, t)


def _generation_label(include_time: bool) -> str:
    """Return the timestamp shown on reports.

    Honors the ``SOURCE_DATE_EPOCH`` reproducible-builds variable when set;
    returns an empty string in deterministic mode so the artifact is stable.
    """
    if not include_time:
        return ""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
        except (TypeError, ValueError):
            pass
    return datetime.now(tz=timezone.utc).isoformat()


def _classify_rule(rule: Rule) -> str:
    if rule.normalized_domain == "":
        return "regex"
    if rule.wildcard:
        return "wildcard"
    parts = rule.normalized_domain.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return "ip"
    return "domain"


def _extract_suffix(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) < 2:
        return domain
    second_level_cc = {"co", "com", "net", "org", "gov", "edu"}
    if len(parts) >= 3 and parts[-2] in second_level_cc and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def analyze_rules(blocks: list[Rule], allows: list[Rule]) -> dict[str, Any]:
    all_rules = blocks + allows
    type_counts = Counter(_classify_rule(r) for r in all_rules)
    # E-1: single pass over blocks for category, suffix and length (previously
    # two loops — cat_counts and the suffix/length walk — over the same list).
    cat_counts: Counter[str] = Counter()
    suffix_counts: Counter[str] = Counter()
    domain_lengths = []
    for r in blocks:
        cat_counts[r.category] += 1
        if r.normalized_domain:
            suffix_counts[_extract_suffix(r.normalized_domain)] += 1
            domain_lengths.append(len(r.normalized_domain))
    return {
        "rule_types": dict(type_counts),
        "categories": dict(cat_counts),
        "top_suffixes": suffix_counts.most_common(20),
        "allow_types": dict(Counter(_classify_rule(r) for r in allows)),
        "avg_domain_length": sum(domain_lengths) / len(domain_lengths) if domain_lengths else 0,
        "max_domain_length": max(domain_lengths) if domain_lengths else 0,
        "min_domain_length": min(domain_lengths) if domain_lengths else 0,
    }


def _json_for_script(data) -> str:
    """JSON safe to embed inside a ``<script>`` block.

    ``json.dumps`` escapes non-ASCII but not ``</script>``; a hostile domain
    label such as ``x</script><script>alert(1)</script>.com`` would otherwise
    terminate the script element and inject markup. Escaping every ``</``
    (JSON only ever produces it inside string values) neutralises this.
    E-2: U+2028/U+2029 are JS line terminators; ``json.dumps`` already escapes
    them to ``\\u2028``/``\\u2029`` via the default ``ensure_ascii=True``, but
    this guard keeps that invariant even if the default ever changes.
    """
    s = json.dumps(data).replace("</", "<\\/")
    return s.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


# ── shared helpers ────────────────────────────────────────────────


def _modifier_total(modifier_stats: dict[str, int]) -> int:
    return sum(modifier_stats.values())


def _overlap_heat_color(rate: float) -> str:
    """Return a background color for an overlap rate (0-100)."""
    if rate >= 80:
        return "#f8d7da"
    if rate >= 50:
        return "#fff3cd"
    if rate >= 20:
        return "#d1ecf1"
    return "#d4edda"


# ── V5.2 duplicate-rate heat scale (symmetric Jaccard) ─────────────


def _dup_color(rate: float) -> str:
    """Background color for a duplicate rate (Jaccard %, higher = redder)."""
    if rate < 20:
        return "#d9ead3"  # green — low duplication (incl. 0%)
    if rate < 50:
        return "#fff2cc"  # yellow
    if rate < 80:
        return "#f9cb9c"  # orange
    return "#e06666"  # red — high duplication


def _dup_emoji(rate: float) -> str:
    """Markdown-safe color marker for a duplicate rate."""
    if rate < 20:
        return "🟩"
    if rate < 50:
        return "🟨"
    if rate < 80:
        return "🟧"
    return "🟥"


def _dup_legend_html() -> str:
    return (
        '<span style="background:#e06666;padding:2px 8px;">≥80%</span> '
        '<span style="background:#f9cb9c;padding:2px 8px;">50–80%</span> '
        '<span style="background:#fff2cc;padding:2px 8px;">20–50%</span> '
        '<span style="background:#d9ead3;padding:2px 8px;">&lt;20%（含 0）</span>'
    )


# ── Defense layer catalog (single source of truth for HTML + MD) ──────────
# Row tuple: (enabled_key, name, description, cost, hit_keys, always_on,
# no_count). ``enabled_key=None`` marks an always-on built-in layer with no
# switch in ``layers_enabled``. ``hit_keys`` are summed from ``layer_hits``;
# an empty tuple means the layer has no independent counter (show "—").
# Order, names, descriptions and cost labels below are shared verbatim by
# the HTML table and the Markdown table so the two stay byte-aligned.
DEFENSE_LAYERS: list[tuple[str | None, str, str, str, tuple[str, ...], bool, bool]] = [
    (
        "dns",
        "DNS 解析",
        "NXDOMAIN/私有IP检测",
        "免费",
        ("dns_nxdomain", "dns_private_ip"),
        False,
        False,
    ),
    ("doh", "DoH 加密解析", "NextDNS 加密传输，失败回退系统DNS", "免费", (), False, True),
    ("urlhaus", "URLhaus", "恶意软件分发域名", "免费", ("urlhaus",), False, False),
    ("threatfox", "ThreatFox", "C2 命令控制域名", "免费", ("threatfox",), False, False),
    ("rdap", "RDAP 域名年龄", "新注册<30天标记", "免费", ("rdap_new_domain",), False, False),
    (
        "scam_check",
        "MarketNow 诈骗检测",
        "拼写劫持/可疑TLD/未注册",
        "免费",
        ("scam_check",),
        False,
        False,
    ),
    (
        "dnsbl",
        "DNSBL 黑名单",
        "Spamhaus DBL + SURBL",
        "免费",
        ("dnsbl_malicious", "dnsbl_listed"),
        False,
        False,
    ),
    ("virustotal", "VirusTotal", "多引擎厂商信誉", "需API Key", ("virustotal",), False, False),
    ("ai", "AI/LLM 分类", "低置信语义分类", "需API Key", ("ai_classified",), False, False),
    (
        None,
        "内置离线启发式",
        "滥用TLD/连字符等（常驻，无开关键）",
        "免费",
        ("heuristics",),
        True,
        False,
    ),
    (
        "homograph",
        "同形字/拼写劫持",
        "Cyrillic/Greek 折叠+编辑距离",
        "免费·默认开",
        ("homograph",),
        False,
        False,
    ),
    ("dns_mx", "MX/SPF 缺失线索", "需 DNS，默认关", "可选", ("dns_mx_missing",), False, False),
    ("gsb", "Google Safe Browsing", "在线情报", "需API Key", ("gsb",), False, False),
    ("phishtank", "PhishTank", "钓鱼库", "需API Key", ("phishtank",), False, False),
    ("urlscan", "urlscan 沙箱", "可疑页面扫描", "需API Key(可选)", ("urlscan",), False, False),
    ("crtsh", "证书透明度 CT", "接口预留，默认关", "可选", (), False, True),
]


def _defense_layer_rows(layers_enabled: dict, layer_hits: dict) -> list[dict[str, Any]]:
    """Render the shared defense-layer rows from ``layers_enabled`` / ``layer_hits``.

    Presentation only: no statistic is recomputed here; ``dns`` aggregates
    ``dns_nxdomain`` + ``dns_private_ip``, ``dnsbl`` aggregates
    ``dnsbl_malicious`` + ``dnsbl_listed``, ``doh``/``crtsh`` have no
    independent counter, and ``heuristics`` is always on.
    """
    rows: list[dict[str, Any]] = []
    for key, name, desc, cost, hit_keys, always_on, no_count in DEFENSE_LAYERS:
        enabled = True if always_on else bool(layers_enabled.get(key, False))
        if no_count:
            hits_display = "—"
        elif enabled:
            hits_display = str(sum(layer_hits.get(hk, 0) for hk in hit_keys))
        else:
            hits_display = "-"
        rows.append(
            {
                "name": name,
                "desc": desc,
                "cost": cost,
                "enabled": enabled,
                "status": "✅ 启用" if enabled else "⬜ 未启用",
                "status_cls": "tag-green" if enabled else "tag-blue",
                "hits": hits_display,
            }
        )
    return rows


def _build_matrix(source_overlap: dict[str, Any]) -> dict[str, Any]:
    """Return {order, effective, get(a,b)->cell}. Builds from the pairwise
    matrix when present, falling back to the flat pairs list (V5.0 stats)."""
    mtx = source_overlap.get("matrix") or {}
    order = mtx.get("order") or list((source_overlap.get("source_effective") or {}).keys())
    effective = mtx.get("effective") or source_overlap.get("source_effective") or {}
    cells: dict[str, dict[str, Any]] = mtx.get("cells") or {}
    if not cells:
        pos = {name: i for i, name in enumerate(order)}
        for p in source_overlap.get("pairs") or []:
            a, b = p["source_a"], p["source_b"]
            if pos.get(a, -1) > pos.get(b, -1):
                a, b = b, a
            ea = effective.get(a, 0)
            eb = effective.get(b, 0)
            union = ea + eb - p["overlap"]
            cells.setdefault(a, {})[b] = {
                "overlap": p["overlap"],
                "jaccard": p.get("jaccard")
                or (round(p["overlap"] / union * 100, 1) if union else 0.0),
                "rate_a": p["rate_a"] if p["source_a"] == a else p["rate_b"],
                "rate_b": p["rate_b"] if p["source_a"] == a else p["rate_a"],
            }

    def get(a: str, b: str):
        if a == b:
            return None
        # cells are stored upper-triangular (smaller pos → larger pos), but
        # fall back to the mirrored key so the matrix is always symmetric.
        cell = cells.get(a, {}).get(b)
        if cell is None:
            cell = cells.get(b, {}).get(a)
        return cell

    return {"order": order, "effective": effective, "get": get}
