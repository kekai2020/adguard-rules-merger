"""P2 report-UX regression tests (offline, deterministic).

Guards the V7 report improvements:
  - Chinese category / rule-type legend in §三 (no raw machine keys).
  - Empty-state placeholder rows (contributions / self-dedup / suffix).
  - Whitelist-audit risk_score / recommendation_label / top_risky rendered.
  - ECharts offline guard and the docstring no longer claims self-contained.
  - MD failed sources promoted near the overview.
"""

from pathlib import Path
from types import SimpleNamespace

from merger.core import AsyncRuleEngine
from merger.models import SourceMeta
from merger.report import (
    analyze_rules,
    generate_html_report,
    generate_markdown_report,
)

SRC_TEXT = (
    "||ads.example.com^\n"
    "||track.example.com^\n"
    "||ads.example.com^\n"
    "||child.ads.example.com^\n"
    "@@||cdn.example.com^\n"
    "0.0.0.0 host.example.com\n"
)


def _outcome(tmp_path: Path):
    src = tmp_path / "source.txt"
    src.write_text(SRC_TEXT, encoding="utf-8")
    return AsyncRuleEngine(cache_dir=None).run_sync(
        [SourceMeta(name="s1", url=str(src), category="ads")]
    )


def _render(outcome):
    analysis = analyze_rules(outcome.blocks, outcome.allows)
    html = generate_html_report(
        outcome.blocks, outcome.allows, outcome, analysis, include_time=False
    )
    md = generate_markdown_report(
        outcome.blocks, outcome.allows, outcome, analysis, include_time=False
    )
    return html, md, analysis


# ── Chinese category / rule-type legend ──────────────────────────────


def test_md_category_labels_are_chinese(tmp_path):
    outcome = _outcome(tmp_path)
    _, md, _ = _render(outcome)
    # §三 renders Chinese labels for the block-category machine keys
    # (the single source in SRC_TEXT is category "ads").
    assert "| 广告 |" in md
    # raw machine keys should not appear as a category row label.
    assert "| ads |" not in md
    assert "| tracking |" not in md


def test_html_category_chart_labels_chinese(tmp_path):
    outcome = _outcome(tmp_path)
    html, _, _ = _render(outcome)
    assert "广告" in html
    assert "追踪" in html


# ── empty-state placeholders ──────────────────────────────────────────


def test_empty_contributions_show_placeholder(tmp_path):
    outcome = _outcome(tmp_path)
    # Force empty contribution views.
    outcome.contributions = []
    outcome.source_overlap = {"pairs": [], "source_effective": {}}
    _, md, _ = _render(outcome)
    assert "无数据" in md


def test_html_empty_tbody_has_placeholder(tmp_path):
    outcome = _outcome(tmp_path)
    outcome.contributions = []
    outcome.source_overlap = {"pairs": [], "source_effective": {}}
    html, _, _ = _render(outcome)
    assert "暂无数据" in html


# ── audit risk_score / recommendation / top_risky rendered ──────────


def _audit_outcome(outcome):
    outcome.whitelist_audit = {
        "summary": {
            "malicious": 1,
            "suspicious": 0,
            "safe": 0,
            "unknown": 0,
            "risk_score_buckets": {
                "high(>=50)": 1,
                "medium(20-49)": 0,
                "low(1-19)": 0,
                "none(0)": 0,
            },
            "top_risky": [
                {
                    "domain": "bad.example.com",
                    "rating": "malicious",
                    "risk_score": 80,
                    "reason": "urlhaus hit",
                }
            ],
        },
        "rules": [
            {
                "domain": "bad.example.com",
                "rating": "malicious",
                "category": "ads",
                "category_confidence": 0.95,
                "reason": "urlhaus hit",
                "sources": ["manual"],
                "risk_score": 80,
                "recommendation_label": "建议移除",
            }
        ],
    }
    return outcome


def test_md_renders_top_risky_and_recommendation(tmp_path):
    outcome = _audit_outcome(_outcome(tmp_path))
    _, md, _ = _render(outcome)
    assert "风险最高 Top 10" in md
    assert "bad.example.com" in md
    assert "建议移除" in md
    assert "风险分" in md


def test_html_renders_risk_score_column(tmp_path):
    outcome = _audit_outcome(_outcome(tmp_path))
    html, _, _ = _render(outcome)
    assert "建议动作" in html
    assert ">80<" in html
    assert "建议移除" in html


# ── ECharts offline guard ────────────────────────────────────────────


def test_html_self_contained_offline():
    import inspect

    from merger.report import html as html_mod

    src = inspect.getsource(html_mod.generate_html_report)
    # Doubao: the report is fully self-contained — no CDN, no chart library,
    # no guard script; the distribution charts are pure-CSS bars.
    assert "cdn.jsdelivr" not in src
    assert "echarts" not in src
    assert "self-contained" in html_mod.__doc__.lower()


# ── failed sources promoted near overview in MD ──────────────────────


def test_md_failed_sources_near_overview(tmp_path):
    outcome = _outcome(tmp_path)
    outcome.failed_sources = [{"name": "dead", "error": "timeout", "error_type": "timeout"}]
    _, md, _ = _render(outcome)
    # The failed-source callout appears right after the overview, before the
    # pipeline section — find its position relative to the two headings.
    ov = md.index("## 一、概览")
    fail = md.index("失败源")
    pipe = md.index("## 二、优化流水线")
    assert ov < fail < pipe
    assert "[timeout]" in md


def test_md_overview_shows_compression_delta(tmp_path):
    outcome = _outcome(tmp_path)
    _, md, _ = _render(outcome)
    assert "最终压缩" in md
    assert "→" in md
