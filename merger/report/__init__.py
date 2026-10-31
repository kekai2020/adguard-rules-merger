"""``merger.report`` package: HTML + Markdown report rendering and analysis.

Backwards-compatible facade: every import path that worked against the old
flat ``merger/report.py`` keeps working (including test-visible privates).
"""

from .analysis import (
    DEFENSE_LAYERS,
    _build_matrix,
    _classify_rule,
    _defense_layer_rows,
    _dup_color,
    _dup_emoji,
    _dup_legend_html,
    _extract_suffix,
    _generation_label,
    _modifier_total,
    _overlap_heat_color,
    analyze_rules,
)
from .html import generate_html_report
from .markdown import generate_markdown_report
from .render import render_reports

__all__ = [
    "analyze_rules",
    "generate_html_report",
    "generate_markdown_report",
    "render_reports",
    "DEFENSE_LAYERS",
    "_build_matrix",
    "_defense_layer_rows",
    "_dup_color",
    "_dup_emoji",
    "_dup_legend_html",
    "_overlap_heat_color",
    "_modifier_total",
    "_generation_label",
    "_classify_rule",
    "_extract_suffix",
]
