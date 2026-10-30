"""R5 independent report rendering stage.

Orchestration (the CLI) calls :func:`render_reports` to turn the merged
``blocks`` / ``allows`` into final HTML + Markdown strings; the disk-writing
:class:`merger.exporter.Exporter` only persists the produced bytes. This module
performs analysis once and renders both views — it owns no IO, no filesystem
writes and no wall-clock decisions beyond honoring ``include_time``.
"""

from __future__ import annotations

from typing import Any

from .analysis import analyze_rules
from .html import generate_html_report
from .markdown import generate_markdown_report


def render_reports(
    blocks: list[Any],
    allows: list[Any],
    outcome: Any,
    include_time: bool = False,
) -> tuple[str, str]:
    """Analyze once, render HTML + Markdown, return ``(html, markdown)``.

    The analysis dict is computed exactly once and shared by both renderers, so
    the HTML dashboard and the Markdown report always describe the same rule
    set. ``include_time`` is forwarded unchanged; in deterministic mode
    (``False``) neither view embeds a wall-clock stamp.
    """
    analysis = analyze_rules(blocks, allows)
    html = generate_html_report(blocks, allows, outcome, analysis, include_time=include_time)
    markdown = generate_markdown_report(
        blocks, allows, outcome, analysis, include_time=include_time
    )
    return html, markdown
