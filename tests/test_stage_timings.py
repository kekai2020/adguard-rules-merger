"""Tests for per-stage timing collection and rendering."""

from __future__ import annotations

from merger.report.html import (
    _STAGE_ORDER,
    _format_stage_time,
    _render_stage_timing_rows,
)
from merger.report.markdown import (
    _format_stage_time_md,
    _render_stage_timings_md,
)


class TestFormatStageTime:
    def test_sub_millisecond_shown_as_microseconds(self):
        assert _format_stage_time(0.0005) == "500 µs"
        assert _format_stage_time_md(0.0005) == "500 µs"

    def test_one_millisecond_boundary(self):
        # Exactly 1ms should show as ms
        assert _format_stage_time(0.001) == "1.0 ms"
        assert _format_stage_time_md(0.001) == "1.0 ms"

    def test_larger_times_shown_as_milliseconds(self):
        assert _format_stage_time(0.5) == "500.0 ms"
        assert _format_stage_time_md(1.234) == "1234.0 ms"


class TestHtmlRenderStageTimings:
    def test_empty_dict_shows_empty_state(self):
        html = _render_stage_timing_rows({})
        assert "无阶段耗时数据" in html
        assert "<tr>" in html

    def test_known_renders_in_fixed_order(self):
        timings = {
            "fetch": 0.5,
            "sort": 0.01,
            "aggregation": 0.1,
        }
        html = _render_stage_timing_rows(timings)
        # Check order: fetch before aggregation before sort (fixed pipeline order)
        assert html.index("抓取/解析") < html.index("聚合") < html.index("排序")

    def test_unknown_key_appended_at_end(self):
        timings = {
            "fetch": 0.5,
            "custom_new_stage": 0.05,
        }
        html = _render_stage_timing_rows(timings)
        # known key first, unknown at end (before total row)
        assert html.index("抓取/解析") < html.index("custom_new_stage") < html.index("合计")

    def test_total_row_present(self):
        html = _render_stage_timing_rows({"fetch": 0.1})
        assert "合计" in html
        assert "100.0%" in html

    def test_adaptive_time_format_in_output(self):
        timings = {"fast_stage": 0.0005, "slow_stage": 0.5}
        html = _render_stage_timing_rows(timings)
        assert "500 µs" in html
        assert "500.0 ms" in html


class TestMarkdownRenderStageTimings:
    def test_empty_dict_returns_empty_list(self):
        lines = _render_stage_timings_md({})
        assert lines == []

    def test_table_structure(self):
        timings = {"fetch": 0.5, "sort": 0.01}
        lines = _render_stage_timings_md(timings)
        assert "### ⏱️ 各阶段执行耗时" in lines
        assert "| 流水线阶段 | 耗时 | 占比 |" in lines
        assert "|---|---:|---:|" in lines

    def test_renders_in_fixed_order(self):
        timings = {"sort": 0.01, "fetch": 0.5, "aggregation": 0.1}
        lines = _render_stage_timings_md(timings)
        # Find line indices
        fetch_idx = next(i for i, ln in enumerate(lines) if "抓取/解析" in ln)
        agg_idx = next(i for i, ln in enumerate(lines) if "聚合" in ln)
        sort_idx = next(i for i, ln in enumerate(lines) if "排序" in ln)
        assert fetch_idx < agg_idx < sort_idx

    def test_total_row(self):
        timings = {"fetch": 0.1}
        lines = _render_stage_timings_md(timings)
        total_line = next(ln for ln in lines if "合计" in ln)
        assert "100.0%" in total_line


class TestStageOrderConsistency:
    def test_html_and_md_use_same_stage_order(self):
        """Both HTML and Markdown should render stages in the same pipeline order."""
        # Import from both modules and compare
        from merger.report.html import _STAGE_ORDER as HTML_ORDER
        from merger.report.markdown import _STAGE_ORDER as MD_ORDER

        assert HTML_ORDER == MD_ORDER

    def test_all_labels_have_chinese_names(self):
        """Every stage in _STAGE_ORDER should have a Chinese label, not raw key."""
        for key, label in _STAGE_ORDER:
            assert label, f"Missing label for {key}"
            # Label should not be the raw English key
            assert label != key
