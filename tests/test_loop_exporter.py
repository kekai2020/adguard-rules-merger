"""Deterministic exporter header: no cache-hit / time leak."""

from merger.exporter import Exporter


class Outcome:
    sources_ok = 3
    sources_total = 3
    sources_cached = 2
    sources_total = 3
    raw_count = 100
    exact_merged = 0
    normalized_merged = 0
    regex_merged = 0
    aggregated = 0
    wildcard_aggregated = 0
    wildcard_promoted = 0
    conflicts = []
    pattern_dropped = 0
    quality_dropped = 0
    css_dropped = 0
    failed_sources = []


def test_header_no_cache_hit_in_deterministic_mode(tmp_path):
    from collections import Counter

    ex = Exporter(tmp_path, report_timestamp=False)
    lines = ex._main_header([], [], Outcome(), Counter())
    body = "\n".join(lines)
    # cache-hit count must NOT leak in deterministic mode.
    assert "cached" not in body
