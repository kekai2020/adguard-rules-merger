"""Exercise engine branches: badfilter, diff_against, aggregation."""

from __future__ import annotations

import pytest

from merger import AsyncRuleEngine
from merger.models import SourceMeta


def test_badfilter_cancellation(tmp_path):
    src = tmp_path / "s.txt"
    src.write_text(
        "||ads.example.com^\n"
        "||ads.example.com$badfilter\n"
        "||track.example.com^\n",
        encoding="utf-8",
    )
    engine = AsyncRuleEngine(cache_dir=None)
    out = engine.run_sync([SourceMeta(name="s", url=str(src), category="ads")])
    # The badfilter line cancels the earlier block.
    assert out.badfilter_removed >= 1


def test_diff_against_prev(tmp_path):
    prev = tmp_path / "prev"
    prev.mkdir()
    (prev / "merged_rules.txt").write_text("||old.example.com^\n", encoding="utf-8")
    src = tmp_path / "s.txt"
    src.write_text("||new.example.com^\n", encoding="utf-8")
    engine = AsyncRuleEngine(cache_dir=None, diff_against=str(prev))
    out = engine.run_sync([SourceMeta(name="s", url=str(src), category="ads")])
    assert "new.example.com" in out.added
    assert "old.example.com" in out.removed


def test_aggregation_wildcard(tmp_path):
    src = tmp_path / "s.txt"
    src.write_text(
        "||cdn1.static.example.com^\n"
        "||cdn2.static.example.com^\n"
        "||cdn3.static.example.com^\n"
        "||cdn4.static.example.com^\n",
        encoding="utf-8",
    )
    engine = AsyncRuleEngine(cache_dir=None, wildcard_promotion_threshold=2)
    out = engine.run_sync([SourceMeta(name="s", url=str(src), category="ads")])
    # Should have promoted a wildcard parent.
    assert out.wildcard_promoted >= 1 or out.aggregated >= 1


def test_conflict_keeps_block(tmp_path):
    src = tmp_path / "s.txt"
    src.write_text("||example.com^\n@@||example.com^\n", encoding="utf-8")
    engine = AsyncRuleEngine(cache_dir=None, conflict_resolution_enabled=True)
    out = engine.run_sync([SourceMeta(name="s", url=str(src), category="ads")])
    assert len(out.conflicts) == 1
