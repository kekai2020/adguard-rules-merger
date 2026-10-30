"""P1-1: warm-start diff must normalize previous-output rule lines.

The previous ``merged_rules.txt`` / ``whitelist.txt`` are stored in AdGuard
syntax (``||domain^``, ``*.`` wildcards, ``$important``, ``@@`` allow marker).
The new-side set is built from ``Rule.normalized_domain`` bare keys.  Without
normalizing the old lines the two sets never overlap, so every warm run
reported "everything added + everything removed".  These tests lock that the
old symbolic lines fold onto the same bare domains the engine emits.
"""

from __future__ import annotations

from pathlib import Path

from merger.core import AsyncRuleEngine
from merger.core.stats import StatsMixin
from merger.models import SourceMeta

# ── unit: line normalization ─────────────────────────────────────────


def test_normalize_prev_line_strips_aghl_syntax():
    n = StatsMixin._normalize_prev_line
    assert n("||ads.com^") == "ads.com"
    assert n("||track.com^$important") == "track.com"
    assert n("||*.child.example.com^") == "child.example.com"
    assert n("@@||safe.com^") == "safe.com"
    assert n("||ADS.Example.COM^") == "ads.example.com"
    assert n("! a comment") == ""
    assert n("# also a comment") == ""
    assert n("") == ""
    assert n("   ") == ""


# ── integration: diff_against warm-start added/removed ──────────────


def _write_prev(d: Path):
    (d / "merged_rules.txt").write_text(
        "! previous run\n||ads.com^\n||track.com^$important\n||gone.com^\n",
        encoding="utf-8",
    )
    (d / "whitelist.txt").write_text(
        "@@||safe.com^\n@@||oldallow.com^\n",
        encoding="utf-8",
    )


def test_diff_against_warm_start_normalizes_old_lines(tmp_path):
    prev = tmp_path / "prev"
    prev.mkdir()
    _write_prev(prev)

    src = tmp_path / "list.txt"
    src.write_text(
        "||ads.com^\n||track.com^$important\n||new.com^\n@@||safe.com^\n@@||newallow.com^\n",
        encoding="utf-8",
    )

    eng = AsyncRuleEngine(cache_dir=None, diff_against=str(prev))
    out = eng.run_sync([SourceMeta(name="s1", url=str(src), category="ads")])

    # ads.com / track.com already existed -> NOT reported as added.
    assert out.added == ["new.com"], out.added
    # gone.com was dropped -> reported removed (and NOT a raw symbolic line).
    assert out.removed == ["gone.com"], out.removed
    # Allow side follows the same normalization.
    assert out.added_allows == ["newallow.com"], out.added_allows
    assert out.removed_allows == ["oldallow.com"], out.removed_allows


def test_diff_against_identical_runs_have_no_delta(tmp_path):
    prev = tmp_path / "prev"
    prev.mkdir()
    _write_prev(prev)
    # New run re-emits exactly the previous block/allow set (no new, no gone).
    src = tmp_path / "list.txt"
    src.write_text(
        "||ads.com^\n||track.com^$important\n@@||safe.com^\n",
        encoding="utf-8",
    )
    eng = AsyncRuleEngine(cache_dir=None, diff_against=str(prev))
    out = eng.run_sync([SourceMeta(name="s1", url=str(src), category="ads")])
    assert out.added == []
    assert out.removed == ["gone.com"]
    assert out.added_allows == []
    assert out.removed_allows == ["oldallow.com"]
