"""V5.3 integration test — end-to-end pipeline with local file sources.

Covers: parse → dedup → aggregate → conflict → export, asserting that
statistics fields are self-consistent and output files are produced.
Uses tmp_path isolation; never touches real cache/ or output/.
"""

import hashlib

import pytest

from merger import AsyncRuleEngine, Exporter
from merger.models import SourceMeta

SRC_TEXT = (
    "||ads.example.com^\n"
    "||track.example.com^\n"
    "||ads.example.com^\n"
    "||child.ads.example.com^\n"
    "0.0.0.0 host.example.com\n"
    "@@||allow.example.com^\n"
    "@@||ads.example.com^\n"
    "||cdn1.static.example.com^\n"
    "||cdn2.static.example.com^\n"
    "||cdn3.static.example.com^\n"
    "# comment line\n"
    "/^192\\.168\\.\\d+\\.\\d+$/\n"
)


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_full_pipeline_stats_self_consistent(tmp_path):
    src = tmp_path / "source.txt"
    src.write_text(SRC_TEXT, encoding="utf-8")

    engine = AsyncRuleEngine(
        cache_dir=None,
        aggregation_enabled=True,
        wildcard_promotion_threshold=2,
    )
    sources = [SourceMeta(name="s1", url=str(src), category="ads")]
    outcome = engine.run_sync(sources)

    assert outcome.sources_total == 1
    assert outcome.sources_ok == 1
    assert outcome.raw_count > 0
    assert outcome.exact_merged > 0 or outcome.normalized_merged > 0
    assert len(outcome.blocks) > 0
    assert len(outcome.allows) >= 1

    out = tmp_path / "output"
    Exporter(out, report=False, write_diff=False).export_all(
        outcome.blocks, outcome.allows, outcome
    )

    merged = (out / "merged_rules.txt").read_text(encoding="utf-8")
    assert "*.example.com" in merged
    assert "Generated:" not in merged
    for name in ("merged_rules.txt", "hosts.txt", "domains.txt"):
        assert (out / name).exists()


def test_determinism_across_runs(tmp_path):
    src = tmp_path / "source.txt"
    src.write_text(SRC_TEXT, encoding="utf-8")
    sources = [SourceMeta(name="s1", url=str(src), category="ads")]

    hashes = {}
    for tag in ("run1", "run2"):
        engine = AsyncRuleEngine(cache_dir=None)
        outcome = engine.run_sync(sources)
        out = tmp_path / tag
        Exporter(out, report=False, write_diff=False).export_all(
            outcome.blocks, outcome.allows, outcome
        )
        for name in ("merged_rules.txt", "hosts.txt", "domains.txt"):
            hashes[(tag, name)] = _sha256(out / name)

    for name in ("merged_rules.txt", "hosts.txt", "domains.txt"):
        assert hashes[("run1", name)] == hashes[("run2", name)], f"{name} diverged between runs"


def test_multiple_sources_merged(tmp_path):
    src1 = tmp_path / "s1.txt"
    src2 = tmp_path / "s2.txt"
    src1.write_text("||a.example.com^\n||b.example.com^\n", encoding="utf-8")
    src2.write_text("||b.example.com^\n||c.example.com^\n", encoding="utf-8")

    engine = AsyncRuleEngine(cache_dir=None)
    sources = [
        SourceMeta(name="s1", url=str(src1), category="ads"),
        SourceMeta(name="s2", url=str(src2), category="tracking"),
    ]
    outcome = engine.run_sync(sources)

    assert outcome.sources_ok == 2
    domains = {r.normalized_domain for r in outcome.blocks}
    assert "a.example.com" in domains
    assert "b.example.com" in domains
    assert "c.example.com" in domains
    assert outcome.exact_merged + outcome.normalized_merged >= 1


def test_allow_keeps_block_and_records_conflict(tmp_path):
    src = tmp_path / "source.txt"
    src.write_text("||example.com^\n@@||example.com^\n", encoding="utf-8")
    sources = [SourceMeta(name="s1", url=str(src), category="ads")]
    engine = AsyncRuleEngine(cache_dir=None, conflict_resolution_enabled=True)
    outcome = engine.run_sync(sources)
    block_domains = {r.normalized_domain for r in outcome.blocks}
    # V7 policy: the block rule is KEPT, only the overlap is recorded.
    assert "example.com" in block_domains
    assert len(outcome.conflicts) == 1
    assert outcome.conflicts[0]["action"] == "kept_block"


@pytest.mark.slow
def test_slow_performance_baseline(tmp_path):
    """Optional slow benchmark — run with: uv run pytest -m slow"""
    lines = [f"||domain{i}.example.com^" for i in range(5000)]
    src = tmp_path / "big.txt"
    src.write_text("\n".join(lines), encoding="utf-8")
    sources = [SourceMeta(name="big", url=str(src), category="ads")]
    engine = AsyncRuleEngine(cache_dir=None)
    outcome = engine.run_sync(sources)
    assert len(outcome.blocks) == 5000
