"""Exercise Exporter.export_all and the per-format writers."""

from __future__ import annotations

from types import SimpleNamespace

from merger.exporter import Exporter
from merger.models import Rule


def _rule(domain: str, rule_type: str = "block") -> Rule:
    return Rule(
        raw=f"||{domain}^",
        domain=domain,
        rule_type=rule_type,
        wildcard=False,
        modifiers="",
        category="advertising",
        sources=("test",),
    )


def _outcome() -> SimpleNamespace:
    return SimpleNamespace(
        sources_ok=3, sources_total=3, sources_cached=1,
        raw_count=100, exact_merged=5, normalized_merged=2, regex_merged=1,
        aggregated=10, wildcard_aggregated=3, wildcard_promoted=1,
        conflict_resolved=2, conflicts=[],
        whitelist_blocked=0,
        pattern_dropped=0, quality_dropped=0, css_dropped=0,
        failed_sources=[], added=[], removed=[],
        content_version="cv1", elapsed=0.5,
        modifier_stats={"important": 1},
        contributions=[], source_overlap={"pairs": [], "source_effective": {}},
        whitelist_audit={"summary": {}, "rules": []},
        unrecognized_dropped=0, unsupported_modifier=0,
    )


def test_export_all_writes_files(tmp_path):
    blocks = [_rule("example.com"), _rule("ads.tracker.com")]
    allows = [_rule("allow.example.com", rule_type="allow")]
    ex = Exporter(tmp_path, report_timestamp=False)
    counts = ex.export_all(blocks, allows, _outcome())
    assert isinstance(counts, dict) or hasattr(counts, "items")
    # Key output files should exist
    for name in ["merged_rules.txt", "whitelist.txt"]:
        assert (tmp_path / name).exists(), f"{name} missing"


def test_write_stats(tmp_path):
    ex = Exporter(tmp_path, report_timestamp=False)
    blocks = [_rule("example.com")]
    ex.write_stats(blocks, [], _outcome())
    assert (tmp_path / "stats.json").exists()


def test_write_conflicts(tmp_path):
    ex = Exporter(tmp_path, report_timestamp=False)
    ex.write_conflicts([{
        "domain": "x.com", "blocked_rule": "||x.com", "blocked_sources": ["a"],
        "whitelist_rule": "@@||x.com", "whitelist_sources": ["b"], "conflict_type": "exact",
    }])
    assert (tmp_path / "conflicts.json").exists()


def test_write_contributions(tmp_path):
    ex = Exporter(tmp_path, report_timestamp=False)
    ex.write_contributions([{
        "name": "ad", "raw_rules": 100, "effective_rules": 90,
        "unique_rules": 40, "shared_rules": 50,
    }])
    assert (tmp_path / "contributions.json").exists()


def test_write_whitelist_audit(tmp_path):
    ex = Exporter(tmp_path, report_timestamp=False)
    out = _outcome()
    out.whitelist_audit = {"summary": {"total": 1}, "rules": [
        {"domain": "good.com", "rating": "safe", "category": "advertising",
         "category_confidence": 0.9, "risk_score": 0, "recommendation_label": "ok",
         "reason": "ok", "sources": ["test"]}
    ]}
    ex.write_whitelist_audit(out)
    assert (tmp_path / "whitelist_audit.json").exists()


def test_write_diff_files(tmp_path):
    ex = Exporter(tmp_path, report_timestamp=False, write_diff=True)
    out = _outcome()
    out.added = ["new.com"]
    out.removed = ["gone.com"]
    ex.write_diff_files(out)
    assert (tmp_path / "added.txt").exists()
    assert (tmp_path / "removed.txt").exists()


def test_write_report(tmp_path):
    ex = Exporter(tmp_path, report_timestamp=False)
    blocks = [_rule("example.com")]
    ex.write_report(blocks, [], _outcome())
    assert (tmp_path / "report.html").exists()
