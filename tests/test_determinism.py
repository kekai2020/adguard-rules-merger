"""M0 determinism guard: identical inputs must produce byte-identical output.

Two consecutive ``run_sync`` + ``export_all`` runs over the same local source
must yield the same ``merged_rules.txt`` / ``hosts.txt`` / ``domains.txt``
bytes, with no wall-clock timestamp leaking into the rule files.
"""

import hashlib

from merger import AsyncRuleEngine, Exporter
from merger.models import SourceMeta


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(tmp_path, tag, source_path):
    engine = AsyncRuleEngine(cache_dir=None)
    sources = [SourceMeta(name="s1", url=str(source_path), category="ads")]
    outcome = engine.run_sync(sources)
    out = tmp_path / tag
    Exporter(out, report=False, write_diff=False).export_all(
        outcome.blocks, outcome.allows, outcome
    )
    return outcome


def test_deterministic_rule_files(tmp_path):
    src = tmp_path / "source1.txt"
    src.write_text(
        "||ads.example.com^\n"
        "||track.example.com^\n"
        "||ads.example.com^\n"  # exact duplicate
        "0.0.0.0 host.example.com\n"
        "@@||allow.example.com^\n"
        "||child.ads.example.com^\n",  # folded into ads.example.com
        encoding="utf-8",
    )

    o1 = _run(tmp_path, "run1", src)
    o2 = _run(tmp_path, "run2", src)

    assert o1.content_version == o2.content_version
    for name in ("merged_rules.txt", "hosts.txt", "domains.txt"):
        h1 = _sha256(tmp_path / "run1" / name)
        h2 = _sha256(tmp_path / "run2" / name)
        assert h1 == h2, f"{name} diverged between runs"

    merged = (tmp_path / "run1" / "merged_rules.txt").read_text(encoding="utf-8")
    assert "Generated:" not in merged
