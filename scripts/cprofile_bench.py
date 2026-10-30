"""cProfile harness for bench."""
from __future__ import annotations

import cProfile
import pstats
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from merger.config import MergeConfig
from merger.core import AsyncRuleEngine
from merger.exporter import Exporter
from merger.models import SourceMeta

FIXTURE = REPO / "tests" / "fixtures" / "bench_rules"


def run():
    cats = {0: "ads", 1: "tracking", 2: "malware", 3: "other"}
    sources = []
    for i, p in enumerate(sorted(FIXTURE.glob("*.txt"))):
        sources.append(SourceMeta(name=p.stem, url=str(p), category=cats[i % 4]))
    engine = AsyncRuleEngine(cache_dir=None, aggregation_enabled=True,
                             wildcard_promotion_threshold=3)
    outcome = engine.run_sync(sources)
    out = REPO / "release" / "bench" / "profile"
    out.mkdir(parents=True, exist_ok=True)
    Exporter(out, report=False, write_diff=False).export_all(
        outcome.blocks, outcome.allows, outcome)


if __name__ == "__main__":
    pr = cProfile.Profile()
    pr.enable()
    run()
    pr.disable()
    st = pstats.Stats(pr)
    st.sort_stats("cumulative")
    st.print_stats(25)
