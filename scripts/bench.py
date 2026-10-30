"""Offline deterministic benchmark + byte-hash harness.

Runs the V8 pipeline over ``tests/fixtures/bench_rules/`` (pure local files,
no network, deterministic mode) and records:
  - median wall-clock over 3 runs
  - tracemalloc peak (one run)
  - sha256[:16] of every output file

Usage:
  python scripts/bench.py <out_dir> <label>
    -> prints/merges perf.json + hashes under release/bench/<label>/

This script NEVER mutates rule semantics; it only reads the fixture and
runs the public engine + exporter exactly as the CLI does in offline mode.
"""

from __future__ import annotations

import hashlib
import json
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from merger.config import MergeConfig
from merger.core import AsyncRuleEngine
from merger.exporter import Exporter
from merger.models import SourceMeta

FIXTURE = REPO / "tests" / "fixtures" / "bench_rules"
OUT_DIR = REPO / "release" / "bench"


def _sources() -> list[SourceMeta]:
    cats = {0: "ads", 1: "tracking", 2: "malware", 3: "other"}
    out = []
    for f in sorted(FIXTURE.glob("src_*.txt")):
        idx = int(f.name.split("_")[1])
        out.append(SourceMeta(name=f.stem, url=str(f), category=cats[idx]))
    return out


def run_once(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    cfg = MergeConfig()
    cfg.cache.enabled = False
    cfg.output.report_timestamp = False
    eng = AsyncRuleEngine(cache_dir=None)
    outcome = eng.run_sync(_sources())
    Exporter(
        str(out),
        tiered=True,
        report=True,
        write_diff=False,
        whitelist_output=cfg.whitelist_output,
        report_timestamp=False,
    ).export_all(outcome.blocks, outcome.allows, outcome)


def hashes(out: Path) -> dict:
    h = {}
    for p in sorted(out.rglob("*")):
        if p.is_file() and p.suffix not in (".tmp",):
            h[str(p.relative_to(out)).replace("\\", "/")] = hashlib.sha256(
                p.read_bytes()
            ).hexdigest()[:16]
    return h


def main() -> None:
    work = Path(sys.argv[1])
    label = sys.argv[2]
    target = OUT_DIR / label
    target.mkdir(parents=True, exist_ok=True)

    # 3 timed runs (warm-up excluded implicitly by median of 3).
    times = []
    for i in range(3):
        o = work / f"run{i}"
        t0 = time.perf_counter()
        run_once(o)
        times.append(time.perf_counter() - t0)
    median = statistics.median(times)

    # tracemalloc peak on a fresh run.
    tracemalloc.start()
    peak = 0
    try:
        run_once(work / "mem")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    peak_mb = peak / (1024 * 1024)

    h = hashes(work / "run0")
    (target / "curr_hashes.json").write_text(
        json.dumps(h, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )

    perf = {
        "label": label,
        "merge_wallclock_s_runs": [round(t, 4) for t in times],
        "merge_wallclock_s_median": round(median, 4),
        "tracemalloc_peak_mb": round(peak_mb, 2),
        "n_outputs": len(h),
    }
    (target / "perf.json").write_text(
        json.dumps(perf, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(perf, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
