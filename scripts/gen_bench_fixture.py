"""Deterministic offline benchmark fixture generator.

Materialises ~50k local rule files under ``tests/fixtures/bench_rules/``.
Pure local files, no network, no time/randomness dependence — every run
produces byte-identical fixtures (a fixed PRNG seed). The fixtures exercise:
  - exact / wildcard / regex rules
  - cross-source duplicates (dedup)
  - aggregatable parent/child chains
  - block+allow conflicts (whitelist override)
  - $important / $badfilter modifiers
  - hosts-format lines and comments
  - multiple categories (ads / tracking / malware / other)

Usage: uv run python scripts/gen_bench_fixture.py
"""

from __future__ import annotations

import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "fixtures" / "bench_rules"

CATEGORIES = ["ads", "tracking", "malware", "other"]


def _domain(i: int) -> str:
    # Deterministic pseudo-domain in a fixed pseudo-TLD namespace.
    return f"d{i:06d}.example"


def build_source(name: str, category: str, rng: random.Random, n: int, dup_pool: list[str]) -> str:
    lines: list[str] = [f"! {name} — deterministic benchmark fixture ({category})"]
    for i in range(n):
        kind = rng.random()
        d = _domain(rng.randrange(0, 60000))
        if kind < 0.10:
            # wildcard rule
            lines.append(f"||*.{d}^")
        elif kind < 0.13:
            # regex rule
            lines.append(f"/(ad|track)-{rng.randrange(0, 9999)}-[a-z]{{2}}/")
        elif kind < 0.18:
            # hosts-format line
            lines.append(f"0.0.0.0 {d}")
        elif kind < 0.22:
            # allow rule (@@) — some conflict with a later block
            lines.append(f"@@||{d}^")
        elif kind < 0.27:
            # $important block (must skip dedup-by-other-modifier)
            lines.append(f"||{d}^$important")
        elif kind < 0.31:
            # $badfilter cancels another rule
            lines.append(f"||{d}^$badfilter")
        else:
            # plain exact block
            lines.append(f"||{d}^")
        # sprinkle cross-source duplicates from a shared pool
        if rng.random() < 0.12:
            lines.append(f"||{rng.choice(dup_pool)}^")
    return "\n".join(lines) + "\n"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20261026)
    # Shared duplicate pool referenced across all sources.
    dup_pool = [_domain(i) for i in range(0, 50000, 7)]
    per_source = 12500
    total = 0
    for idx, cat in enumerate(CATEGORIES):
        text = build_source(f"bench_{cat}_{idx}", cat, rng, per_source, dup_pool)
        (OUT / f"src_{idx}_{cat}.txt").write_text(text, encoding="utf-8")
        total += text.count("\n")
    print(f"wrote {len(CATEGORIES)} sources, ~{total} lines -> {OUT}")


if __name__ == "__main__":
    main()
