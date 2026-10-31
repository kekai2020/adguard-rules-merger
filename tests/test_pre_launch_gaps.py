"""Pre-launch coverage for the three audit-flagged gaps (side-chat round):
error classification, offline heuristics branches, CLI cache commands."""

from __future__ import annotations

import asyncio

import pytest
from typer.testing import CliRunner

from merger.cache import SourceCache
from merger.cli import app
from merger.core.outcome import classify_source_error
from merger.whitelist_audit.heuristics import local_heuristics, recycled_domain_clue


# ── classify_source_error: the substring taxonomy drives failed_sources diagnosis
def test_classify_source_error_taxonomy():
    assert classify_source_error(asyncio.TimeoutError()) == "timeout"
    assert classify_source_error("per-source deadline 120s exhausted") == "timeout"
    assert classify_source_error("HTTP 404 Not Found: u") == "not_found"
    assert classify_source_error("HTTP 403") == "auth"
    assert classify_source_error("HTTP 401") == "auth"
    assert classify_source_error("getaddrinfo failed") == "dns"
    assert classify_source_error("Name or service not known") == "dns"
    assert classify_source_error("connection refused") == "network"
    # substring precedence: "connect timeout" contains "timeout" first —
    # documents the classifier's known ambiguity rather than an ideal
    assert classify_source_error("connect timeout") == "timeout"
    assert classify_source_error("weird failure") == "unknown"


# ── local_heuristics: every flag branch (offline layer, default-on)
def test_heuristics_flag_branches():
    puny = local_heuristics("xn--e1afmkfd.example.com")
    assert "punycode/IDN" in puny["flags"]

    tld = local_heuristics("shop.example.xyz")
    assert any("可疑TLD" in f for f in tld["flags"])

    deep = local_heuristics(".".join(f"l{i}" for i in range(8)) + ".com")
    assert any("子域过深" in f for f in deep["flags"])

    long = local_heuristics("a" * 70 + ".com")
    assert any("域名过长" in f for f in long["flags"])

    digits = local_heuristics("a1234b.com")
    assert any("数字" in f for f in digits["flags"])

    homoglyph = local_heuristics("o1il.com")
    assert any("仿冒" in f for f in homoglyph["flags"])

    hyphens = local_heuristics("a-b-c-d.com")
    assert any("连字符" in f for f in hyphens["flags"])

    clean = local_heuristics("wikipedia.org")
    assert clean["is_risky"] is False and clean["score"] == 0


def test_recycled_domain_clue_combinations():
    # registrar present → never a recycled clue
    assert recycled_domain_clue({"registrar": "X"}, {"ips": ["1.1.1.1"]}) is False
    # new domain → excluded
    assert recycled_domain_clue({"is_new_domain": True}, {"ips": ["1.1.1.1"]}) is False
    # no registrar, not new, resolves → clue
    assert recycled_domain_clue({"registrar": None}, {"ips": ["1.1.1.1"]}) is True
    # does not resolve → no clue
    assert recycled_domain_clue({"registrar": None}, {"ips": []}) is False


# ── CLI cache commands (delete behavior deserves coverage)
@pytest.fixture()
def populated_cache(tmp_path):
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.store("https://s/l.txt", "body")
    c.save_if_dirty()  # CLI reads the on-disk index, not this instance
    return c


def test_cli_cache_stats_and_clear(tmp_path, populated_cache):
    runner = CliRunner()
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        f"cache:\n  directory: {tmp_path / 'cache'}\n"
        "sources:\n  - id: 1\n    url: https://s/l.txt\n    name: S\n    category: ads\n",
        encoding="utf-8",
    )

    stats = runner.invoke(app, ["cache", "stats", "--config", str(cfg)])
    assert stats.exit_code == 0
    assert "Cached source entries: 1" in stats.output

    cleared = runner.invoke(app, ["cache", "clear", "--config", str(cfg), "--yes"])
    assert cleared.exit_code == 0
    # CLI clear operates on the on-disk index via a fresh instance
    assert not (tmp_path / "cache" / "index.json").exists()

    after = runner.invoke(app, ["cache", "stats", "--config", str(cfg)])
    assert "Cached source entries: 0" in after.output


def test_cli_cache_clear_aborts_without_yes(tmp_path):
    runner = CliRunner()
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        f"cache:\n  directory: {tmp_path / 'cache'}\n"
        "sources:\n  - id: 1\n    url: https://s/l.txt\n    name: S\n    category: ads\n",
        encoding="utf-8",
    )
    (tmp_path / "cache").mkdir(parents=True, exist_ok=True)  # else CLI exits "not found"
    aborted = runner.invoke(app, ["cache", "clear", "--config", str(cfg)], input="n\n")
    assert aborted.exit_code == 0
    assert "Aborted" in aborted.output
