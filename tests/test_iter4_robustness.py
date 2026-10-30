"""iter4 — robustness / fault-injection tests.

Feeds malformed / hostile / half-written inputs and asserts the pipeline degrades
gracefully (never crashes, never raises to the user). No behavior change.
"""

from __future__ import annotations

import json

import pytest

from merger.feed_cache import FeedCache
from merger.parser import RuleParser

# ── parser: hostile input must not crash ─────────────────────────────


@pytest.mark.parametrize(
    "blob",
    [
        b"\x00\x01\x02\x03 binary garbage \xff\xfe",
        "a" * 5000 + "\n",  # extremely long single line
        "||bad space .com^\n",
        "https://example.com/script.js\n",  # URL-layer -> dropped, not crash
        "##\n#@#\n#%#\n",  # CSS markers
        "||\n||^\n$important\n",  # empty anchors
        "0.0.0.0\n127.0.0.1\n",  # hosts without hostname
        "/unclosed regex\n",
        "\x7f\x81 mixed utf8 \xe2\x82\n",
    ],
)
def test_parser_survives_hostile_input(blob):
    p = RuleParser()
    text = blob.decode("utf-8", errors="replace") if isinstance(blob, bytes) else blob
    rules = p.parse_text(text, source="s", category="ads")
    # Must return (possibly empty) without raising.
    assert isinstance(rules, list)


def test_parser_counts_unrecognized_not_silent():
    p = RuleParser()
    p.parse_text("not a rule at all\n||good.example.com^\n", source="s")
    assert p.unrecognized_dropped >= 1


# ── feed cache: corrupt / missing ────────────────────────────────────


def test_feed_cache_corrupt_meta_returns_none(tmp_path):
    fc = FeedCache(str(tmp_path))
    h = fc.store_blob("feed", b"hello")
    assert h
    # Corrupt the meta json.
    (tmp_path / "feeds" / "feed.meta.json").write_text("{not json", encoding="utf-8")
    assert fc.load_blob("feed") is None


def test_feed_cache_missing_returns_none(tmp_path):
    fc = FeedCache(str(tmp_path))
    assert fc.load_blob("nope") is None


def test_feed_cache_atomic_write_leaves_no_tmp(tmp_path):
    fc = FeedCache(str(tmp_path))
    fc.store_blob("feed", b"data")
    leftovers = list((tmp_path / "feeds").glob("*.tmp-*"))
    assert leftovers == []


# ── disk cache: corrupt audit cache falls back ───────────────────────


def test_disk_cache_corrupt_json_falls_back(tmp_path):
    from merger.whitelist_audit.config import AuditConfig
    from merger.whitelist_audit.constants import AUDIT_CACHE_FILENAME
    from merger.whitelist_audit.disk_cache import _disk_cache_load

    cfg = AuditConfig(cache_results=True, cache_dir=str(tmp_path))
    (tmp_path / AUDIT_CACHE_FILENAME).write_text("{broken", encoding="utf-8")
    # Must not raise on a corrupt cache file.
    assert _disk_cache_load(cfg) == {}
