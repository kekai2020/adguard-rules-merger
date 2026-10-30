"""Cache coverage: save/load, expiry, content read errors, clear, parsed cache."""

from __future__ import annotations

import json
import time

import pytest

from merger.cache import SourceCache


def test_cache_save_load(tmp_path):
    c = SourceCache(cache_dir=tmp_path, ttl_seconds=3600)
    c.store("http://x/rules.txt", "||a.com^\n", content_hash="abc")
    c.save()
    # Reload from disk
    c2 = SourceCache(cache_dir=tmp_path, ttl_seconds=3600)
    assert c2.get_content("http://x/rules.txt") == "||a.com^\n"


def test_cache_expiry(tmp_path):
    c = SourceCache(cache_dir=tmp_path, ttl_seconds=1)
    c.store("http://x/rules.txt", "||a.com^\n", content_hash="abc")
    time.sleep(1.1)
    assert c.get_content("http://x/rules.txt") is None


def test_cache_corrupt_index(tmp_path):
    idx = tmp_path / "cache_index.json"
    idx.write_text("{not json", encoding="utf-8")
    c = SourceCache(cache_dir=tmp_path, ttl_seconds=3600)
    assert c.get_content("http://x/rules.txt") is None


def test_cache_clear(tmp_path):
    c = SourceCache(cache_dir=tmp_path, ttl_seconds=3600)
    c.store("http://x/rules.txt", "||a.com^\n", content_hash="abc")
    c.save()
    c.clear()
    assert c.get_content("http://x/rules.txt") is None


def test_cache_parsed_roundtrip(tmp_path):
    c = SourceCache(cache_dir=tmp_path, ttl_seconds=3600)
    c.store("http://x/rules.txt", "||a.com^\n", content_hash="deadbeef")
    c.store_parsed("deadbeef", [("||a.com^", {"important": 1})], counters={"important": 1})
    out = c.load_parsed("deadbeef")
    assert out is not None
    recs, counters = out
    assert recs[0][0] == "||a.com^"
    assert counters == {"important": 1}


def test_cache_parsed_missing(tmp_path):
    c = SourceCache(cache_dir=tmp_path, ttl_seconds=3600)
    assert c.load_parsed("nonexistent") is None
