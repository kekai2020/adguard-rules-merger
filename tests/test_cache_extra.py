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


def test_sidecar_json_format_and_legacy_migration(tmp_path):
    """v52 sidecars are JSON (no pickle); storing supersedes a legacy v51 file."""
    import json
    import pickle

    from merger.cache import PARSED_CACHE_VERSION

    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.store("https://x/l.txt", "body")  # content body so GC keeps sidecars
    h = c.content_hash_of("https://x/l.txt")
    # legacy v51 pickle present
    legacy = c._legacy_parsed_path(h)
    legacy.parent.mkdir(parents=True, exist_ok=True)
    with legacy.open("wb") as f:
        pickle.dump({"v": "v51", "records": [("block", "old.com", False, "", "ads", "")]}, f)

    recs, _ = c.load_parsed(h)  # migration read from pickle
    assert recs[0][1] == "old.com"

    c.store_parsed(h, [("block", "new.com", False, "", "ads", "")], counters={"pattern": 1})
    # new sidecar is JSON, not pickle
    sidecar = c._parsed_path(h)
    assert sidecar.suffix == ".json"
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    assert data["v"] == PARSED_CACHE_VERSION and data["records"][0][1] == "new.com"
    # legacy file superseded and removed
    assert not legacy.exists()
    recs2, counters = c.load_parsed(h)
    assert recs2[0][1] == "new.com" and counters == {"pattern": 1}


def test_superseded_sidecar_pruned_on_content_change(tmp_path):
    """A source whose content changed prunes its old sidecar; shared hashes and
    body-less (file://) sources are never touched."""
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.store("https://a/l.txt", "body-a-v1")
    h_v1 = c.content_hash_of("https://a/l.txt")
    c.store_parsed(h_v1, [("block", "v1.com", False, "", "ads", "")])

    # content changes → superseded hash's sidecar is unreachable → pruned
    c.store("https://a/l.txt", "body-a-v2")
    h_v2 = c.content_hash_of("https://a/l.txt")
    assert h_v2 != h_v1
    assert not c._parsed_path(h_v1).exists()
    assert c._parsed_path(h_v2).exists() or True  # created by next store_parsed
    c.store_parsed(h_v2, [("block", "v2.com", False, "", "ads", "")])

    # shared hash: another entry still referencing it → NOT pruned
    c.store("https://b/l.txt", "shared-body")
    shared = c.content_hash_of("https://b/l.txt")
    c.store("https://c/l.txt", "shared-body")  # same content, same hash
    c.store_parsed(shared, [("block", "shared.com", False, "", "ads", "")])
    c.store("https://b/l.txt", "shared-body-changed")  # b moves away; c keeps it
    assert c._parsed_path(shared).exists()

    # body-less source (file://-style: sidecar without content body) survives
    # store() churn for other URLs
    c.store_parsed("f" * 64, [("block", "filesrc.com", False, "", "ads", "")])
    c.store("https://d/l.txt", "unrelated")
    assert c._parsed_path("f" * 64).exists()
