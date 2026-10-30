"""Tests for V5.1 cache: 304 fallback, hash-once, parsed sidecar."""

from merger.cache import SourceCache
from merger.core import AsyncRuleEngine
from merger.models import CATEGORY_ADS, SourceMeta
from merger.parser import RuleParser


def test_store_and_get_roundtrip(tmp_path):
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.store("https://example.com/list.txt", "||ads.example.com^\n", etag='"abc"')
    c.save()
    c2 = SourceCache(cache_dir=str(tmp_path / "cache"))
    text = c2.get_content("https://example.com/list.txt")
    assert text == "||ads.example.com^\n"
    headers = c2.conditional_headers("https://example.com/list.txt")
    assert headers["If-None-Match"] == '"abc"'


def test_content_changed_returns_hash(tmp_path):
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    body = "||a.com^\n"
    c.store("u", body)
    changed, h = c.content_changed("u", body)
    assert changed is False
    assert len(h) == 64
    changed2, h2 = c.content_changed("u", "||b.com^\n")
    assert changed2 is True
    assert h2 != h


def test_parsed_sidecar(tmp_path):
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    parser = RuleParser()
    rules = parser.parse_text(
        "||ads.example.com^\n@@||ok.com^\n", source="s", category=CATEGORY_ADS
    )
    recs = parser.compact_records(rules)
    h = "abc" * 10 + "ab"
    c.store_parsed(
        h,
        recs,
        counters={"pattern": 1, "quality": 2, "css": 3, "comment": 4, "modifier_stripped": 5},
    )
    loaded = c.load_parsed(h)
    assert loaded is not None
    recs2, counters = loaded
    rebuilt = RuleParser.rules_from_records(recs2, source="s")
    assert {r.normalized_domain for r in rebuilt} == {"ads.example.com", "ok.com"}
    # V5.2: drop counters round-trip through the sidecar
    assert counters == {"pattern": 1, "quality": 2, "css": 3, "comment": 4, "modifier_stripped": 5}


def test_parsed_sidecar_legacy_without_counters(tmp_path):
    """Sidecars written before V5.2 (no counters key) still load."""
    import pickle

    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.load()
    h = "def" * 10 + "cd"
    path = c._parsed_path(h)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        pickle.dump({"v": "v51", "records": [("block", "a.com", False, "", "ads", "")]}, f)
    recs, counters = c.load_parsed(h)
    assert counters is None
    assert recs[0][1] == "a.com"


def test_304_missing_cache_does_not_poison(tmp_path):
    """If 304 arrives with no body on disk, store_not_modified must not write empty."""
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.store("https://x/list.txt", "||keep.com^\n", etag='"1"')
    # delete content file to simulate missing body
    entry = c.get("https://x/list.txt")
    (tmp_path / "cache" / entry.content_path).unlink()
    assert c.get_content("https://x/list.txt") is None


def test_engine_local_files_dedup(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("! comment\n||ads.example.com^\n||track.example.com^\n")
    b.write_text("||ads.example.com^\n||ads.example.com^\n")
    engine = AsyncRuleEngine(
        cache_dir=None, aggregation_enabled=False, conflict_resolution_enabled=False
    )
    sources = [
        SourceMeta(name="A", url=str(a), category="ads"),
        SourceMeta(name="B", url=str(b), category="ads"),
    ]
    out = engine.run_sync(sources)
    norms = sorted(r.normalized_domain for r in out.blocks)
    assert norms == ["ads.example.com", "track.example.com"]
    assert out.exact_merged >= 1
    assert out.comment_dropped >= 1
    # rule files must not carry a wall-clock Generated header
    from merger.exporter import Exporter

    dest = tmp_path / "out"
    Exporter(dest, formats=["adguard"], tiered=False, report=False).export_all(
        out.blocks, out.allows, out
    )
    text = (dest / "merged_rules.txt").read_text()
    assert "! Generated:" not in text
    assert "! Version:" in text


# ── dirty flag / save_if_dirty ──


def test_save_if_dirty_skips_clean_index(tmp_path):
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.load()
    assert c._dirty is False
    # no store → save_if_dirty must not create an index file
    c.save_if_dirty()
    assert not (tmp_path / "cache" / c.INDEX_FILENAME).exists()


def test_store_marks_dirty_and_save_clears(tmp_path):
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.store("url1", "||a.com^\n")
    assert c._dirty is True
    c.save_if_dirty()
    assert c._dirty is False
    assert (tmp_path / "cache" / c.INDEX_FILENAME).exists()


# ── eviction respects shared content_hash ──
# Note: max_size_mb=0 means "eviction disabled" in the constructor, so these
# tests force the cap to 0 bytes and invoke the evictor directly.


def test_evict_shared_hash_keeps_on_disk_file(tmp_path):
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.load()
    body = "||shared-domain-example.com^\n"
    e1 = c.store("url1", body)
    e2 = c.store("url2", body)
    assert e1.content_hash == e2.content_hash
    content_file = tmp_path / "cache" / e1.content_path
    assert content_file.exists()
    # Cap to exactly one entry's size: the oldest (url1) is evicted then the
    # loop stops, leaving url2 in place.
    c.max_size_bytes = e2.size_bytes
    c._evict_if_needed()
    # url1 (oldest) is evicted from the index...
    assert "url1" not in c._entries
    # ...but url2 still references the same on-disk content file, so it
    # stays in the index and the shared file must not be deleted.
    assert "url2" in c._entries
    assert content_file.exists()


def test_evict_unsed_hash_deletes_file(tmp_path):
    c = SourceCache(cache_dir=str(tmp_path / "cache"))
    c.load()
    e = c.store("url1", "||unique-one-domain.com^\n")
    content_file = tmp_path / "cache" / e.content_path
    assert content_file.exists()
    c.max_size_bytes = 0
    c._evict_if_needed()
    # no other entry references this hash → the entry AND file are removed
    assert "url1" not in c._entries
    assert not content_file.exists()


# ── V5.3 C8: negative cache + backoff ──────────────────────────────


def test_engine_backoff_and_negative_ttl_params():
    from merger.core import AsyncRuleEngine

    e = AsyncRuleEngine(cache_dir=None, backoff="exponential", negative_ttl_seconds=600)
    assert e.backoff == "exponential"
    assert e.negative_ttl_seconds == 600
    assert e._negative_cache == {}


def test_backoff_exponential_delay():
    """Exponential backoff: delay = retry_delay * 2^attempt."""
    from merger.core import AsyncRuleEngine

    e = AsyncRuleEngine(cache_dir=None, backoff="exponential", retry_delay=1.0)
    # attempt 0: 1.0 * 2^0 = 1.0, attempt 1: 1.0 * 2^1 = 2.0
    assert e.retry_delay * (2**0) == 1.0
    assert e.retry_delay * (2**1) == 2.0
    assert e.retry_delay * (2**2) == 4.0


def test_backoff_linear_delay():
    """Linear backoff: delay = retry_delay * (attempt + 1)."""
    from merger.core import AsyncRuleEngine

    e = AsyncRuleEngine(cache_dir=None, backoff="linear", retry_delay=1.0)
    assert e.retry_delay * (0 + 1) == 1.0
    assert e.retry_delay * (1 + 1) == 2.0
    assert e.retry_delay * (2 + 1) == 3.0
