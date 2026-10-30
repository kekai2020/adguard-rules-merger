"""ThreatFeedIndex unit tests — mock feeds, no network access.

Covers C5: dataset build + O(1) lookup + cache reuse + schema error +
the _query_threat_intel_dataset wrapper shape contract.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from merger.feed_cache import FeedCache
from merger.threat_feeds import ThreatFeedIndex

URLHAUS_BLOB = b"""# urlhaus host list
bad1.example
bad2.example
"""

THREATFOX_BLOB = b"""id,ioc_type,ioc_value,threat_type,tags
1,domain,bad3.example,malware,"tag1"
2,ip,192.0.2.1,botnet,"tag2"
3,domain,bad4.example,phishing,"tag3"
"""


class TestThreatFeedIndex:
    def _index(self, tmp_path):
        return ThreatFeedIndex(cache_dir=str(tmp_path), ttl_seconds=3600)

    @pytest.mark.asyncio
    async def test_build_and_lookup(self, tmp_path):
        idx = self._index(tmp_path)

        async def fake_fetch(session, name, url):
            if "urlhaus" in name:
                return (URLHAUS_BLOB, False)
            return (THREATFOX_BLOB, False)

        idx._fetch_feed = fake_fetch
        await idx.build(session=None)
        assert idx.ready is True
        assert idx.lookup_domain("bad1.example")["listed"] is True
        assert idx.lookup_domain("bad1.example")["source"] == "URLhaus"
        assert idx.lookup_domain("bad3.example")["listed"] is True
        assert idx.lookup_domain("bad3.example")["source"] == "ThreatFox"
        assert idx.lookup_domain("clean.example")["listed"] is False
        assert idx.stats["domains_indexed"] == 4
        assert idx.stats["urlhaus_loaded"] is True
        assert idx.stats["threatfox_loaded"] is True

    @pytest.mark.asyncio
    async def test_second_run_uses_cache(self, tmp_path):
        """First run downloads via session; second run hits FeedCache (no session.get)."""

        class FakeResp:
            def __init__(self, blob):
                self.status = 200
                self._blob = blob

            async def read(self):
                return self._blob

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class FakeSession:
            def __init__(self):
                self.get_count = 0

            def get(self, url, **kw):
                self.get_count += 1
                blob = URLHAUS_BLOB if "host" in url else THREATFOX_BLOB
                return FakeResp(blob)

        sess1 = FakeSession()
        idx1 = self._index(tmp_path)
        await idx1.build(session=sess1)
        assert sess1.get_count == 2
        assert idx1.ready is True

        sess2 = FakeSession()
        idx2 = self._index(tmp_path)
        await idx2.build(session=sess2)
        assert sess2.get_count == 0
        assert idx2.ready is True
        assert idx2.lookup_domain("bad1.example")["listed"] is True

    @pytest.mark.asyncio
    async def test_build_failure_graceful_degradation(self, tmp_path):
        """If _build_urlhaus raises, build() catches it and stays not-ready."""
        idx = self._index(tmp_path)
        idx._build_urlhaus = AsyncMock(side_effect=RuntimeError("boom"))
        idx._build_threatfox = AsyncMock()
        await idx.build(session=None)
        assert idx.ready is False

    @pytest.mark.asyncio
    async def test_empty_feeds_not_ready(self, tmp_path):
        idx = self._index(tmp_path)

        async def fake_fetch(session, name, url):
            return (b"", False)

        idx._fetch_feed = fake_fetch
        await idx.build(session=None)
        assert idx.ready is False

    @pytest.mark.asyncio
    async def test_fallback_to_api_when_not_ready(self, tmp_path):
        idx = self._index(tmp_path)

        async def fake_fetch(session, name, url):
            return None

        idx._fetch_feed = fake_fetch
        await idx.build(session=None)
        assert idx.ready is False
        assert idx.lookup_domain("anything")["listed"] is False


class TestQueryThreatIntelDataset:
    @pytest.mark.asyncio
    async def test_listed_urlhaus(self):
        from merger.whitelist_audit import _query_threat_intel_dataset

        idx = MagicMock()
        idx.lookup_domain = MagicMock(return_value={"listed": True, "source": "URLhaus"})
        uh, tf = await _query_threat_intel_dataset("bad.example", idx)
        assert uh["malicious"] is True
        assert tf["malicious"] is False

    @pytest.mark.asyncio
    async def test_listed_threatfox(self):
        from merger.whitelist_audit import _query_threat_intel_dataset

        idx = MagicMock()
        idx.lookup_domain = MagicMock(return_value={"listed": True, "source": "ThreatFox"})
        uh, tf = await _query_threat_intel_dataset("bad.example", idx)
        assert uh["malicious"] is False
        assert tf["malicious"] is True

    @pytest.mark.asyncio
    async def test_not_listed(self):
        from merger.whitelist_audit import _query_threat_intel_dataset

        idx = MagicMock()
        idx.lookup_domain = MagicMock(return_value={"listed": False, "source": None})
        uh, tf = await _query_threat_intel_dataset("clean.example", idx)
        assert uh["malicious"] is False
        assert tf["malicious"] is False


class TestFeedCache:
    def test_store_and_load(self, tmp_path):
        fc = FeedCache(str(tmp_path))
        h = fc.store_blob("test", b"hello")
        result = fc.load_blob("test")
        assert result is not None
        blob, meta = result
        assert blob == b"hello"
        assert meta["content_hash"] == h
        assert meta["size"] == 5

    def test_load_missing(self, tmp_path):
        fc = FeedCache(str(tmp_path))
        assert fc.load_blob("nope") is None

    def test_update_checked_time(self, tmp_path):
        import time

        fc = FeedCache(str(tmp_path))
        fc.store_blob("test", b"hello")
        _, meta1 = fc.load_blob("test")
        time.sleep(0.01)
        fc.update_checked_time("test")
        _, meta2 = fc.load_blob("test")
        assert meta2["last_checked_at"] > meta1["last_checked_at"]
        assert meta2["content_hash"] == meta1["content_hash"]
