"""Threat-intel feed index (V5.3) — dataset-mode threat lookup.

Downloads URLhaus host text + ThreatFox CSV once per run, builds an O(1)
domain-set index, and replaces per-domain API calls when ti_mode=auto.
Falls back to per-domain API when feeds are unavailable.
"""

from __future__ import annotations

import csv
import hashlib
import io
import logging
import time
from typing import Any

from ._http_hardening import read_response_bytes
from .feed_cache import FeedCache

logger = logging.getLogger(__name__)

URLHAUS_HOSTS_URL = "https://urlhaus.abuse.ch/downloads/host/"
THREATFOX_CSV_URL = "https://threatfox-api.abuse.ch/api/v1/?export=csv"
FEED_TTL = 3600  # 1 hour


class ThreatFeedIndex:
    """Local index of malicious domains from URLhaus + ThreatFox."""

    def __init__(self, cache_dir: str = "cache", ttl_seconds: int = FEED_TTL) -> None:
        self._cache = FeedCache(cache_dir)
        self._ttl = ttl_seconds
        self._domains: set[str] = set()
        self._sources: dict[str, str] = {}
        self._ready = False
        self._last_checked: float | None = None
        self._urlhaus_hash: str | None = None
        self._threatfox_hash: str | None = None
        self.stats: dict[str, Any] = {
            "dataset_hits": 0,
            "api_fallbacks": 0,
            "feed_schema_error": 0,
            "feed_age_hours": None,
            "freshness": "unknown",
            "domains_indexed": 0,
            "urlhaus_loaded": False,
            "threatfox_loaded": False,
        }

    @property
    def ready(self) -> bool:
        return self._ready

    async def build(self, session) -> None:
        """Download (or load cached) feeds and build the domain index."""
        try:
            await self._build_urlhaus(session)
            await self._build_threatfox(session)
            self._ready = bool(self._domains)
            self.stats["domains_indexed"] = len(self._domains)
            age = self._cache_age_hours()
            self.stats["feed_age_hours"] = age
            self.stats["freshness"] = self._freshness_label(age)
        except Exception as e:  # noqa: BLE001
            logger.warning("ThreatFeedIndex build failed: %s", e)
            self._ready = False

    async def _build_urlhaus(self, session) -> None:
        result = await self._fetch_feed(session, "urlhaus_hosts", URLHAUS_HOSTS_URL)
        if result is None:
            return
        blob, from_cache = result
        new_hash = hashlib.sha256(blob).hexdigest()
        if from_cache and self._urlhaus_hash == new_hash:
            self._cache.update_checked_time("urlhaus_hosts")
            self._last_checked = time.time()
            return
        try:
            text = blob.decode("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                d = line.lower()
                if "." not in d or "<" in d or ">" in d or "/" in d or " " in d:
                    continue
                self._domains.add(d)
                self._sources.setdefault(d, "URLhaus")
            self._urlhaus_hash = new_hash
            self.stats["urlhaus_loaded"] = True
        except Exception as e:  # noqa: BLE001
            self.stats["feed_schema_error"] += 1
            logger.warning("URLhaus parse error: %s", e)

    async def _build_threatfox(self, session) -> None:
        result = await self._fetch_feed(session, "threatfox_csv", THREATFOX_CSV_URL)
        if result is None:
            return
        blob, from_cache = result
        new_hash = hashlib.sha256(blob).hexdigest()
        if from_cache and self._threatfox_hash == new_hash:
            self._cache.update_checked_time("threatfox_csv")
            self._last_checked = time.time()
            return
        try:
            text = blob.decode("utf-8", errors="replace")
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                if row.get("ioc_type") == "domain":
                    d = (row.get("ioc_value") or "").strip().lower()
                    if d:
                        self._domains.add(d)
                        self._sources.setdefault(d, "ThreatFox")
            self._threatfox_hash = new_hash
            self.stats["threatfox_loaded"] = True
        except Exception as e:  # noqa: BLE001
            self.stats["feed_schema_error"] += 1
            logger.warning("ThreatFox parse error: %s", e)

    async def _fetch_feed(self, session, name: str, url: str) -> tuple[bytes, bool] | None:
        """Fetch feed with cache fallback.

        Returns ``(blob, from_cache)`` or None. ``from_cache=True`` means
        the blob came from cache (either TTL hit or download-failure fallback);
        ``from_cache=False`` means a fresh download.
        """
        cached = self._cache.load_blob(name)
        now = time.time()
        if cached:
            blob, meta = cached
            if now - meta.get("last_checked_at", 0) < self._ttl:
                self._last_checked = meta.get("last_checked_at")
                return blob, True
        try:
            async with session.get(url, timeout=30) as resp:
                if resp.status != 200:
                    return (cached[0], True) if cached else None
                blob = await read_response_bytes(resp)
                self._cache.store_blob(name, blob)
                self._last_checked = now
                return blob, False
        except Exception as e:  # noqa: BLE001
            logger.warning("feed '%s' download failed: %s", name, e)
            return (cached[0], True) if cached else None

    def lookup_domain(self, domain: str) -> dict[str, Any]:
        """O(1) lookup. Returns ``{"listed", "source"}``."""
        d = (domain or "").lower().strip(".")
        self.stats["dataset_hits"] += 1
        if d in self._domains:
            return {"listed": True, "source": self._sources.get(d)}
        return {"listed": False, "source": None}

    def _cache_age_hours(self) -> float | None:
        if self._last_checked is None:
            return None
        return round((time.time() - self._last_checked) / 3600, 2)

    @staticmethod
    def _freshness_label(age: float | None) -> str:
        if age is None:
            return "unknown"
        if age < 1:
            return "fresh"
        if age < 6:
            return "stale"
        return "expired"
