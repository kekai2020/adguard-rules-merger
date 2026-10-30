"""V7 incremental cache — HTTP ETag / Last-Modified / content hash + parsed sidecar.

- Conditional GET (If-None-Match / If-Modified-Since); 304 reuses the body.
- SHA-256 content hash skips re-parsing when the bytes did not change.
- Parsed-rule sidecar (pickle of compact tuples) so a cache hit does not
  re-run the regex parser.
- Index is written atomically; content files are written via tmp+replace.
"""

from __future__ import annotations

import hashlib
import json
import logging
import pickle
import shutil
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PARSED_CACHE_VERSION = "v51"  # sidecar schema version — bump ONLY when the
# pickled record format actually changes (older sidecars must keep loading)


@dataclass
class CacheEntry:
    """Metadata for one cached source."""

    url: str
    etag: str | None = None
    last_modified: str | None = None
    content_hash: str | None = None  # SHA-256 hex
    content_path: str | None = None  # relative path within cache_dir
    fetched_at: float = 0.0  # Unix timestamp
    size_bytes: int = 0
    rule_count: int = 0  # populated after parse

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> CacheEntry:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class SourceCache:
    """File-backed cache for source responses with conditional-request support.

    Args:
        cache_dir:    Directory for cache storage.
        ttl_seconds:  Maximum age of a cache entry before it's considered
                      stale (0 = never expire based on time).
        max_size_mb:  Maximum total cache size in MB; oldest entries are
                      evicted when exceeded (0 = unlimited).
    """

    INDEX_FILENAME = "index.json"
    CONTENT_SUBDIR = "content"
    PARSED_SUBDIR = "parsed"

    def __init__(
        self,
        cache_dir: str = "cache",
        ttl_seconds: int = 0,
        max_size_mb: int = 0,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.ttl_seconds = ttl_seconds
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self._entries: dict[str, CacheEntry] = {}
        self._loaded = False
        self._dirty = False

    @staticmethod
    def hash_text(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    # ── persistence ─────────────────────────────────────────────

    def _index_path(self) -> Path:
        return self.cache_dir / self.INDEX_FILENAME

    def _content_dir(self) -> Path:
        return self.cache_dir / self.CONTENT_SUBDIR

    def _parsed_dir(self) -> Path:
        return self.cache_dir / self.PARSED_SUBDIR

    def _parsed_path(self, content_hash: str) -> Path:
        return self._parsed_dir() / f"{PARSED_CACHE_VERSION}-{content_hash}.pkl"

    def load(self) -> None:
        """Load cache index from disk (idempotent)."""
        if self._loaded:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._content_dir().mkdir(parents=True, exist_ok=True)
        self._parsed_dir().mkdir(parents=True, exist_ok=True)

        idx = self._index_path()
        if idx.exists():
            try:
                data = json.loads(idx.read_text(encoding="utf-8"))
                for url, entry_dict in data.get("entries", {}).items():
                    self._entries[url] = CacheEntry.from_dict(entry_dict)
                logger.debug("Loaded %d cache entries", len(self._entries))
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Cache index corrupted, starting fresh: %s", e)
                self._entries = {}
        self._loaded = True

    def save(self) -> None:
        """Persist cache index to disk atomically."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 51,
            "updated_at": time.time(),
            "entries": {url: e.to_dict() for url, e in self._entries.items()},
        }
        tmp = self._index_path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._index_path())
        self._dirty = False

    def save_if_dirty(self) -> None:
        """Flush the index only when it changed since the last save."""
        if self._dirty:
            self.save()

    # ── lookup ──────────────────────────────────────────────────

    def get(self, url: str) -> CacheEntry | None:
        """Get cache entry for a URL, or None if not cached / expired."""
        self.load()
        entry = self._entries.get(url)
        if entry is None:
            return None
        if self.ttl_seconds > 0:
            age = time.time() - entry.fetched_at
            if age > self.ttl_seconds:
                logger.debug("Cache expired for %s (age %.0fs)", url, age)
                return None
        if entry.content_path:
            full = self.cache_dir / entry.content_path
            if not full.exists():
                logger.debug("Cache content missing for %s", url)
                return None
        return entry

    def get_content(self, url: str) -> str | None:
        """Get cached response body text, or None."""
        entry = self.get(url)
        if entry is None or not entry.content_path:
            return None
        full = self.cache_dir / entry.content_path
        try:
            return full.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Failed to read cache content for %s: %s", url, e)
            return None

    def content_hash_of(self, url: str) -> str | None:
        entry = self.get(url)
        return entry.content_hash if entry else None

    # ── parsed sidecar ──────────────────────────────────────────

    def load_parsed(self, content_hash: str) -> tuple[list[tuple], dict[str, int] | None] | None:
        """Return ``(compact rule tuples, parse counters)`` for this content
        hash, or None. Counters are optional (older sidecars lack them)."""
        if not content_hash:
            return None
        path = self._parsed_path(content_hash)
        if not path.exists():
            return None
        try:
            # Trust boundary: the parsed cache is written by this process under
            # ``cache_dir``. Treat the file as local-trust; do not point the
            # cache dir at a world-writable location.
            with path.open("rb") as f:
                data = pickle.load(f)
            if isinstance(data, dict) and data.get("v") == PARSED_CACHE_VERSION:
                recs = data.get("records")
                if isinstance(recs, list):
                    counters = data.get("counters")
                    return recs, (counters if isinstance(counters, dict) else None)
        except (OSError, pickle.UnpicklingError, EOFError) as e:
            logger.debug("parsed cache unreadable for %s: %s", content_hash[:12], e)
        return None

    def store_parsed(
        self, content_hash: str, records: list[tuple], counters: dict[str, int] | None = None
    ) -> None:
        if not content_hash:
            return
        self.load()
        path = self._parsed_path(content_hash)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {"v": PARSED_CACHE_VERSION, "records": records}
        if counters:
            # V5.2: persist drop counters so cache-hit runs report the same
            # diagnostics as full-parse runs.
            payload["counters"] = counters
        tmp = path.with_suffix(".pkl.tmp")
        with tmp.open("wb") as f:
            pickle.dump(payload, f, protocol=5)
        tmp.replace(path)

    # ── conditional request headers ──────────────────────────────

    def conditional_headers(self, url: str) -> dict[str, str]:
        """Return HTTP headers for a conditional GET, or empty dict."""
        entry = self.get(url)
        if entry is None:
            return {}
        headers: dict[str, str] = {}
        if entry.etag:
            headers["If-None-Match"] = entry.etag
        if entry.last_modified:
            headers["If-Modified-Since"] = entry.last_modified
        return headers

    # ── store ───────────────────────────────────────────────────

    def store(
        self,
        url: str,
        content: str,
        etag: str | None = None,
        last_modified: str | None = None,
        rule_count: int = 0,
        content_hash: str | None = None,
    ) -> CacheEntry:
        """Store a response in the cache and return the new entry."""
        self.load()

        if content_hash is None:
            content_hash = self.hash_text(content)
        rel_path = f"{self.CONTENT_SUBDIR}/{content_hash}.txt"
        full_path = self.cache_dir / rel_path

        if not full_path.exists():
            full_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = full_path.with_suffix(".txt.tmp")
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(full_path)

        entry = CacheEntry(
            url=url,
            etag=etag,
            last_modified=last_modified,
            content_hash=content_hash,
            content_path=rel_path,
            fetched_at=time.time(),
            size_bytes=len(content.encode("utf-8")),
            rule_count=rule_count,
        )
        self._entries[url] = entry
        self._dirty = True

        if self.max_size_bytes > 0:
            self._evict_if_needed()

        return entry

    def store_not_modified(self, url: str) -> CacheEntry | None:
        """Update the fetched_at timestamp for a 304 response."""
        entry = self._entries.get(url)
        if entry is None:
            return None
        entry.fetched_at = time.time()
        self._dirty = True
        return entry

    # ── content hash comparison ──────────────────────────────────

    def content_changed(
        self, url: str, content: str, content_hash: str | None = None
    ) -> tuple[bool, str]:
        """Return (changed, hash). Hash is computed at most once."""
        new_hash = content_hash or self.hash_text(content)
        entry = self._entries.get(url)
        if entry is None or not entry.content_hash:
            return True, new_hash
        return new_hash != entry.content_hash, new_hash

    # ── eviction ─────────────────────────────────────────────────

    def _evict_if_needed(self) -> None:
        """Evict oldest entries when total cache size exceeds limit."""
        total = sum(e.size_bytes for e in self._entries.values())
        if total <= self.max_size_bytes:
            return

        # Precompute reference counts per content_hash so we can tell whether
        # another entry still references the same on-disk file — O(n) instead
        # of O(n²) per evicted entry.
        hash_refs: dict[str, int] = {}
        for e in self._entries.values():
            if e.content_hash:
                hash_refs[e.content_hash] = hash_refs.get(e.content_hash, 0) + 1

        sorted_entries = sorted(self._entries.values(), key=lambda e: e.fetched_at)
        for entry in sorted_entries:
            if total <= self.max_size_bytes:
                break
            if entry.content_path:
                full = self.cache_dir / entry.content_path
                refs = hash_refs.get(entry.content_hash or "", 0)
                if refs <= 1:
                    if full.exists():
                        full.unlink()
                    if entry.content_hash:
                        pkl = self._parsed_path(entry.content_hash)
                        if pkl.exists():
                            pkl.unlink()
            if entry.content_hash:
                hash_refs[entry.content_hash] = hash_refs.get(entry.content_hash, 1) - 1
            total -= entry.size_bytes
            del self._entries[entry.url]
            logger.debug("Evicted cache entry for %s", entry.url)

    # ── stats ────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return cache statistics."""
        self.load()
        total_size = sum(e.size_bytes for e in self._entries.values())
        return {
            "entry_count": len(self._entries),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "ttl_seconds": self.ttl_seconds,
            "max_size_mb": self.max_size_bytes // (1024 * 1024),
        }

    def clear(self) -> None:
        """Remove all cache entries, content files, feed blobs and the audit cache.

        This clears everything under the cache directory that the merger owns:
        the source index, content bodies, the parsed-rule sidecar, the
        threat-intel ``feeds/`` blob cache, and the whitelist-audit disk cache.
        It matches the ``cache clear`` CLI promise of deleting all cached state.
        """
        self._entries = {}
        idx = self._index_path()
        if idx.exists():
            idx.unlink()
        # C-3/D-10: remove the content / parsed / feeds directories entirely
        # (the old per-file unlink left empty dirs behind, breaking the
        # "delete everything" promise). load()/writes recreate them on demand.
        for sub in (self._content_dir(), self._parsed_dir()):
            shutil.rmtree(sub, ignore_errors=True)
        # V7 C-06: also purge the threat-feed blob cache and the audit disk
        # cache, which previously survived `cache clear` despite the prompt
        # saying "delete everything".
        feeds = self.cache_dir / "feeds"
        shutil.rmtree(feeds, ignore_errors=True)
        audit_cache = self.cache_dir / "whitelist_audit_cache.json"
        if audit_cache.exists():
            audit_cache.unlink()
        logger.info("Cache cleared")
