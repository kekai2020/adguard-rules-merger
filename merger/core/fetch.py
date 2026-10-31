"""Network/session fetch layer mixed into :class:`AsyncRuleEngine`.

Holds the async context manager, ETag/SHA256/parsed-cache fetch, per-source
parse dispatch and concurrent ``fetch_all`` dedup. Moved verbatim during the
P1-3 package split.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

import aiohttp

from .._http_hardening import read_response_bytes
from ..cache import SourceCache
from ..models import Rule, SourceMeta
from ..parser import RuleParser
from .outcome import SourceFailure, classify_source_error

logger = logging.getLogger(__name__)


def _file_url_to_path(source: str) -> str | None:
    """Decode a ``file://`` URL to a local path, or None if not one.

    ``file:///C:/x/rules.txt`` / ``file://C:/x/rules.txt`` (Windows) and
    ``file:///x/rules.txt`` (POSIX) all map to a concrete filesystem path.
    """
    if not isinstance(source, str) or not source.startswith("file://"):
        return None
    parsed = urlparse(source)
    # Windows: netloc is the drive letter (C:); POSIX: netloc is empty or host.
    path = parsed.path
    if parsed.netloc:
        if len(parsed.netloc) == 2 and parsed.netloc[1] == ":":
            path = f"{parsed.netloc}{path}"
        elif parsed.netloc not in ("", "localhost"):
            path = f"//{parsed.netloc}{path}"
    elif len(path) >= 3 and path[0] == "/" and path[1].isalpha() and path[2] == ":":
        # file:///C:/x on Windows → urlparse gives path=/C:/x; strip the
        # leading slash so Path() sees a valid drive-qualified path.
        path = path[1:]
    return unquote(path)


def _read_source_text(p: Path) -> str:
    """Read a local source file (executor target: blocking IO off the loop)."""
    return p.read_text(encoding="utf-8-sig", errors="replace")


class FetchMixin:
    """Mixin attributes populated by AsyncRuleEngine.__init__."""

    timeout: float
    max_concurrency: int
    user_agent: str
    retry_count: int
    retry_delay: float
    source_deadline: float
    backoff: str
    strip_www: bool
    negative_ttl_seconds: int
    http_port: Any
    cache: SourceCache | None
    cache_port: Any
    _parser_kwargs: dict[str, Any]
    _session: aiohttp.ClientSession | None
    _cache_lock: asyncio.Lock | None
    _negative_cache: dict[str, float]
    pattern_dropped: int
    quality_dropped: int
    css_dropped: int
    comment_dropped: int
    modifier_stripped: int
    unrecognized_dropped: int
    unsupported_modifier: int

    # ── async context ───────────────────────────────────────────

    async def __aenter__(self):
        await self._ensure_session()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self.timeout, sock_connect=30, sock_read=self.timeout
            )
            connector = aiohttp.TCPConnector(
                limit=self.max_concurrency, ttl_dns_cache=300, force_close=False
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": self.user_agent},
            )
        if self._cache_lock is None:
            self._cache_lock = asyncio.Lock()

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        if self.cache:
            # Flushing the index is a blocking JSON dump — keep it off the loop.
            await asyncio.get_running_loop().run_in_executor(None, self.cache_port.save_if_dirty)

    # ── fetch ────────────────────────────────────────────────────

    async def _fetch_text(
        self,
        source: str,
        retries: int = 2,
        timeout: int | None = None,
    ) -> tuple[str, bool, str | None, str | None]:
        """Return (text, from_cache, error, content_hash)."""
        # file:// URLs are validated as a legal source scheme (config.py) but
        # were previously treated as a relative path, so ``file:///C:/x/rules.txt``
        # fell through to aiohttp and failed with NonHttpUrlClientError. Decode
        # the scheme explicitly so local file sources actually work.
        local_path = _file_url_to_path(source)
        if local_path is not None:
            p = Path(local_path)
            try:
                # Local reads can be large (or live on a network drive): keep
                # the blocking IO off the event loop (ASYNC240).
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(None, _read_source_text, p)
            except OSError as e:
                return "", False, f"local file unreadable: {e}", None
            h = SourceCache.hash_text(text)
            return text, False, None, h

        p = Path(source)
        if p.exists() and p.is_file():
            try:
                # utf-8-sig strips a leading BOM; otherwise the first line of a
                # BOM-prefixed list would carry U+FEFF and be dropped as
                # unrecognized. Rule content never legitimately starts with BOM.
                loop = asyncio.get_running_loop()
                text = await loop.run_in_executor(None, _read_source_text, p)
            except OSError as e:
                return "", False, f"local file unreadable: {e}", None
            h = SourceCache.hash_text(text)
            return text, False, None, h

        cond_headers: dict[str, str] = {}
        if self.cache:
            cond_headers = self.cache_port.conditional_headers(source)

        # V5.3 — negative cache: skip sources that failed recently
        if self.negative_ttl_seconds > 0:
            neg_ts = self._negative_cache.get(source)
            if neg_ts is not None and (time.monotonic() - neg_ts) < self.negative_ttl_seconds:
                if self.cache:
                    # Stale read ignores TTL: a lamed source must fall back to
                    # its cached body even when cache.ttl_seconds has passed.
                    cached = self.cache_port.get_content_stale(source)
                    if cached is not None:
                        logger.warning("negative cache hit for %s; using stale", source)
                        # err=None so _fetch_one actually consumes the stale
                        # body — the old "negative cache hit" error string made
                        # the caller discard the content this fallback exists
                        # to provide (defeating the whole feature).
                        return (cached, True, None, self.cache_port.content_hash_of(source))
                return "", False, "negative cache hit (no stale content)", None

        await self._ensure_session()
        assert self._session is not None
        last_exc: Exception | None = None
        start = time.monotonic()
        deadline = (start + self.source_deadline) if self.source_deadline else None

        async def _get(headers: dict[str, str], req_timeout):
            # R4: issue through the injected HttpPort; retry/backoff, 304
            # conditional request and response handling below are unchanged.
            return self.http_port.get(source, headers=headers, timeout=req_timeout)

        for attempt in range(retries + 1):
            base = timeout or self.timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0.5:
                    last_exc = TimeoutError(
                        f"per-source deadline {self.source_deadline:g}s exhausted"
                    )
                    break
                base = min(base, max(1.0, remaining))
            req_timeout = aiohttp.ClientTimeout(
                total=base, sock_connect=min(30.0, base), sock_read=base
            )
            try:
                async with await _get(cond_headers, req_timeout) as resp:
                    if resp.status == 404:
                        return "", False, f"HTTP 404 Not Found: {source}", None
                    if resp.status == 304:
                        if self.cache:
                            cached = self.cache_port.get_content(source)
                            if cached is not None:
                                async with self._cache_lock:  # type: ignore[union-attr]
                                    self.cache_port.store_not_modified(source)
                                    await asyncio.get_running_loop().run_in_executor(
                                        None, self.cache_port.save_if_dirty
                                    )
                                return cached, True, None, self.cache_port.content_hash_of(source)
                        # 304 but body/cache missing: retry once without validators.
                        logger.warning(
                            "304 with missing cache for %s; retrying unconditional", source
                        )
                        cond_headers = {}
                        async with await _get({}, req_timeout) as resp2:
                            resp2.raise_for_status()
                            text = (await read_response_bytes(resp2)).decode(
                                "utf-8", errors="replace"
                            )
                            content_hash: str | None = None
                            if self.cache:
                                content_hash = SourceCache.hash_text(text)
                                async with self._cache_lock:  # type: ignore[union-attr]
                                    self.cache_port.store(
                                        url=source,
                                        content=text,
                                        etag=resp2.headers.get("ETag"),
                                        last_modified=resp2.headers.get("Last-Modified"),
                                        content_hash=content_hash,
                                    )
                                    await asyncio.get_running_loop().run_in_executor(
                                        None, self.cache_port.save_if_dirty
                                    )
                            return text, False, None, content_hash
                    resp.raise_for_status()
                    text = (await read_response_bytes(resp)).decode("utf-8", errors="replace")
                    h2: str | None = None
                    from_cache = False
                    if self.cache:
                        changed, h2 = self.cache_port.content_changed(source, text)
                        async with self._cache_lock:  # type: ignore[union-attr]
                            self.cache_port.store(
                                url=source,
                                content=text,
                                etag=resp.headers.get("ETag"),
                                last_modified=resp.headers.get("Last-Modified"),
                                content_hash=h2,
                            )
                            await asyncio.get_running_loop().run_in_executor(
                                None, self.cache_port.save_if_dirty
                            )
                        if not changed:
                            from_cache = True
                    return text, from_cache, None, h2
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                last_exc = e
                if attempt < retries:
                    if self.backoff == "exponential":
                        delay = self.retry_delay * (2**attempt)
                    else:
                        delay = self.retry_delay * (attempt + 1)
                    await asyncio.sleep(delay)
                    continue
        # V5.3 — record negative cache for this source
        if self.negative_ttl_seconds > 0:
            self._negative_cache[source] = time.monotonic()
        if self.cache:
            # Stale read ignores TTL (see get_content_stale): with a configured
            # cache.ttl_seconds the old get_content() returned None for expired
            # entries, silently defeating the documented stale fallback.
            cached = self.cache_port.get_content_stale(source)
            if cached is not None:
                logger.warning("fetch %s failed (%s); using stale cache", source, last_exc)
                return cached, True, None, self.cache_port.content_hash_of(source)
        return (
            "",
            False,
            f"{type(last_exc).__name__}: {last_exc}" if last_exc else "unknown error",
            None,
        )

    def _parse_text(
        self, text: str, url: str, category: str
    ) -> tuple[list[Rule], int, int, int, int, int, int, int]:
        """CPU-bound parse; safe to run in a worker thread (own parser)."""
        parser = RuleParser(**self._parser_kwargs)
        rules = parser.parse_text(text, source=url, category=category)
        return (
            rules,
            parser.pattern_dropped,
            parser.quality_dropped,
            parser.css_dropped,
            parser.comment_dropped,
            parser.modifier_stripped,
            parser.unrecognized_dropped,
            getattr(parser, "unsupported_modifier", 0),
        )

    async def _fetch_one(self, meta: SourceMeta) -> tuple[list[Rule], bool, bool, int, str | None]:
        """Return (rules, success, from_cache, raw_line_count, error)."""
        t0 = time.time()
        text, from_cache, err, content_hash = await self._fetch_text(
            meta.url, retries=self.retry_count, timeout=meta.timeout
        )
        if err:
            logger.warning("source failed %s: %s", meta.url, err)
            return [], False, False, 0, err

        rules: list[Rule] | None = None
        if self.cache and content_hash:
            loaded = self.cache_port.load_parsed(content_hash)
            if loaded is not None:
                recs, counters = loaded
                rules = RuleParser.rules_from_records(
                    recs, source=meta.url, strip_www=self.strip_www
                )
                if counters:  # V5.2: drop counters survive the parsed cache
                    self.pattern_dropped += counters.get("pattern", 0)
                    self.quality_dropped += counters.get("quality", 0)
                    self.css_dropped += counters.get("css", 0)
                    self.comment_dropped += counters.get("comment", 0)
                    self.modifier_stripped += counters.get("modifier_stripped", 0)
                    self.unrecognized_dropped += counters.get("unrecognized", 0)
                    self.unsupported_modifier += counters.get("unsupported_modifier", 0)
                logger.info(
                    "parsed %6d rules from %-40s (parsed-cache, %.2fs)",
                    len(rules),
                    meta.url.split("/")[-1],
                    time.time() - t0,
                )
                return rules, True, True, len(rules), None

        loop = asyncio.get_running_loop()
        (
            rules,
            pat,
            qual,
            css,
            comments,
            modstrip,
            unrec,
            unsupported,
        ) = await loop.run_in_executor(None, self._parse_text, text, meta.url, meta.category)
        assert rules is not None
        self.pattern_dropped += pat
        self.quality_dropped += qual
        self.css_dropped += css
        self.comment_dropped += comments
        self.modifier_stripped += modstrip
        self.unrecognized_dropped += unrec
        self.unsupported_modifier += unsupported
        if self.cache and content_hash:
            try:
                recs = RuleParser.compact_records(rules)
                self.cache_port.store_parsed(
                    content_hash,
                    recs,
                    counters={
                        "pattern": pat,
                        "quality": qual,
                        "css": css,
                        "comment": comments,
                        "modifier_stripped": modstrip,
                        "unrecognized": unrec,
                        "unsupported_modifier": unsupported,
                    },
                )
            except OSError as e:
                logger.debug("parsed sidecar write failed: %s", e)
        logger.info(
            "parsed %6d rules from %-40s (%s, %.2fs)",
            len(rules),
            meta.url.split("/")[-1],
            "cache" if from_cache else "net",
            time.time() - t0,
        )
        return rules, True, from_cache, len(rules), None

    async def fetch_all(self, sources: list[SourceMeta]):
        sem = asyncio.Semaphore(self.max_concurrency)
        block_map: dict[tuple[str, bool, str], Rule] = {}
        allow_map: dict[tuple[str, bool, str], Rule] = {}
        regex_blocks: dict[str, Rule] = {}
        regex_allows: dict[str, Rule] = {}
        raw_count = ok = cached = 0
        exact_merged = normalized_merged = regex_merged = 0
        failures: list[SourceFailure] = []
        source_raw_counts: dict[str, int] = {}
        source_names: dict[str, str] = {}

        async def bounded(meta: SourceMeta):
            async with sem:
                return meta, await self._fetch_one(meta)

        for fut in asyncio.as_completed([bounded(s) for s in sources]):
            meta, (rules, success, from_cache, n, err) = await fut
            source_names[meta.url] = meta.name
            if not success:
                failures.append(
                    SourceFailure(
                        url=meta.url,
                        name=meta.name,
                        error=err or "unknown",
                        error_type=classify_source_error(err or ""),
                    )
                )
                continue
            ok += 1
            raw_count += n
            source_raw_counts[meta.url] = n
            if from_cache:
                cached += 1

            for r in rules:
                if r.rule_type == "comment":
                    continue
                if r.normalized_domain == "":
                    m = regex_blocks if r.rule_type == "block" else regex_allows
                    key = r.raw
                    existing = m.get(key)
                    if existing is None:
                        m[key] = r
                    else:
                        existing.merge_from(r)
                        regex_merged += 1
                    continue
                tmap = block_map if r.rule_type == "block" else allow_map
                key = (r.normalized_domain, r.wildcard, r.modifiers)
                existing = tmap.get(key)
                if existing is None:
                    tmap[key] = r
                else:
                    if existing.raw and r.raw and existing.raw != r.raw:
                        normalized_merged += 1
                    else:
                        exact_merged += 1
                    existing.merge_from(r)
            del rules

        return (
            block_map,
            allow_map,
            list(regex_blocks.values()),
            list(regex_allows.values()),
            raw_count,
            ok,
            cached,
            exact_merged,
            normalized_merged,
            regex_merged,
            failures,
            source_raw_counts,
            source_names,
        )
