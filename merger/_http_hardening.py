"""Shared hardening for the optional external-API layers.

Provides:

* :class:`_TTLCache` — a tiny monotonic-clock in-process result cache so that
  repeated identical inputs do not re-hit the network within the TTL window
  (default 5 minutes).
* :func:`with_retry` — run an async request factory with exponential-backoff
  retry on *transport* errors (≥2 retries, ≤3 calls). Every failure is logged
  with a full traceback via :func:`logging.exception`; the original exception
  is re-raised so the caller can translate it into its own error dict.

Offline tests never issue a real request: every layer short-circuits before the
transport call (e.g. no API key), so the retry/cache paths are only exercised
when a genuine request is attempted.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

DEFAULT_TTL = 300.0  # seconds (5 minutes)
DEFAULT_RETRIES = 2  # extra attempts after the first call (≤3 total)
_DEFAULT_BACKOFF = 0.5  # base seconds; doubled per attempt
# Hard cap on a single response body (64 MiB): a corrupted or hostile upstream
# that streams an unbounded body must fail the fetch instead of OOM-ing the
# merger. Raised as aiohttp.ClientPayloadError (a ClientError) so existing
# retry / stale-fallback paths handle it unchanged.
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024


async def read_response_bytes(resp: Any, limit: int = DEFAULT_MAX_RESPONSE_BYTES) -> bytes:
    """Stream an aiohttp response body with a hard byte cap.

    ``Content-Length`` is fast-rejected before reading when present; chunked
    bodies are accumulated with a running total. Raises
    ``aiohttp.ClientPayloadError`` on any breach.

    Duck-typed responses without ``.content`` (test doubles, alternate
    transports) fall back to ``read()`` / ``text()`` — the cap is still
    enforced after the read, so a fake can never smuggle an oversized body
    past this. Real aiohttp responses always take the streaming path.
    """
    length = getattr(resp, "content_length", None)
    if length is not None and length > limit:
        raise aiohttp.ClientPayloadError(f"response too large: {length} > {limit} bytes")
    content = getattr(resp, "content", None)
    if content is not None:
        chunks: list[bytes] = []
        total = 0
        async for chunk in content.iter_chunked(1 << 20):
            total += len(chunk)
            if total > limit:
                raise aiohttp.ClientPayloadError(f"response exceeds {limit} byte limit")
            chunks.append(chunk)
        return b"".join(chunks)
    if hasattr(resp, "read"):
        data = await resp.read()
        if len(data) > limit:
            raise aiohttp.ClientPayloadError(f"response exceeds {limit} byte limit")
        return data
    text_fn = getattr(resp, "text", None)
    if text_fn is not None:
        data = (await text_fn(encoding="utf-8", errors="replace")).encode("utf-8", errors="replace")
        if len(data) > limit:
            raise aiohttp.ClientPayloadError(f"response exceeds {limit} byte limit")
        return data
    raise aiohttp.ClientPayloadError(f"unsupported response object: {type(resp).__name__}")


class _TTLCache:
    """A small monotonic-clock TTL cache with a hard size cap.

    Entries expire lazily on access. When the size exceeds ``maxsize`` the
    oldest (earliest-expiry) entry is evicted to keep memory bounded. Not
    thread-safe; the audit pipeline is single-process.
    """

    def __init__(self, ttl: float = DEFAULT_TTL, maxsize: int = 1024) -> None:
        self.ttl = ttl
        self.maxsize = maxsize
        self._store: dict[Any, tuple[float, Any]] = {}

    def get(self, key: Any) -> Any | None:
        item = self._store.get(key)
        if item is None:
            return None
        expires, value = item
        # >= so a ttl of 0 (set-and-already-expired) holds even on coarse
        # monotonic clocks (e.g. Windows tick granularity), where monotonic()
        # may not have advanced past the set instant yet.
        if time.monotonic() >= expires:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: Any, value: Any) -> None:
        now = time.monotonic()
        self._store[key] = (now + self.ttl, value)
        # Evict oldest-expiry entries when over capacity.
        if len(self._store) > self.maxsize:
            # Drop the single oldest entry; dict preserves insertion order, so
            # the first key is the least-recently-set. Expired entries are
            # already lazily purged on get(); this is a hard cap backstop.
            oldest = next(iter(self._store))
            self._store.pop(oldest, None)


async def with_retry(
    factory: Callable[[], Awaitable[Any]],
    *,
    what: str = "request",
    retries: int = DEFAULT_RETRIES,
    backoff_base: float = _DEFAULT_BACKOFF,
) -> Any:
    """Await ``factory()``, retrying on transport errors with exponential backoff.

    ``factory`` is called fresh on each attempt. Any exception is logged with a
    full traceback and retried up to ``retries`` extra times; after the final
    failure the exception is re-raised for the caller to translate.
    """
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await factory()
        except Exception as exc:  # noqa: BLE001 - we re-raise after retries
            last_exc = exc
            logger.exception("%s failed (attempt %d/%d)", what, attempt + 1, retries + 1)
            if attempt < retries:
                await asyncio.sleep(backoff_base * (2**attempt))
    assert last_exc is not None
    raise last_exc
