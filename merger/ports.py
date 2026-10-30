"""R4 thin IO ports: HTTP / DNS / Cache seams for optional fake injection.

Minimal protocols plus default adapters that wrap the existing aiohttp
session, the dnspython resolver and ``SourceCache`` verbatim. Default
behaviour — timeouts, retry/backoff, conditional requests (ETag/304),
negative/stale caching, cache keys/TTL/eviction, the 5-hop CNAME walk and its
seen-set loop guard — is unchanged. Ports are optional constructor kwargs;
when omitted the production adapter is used, so every existing call site and
public API keeps working. No new dependencies; ``aiohttp`` / ``dns`` are
imported lazily inside the adapters so an offline environment never fails at
import time.

Scope (R4 only): this is NOT a full hexagonal architecture. The ports are
thin seams over the existing call points; retry/backoff, 304, negative cache,
failure fallback and the R2 audit layers stay exactly where they are.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

# ── HTTP ────────────────────────────────────────────────────────────────


@runtime_checkable
class HttpPort(Protocol):
    """Thin HTTP GET seam over a request call point.

    ``get`` returns an async context manager yielding a response with
    ``status``, ``headers``, ``raise_for_status()`` and ``text()`` /
    ``json()``, matching an aiohttp response. Retry/backoff and
    conditional-request logic stay in the caller; the port only issues the
    request.  Production POSTs (AI / threat-intel / online layers) still use
    the shared session directly and are deliberately not routed through this
    GET-only port.
    """

    def get(self, url: str, headers: dict[str, str] | None = None, timeout: Any = None):
        """Return an async CM yielding the response for ``GET url``."""
        ...


class AioHttpHttpPort:
    """Default HttpPort: delegates to the engine's live aiohttp session.

    The session itself is still built/owned by the existing
    ``_ensure_session`` (ClientTimeout, TCPConnector limit/ttl_dns_cache, UA
    header unchanged); this adapter only forwards the GET request call so a
    fake port can be injected for offline tests without touching retry/backoff
    or the 304 conditional-request logic.
    """

    def __init__(self, session_provider: Callable[[], Any]) -> None:
        self._session = session_provider

    def get(self, url: str, headers: dict[str, str] | None = None, timeout: Any = None):
        return self._session().get(url, headers=headers, timeout=timeout)


def default_audit_session_factory() -> Any:
    """Production audit session factory: a plain ``aiohttp.ClientSession`` CM.

    The R2 registry layers still receive the raw session object (registry and
    layer signatures unchanged); this only replaces the inline
    ``aiohttp.ClientSession()`` construction in ``audit_whitelist`` so a fake
    session factory can be injected for offline tests.
    """
    import aiohttp

    return aiohttp.ClientSession()


# ── DNS ──────────────────────────────────────────────────────────────────


@runtime_checkable
class DnsPort(Protocol):
    """Thin DNS seam; one CNAME lookup per call (the walk lives in the caller)."""

    def resolve_cname(self, name: str) -> list[str]:
        """Return normalized CNAME targets for ``name``; ``[]`` on any failure."""
        ...


class DnspythonDnsPort:
    """Default DnsPort: single-hop CNAME lookup via dnspython.

    Returns normalized (trailing dot stripped, lower-cased) target names;
    ``[]`` on ImportError / NXDOMAIN / NoAnswer / timeout / SERVFAIL / any
    resolver error so the caller's walk degrades exactly as before. The
    5-hop budget, seen-set loop guard and ``lower().strip(".")`` normalization
    of the start domain live in the caller seam; this adapter performs one
    resolve only and never raises.
    """

    def __init__(self, timeout: float = 2.0) -> None:
        self.timeout = timeout

    def resolve_cname(self, name: str) -> list[str]:
        try:
            import dns.resolver
        except ImportError:
            return []
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            resolver.timeout = self.timeout
            answer = resolver.resolve(name, "CNAME")
            return [r.target.to_text().rstrip(".").lower() for r in answer]
        except Exception:
            return []


# ── Cache ────────────────────────────────────────────────────────────────


@runtime_checkable
class CachePort(Protocol):
    """Thin cache seam over ``SourceCache`` (ETag/304/SHA-256/parsed sidecar).

    Keys, TTL, eviction, ``PARSED_CACHE_VERSION`` sidecar schema and SHA-256
    hashing all live in ``SourceCache``; the port adds no policy of its own.
    """

    def conditional_headers(self, url: str) -> dict[str, str]: ...

    def get_content(self, url: str) -> str | None: ...

    def content_hash_of(self, url: str) -> str | None: ...

    def store_not_modified(self, url: str) -> Any: ...

    def content_changed(
        self, url: str, content: str, content_hash: str | None = None
    ) -> tuple[bool, str]: ...

    def load_parsed(self, content_hash: str) -> Any: ...

    def store_parsed(
        self, content_hash: str, records: list[tuple], counters: dict[str, int] | None = None
    ) -> None: ...

    def save_if_dirty(self) -> None: ...


class SourceCachePort:
    """Transparent adapter over ``SourceCache``; delegates every call verbatim.

    R4 holds the port on the engine as an injection point; the fetch path now
    routes all cache reads/writes through this port (D-5), so an injected fake
    cache is honoured for offline tests while keys / TTL / eviction / sidecar /
    SHA-256 stay in ``SourceCache``. The fetch guard remains on the real
    ``engine.cache`` (None → skip), so a missing cache never touches the proxy.
    """

    def __init__(self, cache: Any) -> None:
        self._cache = cache

    def __getattr__(self, name: str) -> Any:
        return getattr(self._cache, name)
