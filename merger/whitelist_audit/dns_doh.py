"""DNS / DoH resolution layer and the optional MX/SPF missing-record clue.

DoH reuses the audit's shared aiohttp session when one is provided (connection
pooling); standalone callers without a session still get a short-lived
per-call session. Any DoH transport / parse failure falls back to the system
resolver, so the layer never hard-fails on a misconfigured proxy.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..version import user_agent
from .seam import resolve


def _parse_doh_json(data: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a Google/NextDNS JSON DoH payload into the legacy DNS shape.

    Status 3 = NXDOMAIN; Status 0 collects A/AAAA answer data; any other
    status (SERVFAIL/REFUSED/...) returns None so the caller falls back to
    the system resolver instead of misreading a resolver error as expired.
    A null / non-dict / malformed payload also returns None (never raises).
    """
    if not isinstance(data, dict):
        return None
    status = data.get("Status")
    if status == 3:  # NXDOMAIN
        return {"nxdomain": True, "ips": [], "error": None}
    if status != 0:
        return None
    ips: list[str] = []
    answers = data.get("Answer")
    if isinstance(answers, list):
        for ans in answers:
            if not isinstance(ans, dict):
                continue
            if ans.get("type") in (1, 28):  # A / AAAA (skip CNAME chains)
                ip = ans.get("data")
                if ip:
                    ips.append(ip)
    return {"nxdomain": False, "ips": ips, "error": None}


async def _doh_lookup(
    domain: str, endpoint: str, timeout: float = 5.0, session=None
) -> dict[str, Any] | None:
    """Query a Google/NextDNS-style JSON DoH endpoint, return the legacy shape.

    ``GET <endpoint>?name=<domain>&type=A`` with ``Accept: application/dns-json``.
    Returns ``None`` on any transport / non-200 / parse failure so the caller
    can fall back to the system resolver instead of declaring the domain
    unknown.

    When ``session`` is provided (the audit's shared aiohttp session) it is
    reused for connection pooling; otherwise a short-lived per-call session is
    opened as before. The caller owns any provided session's lifecycle.
    """
    import aiohttp

    base = endpoint.rstrip("/")
    headers = {"Accept": "application/dns-json", "User-Agent": user_agent()}
    try:
        if session is None:
            session_cm: Any = aiohttp.ClientSession()
        else:
            session_cm = _NullAiohttpCM(session)
        async with session_cm as reused:
            async with reused.get(
                base,
                params={"name": domain, "type": "A"},
                headers=headers,
                timeout=timeout,
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
    except Exception:  # noqa: BLE001 — any DoH failure degrades to system DNS
        return None

    return _parse_doh_json(data)


class _NullAiohttpCM:
    """Async CM that yields an existing session without closing it."""

    def __init__(self, session) -> None:
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *a):
        return None


async def _dns_check(
    domain: str, timeout: int = 5, doh_endpoint: str = "", session=None
) -> dict[str, Any]:
    """Async DNS resolution via DoH (when configured) then DnsChecker fallback.

    Thin wrapper preserving the legacy ``{nxdomain, ips, error}`` shape so
    ``_fuse_rating`` and existing tests don't need to change. The actual
    system resolution goes through :class:`merger.dnsx.DnsChecker` which uses
    dnspython's explicit rcode (works on glibc / musl / Windows) and falls
    back to getaddrinfo when dnspython is unavailable.
    """
    if doh_endpoint:
        via_doh = await resolve("_doh_lookup")(
            domain, doh_endpoint, timeout=timeout, session=session
        )
        if via_doh is not None:
            return via_doh

    from ..dnsx import DnsChecker

    result: dict[str, Any] = await DnsChecker(timeout=timeout).check(domain)
    error = result.get("error_type")
    if error == "nxdomain":
        error = None
    return {"nxdomain": result["nxdomain"], "ips": result["ips"], "error": error}


async def _query_mx_spf(domain: str, timeout: float = 5.0) -> dict[str, Any]:
    """DNS-derived MX + SPF TXT presence clue (dnspython in executor).

    Missing SPF/MX is a weak clue only; the layer defaults off so benign
    websites (which usually publish no MX) never contribute by default.
    """
    result: dict[str, Any] = {
        "has_mx": None,
        "has_spf": None,
        "missing_mx": False,
        "missing_spf": False,
        "recycled_clue": False,
        "reasons": [],
        "error": None,
    }
    try:
        import dns.resolver

        loop = asyncio.get_running_loop()

        def _resolve(rdtype: str) -> list[str]:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            try:
                answer = resolver.resolve(domain, rdtype)
                return [r.to_text() for r in answer]
            except dns.resolver.NoAnswer:
                return []

        mx = await loop.run_in_executor(None, _resolve, "MX")
        txt = await loop.run_in_executor(None, _resolve, "TXT")
        result["has_mx"] = bool(mx)
        result["has_spf"] = any("v=spf1" in t.lower() for t in txt)
        result["missing_mx"] = not result["has_mx"]
        result["missing_spf"] = not result["has_spf"]
        if result["missing_mx"]:
            result["reasons"].append("无 MX 记录")
        if result["missing_spf"]:
            result["reasons"].append("无 SPF TXT 记录")
        return result
    except Exception as e:  # noqa: BLE001 — resolver error degrades to clue error
        result["error"] = str(e)
        return result
