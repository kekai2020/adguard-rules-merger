"""URLhaus + ThreatFox threat-intel queries (per-domain API or dataset index).

Moved verbatim during the P1-3 package split; rate-limit semaphore and delay
behaviour are unchanged.
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..version import user_agent
from .config import AuditConfig
from .constants import THREATFOX_API, URLHAUS_HOST_API
from .seam import resolve


async def _query_urlhaus(domain: str, session, timeout: int = 8) -> dict[str, Any]:
    try:
        data = {"host": domain}
        headers = {"User-Agent": user_agent()}
        async with session.post(
            URLHAUS_HOST_API, data=data, headers=headers, timeout=timeout
        ) as resp:
            if resp.status != 200:
                return {"malicious": False, "error": f"HTTP {resp.status}"}
            result = await resp.json(content_type=None)
            if result.get("query_status") == "ok":
                return {"malicious": True, "error": None}
            return {"malicious": False, "error": None}
    except Exception as e:
        return {"malicious": False, "error": str(e)}


async def _query_threatfox(domain: str, session, timeout: int = 8) -> dict[str, Any]:
    try:
        data = {"query": "search_ioc", "search_term": domain}
        headers = {"User-Agent": user_agent()}
        async with session.post(THREATFOX_API, json=data, headers=headers, timeout=timeout) as resp:
            if resp.status != 200:
                return {"malicious": False, "error": f"HTTP {resp.status}"}
            result = await resp.json(content_type=None)
            if result.get("query_status") == "ok" and result.get("data"):
                return {"malicious": True, "error": None}
            return {"malicious": False, "error": None}
    except Exception as e:
        return {"malicious": False, "error": str(e)}


async def _query_threat_intel(
    domain: str, session, config: AuditConfig, ti_sem=None
) -> tuple[dict, dict]:
    """Query URLhaus + ThreatFox with rate-limit semaphore.

    Uses a per-run semaphore (default 3 concurrent) instead of a global lock,
    and a fixed small delay rather than idx-proportional sleep.
    Returns (urlhaus_result, threatfox_result).
    """
    urlhaus = {"malicious": False, "error": "disabled"}
    threatfox = {"malicious": False, "error": "disabled"}

    if not (config.use_urlhaus or config.use_threatfox):
        return urlhaus, threatfox

    async with ti_sem:
        # Fixed small delay to avoid burst; NOT idx-proportional.
        if config.urlhaus_delay > 0:
            await asyncio.sleep(config.urlhaus_delay)
        if config.use_urlhaus:
            urlhaus = await resolve("_query_urlhaus")(domain, session)
        if config.use_threatfox:
            threatfox = await resolve("_query_threatfox")(domain, session)

    return urlhaus, threatfox


async def _query_threat_intel_dataset(
    domain: str,
    feed_index,
) -> tuple[dict, dict]:
    """Dataset-mode threat lookup (V5.3) — replaces per-domain API calls.

    Returns (urlhaus_result, threatfox_result) with the same shape as
    ``_query_threat_intel`` so ``_fuse_rating`` is unchanged.
    """
    hit = feed_index.lookup_domain(domain)
    no = {"malicious": False, "error": None}
    if not hit["listed"]:
        return no, no
    source = hit.get("source") or ""
    if source == "ThreatFox":
        return no, {"malicious": True, "error": None}
    return {"malicious": True, "error": None}, no
