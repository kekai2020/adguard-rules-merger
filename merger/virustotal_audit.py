"""V5 VirusTotal optional integration (requires API key, disabled by default).

VirusTotal provides free API access (500 requests/day, 4/minute) for domain
reputation checking.  This module queries the domain report endpoint and
extracts:
  - malicious_votes: number of security vendors flagging the domain
  - total_votes: total number of vendors that analyzed the domain
  - reputation_score: malicious / total (0.0 = clean, 1.0 = universally flagged)
  - categories: VirusTotal's own domain categorization

This is an OPTIONAL layer.  It requires the user to provide their own
VirusTotal API key via config.  Without a key, this layer is skipped
entirely and the audit falls back to URLhaus + ThreatFox + DNS + RDAP.

API docs: https://docs.virustotal.com/reference/domains-get
"""

from __future__ import annotations

import logging
from typing import Any

from ._http_hardening import _TTLCache, with_retry
from .version import user_agent

VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains/{domain}"

# If >= this fraction of vendors flag a domain, treat as malicious.
# VirusTotal uses ~70 vendors; 10% = ~7 vendors flagging was too aggressive
# (a handful of low-reputation vendors could push a clean domain over the
# line). 20% = ~14 vendors is a more conservative, false-positive-resistant
# threshold for a DNS whitelist audit where over-blocking is worse than a
# missed hit. W-5.
MALICIOUS_THRESHOLD = 0.20

logger = logging.getLogger(__name__)

# In-process result cache: repeated identical (domain, key) lookups within the
# TTL window do not re-hit the network.
_vt_cache = _TTLCache()


async def query_virustotal(
    domain: str,
    api_key: str,
    session,
    timeout: int = 20,
) -> dict[str, Any]:
    """Query VirusTotal domain report.

    Args:
        domain: domain to check
        api_key: VirusTotal API key (required)
        session: aiohttp.ClientSession
        timeout: request timeout

    Returns:
        Dict with: malicious, reputation_score, malicious_votes,
        total_votes, categories, error.
    """
    result: dict[str, Any] = {
        "malicious": False,
        "reputation_score": 0.0,
        "malicious_votes": 0,
        "total_votes": 0,
        "categories": [],
        "error": None,
    }

    if not api_key:
        result["error"] = "no API key configured"
        return result

    cache_key = ("vt", domain, api_key)
    cached = _vt_cache.get(cache_key)
    if cached is not None:
        return cached

    url = VT_DOMAIN_API.format(domain=domain)
    headers = {
        "x-apikey": api_key,
        "User-Agent": user_agent(),
    }

    async def _do() -> dict[str, Any]:
        async with session.get(url, headers=headers, timeout=timeout) as resp:
            if resp.status == 404:
                result["error"] = "domain not found on VirusTotal"
                return result
            if resp.status == 429:
                result["error"] = "rate limited (429)"
                return result
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result

            data = await resp.json(content_type=None)
            attrs = data.get("data", {}).get("attributes", {})

            # Vendor analysis stats
            stats = attrs.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
            total = malicious + suspicious + harmless + undetected

            result["malicious_votes"] = malicious
            result["total_votes"] = total
            if total > 0:
                result["reputation_score"] = round((malicious + suspicious * 0.5) / total, 3)
                result["malicious"] = float(result["reputation_score"]) >= MALICIOUS_THRESHOLD

            # Categories
            cats = attrs.get("categories", {})
            if isinstance(cats, dict):
                result["categories"] = list(cats.values())

            return result

    try:
        result = await with_retry(_do, what=f"virustotal:{domain}")
    except Exception:
        logger.exception("VirusTotal query failed for %s", domain)
        result["error"] = "transport error"
    _vt_cache.set(cache_key, result)
    return result
