"""Optional online intel layers: Google Safe Browsing, PhishTank, urlscan, crt.sh.

Every layer returns a plain dict and degrades to an error dict; disabled/keyless
layers report ``disabled`` / ``no API key configured``. Moved verbatim during the
P1-3 package split.
"""

from __future__ import annotations

from typing import Any

from ..version import user_agent

GSB_LOOKUP_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_API = "http://checkurl.phishtank.com/checkurl/"
URLSCAN_SEARCH_API = "https://urlscan.io/api/v1/search/"
CRT_SH_API = "https://crt.sh/"


async def _query_gsb(domain: str, api_key: str, session, timeout: int = 8) -> dict[str, Any]:
    """Google Safe Browsing v4 threatMatches/find (needs API key, optional)."""
    result: dict[str, Any] = {"malicious": False, "threats": [], "error": None}
    if not api_key:
        result["error"] = "no API key configured"
        return result
    try:
        payload = {
            "client": {"clientId": "adguard-rules-merger", "clientVersion": "6"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ALL_PLATFORMS"],
                "threatEntries": [{"url": f"http://{domain}"}],
            },
        }
        async with session.post(
            GSB_LOOKUP_API,
            params={"key": api_key},
            json=payload,
            headers={"User-Agent": user_agent()},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
        matches = data.get("matches") or []
        result["threats"] = sorted({m.get("threatType", "?") for m in matches})
        result["malicious"] = bool(result["threats"])
        return result
    except Exception as e:  # noqa: BLE001 — layer degrades to error dict
        result["error"] = str(e)
        return result


async def _query_phishtank(domain: str, api_key: str, session, timeout: int = 10) -> dict[str, Any]:
    """PhishTank checkurl (needs app key, optional)."""
    result: dict[str, Any] = {"malicious": False, "phish_id": None, "error": None}
    if not api_key:
        result["error"] = "no API key configured"
        return result
    try:
        async with session.post(
            PHISHTANK_API,
            data={"url": f"http://{domain}", "app_key": api_key, "format": "json"},
            headers={"User-Agent": user_agent()},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
        phish = (data.get("results") or {}).get("phish") or {}
        result["phish_id"] = phish.get("phish_id")
        result["malicious"] = bool(phish.get("in_database")) and str(
            phish.get("valid", "")
        ).lower() not in ("false", "0")
        return result
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        return result


async def _query_urlscan(domain: str, api_key: str, session, timeout: int = 10) -> dict[str, Any]:
    """urlscan.io community verdicts search (key optional, layer off by default)."""
    result: dict[str, Any] = {"malicious": False, "verdict": None, "error": None}
    try:
        headers = {"User-Agent": user_agent()}
        if api_key:
            headers["API-Key"] = api_key
        async with session.get(
            URLSCAN_SEARCH_API,
            params={"q": f"domain:{domain}"},
            headers=headers,
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
        for hit in data.get("results") or []:
            community = (hit.get("verdicts") or {}).get("community") or {}
            if community.get("malicious"):
                result["malicious"] = True
                result["verdict"] = "community-malicious"
                break
        return result
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        return result


async def _query_crtsh(domain: str, session, timeout: int = 10) -> dict[str, Any]:
    """Certificate transparency via crt.sh (informational; never scores alone)."""
    result: dict[str, Any] = {"entries": [], "error": None}
    try:
        async with session.get(
            CRT_SH_API,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": user_agent()},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
        result["entries"] = [
            {"issuer": e.get("issuer_name"), "not_before": e.get("not_before")}
            for e in (data or [])[:20]
        ]
        return result
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        return result
