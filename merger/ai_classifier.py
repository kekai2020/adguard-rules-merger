"""V5 AI-assisted domain classification (optional, requires API key).

Uses an OpenAI-compatible LLM API to classify domains that the offline
classifier couldn't categorize with high confidence.  This is the 4th layer
in the defense-in-depth strategy:

  1. PSL-based registered-domain matching (offline, high confidence)
  2. Subdomain prefix matching (offline, medium confidence)
  3. Threat intel APIs (URLhaus / ThreatFox / VirusTotal)
  4. AI semantic classification (this module, low confidence fallback)

The AI is ONLY called for domains with offline confidence < 0.6 (i.e. the
"other" category).  This keeps API costs low — with 224 whitelist domains,
only ~140 would need AI classification, and at ~$0.00015 per gpt-4o-mini
request that's ~$0.02 per run.

Configuration (all optional):
  whitelist_audit.ai.enabled: false
  whitelist_audit.ai.api_key: ""
  whitelist_audit.ai.base_url: "https://api.openai.com/v1"
  whitelist_audit.ai.model: "gpt-4o-mini"
  whitelist_audit.ai.min_confidence: 0.6  # only call AI below this confidence
  whitelist_audit.ai.max_domains: 100     # safety cap per run
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ._http_hardening import _TTLCache, with_retry

# Categories the AI may return — must match domain_classifier.CATEGORY_ORDER
AI_CATEGORIES = [
    "advertising",
    "analytics",
    "cdn",
    "microsoft_telemetry",
    "affiliate",
    "social",
    "ecommerce_payment",
    "privacy_security",
    "other",
]

AI_SYSTEM_PROMPT = """You are a domain classification expert for ad-blocking whitelists.
Classify each domain into exactly ONE category based on its primary purpose.

Categories:
- advertising: ad networks, DSPs, ad serving, marketing pixels
- analytics: site analytics, tracking, performance monitoring, telemetry
- cdn: content delivery, static asset hosting, image/media CDN
- microsoft_telemetry: Windows/Office/Azure telemetry, connectivity checks
- affiliate: affiliate marketing, link redirect, attribution, short links
- social: social media, sharing widgets, messaging
- ecommerce_payment: payment gateways, checkout, shopping, ecommerce
- privacy_security: privacy tools, VPN, security software, threat intel
- other: anything that doesn't fit the above

Return ONLY valid JSON: {"category": "...", "confidence": 0.0-1.0, "reason": "..."}
Be conservative — if unsure, use "other" with low confidence."""


logger = logging.getLogger(__name__)

# In-process result cache: repeated identical domain classifications within the
# TTL window do not re-hit the LLM API.
_ai_cache = _TTLCache()

def _build_user_prompt(domain: str) -> str:
    return f'Classify the domain "{domain}". Return JSON only.'


async def classify_with_ai(
    domain: str,
    api_key: str,
    session,
    base_url: str = "https://api.openai.com/v1",
    model: str = "gpt-4o-mini",
    timeout: int = 30,
) -> dict[str, Any]:
    """Classify a single domain using an OpenAI-compatible LLM.

    Returns {category, confidence, reason, error}.
    """
    result = {"category": "other", "confidence": 0.0, "reason": "", "error": None}

    if not api_key:
        result["error"] = "no API key"
        return result

    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": AI_SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(domain)},
        ],
        "temperature": 0.1,
        "max_tokens": 200,
        "response_format": {"type": "json_object"},
    }

    cache_key = ("ai", domain, api_key, model)
    cached = _ai_cache.get(cache_key)
    if cached is not None:
        return cached

    async def _do() -> dict[str, Any]:
        async with session.post(url, headers=headers, json=payload, timeout=timeout) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)

            cat = parsed.get("category", "other").lower().strip()
            if cat not in AI_CATEGORIES:
                cat = "other"
            conf = float(parsed.get("confidence", 0.0))
            conf = max(0.0, min(1.0, conf))
            reason = str(parsed.get("reason", ""))[:200]

            result["category"] = cat
            result["confidence"] = conf
            result["reason"] = reason
            return result

    try:
        result = await with_retry(_do, what=f"ai-classify:{domain}")
    except Exception:
        logger.exception("AI classification failed for %s", domain)
        result["error"] = "transport error"
    _ai_cache.set(cache_key, result)
    return result
