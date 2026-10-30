"""V5 MarketNow scam/phishing detection (free, no API key).

Queries the MarketNow Scam Check API, which analyzes a domain for social-
engineering risk using multiple heuristics:
  - suspicious TLD (.xyz/.top etc. commonly abused)
  - typosquatting (e.g. "micros0ft" ~ "microsoft")
  - punycode / IDN homograph attacks
  - URL shortener detection
  - domain age via RDAP (newly registered / unregistered)
  - subdomain abuse
  - HTTP token analysis

This complements the other threat-intel layers:
  - URLhaus  → actively distributing malware
  - ThreatFox → C2 command & control endpoints
  - MarketNow → scam / phishing / social engineering (this module)

API: GET https://www.marketnow.site/api/scam-check?domain={domain}
Returns JSON: {decision, risk_score, reasons, checks, ...}

Decision levels (ascending risk):
  TRUSTED     known-popular / established domain
  UNKNOWN     no strong signal either way
  CAUTION     mild indicators (e.g. unregistered, numeric sequence)
  SUSPICIOUS  multiple/strong scam indicators
  SCAM        confirmed/near-certain scam (if returned)

No API key, no registration.  Observed ~0.8s per response with no strict
rate limit; callers should still bound concurrency.
"""

from __future__ import annotations

from typing import Any

from .version import user_agent

SCAM_CHECK_API = "https://www.marketnow.site/api/scam-check"

# Decisions that indicate scam/phishing risk
_RISKY_DECISIONS = {"SUSPICIOUS", "SCAM", "BLOCKED", "HIGH_RISK"}
_CONFIRMED_SCAM = {"SCAM", "BLOCKED", "MALICIOUS"}

# Benign labels that must never be treated as suspicious regardless of the
# numeric score. CAUTION means "mild indicators, review manually" and TRUSTED
# means "established domain" — escalating either would create false positives.
# UNKNOWN is deliberately excluded: with no label signal, a high score still
# warrants suspicion.
_NEVER_SUSPICIOUS = {"CAUTION", "TRUSTED"}

# risk_score at/above which a non-benign-labelled result is treated as
# suspicious (defensive, in case new labels appear)
SCORE_SUSPICIOUS = 50
SCORE_HIGH = 70


def evaluate_scam_decision(decision: str, risk_score: int):
    """Map a (decision label, score) pair to (is_suspicious, is_confirmed).

    Centralises the rule so the label semantics can be unit-tested without any
    network access. Benign labels in ``_NEVER_SUSPICIOUS`` always short-circuit
    to (False, False), even if the API returns a high numeric score.
    """
    decision = (decision or "").upper().strip()
    if decision in _NEVER_SUSPICIOUS:
        return False, False
    is_confirmed = decision in _CONFIRMED_SCAM or risk_score >= SCORE_HIGH
    is_suspicious = decision in _RISKY_DECISIONS or risk_score >= SCORE_SUSPICIOUS
    return is_suspicious, is_confirmed


async def query_scam_check(domain: str, session, timeout: int = 10) -> dict[str, Any]:
    """Query MarketNow scam check for a domain.

    Returns:
        {decision, risk_score, reasons, is_suspicious, is_confirmed_scam,
         error}
    """
    result: dict[str, Any] = {
        "decision": None,
        "risk_score": 0,
        "reasons": [],
        "is_suspicious": False,
        "is_confirmed_scam": False,
        "error": None,
    }

    params = {"domain": domain}
    headers = {"User-Agent": user_agent(), "Accept": "application/json"}

    try:
        async with session.get(
            SCAM_CHECK_API, params=params, headers=headers, timeout=timeout
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)

        decision = str(data.get("decision", "")).upper().strip()
        risk_score = data.get("risk_score", 0)
        try:
            risk_score = int(risk_score)
        except (TypeError, ValueError):
            risk_score = 0
        reasons = data.get("reasons", [])
        # Coerce to a list[str]: a malformed API payload may return a bare
        # string; fusion joins it, so normalize instead of iterating chars.
        if isinstance(reasons, str):
            reasons = [reasons]
        elif not isinstance(reasons, list):
            reasons = []
        else:
            reasons = [r for r in reasons if isinstance(r, str)]

        is_suspicious, is_confirmed = evaluate_scam_decision(decision, risk_score)

        result.update(
            {
                "decision": decision or "UNKNOWN",
                "risk_score": risk_score,
                "reasons": reasons,
                "is_suspicious": is_suspicious,
                "is_confirmed_scam": is_confirmed,
            }
        )
        return result

    except Exception as e:
        result["error"] = str(e)
        return result
