"""Offline keyless signals: recycled-domain clue and local heuristics.

Moved verbatim during the P1-3 package split; the score>=3 threshold and every
flag string are unchanged.
"""

from __future__ import annotations

from typing import Any

from .constants import _SUSPICIOUS_TLDS


def recycled_domain_clue(rdap: dict[str, Any], dns: dict[str, Any]) -> bool:
    """Offline recycled/dropped-domain clue from already-collected signals.

    True when RDAP exposes no registrar record, the domain is not flagged as
    newly registered, yet it still resolves — a weak hint that the old
    registration record was dropped after expiry (a recycled domain being
    re-used). Informational only: it never contributes to the risk score on
    its own.
    """
    try:
        if rdap.get("registrar"):
            return False
        if rdap.get("is_new_domain"):
            return False
        return bool(dns.get("ips"))
    except AttributeError:
        return False


def local_heuristics(domain: str) -> dict[str, Any]:
    """Offline, keyless signals. ``is_risky`` only when score >= 3.

    Checks: punycode/IDN, abused TLD, deep subdomains, over-long domain,
    digit-heavy core label, digit-letter homoglyph substitution.
    """
    flags: list[str] = []
    score = 0
    d = (domain or "").lower().strip(".")
    if not d:
        return {"score": 0, "flags": [], "is_risky": False, "tld": ""}

    if d.startswith("xn--") or ".xn--" in d:
        flags.append("punycode/IDN")
        score += 2

    labels = d.split(".")
    tld = labels[-1] if labels else ""
    if tld in _SUSPICIOUS_TLDS:
        flags.append(f"可疑TLD .{tld}")
        score += 1
    if len(labels) >= 6:
        flags.append(f"子域过深({len(labels)})")
        score += 1
    if len(d) >= 60:
        flags.append(f"域名过长({len(d)})")
        score += 1

    core = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    digits = sum(c.isdigit() for c in core)
    if core and digits >= 3 and len(core) <= 12:
        flags.append("标签含大量数字")
        score += 1
    if core and any(c in core for c in "01") and any(c in core for c in "olil"):
        flags.append("数字字母混用(疑似仿冒)")
        score += 2
    # V6: phishing kits stack branding across hyphens (e.g. "apple-support-login")
    if core and core.count("-") >= 2:
        flags.append("标签含多个连字符")
        score += 1

    return {
        "score": score,
        "flags": flags,
        "is_risky": score >= 3,
        "tld": tld,
    }
