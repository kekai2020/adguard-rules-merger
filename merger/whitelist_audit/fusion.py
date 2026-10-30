"""Multi-layer fusion: collect ALL reasons + weighted risk score (no early return).

Weights come from ``config.fusion_weights`` (defaults equal the V5.2 hard-coded
scores). Moved verbatim during the P1-3 package split; every weight default,
reason string and rating rule is unchanged.
"""

from __future__ import annotations

from .constants import (
    RATING_MALICIOUS,
    RATING_SAFE,
    RATING_SUSPICIOUS,
    RATING_UNKNOWN,
)
from .disk_cache import _is_private_ip


def _fuse_rating(
    dns,
    urlhaus,
    threatfox,
    rdap,
    scam,
    vt,
    config,
    dnsbl=None,
    heuristics=None,
    homograph=None,
    mxspf=None,
    gsb=None,
    phishtank=None,
    urlscan=None,
) -> tuple[str, list[str], int]:
    """Multi-layer fusion (V5.2): collect ALL reasons + weighted risk score.

    Returns (rating, reasons, risk_score 0-100). Every enabled layer
    contributes its reason and score — no early return — so the audit output
    shows the complete evidence picture for each domain.
    """
    reasons: list[str] = []
    score = 0
    malicious_signal = False
    suspicious_signal = False
    dnsbl = dnsbl or {"listed": False, "malicious": False, "hits": [], "error": None}
    heuristics = heuristics or {"score": 0, "flags": [], "is_risky": False}
    homograph = homograph or {
        "is_typosquat": False,
        "matched_brand": None,
        "distance": None,
        "reasons": [],
    }
    mxspf = mxspf or {
        "missing_mx": False,
        "missing_spf": False,
        "reasons": [],
        "error": None,
    }
    gsb = gsb or {"malicious": False, "threats": [], "error": None}
    phishtank = phishtank or {"malicious": False, "error": None}
    urlscan = urlscan or {"malicious": False, "verdict": None, "error": None}
    # V6: fusion weights are read from config (defaults equal the original
    # hard-coded scores, so default behaviour is unchanged) and participate
    # in the disk-cache fingerprint.
    w = config.fusion_weights or {}

    # Threat intelligence: any positive → malicious
    ti_sources = []
    if urlhaus.get("malicious"):
        ti_sources.append("URLhaus")
    if threatfox.get("malicious"):
        ti_sources.append("ThreatFox")
    if vt.get("malicious"):
        ti_sources.append("VirusTotal")
    if ti_sources:
        malicious_signal = True
        score += w.get("threat_intel", 40)
        reasons.append(f"威胁情报命中 ({'+'.join(ti_sources)})")

    # V5.2 DNSBL: phishing / malware / scam listings are malicious signals
    if dnsbl.get("malicious"):
        malicious_signal = True
        score += w.get("dnsbl_malicious", 30)
        reasons.append(f"DNSBL 命中（{'+'.join(dnsbl.get('hits', []))}）")
    elif dnsbl.get("listed"):
        suspicious_signal = True
        score += w.get("dnsbl_listed", 15)
        reasons.append(f"DNSBL 列表命中（{'+'.join(dnsbl.get('hits', []))}）")

    # DNS: expired or private IP → suspicious
    if dns.get("nxdomain"):
        suspicious_signal = True
        score += w.get("dns_nxdomain", 15)
        reasons.append("DNS NXDOMAIN（域名已过期，白名单可能无效）")
    elif dns.get("ips") and any(_is_private_ip(ip) for ip in dns["ips"]):
        suspicious_signal = True
        score += w.get("dns_private_ip", 20)
        reasons.append(f"解析到私有/回环 IP: {dns['ips']}")

    # RDAP: newly registered → suspicious
    if rdap.get("is_new_domain"):
        suspicious_signal = True
        score += w.get("rdap_new_domain", 15)
        age = rdap.get("domain_age_days", "?")
        reasons.append(f"新注册域名（{age}天，<{config.new_domain_threshold_days}天阈值）")

    # MarketNow scam check → suspicious
    if scam.get("is_suspicious"):
        suspicious_signal = True
        score += (
            w.get("scam_confirmed", 30)
            if scam.get("is_confirmed_scam")
            else w.get("scam_suspicious", 20)
        )
        decision = scam.get("decision", "?")
        risk = scam.get("risk_score", 0)
        scam_reasons = scam.get("reasons", [])
        detail = "; ".join(scam_reasons[:2]) if scam_reasons else ""
        reasons.append(
            f"诈骗/钓鱼检测 [{decision}, 风险分{risk}]" + (f": {detail}" if detail else "")
        )

    # Offline heuristics: only escalate when several signals fire (score>=3).
    if heuristics.get("is_risky"):
        suspicious_signal = True
        score += w.get("heuristics", 10)
        flags = ", ".join(heuristics.get("flags") or []) or f"score={heuristics.get('score', 0)}"
        reasons.append(f"本地启发式风险 ({flags})")

    # V6: offline homograph / typosquat impersonation → suspicious
    if config.use_homograph and homograph.get("is_typosquat"):
        suspicious_signal = True
        score += w.get("homograph", 12)
        kind = "同形字" if homograph.get("homograph") else "拼写劫持"
        brand = homograph.get("matched_brand")
        dist = homograph.get("distance")
        reasons.append(f"{kind}仿冒品牌 {brand}（编辑距离 {dist}）")

    # V6: MX/SPF missing clue → weak suspicious (layer off by default)
    if config.use_dns_mx and (mxspf.get("missing_mx") or mxspf.get("missing_spf")):
        suspicious_signal = True
        score += w.get("dns_mx_missing", 8)
        clues = ", ".join(mxspf.get("reasons") or [])
        reasons.append(f"MX/SPF 记录缺失线索（{clues}）")

    # V6: Google Safe Browsing → malicious
    if config.use_gsb and gsb.get("malicious"):
        malicious_signal = True
        score += w.get("gsb_malicious", 35)
        threats = "; ".join(gsb.get("threats") or []) or "Safe Browsing"
        reasons.append(f"Google Safe Browsing 命中（{threats}）")

    # V6: PhishTank confirmed phishing → malicious
    if config.use_phishtank and phishtank.get("malicious"):
        malicious_signal = True
        score += w.get("phishtank_malicious", 30)
        reasons.append("PhishTank 确认钓鱼域名")

    # V6: urlscan community malicious verdict → suspicious
    if config.use_urlscan and urlscan.get("malicious"):
        suspicious_signal = True
        score += w.get("urlscan_suspicious", 20)
        verdict = urlscan.get("verdict") or "suspicious"
        reasons.append(f"urlscan 社区标记（{verdict}）")

    score = min(score, 100)

    if malicious_signal:
        return RATING_MALICIOUS, reasons, score

    # DNS failure fallbacks: never claim "DNS normal" on errors.
    dns_error = dns.get("error")
    # W-6: ti_disabled (all TI layers off) is a subset of ti_all_errors (each
    # layer is off OR errored), so only ti_all_errors is needed below.
    ti_all_errors = (
        (not config.use_urlhaus or urlhaus.get("error") not in (None, "disabled"))
        and (not config.use_threatfox or threatfox.get("error") not in (None, "disabled"))
        and (not config.use_virustotal or vt.get("error") not in (None, "disabled"))
    )
    if suspicious_signal:
        return RATING_SUSPICIOUS, reasons, score
    if dns_error and ti_all_errors:
        reasons.append(f"检测不完整：DNS 查询失败 ({dns_error})，威胁情报无有效命中")
        return RATING_UNKNOWN, reasons, score
    if dns_error:
        reasons.append(f"DNS 查询失败 ({dns_error})，但威胁情报无命中")
        return RATING_UNKNOWN, reasons, score

    # W-1: a SAFE verdict requires at least one evidence layer to have returned
    # a valid (non-error, non-disabled) result. If every threat-intel /
    # reputation layer was disabled or errored, the audit cannot attest safety
    # (a domain resolving normally is not the same as "verified clean"), so it
    # must report UNKNOWN instead of a misleading SAFE.
    def _evidenced(enabled: bool, res: dict) -> bool:
        return bool(enabled) and res.get("error") in (None, "")

    evidence_ok = any(
        (
            _evidenced(config.use_urlhaus, urlhaus),
            _evidenced(config.use_threatfox, threatfox),
            _evidenced(config.use_virustotal, vt),
            _evidenced(config.use_dnsbl, dnsbl),
            _evidenced(config.use_gsb, gsb),
            _evidenced(config.use_phishtank, phishtank),
            _evidenced(config.use_urlscan, urlscan),
            _evidenced(config.use_scam_check, scam),
        )
    )
    if not evidence_ok:
        reasons.append("检测覆盖不足：无威胁情报/信誉层返回有效结果，无法判定为安全")
        return RATING_UNKNOWN, reasons, score

    reasons.append("DNS 正常解析，无威胁情报标记")
    return RATING_SAFE, reasons, score
