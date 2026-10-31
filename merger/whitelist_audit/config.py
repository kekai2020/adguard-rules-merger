"""AuditConfig dataclass (layer switches, fusion weights, thresholds) + _CacheEntry.

Moved verbatim during the P1-3 package split; default weights and defaults are
unchanged. ``from_engine`` is the SINGLE declarative mapping point from the
engine's flattened ``whitelist_audit_*`` attributes to this dataclass.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from typing import Any

from .constants import CACHE_TTL

# ── declarative engine → AuditConfig mapping ────────────────────────
# Convention: an AuditConfig field maps from ``engine.whitelist_audit_<field>``.
# Only fields BREAKING the convention are listed here. Adding a new audit knob
# with a conventional attribute name needs NO entry (guarded by
# tests/test_config_wiring.py::test_build_audit_config_populates_every_audit_field).
_ENGINE_ATTR_GETTERS: dict[str, Callable[[Any], Any]] = {
    "virustotal_api_key": lambda e: e.whitelist_audit_vt_api_key,
    "new_domain_threshold_days": lambda e: e.whitelist_audit_new_domain_days,
    "feed_ttl_seconds": lambda e: e.whitelist_audit_feed_ttl,
    "use_ai": lambda e: e.whitelist_audit_use_ai,
    "ai_api_key": lambda e: e.whitelist_audit_ai_api_key,
    "ai_base_url": lambda e: e.whitelist_audit_ai_base_url,
    "ai_model": lambda e: e.whitelist_audit_ai_model,
    "ai_min_confidence": lambda e: e.whitelist_audit_ai_min_confidence,
    "ai_max_domains": lambda e: e.whitelist_audit_ai_max_domains,
    "fusion_weights": lambda e: e.whitelist_audit_fusion_weights,
}
# AuditConfig-only internal parameters with no engine-side knob (keep defaults).
_AUDIT_ONLY_FIELDS = frozenset({"cache_ttl_seconds", "doh_timeout"})


@dataclass
class AuditConfig:
    """Configuration for the multi-layer audit engine."""

    use_dns: bool = True
    use_urlhaus: bool = True
    use_threatfox: bool = True
    use_rdap: bool = True
    use_scam_check: bool = True
    use_virustotal: bool = False
    virustotal_api_key: str = ""
    use_ai: bool = False
    ai_api_key: str = ""
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"
    ai_min_confidence: float = 0.6
    ai_max_domains: int = 100
    concurrency: int = 20
    urlhaus_delay: float = 0.2
    new_domain_threshold_days: int = 30
    # V5.2 — DNSBL layer + disk cache (opt-in so offline unit tests stay
    # hermetic; enabled in config/sources.yaml).
    use_dnsbl: bool = False
    # Offline heuristics (punycode, abused TLD, deep subdomains, homoglyphs).
    # Always on by default — zero network cost, provides offline signal.
    use_heuristics: bool = True
    cache_results: bool = False
    cache_dir: str = "cache"
    cache_ttl_seconds: int = CACHE_TTL
    # V5.3: configurable fusion weights (defaults = the V5.2 hard-coded scores,
    # so default behaviour is unchanged). Used by the cache fingerprint AND by
    # _fuse_rating (V6: weights are actually wired into scoring).
    fusion_weights: dict[str, int] = field(
        default_factory=lambda: {
            "threat_intel": 40,
            "dnsbl_malicious": 30,
            "scam_confirmed": 30,
            "dns_private_ip": 20,
            "scam_suspicious": 20,
            "dnsbl_listed": 15,
            "dns_nxdomain": 15,
            "rdap_new_domain": 15,
            "heuristics": 10,
            # V6: new signals (conservative defaults; a non-hit domain adds 0).
            "homograph": 12,
            "dns_mx_missing": 8,
            "gsb_malicious": 35,
            "phishtank_malicious": 30,
            "urlscan_suspicious": 20,
        }
    )
    # V5.3: threat-intel mode — "api" (per-domain HTTP, legacy) or
    # "auto" (download feed once, O(1) local lookup, API fallback).
    ti_mode: str = "api"
    feed_ttl_seconds: int = 3600
    # Optional DNS-over-HTTPS JSON endpoint (e.g. a NextDNS profile URL
    # ``https://dns.nextdns.io/<id>``). Empty = use the system resolver via
    # DnsChecker. On any DoH transport/parse failure we fall back to the
    # system resolver so the layer never hard-fails on a misconfigured proxy.
    doh_endpoint: str = ""
    doh_timeout: float = 5.0
    # V6: offline homograph/typosquat layer (zero network, on by default).
    use_homograph: bool = True
    # V6: MX/SPF TXT missing clue (DNS-derived; optional, default off).
    use_dns_mx: bool = False
    # V6: optional online intel layers — default off, skipped without a key.
    use_gsb: bool = False
    gsb_api_key: str = ""
    use_phishtank: bool = False
    phishtank_api_key: str = ""
    use_urlscan: bool = False
    urlscan_api_key: str = ""
    # V6: certificate transparency (crt.sh) — optional interface only, default off.
    use_crtsh: bool = False

    @classmethod
    def from_engine(cls, engine: Any) -> AuditConfig:
        """Build from an ``AsyncRuleEngine`` (single declarative mapping point).

        Fields map from ``engine.whitelist_audit_<field>`` by convention;
        ``_ENGINE_ATTR_GETTERS`` carries only the renames. The user's partial
        ``fusion_weights`` table is shallow-merged over the built-in defaults
        so naming a few keys does not silently zero the unmentioned layers.
        """
        kwargs: dict[str, Any] = {}
        for f in dataclass_fields(cls):
            name = f.name
            getter = _ENGINE_ATTR_GETTERS.get(name)
            if getter is not None:
                kwargs[name] = getter(engine)
            elif name in _AUDIT_ONLY_FIELDS:
                continue  # keep the dataclass default
            else:
                attr = f"whitelist_audit_{name}"
                if hasattr(engine, attr):
                    kwargs[name] = getattr(engine, attr)
        kwargs["fusion_weights"] = {**cls().fusion_weights, **kwargs["fusion_weights"]}
        return cls(**kwargs)


@dataclass
class _CacheEntry:
    result: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
