"""Config→engine wiring guards (AGENTS.md "新增配置项五处同步" defense).

Three automated invariants that previously lived only in one-off probes:

1. every kwarg ``config_to_kwargs`` produces is a real constructor parameter
   (config→engine leg can never TypeError at runtime);
2. every non-port constructor parameter is fed by ``config_to_kwargs``
   (constructor-side drift = dead knob, the publish_domains class of bug);
3. every ``AuditConfig`` field is actually populated by
   ``AsyncRuleEngine._build_audit_config`` (the ~35-field manual mapping
   cannot silently skip a new audit knob).
"""

from __future__ import annotations

import inspect
from dataclasses import fields as dataclass_fields

from merger.config import MergeConfig
from merger.core import AsyncRuleEngine
from merger.core.engine import config_to_kwargs
from merger.whitelist_audit.config import AuditConfig

# Constructor params intentionally NOT fed from MergeConfig (injected IO seams).
_PORT_PARAMS = {"http_port", "dns_port", "cache_port"}


def test_config_to_kwargs_only_passes_real_params():
    sig = set(inspect.signature(AsyncRuleEngine.__init__).parameters)
    produced = set(config_to_kwargs(MergeConfig()))
    unknown = produced - sig
    assert not unknown, f"config_to_kwargs passes params the engine does not accept: {unknown}"


def test_every_engine_param_is_config_fed():
    sig = set(inspect.signature(AsyncRuleEngine.__init__).parameters) - {"self"} - _PORT_PARAMS
    produced = set(config_to_kwargs(MergeConfig()))
    unfed = sig - produced
    assert not unfed, (
        f"engine params not reachable from MergeConfig (dead-knob risk): {sorted(unfed)}"
    )


def test_build_audit_config_populates_every_audit_field():
    cfg = MergeConfig(
        whitelist_audit={
            "enabled": True,
            "concurrency": 11,
            "use_dns": False,
            "use_urlhaus": False,
            "use_threatfox": False,
            "use_rdap": False,
            "use_scam_check": False,
            "use_dnsbl": True,
            "cache_results": True,
            "use_virustotal": True,
            "virustotal_api_key": "vt-key",
            "use_heuristics": False,
            "fusion_weights": {"heuristics": 99},
            "ti_mode": "auto",
            "feed_ttl_seconds": 120,
            "doh_endpoint": "https://dns.example/json",
            "use_homograph": False,
            "use_dns_mx": True,
            "use_gsb": True,
            "gsb_api_key": "gsb-key",
            "use_phishtank": True,
            "phishtank_api_key": "pt-key",
            "use_urlscan": True,
            "urlscan_api_key": "us-key",
            "use_crtsh": True,
            "new_domain_threshold_days": 45,
            "ai": {
                "enabled": True,
                "api_key": "ai-key",
                "base_url": "https://llm.example/v1",
                "model": "model-x",
                "min_confidence": 0.7,
                "max_domains": 7,
            },
        },
        cache={"directory": "custom-cache-dir"},
    )
    engine = AsyncRuleEngine.from_config(cfg)
    audit = engine._build_audit_config()

    # Direct 1:1 fields (source value must arrive unchanged).
    direct = {
        "use_dns": cfg.whitelist_audit.use_dns,
        "use_urlhaus": cfg.whitelist_audit.use_urlhaus,
        "use_threatfox": cfg.whitelist_audit.use_threatfox,
        "use_rdap": cfg.whitelist_audit.use_rdap,
        "use_scam_check": cfg.whitelist_audit.use_scam_check,
        "use_dnsbl": cfg.whitelist_audit.use_dnsbl,
        "cache_results": cfg.whitelist_audit.cache_results,
        "cache_dir": cfg.cache.directory,
        "use_virustotal": cfg.whitelist_audit.use_virustotal,
        "virustotal_api_key": cfg.whitelist_audit.virustotal_api_key,
        "use_ai": cfg.whitelist_audit.ai.enabled,
        "ai_api_key": cfg.whitelist_audit.ai.api_key,
        "ai_base_url": cfg.whitelist_audit.ai.base_url,
        "ai_model": cfg.whitelist_audit.ai.model,
        "ai_min_confidence": cfg.whitelist_audit.ai.min_confidence,
        "ai_max_domains": cfg.whitelist_audit.ai.max_domains,
        "concurrency": cfg.whitelist_audit.concurrency,
        "urlhaus_delay": cfg.whitelist_audit.urlhaus_delay,
        "new_domain_threshold_days": cfg.whitelist_audit.new_domain_threshold_days,
        "ti_mode": cfg.whitelist_audit.ti_mode,
        "feed_ttl_seconds": cfg.whitelist_audit.feed_ttl_seconds,
        "use_heuristics": cfg.whitelist_audit.use_heuristics,
        "doh_endpoint": cfg.whitelist_audit.doh_endpoint,
        "use_homograph": cfg.whitelist_audit.use_homograph,
        "use_dns_mx": cfg.whitelist_audit.use_dns_mx,
        "use_gsb": cfg.whitelist_audit.use_gsb,
        "gsb_api_key": cfg.whitelist_audit.gsb_api_key,
        "use_phishtank": cfg.whitelist_audit.use_phishtank,
        "phishtank_api_key": cfg.whitelist_audit.phishtank_api_key,
        "use_urlscan": cfg.whitelist_audit.use_urlscan,
        "urlscan_api_key": cfg.whitelist_audit.urlscan_api_key,
        "use_crtsh": cfg.whitelist_audit.use_crtsh,
    }
    for field, expected in direct.items():
        assert getattr(audit, field) == expected, f"AuditConfig.{field} not wired from config"

    # fusion_weights: shallow merge — user keys override, defaults preserved.
    assert audit.fusion_weights["heuristics"] == 99
    assert audit.fusion_weights["threat_intel"] == AuditConfig().fusion_weights["threat_intel"]

    # Completeness: every AuditConfig dataclass field is either wired above or
    # explicitly whitelisted (audit-only knobs that MergeConfig does not carry).
    mapped = set(direct) | {"fusion_weights"}
    whitelisted = {
        # AuditConfig-only internal parameters, not exposed as YAML knobs
        # (kept at their dataclass defaults; surfaced here so any future
        # wiring shows up as a deliberate change to this test).
        "doh_timeout",
        "cache_ttl_seconds",
    }
    audit_fields = {f.name for f in dataclass_fields(AuditConfig)}
    unwired = audit_fields - mapped - whitelisted
    assert not unwired, f"AuditConfig fields never populated by _build_audit_config: {unwired}"


def test_from_config_keeps_canonical_config_reference():
    cfg = MergeConfig()
    engine = AsyncRuleEngine.from_config(cfg)
    assert engine.config is cfg
