"""Config-fingerprinted v2 disk cache for audit results (fixed TTL, pruned on save).

Moved verbatim during the P1-3 package split; fingerprint fields, TTL and v1
migration are unchanged.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import time
from pathlib import Path
from typing import Any

from ..version import AUDIT_CACHE_VERSION
from .config import AuditConfig
from .constants import _PRIVATE_NETS, AUDIT_CACHE_FILENAME

logger = logging.getLogger(__name__)


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


# ── V5.3 disk cache (config-fingerprinted, fixed TTL, v2 format) ───


def _disk_cache_path(config: AuditConfig) -> Path:
    return Path(config.cache_dir) / AUDIT_CACHE_FILENAME


def _cfg_fingerprint(config: AuditConfig) -> str:
    """Stable hash of audit-affecting config (layers + weights + thresholds).

    Changing any of these invalidates stale cache entries for this config,
    so flipping a layer switch or a fusion weight produces a fresh subtree
    instead of returning decisions made under the old configuration.
    """
    layers = (
        config.use_dns,
        config.use_urlhaus,
        config.use_threatfox,
        config.use_rdap,
        config.use_scam_check,
        config.use_dnsbl,
        config.use_virustotal,
        config.use_ai,
        config.use_heuristics,
        # V6 layers
        config.use_homograph,
        config.use_dns_mx,
        config.use_gsb,
        config.use_phishtank,
        config.use_urlscan,
        config.use_crtsh,
    )
    payload = {
        "schema": AUDIT_CACHE_VERSION,
        "layers": layers,
        "fusion_weights": config.fusion_weights,
        "new_domain_threshold_days": config.new_domain_threshold_days,
        "cache_ttl_seconds": config.cache_ttl_seconds,
        "doh_endpoint": config.doh_endpoint,
        # Dimensions that change a verdict but were previously missing, so
        # rotating a key / flipping a threshold / switching TI mode would
        # otherwise reuse stale decisions computed under the old settings.
        "ai_min_confidence": config.ai_min_confidence,
        "ti_mode": config.ti_mode,
        "feed_ttl_seconds": config.feed_ttl_seconds,
        # Key fingerprints (not the secrets themselves): presence/value of an
        # online key changes which layers run and what they return.
        "vt_api_key_present": bool(config.virustotal_api_key),
        "ai_api_key_present": bool(config.ai_api_key),
        "gsb_api_key_present": bool(config.gsb_api_key),
        "phishtank_api_key_present": bool(config.phishtank_api_key),
        "urlscan_api_key_present": bool(config.urlscan_api_key),
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _disk_cache_load(config: AuditConfig) -> dict[str, dict[str, Any]]:
    """Load {domain: result} entries still inside the TTL window (v2 format).

    v1 files (flat ``{"version":1,"entries":{...}}``) are read as if their
    entries belonged to the current config fingerprint, so the first save
    after an upgrade migrates them into the v2 subtree automatically.
    """
    if not config.cache_results:
        return {}
    p = _disk_cache_path(config)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("whitelist audit cache unreadable: %s", e)
        return {}
    fp = _cfg_fingerprint(config)
    now = time.time()
    ttl = config.cache_ttl_seconds
    out: dict[str, dict[str, Any]] = {}
    if data.get("version", 1) >= AUDIT_CACHE_VERSION:
        subtree = (data.get("configs") or {}).get(fp) or {}
        for domain, rec in (subtree.get("entries") or {}).items():
            if now - rec.get("ts", 0) < ttl:
                out[domain] = rec.get("result") or {}
    else:
        for domain, rec in (data.get("entries") or {}).items():
            if now - rec.get("ts", 0) < ttl:
                out[domain] = rec.get("result") or {}
    return out


def _disk_cache_save(config: AuditConfig, fresh: dict[str, dict[str, Any]]) -> None:
    """Persist fresh results to the v2 disk cache (fixed TTL, no ts refresh).

    Existing non-expired entries keep their original ``ts`` (fixed-TTL
    semantics — an entry fetched 23h ago is not "renewed" to now just
    because a later run touched the file). Expired entries are pruned.
    A v1 file on disk is migrated into the current fingerprint subtree.
    """
    if not config.cache_results or not fresh:
        return
    p = _disk_cache_path(config)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fp = _cfg_fingerprint(config)
        now = time.time()
        ttl = config.cache_ttl_seconds
        existing_configs: dict[str, Any] = {}
        if p.exists():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = {}
            if raw.get("version", 1) >= AUDIT_CACHE_VERSION:
                existing_configs = raw.get("configs") or {}
            elif raw.get("entries"):
                existing_configs[fp] = {"entries": raw["entries"]}
        subtree = existing_configs.get(fp) or {}
        old_entries = subtree.get("entries") or {}
        merged: dict[str, Any] = {}
        for domain, rec in old_entries.items():
            if now - rec.get("ts", 0) < ttl:
                merged[domain] = rec
        for domain, result in fresh.items():
            merged[domain] = {"ts": now, "result": result}
        existing_configs[fp] = {"entries": merged}
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(
                {"version": AUDIT_CACHE_VERSION, "configs": existing_configs},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        tmp.replace(p)
    except OSError as e:
        logger.warning("whitelist audit cache write failed: %s", e)
