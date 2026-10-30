"""``merger.whitelist_audit`` package: multi-layer whitelist auditor.

Backwards-compatible facade: every import path that worked against the old
flat ``merger/whitelist_audit.py`` keeps working (including test-visible privates).
"""

from .config import AuditConfig, _CacheEntry
from .constants import (
    AUDIT_CACHE_FILENAME,
    CACHE_TTL,
    DNSBL_LISTS,
    RATING_MALICIOUS,
    RATING_SAFE,
    RATING_SUSPICIOUS,
    RATING_UNKNOWN,
    THREATFOX_API,
    URLHAUS_HOST_API,
)
from .disk_cache import (
    _cfg_fingerprint,
    _disk_cache_load,
    _disk_cache_path,
    _disk_cache_save,
    _is_private_ip,
)
from .dns_doh import _dns_check, _doh_lookup, _parse_doh_json, _query_mx_spf
from .dnsbl import _dnsbl_lookup, _query_dnsbl, parse_dnsbl_response
from .engine import audit_whitelist
from .fusion import _fuse_rating
from .heuristics import local_heuristics, recycled_domain_clue
from .online import (
    CRT_SH_API,
    GSB_LOOKUP_API,
    PHISHTANK_API,
    URLSCAN_SEARCH_API,
    _query_crtsh,
    _query_gsb,
    _query_phishtank,
    _query_urlscan,
)
from .rdap import _query_rdap_wrapper
from .threat_intel import (
    _query_threat_intel,
    _query_threat_intel_dataset,
    _query_threatfox,
    _query_urlhaus,
)

__all__ = [
    "audit_whitelist",
    "AuditConfig",
    "RATING_MALICIOUS",
    "RATING_SUSPICIOUS",
    "RATING_SAFE",
    "RATING_UNKNOWN",
    "local_heuristics",
    "recycled_domain_clue",
    "parse_dnsbl_response",
    "_fuse_rating",
    "_is_private_ip",
    "_query_gsb",
    "_query_phishtank",
    "_query_urlscan",
    "_query_crtsh",
    "_query_dnsbl",
    "_dnsbl_lookup",
    "_dns_check",
    "_doh_lookup",
    "_parse_doh_json",
    "_query_mx_spf",
    "_query_urlhaus",
    "_query_threatfox",
    "_query_threat_intel",
    "_query_threat_intel_dataset",
    "_query_rdap_wrapper",
    "_disk_cache_load",
    "_disk_cache_save",
    "_disk_cache_path",
    "_cfg_fingerprint",
    "_CacheEntry",
    "CACHE_TTL",
    "AUDIT_CACHE_FILENAME",
    "DNSBL_LISTS",
    "URLHAUS_HOST_API",
    "THREATFOX_API",
    "GSB_LOOKUP_API",
    "PHISHTANK_API",
    "URLSCAN_SEARCH_API",
    "CRT_SH_API",
]
