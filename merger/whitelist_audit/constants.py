"""Shared constants: API endpoints, DNSBL tables, ratings, cache settings.

Moved verbatim during the P1-3 package split; no value, weight or wording changed.
"""

from __future__ import annotations

import ipaddress

URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

# ── V5.2 DNSBL zones (free keyless DNS lookups) ───────────────────
# Not listed = NXDOMAIN (the normal case). A 127.0.0.x answer = listed.
DNSBL_LISTS = (
    ("dbl.spamhaus.org", "SpamhausDBL"),
    ("multi.surbl.org", "SURBL"),
)
# Spamhaus returns these prefixes when queried from public/open resolvers —
# they mean "query blocked", not "domain listed". Must never be treated as a
# listing (would false-positive every domain on a public resolver).
_DNSBL_BLOCKED = ("127.255.255.", "127.255.254.")

# Spamhaus DBL return codes (last octet).
_DBL_CODES = {
    10: ("spam", False),
    11: ("phishing", True),
    12: ("malware", True),
    13: ("botnet-c2", True),
    14: ("abused-spam", False),
    15: ("hijacked", False),
}
# SURBL multi.surbl.org is a bitmask in the last octet.
_SURBL_BITS = (
    (4, "scam", True),
    (8, "junk", False),
    (16, "phishing", True),
    (32, "malware", True),
    (64, "abused-ads", False),
)

RATING_MALICIOUS = "malicious"
RATING_SUSPICIOUS = "suspicious"
RATING_SAFE = "safe"
RATING_UNKNOWN = "unknown"

CACHE_TTL = 86400  # 24 hours
AUDIT_CACHE_FILENAME = "whitelist_audit_cache.json"

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


# Abused / disposable TLDs frequently used in phishing kits. Conservative
# list — a match alone is not enough to mark a domain suspicious.
_SUSPICIOUS_TLDS = frozenset(
    {
        "xyz",
        "top",
        "click",
        "country",
        "cfd",
        "sbs",
        "zip",
        "mov",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga",
        "work",
        "bond",
        "rest",
        "cyou",
        "qpon",
        "monster",
        "quest",
        "icu",
        "cam",
        "lol",
        "pics",
        "buzz",
        # V6: additional frequently-abused cheap TLDs (conservative; a match
        # alone only adds 1 point, escalation still needs score >= 3).
        "party",
        "review",
        "vip",
        "world",
        "site",
        "online",
        "store",
        "shop",
        "tech",
        "today",
        "stream",
        "racing",
        "club",
        "zone",
        "fun",
        "life",
        "news",
    }
)

# Rating → human-readable action recommendation.
_RECOMMEND = {
    "malicious": "remove",
    "suspicious": "review",
    "unknown": "review",
    "safe": "keep",
}
_RECOMMEND_LABEL = {
    "remove": "建议移除",
    "review": "建议复核",
    "keep": "建议保留",
}
