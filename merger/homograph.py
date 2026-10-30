"""Offline homograph / typosquat detection (pure stdlib, zero network).

Two independent signals, both evaluated against a built-in brand reference
set (eTLD+1 core labels of widely impersonated services):

1. **Homograph attack** — non-Latin characters that look identical to Latin
   ones (Cyrillic ``о``→``o``, Greek ``α``→``a`` ...) are folded to Latin;
   a folded core that exactly matches a brand while the raw core still
   contains the confusable is flagged.
2. **Typosquat** — length-aware Levenshtein edit distance against the same
   brand set; short labels use a stricter threshold than long ones.

The module intentionally performs no DNS, no HTTP and no IO. Every function
is exception-tolerant at the call boundary (whitelist_audit wraps the result
in try/except).
"""

from __future__ import annotations

import functools
from typing import Any

# ── Confusable fold table: non-Latin lookalike → Latin ──────────────
# Only visually identical pairs are mapped; ambiguous glyphs are excluded
# to keep false positives down.
_HOMOGRAPH_FOLD: dict[str, str] = {
    # Cyrillic lowercase
    "а": "a",
    "в": "b",
    "е": "e",
    "һ": "h",
    "і": "i",
    "ј": "j",
    "к": "k",
    "м": "m",
    "н": "n",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "ѕ": "s",
    # Cyrillic uppercase
    "А": "a",
    "В": "b",
    "Е": "e",
    "І": "i",
    "К": "k",
    "М": "m",
    "Н": "h",
    "О": "o",
    "Р": "p",
    "С": "c",
    "Т": "t",
    "У": "y",
    "Х": "x",
    # Greek lowercase (visually identical only)
    "α": "a",
    "β": "b",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "μ": "m",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "ν": "n",
    "υ": "u",
    "ω": "w",
    "η": "h",
}

# ── Built-in brand reference set (core labels, lowercase) ────────────
_BRANDS: frozenset[str] = frozenset(
    {
        "google",
        "gmail",
        "facebook",
        "amazon",
        "microsoft",
        "msn",
        "paypal",
        "apple",
        "icloud",
        "netflix",
        "twitter",
        "instagram",
        "whatsapp",
        "telegram",
        "tiktok",
        "alipay",
        "taobao",
        "wechat",
        "weixin",
        "baidu",
        "youtube",
        "yahoo",
        "hotmail",
        "outlook",
        "linkedin",
        "reddit",
        "spotify",
        "github",
        "cloudflare",
        "stripe",
        "ebay",
        "alibaba",
        "aliexpress",
        "tmall",
        "douyin",
        "bilibili",
        "wikipedia",
        "bing",
        "duckduckgo",
        "twitch",
        "zoom",
        "snapchat",
        "discord",
        "skype",
        "signal",
        "weibo",
        "pinterest",
        "airbnb",
        "uber",
        "booking",
        "etsy",
        "shopify",
        "office",
        "windows",
        "android",
        "chrome",
        "firefox",
        "safari",
        "playstation",
        "xbox",
        "nintendo",
        "roblox",
        "minecraft",
        "tinder",
        "medium",
        "quora",
        "xiaohongshu",
        "meituan",
        "pinduoduo",
    }
)

# Phishing-kit subdomain / label prefixes stripped before brand comparison.
_PHISH_PREFIXES: frozenset[str] = frozenset(
    {
        "www",
        "mail",
        "login",
        "signin",
        "secure",
        "account",
        "accounts",
        "my",
        "support",
        "help",
        "info",
        "portal",
        "admin",
        "home",
        "web",
        "app",
        "mobile",
        "site",
        "page",
        "verify",
        "verification",
        "auth",
        "member",
        "user",
        "service",
        "go",
        "link",
        "click",
        "redirect",
        "sso",
        "dashboard",
        "control",
        "panel",
        "cloud",
        "online",
        "official",
        "customer",
        "care",
        "contact",
        "safe",
        "security",
        "update",
        "download",
        "reset",
        "password",
        "register",
        "signup",
    }
)


def fold_homographs(label: str) -> str:
    """Replace every non-Latin confusable in ``label`` with its Latin lookalike.

    Latin letters, digits and symbols are preserved untouched.
    """
    return "".join(_HOMOGRAPH_FOLD.get(ch, ch) for ch in label)


def max_typo_distance(label_len: int) -> int:
    """Length-aware Levenshtein cap: short labels are judged strictly.

    <=4 chars → 1 edit; 5-7 → 1; 8-10 → 2; >=11 → 3.
    """
    if label_len <= 7:
        return 1
    if label_len <= 10:
        return 2
    return 3


def levenshtein(a: str, b: str, cap: int | None = None) -> int:
    """Pure-Python Levenshtein edit distance (rows DP, optional early cap).

    When ``cap`` is set and the current row's minimum exceeds it, the
    function returns ``cap + 1`` early — enough for threshold matching
    without paying for exact distance on clearly-distant strings.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
            if cur[-1] < row_min:
                row_min = cur[-1]
        if cap is not None and row_min > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _strip_prefix(label: str) -> str:
    """Remove a common phishing prefix (``secure-``, ``login_`` ...) from a label."""
    for p in _PHISH_PREFIXES:
        if label == p:
            return ""
        for sep in ("-", "_", "."):
            if label.startswith(p + sep):
                return label[len(p) + 1 :]
    return label


_BRANDS_BY_LEN: dict[int, tuple[str, ...]] | None = None


def _brands_by_len() -> dict[int, tuple[str, ...]]:
    """Brands bucketed by length (O-2): a candidate only scans its length
    neighbourhood instead of the full brand set for every label."""
    global _BRANDS_BY_LEN
    if _BRANDS_BY_LEN is None:
        buckets: dict[int, list[str]] = {}
        for b in _BRANDS:
            if len(b) < 4:
                continue
            buckets.setdefault(len(b), []).append(b)
        _BRANDS_BY_LEN = {k: tuple(v) for k, v in buckets.items()}
    return _BRANDS_BY_LEN


@functools.lru_cache(maxsize=8192)
def _detect_candidate(cand: str) -> tuple[str, str, int, bool] | None:
    """Cacheable single-candidate homograph / typosquat verdict (O-2).

    Returns ``(matched_brand, folded, distance, homograph)`` or ``None``.
    Cached at the candidate (label) level so ``login`` / ``secure`` / ``www``
    etc. reused across thousands of domains are classified once.
    """
    folded = fold_homographs(cand)
    # Signal 1: homograph — folded exactly matches a brand but the raw label
    # still contains the non-Latin confusable.
    if folded in _BRANDS and folded != cand:
        return (folded, folded, 0, True)
    # Signal 2: typosquat — length-aware edit distance to a brand.
    cap = max_typo_distance(len(cand))
    best: tuple[str, int] | None = None
    for blen, brands in _brands_by_len().items():
        if abs(blen - len(cand)) > max_typo_distance(max(blen, len(cand))):
            continue
        for brand in brands:
            dist = levenshtein(cand, brand, cap=cap)
            if 0 < dist <= cap and (best is None or dist < best[1]):
                best = (brand, dist)
    if best:
        return (best[0], folded, best[1], False)
    return None


def detect_typosquat(domain: str) -> dict[str, Any]:
    """Offline homograph / typosquat audit for one domain.

    Returns ``{is_typosquat, matched_brand, distance, reasons, folded,
    homograph}``. ``homograph=True`` means non-Latin confusables were used;
    ``distance=0`` for a homograph exact match, otherwise the Levenshtein
    distance to the closest brand.
    """
    result: dict[str, Any] = {
        "is_typosquat": False,
        "matched_brand": None,
        "distance": None,
        "reasons": [],
        "folded": "",
        "homograph": False,
    }
    d = (domain or "").lower().strip(".")
    if not d:
        return result

    labels = d.split(".")
    last = len(labels) - 1
    for idx, label in enumerate(labels):  # O-4: include the TLD label
        candidates = {label.strip("-_.")}
        stripped = _strip_prefix(label).strip("-_.")
        if stripped:
            candidates.add(stripped)
        # Split stacked branding on separators ("micros0ft-update" →
        # "micros0ft", "update") and test each segment independently.
        for piece in label.replace("_", "-").split("-"):
            piece = piece.strip(".")
            if piece:
                candidates.add(piece)
        for cand in candidates:
            if not cand or cand in _BRANDS:
                continue
            hit = _detect_candidate(cand)
            if hit is None:
                continue
            matched, folded, dist, homograph = hit
            if homograph:
                result.update(
                    {
                        "is_typosquat": True,
                        "matched_brand": matched,
                        "distance": 0,
                        "homograph": True,
                        "folded": folded,
                        "reasons": [f"同形字仿冒品牌 {matched}"],
                    }
                )
                return result
            result.update(
                {
                    "is_typosquat": True,
                    "matched_brand": matched,
                    "distance": dist,
                    "homograph": False,
                    "folded": folded,
                    "reasons": [f"拼写劫持仿冒品牌 {matched}（编辑距离 {dist}）"],
                }
            )
            return result
        # O-4: a confusable TLD (e.g. ``cоm`` → ``com``) is itself a phishing
        # signal even when the folded TLD is not a brand.
        if idx == last and not label.isascii() and fold_homographs(label) != label:
            folded_tld = fold_homographs(label)
            result.update(
                {
                    "is_typosquat": True,
                    "matched_brand": folded_tld,
                    "distance": 0,
                    "homograph": True,
                    "folded": folded_tld,
                    "reasons": [f"同形字混淆顶级域 {folded_tld}"],
                }
            )
            return result
    return result
