"""Seed file loading and merging for the domain classifier."""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_SEEDS_PATH = Path(__file__).resolve().parent.parent / "data" / "category_seeds.json"


def _load_builtin_seeds() -> dict[str, str]:
    """Read ``data/category_seeds.json``; return {} on any read/parse failure.

    The file is a flat ``{registered domain: 9-class}`` map; keys starting
    with ``_`` (comments/metadata) are ignored.
    """
    try:
        with open(_SEEDS_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        logger.warning("built-in category seeds unavailable: %s", e)
        return {}
    return {k: v for k, v in data.items() if not k.startswith("_") and isinstance(v, str)}


# ── external offline seed files (Shallalist / UT1 style) ───────────
# External lists carry their own category IDs/names; collapse them into our
# 9 classes. Unmapped IDs (malware/phishing/gambling/porn/...) are dropped
# rather than forced into a bucket — offline rejudge only owns ads/tracking.
# Single source of truth: the table lives in .rules; importing it here keeps
# the legacy `seeds.EXTERNAL_CATEGORY_MAP` import path working.
from .rules import EXTERNAL_CATEGORY_MAP  # noqa: E402 — deliberately after the docs


def _clean_external_domain(raw: str) -> str:
    """Strip scheme/``||``/path/trailing dot from an external-list host."""
    d = raw.strip().lower()
    d = d.removeprefix("||")
    d = d.split("://", 1)[-1]
    d = d.split("/", 1)[0]
    return d.strip(".").strip()


def load_seed_file(path: str) -> dict[str, str]:
    """Parse an offline Shallalist/UT1-style seed file into ``{domain: 9-class}``.

    Lines are ``domain;category`` (Shallalist) or ``domain,category`` (UT1);
    ``#`` comment lines and blank lines are skipped; unknown category IDs are
    dropped. A missing file, OSError or parse error logs a warning and
    returns an empty dict — it never raises into the merge pipeline.
    """
    mapping: dict[str, str] = {}
    if not path:
        return mapping
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                sep = ";" if ";" in line else ("," if "," in line else "")
                if not sep:
                    continue
                dom, _, raw_cat = line.partition(sep)
                dom = _clean_external_domain(dom) or ""
                cat: str | None = EXTERNAL_CATEGORY_MAP.get(raw_cat.strip().lower())
                if dom and cat:
                    mapping[dom] = cat
    except OSError as e:
        logger.warning("classification seed_file unreadable %s: %s", path, e)
    except (ValueError, UnicodeDecodeError) as e:
        logger.warning("classification seed_file parse failed %s: %s", path, e)
    return mapping


def merge_seed_map(mapping: dict[str, str]) -> int:
    """Legacy compat: merge external seeds into the default singleton.

    setdefault semantics: hand-written and built-in entries always win;
    returns the number of newly added domains.  New code should build a
    ``ClassifierRuleSet`` and call ``with_seeds`` instead of mutating the
    process default.
    """
    from .ruleset import _DEFAULT_RULESET

    return _DEFAULT_RULESET.merge_seeds(mapping)


# ── offline verdict → block bucket mapping ─────────────────────────
# The whitelist classifier reasons in 9 purpose categories; the block
# pipeline only ships 6 buckets (ads/tracking/malware/phishing/mining/
# other).  Only advertising/marketing/telemetry verdicts are allowed to
# move a rule into ads/tracking:
#   advertising        → ads      (ad networks / SSPs / DSPs buy ad inventory)
#   affiliate          → ads      (affiliate/redirect attribution = marketing)
#   analytics          → tracking (site analytics/RUM = behavioural tracking)
#   social             → tracking (social widgets/platforms track; no social
#                                  bucket exists in the block pipeline)
#   microsoft_telemetry→ tracking (Windows/Office telemetry pings)
# cdn / ecommerce_payment / privacy_security / other are deliberately absent:
# infrastructure, commerce and security tools keep the source-declared
# bucket — a heuristic must never push a CDN/payment/security domain into
# malware/phishing/mining (or out of it).  Security-declared rules are
# filtered by the caller before this map is consulted, so a high-confidence
# advertising verdict can never downgrade a security bucket.
