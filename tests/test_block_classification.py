"""Offline high-confidence block-rule reclassification tests (front:
"块规则分类覆盖全面化（离线高置信重判）").

Covers:
- Pure ``block_bucket_for`` mapping from the 9 offline whitelist categories to
  the 6 block buckets (ads/tracking/malware/phishing/mining/other).
- Engine-level rejudge: only high-confidence registered-domain exact matches
  may override the source-declared bucket; security declarations are never
  downgraded; CDN / payment / privacy / unknown keep their source bucket.
- The switch defaults to OFF: with it disabled every rule keeps its source
  category and all artifacts (tiered files + stats.json) are byte-identical.
- Medium-confidence subdomain-prefix verdicts keep the source bucket.
"""

from __future__ import annotations

import hashlib

from merger.config import MergeConfig
from merger.core import AsyncRuleEngine
from merger.domain_classifier import (
    CONFIDENCE_NONE,
    CONFIDENCE_REGISTERED,
    CONFIDENCE_SUBDOMAIN,
    block_bucket_for,
)
from merger.exporter import Exporter
from merger.models import SourceMeta

# ── pure mapping: 9 offline categories → 6 block buckets ────────────


def test_block_bucket_for_advertising_and_affiliate_go_to_ads():
    assert block_bucket_for("advertising", CONFIDENCE_REGISTERED) == "ads"
    assert block_bucket_for("affiliate", CONFIDENCE_REGISTERED) == "ads"


def test_block_bucket_for_analytics_social_telemetry_go_to_tracking():
    assert block_bucket_for("analytics", CONFIDENCE_REGISTERED) == "tracking"
    assert block_bucket_for("social", CONFIDENCE_REGISTERED) == "tracking"
    assert block_bucket_for("microsoft_telemetry", CONFIDENCE_REGISTERED) == "tracking"


def test_block_bucket_for_neutral_categories_keep_source_bucket():
    # CDN / payment / privacy-security / other must never be force-moved into
    # malware/phishing/mining or ads/tracking by the offline verdict.
    for cat in ("cdn", "ecommerce_payment", "privacy_security", "other"):
        assert block_bucket_for(cat, CONFIDENCE_REGISTERED) is None, cat


def test_block_bucket_for_rejects_medium_and_low_confidence():
    # Subdomain prefix (0.6) and no-hit (0.0) verdicts keep the source bucket.
    assert block_bucket_for("advertising", CONFIDENCE_SUBDOMAIN) is None
    assert block_bucket_for("analytics", CONFIDENCE_NONE) is None
    assert block_bucket_for("social", CONFIDENCE_SUBDOMAIN) is None


# ── engine fixtures ────────────────────────────────────────────────


def _run_local(tmp_path, text: str, category: str, classification_enabled: bool):
    src = tmp_path / "source.txt"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(text, encoding="utf-8")
    engine = AsyncRuleEngine(cache_dir=None, classification_enabled=classification_enabled)
    return engine.run_sync([SourceMeta(name="s1", url=str(src), category=category)])


def _by_domain(outcome) -> dict[str, str]:
    return {r.normalized_domain: r.category for r in outcome.blocks}


# ── high-confidence rejudge on ──────────────────────────────────────

_ADS_TEXT = (
    "||doubleclick.net^\n"  # advertising → ads
    "||awin1.com^\n"  # affiliate → ads
)

_TRACKING_TEXT = (
    "||google-analytics.com^\n"  # analytics → tracking
    "||facebook.com^\n"  # social → tracking
    "||microsoft.com^\n"  # microsoft_telemetry → tracking
)

_NEUTRAL_TEXT = (
    "||cloudfront.net^\n"  # cdn → keep source
    "||adguard.com^\n"  # privacy_security → keep source
    "||zzqk-unknown-marker.example.net^\n"  # no match → keep source
)


def test_high_confidence_advertising_redirected_to_ads(tmp_path):
    outcome = _run_local(tmp_path, _ADS_TEXT, "other", classification_enabled=True)
    cats = _by_domain(outcome)
    assert cats["doubleclick.net"] == "ads"
    assert cats["awin1.com"] == "ads"


def test_high_confidence_analytics_social_telemetry_redirected_to_tracking(tmp_path):
    outcome = _run_local(tmp_path, _TRACKING_TEXT, "other", classification_enabled=True)
    cats = _by_domain(outcome)
    assert cats["google-analytics.com"] == "tracking"
    assert cats["facebook.com"] == "tracking"
    assert cats["microsoft.com"] == "tracking"


def test_cdn_privacy_unknown_keep_source_bucket(tmp_path):
    outcome = _run_local(tmp_path, _NEUTRAL_TEXT, "other", classification_enabled=True)
    cats = _by_domain(outcome)
    assert cats["cloudfront.net"] == "other"
    assert cats["adguard.com"] == "other"
    assert cats["zzqk-unknown-marker.example.net"] == "other"


def test_security_declaration_never_downgraded(tmp_path):
    # A malware-declared ad network must stay malware even though the offline
    # classifier labels it advertising.
    text = "||doubleclick.net^\n"
    for declared in ("malware", "phishing", "mining"):
        outcome = _run_local(tmp_path / declared, text, declared, classification_enabled=True)
        cats = _by_domain(outcome)
        assert cats["doubleclick.net"] == declared, declared


def test_medium_confidence_keeps_source_bucket(tmp_path):
    # "ads.example.com" only matches the subdomain prefix (0.6) → keep source.
    text = "||ads.example.com^\n"
    outcome = _run_local(tmp_path, text, "other", classification_enabled=True)
    assert _by_domain(outcome)["ads.example.com"] == "other"


# ── registered_only=False: medium-confidence (0.6) prefix may override ──


def _run_relaxed(tmp_path, text: str, category: str):
    src = tmp_path / "source.txt"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(text, encoding="utf-8")
    engine = AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_registered_only=False,
    )
    return engine.run_sync([SourceMeta(name="s1", url=str(src), category=category)])


def test_relaxed_mode_prefix_advertising_moves_to_ads(tmp_path):
    # First-label "ads" → advertising at 0.6; relaxed mode accepts it.
    outcome = _run_relaxed(tmp_path, "||ads.example.com^\n", "other")
    assert _by_domain(outcome)["ads.example.com"] == "ads"


def test_relaxed_mode_prefix_social_moves_to_tracking(tmp_path):
    outcome = _run_relaxed(tmp_path, "||social.example.com^\n", "other")
    assert _by_domain(outcome)["social.example.com"] == "tracking"


def test_relaxed_mode_cdn_prefix_keeps_source_bucket(tmp_path):
    # "cdn" is neutral (absent from BLOCK_BUCKET_MAP): relaxed mode must not
    # force a CDN-labeled prefix into ads/tracking.
    outcome = _run_relaxed(tmp_path, "||cdn.example.com^\n", "other")
    assert _by_domain(outcome)["cdn.example.com"] == "other"


def test_relaxed_mode_security_bucket_never_downgraded(tmp_path):
    # Even with registered_only=False, a security declaration is filtered
    # before any offline verdict can move it.
    text = "||ads.example.com^\n"
    for declared in ("malware", "phishing", "mining"):
        outcome = _run_relaxed(tmp_path / declared, text, declared)
        assert _by_domain(outcome)["ads.example.com"] == declared, declared


def test_relaxed_mode_no_hit_keeps_source(tmp_path):
    outcome = _run_relaxed(tmp_path, "||zzqk-unknown-marker.example.net^\n", "other")
    assert _by_domain(outcome)["zzqk-unknown-marker.example.net"] == "other"


# ── switch off: byte / count parity with the default pipeline ────


def test_disabled_keeps_source_categories(tmp_path):
    outcome = _run_local(
        tmp_path, _ADS_TEXT + _TRACKING_TEXT, "other", classification_enabled=False
    )
    for dom, cat in _by_domain(outcome).items():
        assert cat == "other", dom


def test_disabled_and_enabled_artifacts_byte_identical_without_hits(tmp_path):
    # A source with nothing classifiable: enabled vs disabled must produce
    # byte-identical tiered files and stats.json (default pipeline untouched).
    text = "||alpha-unknown-marker.example.net^\n||beta-unknown-marker.example.org^\n"
    buckets = {}
    for tag, enabled in (("off", False), ("on", True)):
        outcome = _run_local(tmp_path / tag, text, "other", classification_enabled=enabled)
        out = tmp_path / tag / "out"
        Exporter(out, report=False, write_diff=False).export_all(
            outcome.blocks, outcome.allows, outcome
        )
        buckets[tag] = {}
        for name in (
            "merged_rules.txt",
            "merged_ads.txt",
            "merged_malware.txt",
            "merged_tracking.txt",
            "merged_phishing.txt",
            "merged_mining.txt",
            "merged_other.txt",
            "stats.json",
        ):
            buckets[tag][name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    assert buckets["off"] == buckets["on"]


# ── config defaults + wiring ────────────────────────────────────────


def test_classification_config_defaults_off():
    cfg = MergeConfig()
    assert cfg.classification.enabled is False
    assert cfg.classification.rejudge_registered_only is True


def test_from_config_wires_classification_flag():
    cfg = MergeConfig()
    engine = AsyncRuleEngine.from_config(cfg)
    assert engine.classification_enabled is False
    assert engine.classification_registered_only is True

    cfg.classification.enabled = True
    engine = AsyncRuleEngine.from_config(cfg)
    assert engine.classification_enabled is True
