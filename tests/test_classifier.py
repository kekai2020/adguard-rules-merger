"""Tests for V5 domain classifier (tldextract-based, registered-domain matching)."""

from merger.domain_classifier import (
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    CONFIDENCE_REGISTERED,
    CONFIDENCE_SUBDOMAIN,
    category_counts,
    classify_batch,
    classify_domain,
    classify_domain_with_confidence,
)

# ── registered-domain exact matches (high confidence) ──────────────


def test_advertising_registered():
    assert classify_domain("5471782.fls.doubleclick.net") == "advertising"
    assert classify_domain("adsrvmedia.adk2.co") == "advertising"
    assert classify_domain("googleadservices.com") == "advertising"
    cat, conf, reason = classify_domain_with_confidence("doubleclick.net")
    assert cat == "advertising"
    assert conf == CONFIDENCE_REGISTERED


def test_cdn_registered():
    assert classify_domain("79423.analytics.edgekey.net") == "cdn"
    cat, conf, _ = classify_domain_with_confidence("cdn.edgekey.net")
    assert cat == "cdn"
    assert conf == CONFIDENCE_REGISTERED


def test_microsoft_telemetry_registered():
    assert classify_domain("edge.activity.windows.com") == "microsoft_telemetry"
    assert classify_domain("settings-win.data.microsoft.com") == "microsoft_telemetry"
    assert classify_domain("dns.msftncsi.com") == "microsoft_telemetry"


def test_affiliate_registered():
    assert classify_domain("awin1.com") == "affiliate"
    assert classify_domain("go.redirectingat.com") == "affiliate"


def test_social_registered():
    assert classify_domain("res.wx.qq.com") == "social"
    assert classify_domain("graph.facebook.com") == "social"


def test_ecommerce_registered():
    assert classify_domain("data.orders.costco.com") == "ecommerce_payment"
    assert classify_domain("api.paypal.com") == "ecommerce_payment"


def test_privacy_security_registered():
    assert classify_domain("dns.adguard.com") == "privacy_security"
    assert classify_domain("www.virustotal.com") == "privacy_security"


def test_analytics_registered():
    assert classify_domain("analytics.amplitude.com") == "analytics"
    assert classify_domain("www.statcounter.com") == "analytics"


# ── subdomain prefix matches (medium confidence) ───────────────────


def test_subdomain_prefix_cdn():
    cat, conf, reason = classify_domain_with_confidence("cdn.duurzaam.greenchoice.nl")
    assert cat == "cdn"
    assert conf == CONFIDENCE_SUBDOMAIN
    assert "subdomain prefix: cdn" in reason


def test_subdomain_prefix_affiliate():
    cat, conf, _ = classify_domain_with_confidence("click.avs.io")
    assert cat == "affiliate"
    assert conf == CONFIDENCE_SUBDOMAIN


def test_subdomain_prefix_advertising():
    cat, conf, _ = classify_domain_with_confidence("ads.example.com")
    assert cat == "advertising"
    assert conf == CONFIDENCE_SUBDOMAIN


def test_subdomain_prefix_analytics():
    cat, conf, _ = classify_domain_with_confidence("metrics.example.org")
    assert cat == "analytics"


# ── anti-false-positive: PSL prevents substring attacks ───────────


def test_apple_pay_not_misclassified():
    """apple-pay.com should NOT match 'apple' — we match registered domain."""
    assert classify_domain("apple-pay.com") == "other"


def test_evil_company_not_subdomain():
    """evil-company.com is a registered domain, NOT a subdomain of company.com."""
    assert classify_domain("evil-company.com") == "other"


def test_co_uk_psl():
    """sub.domain.co.uk → registered=domain.co.uk, not subdomain of co.uk."""
    assert classify_domain("sub.domain.co.uk") == "other"


def test_unknown_domain_other():
    assert classify_domain("widget.intercom.io") == "other"
    assert classify_domain("official.paymaya.com") == "other"
    assert classify_domain("sponsor.nitropay.com") == "other"


# ── batch & counts ─────────────────────────────────────────────────


def test_classify_batch():
    result = classify_batch(["doubleclick.net", "google.com"])
    assert result["doubleclick.net"] == "advertising"
    assert result["google.com"] == "other"


def test_category_counts_includes_all():
    counts = category_counts(["advertising", "advertising", "cdn"])
    assert counts["advertising"] == 2
    assert counts["cdn"] == 1
    assert counts["other"] == 0
    assert set(counts.keys()) == set(CATEGORY_ORDER)


def test_category_labels_complete():
    for cat in CATEGORY_ORDER:
        assert cat in CATEGORY_LABELS


def test_case_insensitive():
    assert classify_domain("DoubleClick.NET") == "advertising"


def test_confidence_levels():
    _, conf_reg, _ = classify_domain_with_confidence("doubleclick.net")
    _, conf_sub, _ = classify_domain_with_confidence("ads.example.com")
    _, conf_none, _ = classify_domain_with_confidence("unknown.example.com")
    assert conf_reg > conf_sub > conf_none
