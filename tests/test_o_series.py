"""O-series: O-1 coverage, O-2 homograph cache, O-3 lock, O-4 TLD."""

from merger.homograph import detect_typosquat
from merger.models import intern_source, reset_source_registry


def test_o4_confusable_tld_homograph():
    r = detect_typosquat("paypal.cоm")  # Cyrillic о in TLD
    assert r["homograph"] is True


def test_o2_homograph_brand_label():
    r = detect_typosquat("paypаl.com")  # Cyrillic а
    assert r["homograph"] is True


def test_o3_intern_source_distinct_bits():
    reset_source_registry()
    a = intern_source("src-a")
    b = intern_source("src-b")
    assert a != b
    assert intern_source("src-a") == a
    reset_source_registry()
