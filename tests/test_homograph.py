"""Offline homograph / typosquat layer tests + fusion wiring (zero network).

Covers:
  - Cyrillic/Greek homograph folding against the built-in brand reference set
  - length-aware Levenshtein typosquat matching (threshold boundaries)
  - benign / exact-brand domains must never be flagged
  - _fuse_rating weights the new signals; a layer error never blocks others
  - switching a layer off removes its signal from the score
"""

import pytest

from merger.homograph import (
    detect_typosquat,
    fold_homographs,
    levenshtein,
    max_typo_distance,
)
from merger.whitelist_audit import (
    RATING_MALICIOUS,
    RATING_SAFE,
    RATING_SUSPICIOUS,
    AuditConfig,
    _fuse_rating,
    recycled_domain_clue,
)

# ── fusion fixtures (same clean baseline as test_audit_enrichment) ──

_CLEAN = {"malicious": False, "error": None}
_DNS_OK = {"nxdomain": False, "ips": ["93.184.216.34"], "error": None}
_RDAP_OK = {"is_new_domain": False, "domain_age_days": 500, "registrar": "R", "error": None}
_SCAM_OK = {
    "is_suspicious": False,
    "is_confirmed_scam": False,
    "decision": "LEGIT",
    "risk_score": 0,
    "reasons": [],
    "error": None,
}
_VT_OFF = {"malicious": False, "error": "disabled", "reputation_score": 0.0}


def _cfg(**kw):
    kw.setdefault("use_urlhaus", True)
    kw.setdefault("use_threatfox", True)
    kw.setdefault("use_virustotal", False)
    return AuditConfig(**kw)


# ── homograph folding ────────────────────────────────────────────────


class TestFoldHomographs:
    def test_cyrillic_es_fold_to_latin(self):
        assert fold_homographs("аеорс") == "aeopc"

    def test_latin_untouched(self):
        assert fold_homographs("google") == "google"

    def test_mixed_script_folds(self):
        # Cyrillic о (U+043E) inside an otherwise latin label
        folded = fold_homographs("gоogle")
        assert folded == "google"


# ── homograph / typosquat detection ───────────────────────────────────


class TestDetectTyposquat:
    def test_cyrillic_homograph_google_hit(self):
        # "gоogle" with Cyrillic о (U+043O)
        res = detect_typosquat("gоogle.com")
        assert res["is_typosquat"] is True
        assert res["matched_brand"] == "google"
        assert res["homograph"] is True
        assert res["distance"] == 0
        assert res["folded"] == "google"

    def test_greek_homograph_facebook_hit(self):
        # "fαcebook" with Greek alpha (U+03B1)
        res = detect_typosquat("fαcebook.com")
        assert res["is_typosquat"] is True
        assert res["matched_brand"] == "facebook"
        assert res["homograph"] is True

    def test_exact_brand_not_flagged(self):
        for d in ("google.com", "facebook.com", "microsoft.com", "paypal.com"):
            res = detect_typosquat(d)
            assert res["is_typosquat"] is False, d
            assert res["matched_brand"] is None

    def test_benign_ordinary_domain_not_flagged(self):
        for d in ("example.com", "github.com", "mysite.org", "weather-report.net"):
            res = detect_typosquat(d)
            assert res["is_typosquat"] is False, d

    def test_typosquat_one_edit_google(self):
        res = detect_typosquat("gogle.com")
        assert res["is_typosquat"] is True
        assert res["matched_brand"] == "google"
        assert res["distance"] == 1
        assert res["homograph"] is False

    def test_typosquat_digit_substitution_microsoft(self):
        res = detect_typosquat("micros0ft.com")
        assert res["is_typosquat"] is True
        assert res["matched_brand"] == "microsoft"
        assert res["distance"] == 1

    def test_prefix_stripped_homograph_hit(self):
        # phishing subdomain prefix before the homograph brand core
        res = detect_typosquat("secure-gоogle.login.com")
        assert res["is_typosquat"] is True
        assert res["matched_brand"] == "google"

    def test_far_domain_not_flagged(self):
        res = detect_typosquat("weatherreport.com")
        assert res["is_typosquat"] is False

    def test_result_shape(self):
        res = detect_typosquat("example.com")
        for key in ("is_typosquat", "matched_brand", "distance", "reasons", "folded"):
            assert key in res


# ── Levenshtein + length-aware thresholds ───────────────────────────


class TestLevenshtein:
    def test_basic_distances(self):
        assert levenshtein("google", "gogle") == 1
        assert levenshtein("google", "gooogle") == 1
        assert levenshtein("microsoft", "microsoft") == 0
        assert levenshtein("paypal", "paypa1") == 1

    def test_threshold_tiers_are_length_aware(self):
        # short labels are stricter than long labels
        assert max_typo_distance(4) == 1
        assert max_typo_distance(6) == 1
        assert max_typo_distance(9) == 2
        assert max_typo_distance(20) == 3

    @pytest.mark.parametrize(
        "length,expected",
        [(1, 1), (7, 1), (8, 2), (10, 2), (11, 3), (20, 3)],
    )
    def test_threshold_boundaries(self, length, expected):
        # ≤7 → 1, 8-10 → 2, ≥11 → 3
        assert max_typo_distance(length) == expected

    def test_long_label_two_edits_hit_three_misses(self):
        # microsoft = 9 chars; tier allows 2 edits
        near = detect_typosquat("microsxft.com")  # 2 edits from microsoft
        assert near["is_typosquat"] is True
        assert near["matched_brand"] == "microsoft"
        far = detect_typosquat("m1cr0s0ftx.com")  # >=3 edits away
        assert far["is_typosquat"] is False


class TestBrandLengthTiers:
    def test_xiaohongshu_three_edits_accepted_four_rejected(self):
        # xiaohongshu = 11 chars → tier 3; a 3-edit near form matches, a
        # 5-edit distant form does not.
        brand = "xiaohongshu"
        near = brand[:3] + "xxx" + brand[6:]
        assert levenshtein(brand, near) == 3
        hit = detect_typosquat(near + ".com")
        assert hit["is_typosquat"] is True
        assert hit["matched_brand"] == "xiaohongshu"
        far = brand[:2] + "yyyyy" + brand[7:]
        assert levenshtein(brand, far) == 5
        assert detect_typosquat(far + ".com")["is_typosquat"] is False

    def test_pinduoduo_two_edits_accepted_three_rejected(self):
        # pinduoduo = 9 chars → tier 2; 2 edits match, 3 do not.
        brand = "pinduoduo"
        near = "p1ndu0duo"  # 2 substitutions
        assert levenshtein(brand, near) == 2
        hit = detect_typosquat(near + ".com")
        assert hit["is_typosquat"] is True
        assert hit["matched_brand"] == "pinduoduo"
        far = "p1ndu0du1o"  # 3 substitutions
        assert levenshtein(brand, far) == 3
        assert detect_typosquat(far + ".com")["is_typosquat"] is False


# ── fusion: new signals participate in scoring ──────────────────────


class TestFusionHomograph:
    def test_homograph_hit_adds_weighted_score(self):
        hom = {
            "is_typosquat": True,
            "matched_brand": "google",
            "distance": 1,
            "homograph": False,
            "reasons": ["typosquat google"],
            "folded": "gogle",
        }
        rating, reasons, score = _fuse_rating(
            _DNS_OK,
            _CLEAN,
            _CLEAN,
            _RDAP_OK,
            _SCAM_OK,
            _VT_OFF,
            _cfg(),
            homograph=hom,
        )
        assert rating == RATING_SUSPICIOUS
        assert score >= _cfg().fusion_weights["homograph"]
        assert any("google" in r for r in reasons)

    def test_layer_error_does_not_block_other_signals(self):
        # homograph layer errored; URLhaus still scores malicious
        hom = {"is_typosquat": False, "matched_brand": None, "error": "boom"}
        gsb = {"malicious": False, "threats": [], "error": "gsb down"}
        urlhaus = {"malicious": True, "error": None}
        rating, reasons, score = _fuse_rating(
            _DNS_OK,
            urlhaus,
            _CLEAN,
            _RDAP_OK,
            _SCAM_OK,
            _VT_OFF,
            _cfg(use_gsb=True),
            homograph=hom,
            gsb=gsb,
        )
        assert rating == RATING_MALICIOUS
        assert any("URLhaus" in r for r in reasons)
        assert score >= 40

    def test_clean_domain_still_safe_with_error_layers(self):
        hom = {"is_typosquat": False, "error": "boom"}
        mxspf = {"missing_mx": False, "missing_spf": False, "error": "resolver down"}
        rating, _reasons, score = _fuse_rating(
            _DNS_OK,
            _CLEAN,
            _CLEAN,
            _RDAP_OK,
            _SCAM_OK,
            _VT_OFF,
            _cfg(use_dns_mx=True),
            homograph=hom,
            mxspf=mxspf,
        )
        assert rating == RATING_SAFE
        assert score == 0

    def test_disabled_homograph_switch_skips_signal(self):
        hom = {
            "is_typosquat": True,
            "matched_brand": "google",
            "distance": 1,
            "homograph": False,
            "reasons": ["typosquat google"],
            "folded": "gogle",
        }
        cfg = _cfg(use_homograph=False)
        rating, reasons, score = _fuse_rating(
            _DNS_OK,
            _CLEAN,
            _CLEAN,
            _RDAP_OK,
            _SCAM_OK,
            _VT_OFF,
            cfg,
            homograph=hom,
        )
        assert rating == RATING_SAFE
        assert score == 0
        assert not any("google" in r for r in reasons)

    def test_gsb_malicious_is_malicious_signal(self):
        gsb = {"malicious": True, "threats": ["MALWARE"], "error": None}
        rating, reasons, score = _fuse_rating(
            _DNS_OK,
            _CLEAN,
            _CLEAN,
            _RDAP_OK,
            _SCAM_OK,
            _VT_OFF,
            _cfg(use_gsb=True),
            gsb=gsb,
        )
        assert rating == RATING_MALICIOUS
        assert score >= _cfg(use_gsb=True).fusion_weights["gsb_malicious"]
        assert any("Safe Browsing" in r for r in reasons)

    def test_gsb_disabled_even_with_positive_input(self):
        gsb = {"malicious": True, "threats": ["MALWARE"], "error": None}
        rating, reasons, score = _fuse_rating(
            _DNS_OK,
            _CLEAN,
            _CLEAN,
            _RDAP_OK,
            _SCAM_OK,
            _VT_OFF,
            _cfg(use_gsb=False),
            gsb=gsb,
        )
        assert rating == RATING_SAFE
        assert score == 0
        assert not any("Safe Browsing" in r for r in reasons)

    def test_mxspf_missing_clue_is_suspicious(self):
        mxspf = {
            "has_mx": False,
            "has_spf": False,
            "missing_mx": True,
            "missing_spf": True,
            "reasons": ["no MX", "no SPF TXT"],
            "error": None,
        }
        rating, reasons, score = _fuse_rating(
            _DNS_OK,
            _CLEAN,
            _CLEAN,
            _RDAP_OK,
            _SCAM_OK,
            _VT_OFF,
            _cfg(use_dns_mx=True),
            mxspf=mxspf,
        )
        assert rating == RATING_SUSPICIOUS
        assert score >= _cfg(use_dns_mx=True).fusion_weights["dns_mx_missing"]
        assert any("MX" in r or "SPF" in r for r in reasons)

    def test_mxspf_disabled_ignores_clue(self):
        mxspf = {
            "has_mx": False,
            "has_spf": False,
            "missing_mx": True,
            "missing_spf": True,
            "reasons": ["no MX"],
            "error": None,
        }
        rating, _reasons, score = _fuse_rating(
            _DNS_OK,
            _CLEAN,
            _CLEAN,
            _RDAP_OK,
            _SCAM_OK,
            _VT_OFF,
            _cfg(use_dns_mx=False),
            mxspf=mxspf,
        )
        assert rating == RATING_SAFE
        assert score == 0


# ── offline recycled-domain clue (informational, zero score) ────────


class TestRecycledDomainClue:
    def test_clue_when_no_registrar_but_resolves(self):
        rdap = {"is_new_domain": False, "registrar": None, "error": None}
        dns = {"ips": ["93.184.216.34"], "nxdomain": False}
        assert recycled_domain_clue(rdap, dns) is True

    def test_no_clue_when_registrar_present(self):
        rdap = {"is_new_domain": False, "registrar": "ExampleReg", "error": None}
        dns = {"ips": ["93.184.216.34"], "nxdomain": False}
        assert recycled_domain_clue(rdap, dns) is False

    def test_no_clue_for_new_domain(self):
        rdap = {"is_new_domain": True, "registrar": None, "error": None}
        dns = {"ips": ["93.184.216.34"], "nxdomain": False}
        assert recycled_domain_clue(rdap, dns) is False

    def test_no_clue_when_not_resolving(self):
        rdap = {"is_new_domain": False, "registrar": None, "error": None}
        dns = {"ips": [], "nxdomain": True}
        assert recycled_domain_clue(rdap, dns) is False
