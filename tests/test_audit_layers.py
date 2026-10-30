"""Tests for V5 multi-layer whitelist audit: RDAP, VirusTotal, AI, decision engine."""

from datetime import datetime, timedelta, timezone

import pytest

from merger.ai_classifier import AI_CATEGORIES, _build_user_prompt, classify_with_ai
from merger.models import Rule
from merger.scam_check import (
    SCAM_CHECK_API,
    SCORE_HIGH,
    SCORE_SUSPICIOUS,
    query_scam_check,
)
from merger.virustotal_audit import MALICIOUS_THRESHOLD, query_virustotal
from merger.whitelist_audit import (
    RATING_SAFE,
    RATING_SUSPICIOUS,
    RATING_UNKNOWN,
    AuditConfig,
    _is_private_ip,
    _query_gsb,
    _query_phishtank,
    audit_whitelist,
)
from merger.whois_audit import (
    NEW_DOMAIN_THRESHOLD_DAYS,
    parse_rdap_response,
)

# ── RDAP / whois_audit ──


class TestRDAPParser:
    def test_parse_valid_registration(self):
        now = datetime.now(timezone.utc)
        reg_date = (now - timedelta(days=365)).isoformat()
        data = {
            "events": [
                {"eventAction": "registration", "eventDate": reg_date},
                {"eventAction": "expiration", "eventDate": (now + timedelta(days=365)).isoformat()},
            ],
            "entities": [
                {"roles": ["registrar"], "handle": "ExampleReg"},
            ],
        }
        result = parse_rdap_response(data)
        assert result["domain_age_days"] >= 364
        assert result["is_new_domain"] is False
        assert result["registrar"] == "ExampleReg"
        assert result["error"] is None

    def test_parse_new_domain(self):
        now = datetime.now(timezone.utc)
        reg_date = (now - timedelta(days=5)).isoformat()
        data = {"events": [{"eventAction": "registration", "eventDate": reg_date}]}
        result = parse_rdap_response(data)
        assert result["is_new_domain"] is True
        assert result["domain_age_days"] < NEW_DOMAIN_THRESHOLD_DAYS

    def test_parse_not_found(self):
        result = parse_rdap_response({"errorCode": 404, "title": "Not Found"})
        assert result["error"] is not None
        assert result["is_new_domain"] is False

    def test_parse_empty(self):
        result = parse_rdap_response({})
        assert result["error"] is not None

    def test_parse_vcard_registrar(self):
        data = {
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "Cloudflare, Inc."],
                        ],
                    ],
                }
            ],
        }
        result = parse_rdap_response(data)
        assert result["registrar"] == "Cloudflare, Inc."

    # ── malformed payloads must degrade, never raise ──

    def test_events_not_a_list_is_ignored(self):
        for bad in ("registration", {"eventAction": "registration"}, None, 42):
            out = parse_rdap_response({"events": bad})
            assert out["error"] is None
            assert out["domain_age_days"] is None

    def test_entities_not_a_list_is_ignored(self):
        out = parse_rdap_response({"entities": "registrar-string"})
        assert out["error"] is None
        assert out["registrar"] is None

    def test_entity_mapping_guarded(self):
        out = parse_rdap_response({"entities": ["not-a-dict"]})
        assert out["error"] is None
        assert out["registrar"] is None

    def test_vcard_none_does_not_crash(self):
        data = {
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", None]}],
        }
        out = parse_rdap_response(data)
        assert out["error"] is None
        assert out["registrar"] is None

    def test_vcard_without_fn_falls_back_to_handle(self):
        data = {
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
            "entities": [
                {"roles": ["registrar"], "handle": "FallbackReg", "vcardArray": ["vcard", []]}
            ],
        }
        out = parse_rdap_response(data)
        assert out["registrar"] == "FallbackReg"


# ── VirusTotal ──


class TestVirusTotal:
    @pytest.mark.asyncio
    async def test_no_api_key(self):
        result = await query_virustotal("example.com", "", None)
        assert result["error"] == "no API key configured"
        assert result["malicious"] is False

    def test_threshold_constant(self):
        assert 0 < MALICIOUS_THRESHOLD < 1


# ── MarketNow scam check ──


class TestScamCheck:
    def test_constants(self):
        assert 0 < SCORE_SUSPICIOUS < SCORE_HIGH <= 100
        assert SCAM_CHECK_API.startswith("https://")

    def test_caution_never_suspicious_even_at_high_score(self):
        from merger.scam_check import evaluate_scam_decision

        sus, conf = evaluate_scam_decision("CAUTION", 90)
        assert sus is False
        assert conf is False

    def test_trusted_never_suspicious(self):
        from merger.scam_check import evaluate_scam_decision

        sus, conf = evaluate_scam_decision("TRUSTED", 99)
        assert sus is False
        assert conf is False

    def test_unknown_label_uses_score_threshold(self):
        from merger.scam_check import evaluate_scam_decision

        assert evaluate_scam_decision("UNKNOWN", 30) == (False, False)
        sus, _ = evaluate_scam_decision("UNKNOWN", 60)
        assert sus is True

    def test_suspicious_label_flagged(self):
        from merger.scam_check import evaluate_scam_decision

        sus, conf = evaluate_scam_decision("SUSPICIOUS", 20)
        assert sus is True
        assert conf is False

    def test_scam_label_confirmed(self):
        from merger.scam_check import evaluate_scam_decision

        sus, conf = evaluate_scam_decision("SCAM", 20)
        assert sus is True
        assert conf is True

    def test_high_score_confirms_unknown_label(self):
        from merger.scam_check import evaluate_scam_decision

        sus, conf = evaluate_scam_decision("NEWLABEL", 80)
        assert sus is True
        assert conf is True

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_safe_domain_not_flagged(self):
        import aiohttp

        try:
            async with aiohttp.ClientSession() as s:
                result = await query_scam_check("google.com", s)
        except Exception:
            pytest.skip("network unavailable")
        if result.get("error"):
            pytest.skip(f"API error: {result['error']}")
        assert result["is_suspicious"] is False
        assert result["decision"] == "TRUSTED"

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_typosquat_flagged(self):
        import aiohttp

        try:
            async with aiohttp.ClientSession() as s:
                result = await query_scam_check("micros0ft-login.net", s)
        except Exception:
            pytest.skip("network unavailable")
        if result.get("error"):
            pytest.skip(f"API error: {result['error']}")
        assert result["is_suspicious"] is True
        assert result["risk_score"] >= SCORE_SUSPICIOUS


# ── AI classifier ──


class TestAIClassifier:
    def test_categories_complete(self):
        expected = {
            "advertising",
            "analytics",
            "cdn",
            "microsoft_telemetry",
            "affiliate",
            "social",
            "ecommerce_payment",
            "privacy_security",
            "other",
        }
        assert set(AI_CATEGORIES) == expected

    def test_prompt_contains_domain(self):
        prompt = _build_user_prompt("evil.com")
        assert "evil.com" in prompt


# ── Private IP detection ──


class TestPrivateIP:
    @pytest.mark.parametrize(
        "ip,expected",
        [
            ("10.0.0.1", True),
            ("192.168.1.1", True),
            ("172.16.0.1", True),
            ("127.0.0.1", True),
            ("169.254.1.1", True),
            ("8.8.8.8", False),
            ("1.1.1.1", False),
            ("::1", True),
            ("fc00::1", True),
            ("2001:4860:4860::8888", False),
            ("not-an-ip", False),
        ],
    )
    def test_private_ip(self, ip, expected):
        assert _is_private_ip(ip) is expected


# ── Multi-layer decision engine (offline layers only) ──


class TestDecisionEngine:
    @pytest.mark.asyncio
    async def test_empty_allows(self):
        result = await audit_whitelist([], config=AuditConfig())
        assert result["summary"]["total"] == 0

    @pytest.mark.asyncio
    async def test_dns_only_disabled_ti(self):
        # Use a known-good domain, disable all network layers except DNS
        rule = Rule(
            raw="@@||example.com^",
            domain="example.com",
            rule_type="allow",
            wildcard=False,
            modifiers=(),
            source_ids=("src1",),
        )
        cfg = AuditConfig(
            use_dns=True,
            use_urlhaus=False,
            use_threatfox=False,
            use_rdap=False,
            use_virustotal=False,
            use_ai=False,
        )
        result = await audit_whitelist([rule], source_names={"src1": "Test"}, config=cfg)
        assert result["summary"]["total"] == 1
        # example.com resolves to a public IP → safe
        assert result["rules"][0]["rating"] in (RATING_SAFE, RATING_UNKNOWN)
        assert result["rules"][0]["sources"] == ["Test"]

    @pytest.mark.asyncio
    async def test_nxdomain_suspicious(self):
        # A domain that definitely doesn't exist
        rule = Rule(
            raw="@@||this-domain-definitely-does-not-exist-xyz123.invalid^",
            domain="this-domain-definitely-does-not-exist-xyz123.invalid",
            rule_type="allow",
            wildcard=False,
            modifiers=(),
            source_ids=("src1",),
        )
        cfg = AuditConfig(
            use_dns=True,
            use_urlhaus=False,
            use_threatfox=False,
            use_rdap=False,
            use_virustotal=False,
            use_ai=False,
        )
        result = await audit_whitelist([rule], config=cfg)
        assert result["rules"][0]["rating"] == RATING_SUSPICIOUS
        assert result["rules"][0]["dns_nxdomain"] is True

    @pytest.mark.asyncio
    async def test_layers_enabled_tracking(self):
        rule = Rule(
            raw="@@||example.com^",
            domain="example.com",
            rule_type="allow",
            wildcard=False,
            modifiers=(),
            source_ids=("src1",),
        )
        cfg = AuditConfig(
            use_dns=True,
            use_urlhaus=False,
            use_threatfox=False,
            use_rdap=False,
            use_virustotal=False,
            use_ai=False,
        )
        result = await audit_whitelist([rule], config=cfg)
        layers = result["summary"]["layers_enabled"]
        assert layers["dns"] is True
        assert layers["urlhaus"] is False
        assert layers["rdap"] is False
        assert layers["virustotal"] is False
        assert layers["ai"] is False

    @pytest.mark.asyncio
    async def test_category_confidence_in_output(self):
        rule = Rule(
            raw="@@||doubleclick.net^",
            domain="doubleclick.net",
            rule_type="allow",
            wildcard=False,
            modifiers=(),
            source_ids=("src1",),
        )
        cfg = AuditConfig(
            use_dns=False,
            use_urlhaus=False,
            use_threatfox=False,
            use_rdap=False,
            use_virustotal=False,
            use_ai=False,
        )
        result = await audit_whitelist([rule], config=cfg)
        r = result["rules"][0]
        assert r["category"] == "advertising"
        assert r["category_confidence"] >= 0.9

    @pytest.mark.asyncio
    async def test_legacy_kwargs_backcompat(self):
        """audit_whitelist should still accept legacy kwargs without config."""
        rule = Rule(
            raw="@@||example.com^",
            domain="example.com",
            rule_type="allow",
            wildcard=False,
            modifiers=(),
            source_ids=("src1",),
        )
        result = await audit_whitelist(
            [rule],
            concurrency=5,
            use_dns=False,
            use_urlhaus=False,
            use_threatfox=False,
        )
        assert result["summary"]["total"] == 1


# ── optional online layers: no key → skip, session never touched ──


class _RecordingSession:
    """Records transport calls; raises if one unexpectedly fires."""

    def __init__(self) -> None:
        self.posts: list = []
        self.gets: list = []

    def post(self, *args, **kwargs):
        self.posts.append(args)
        raise AssertionError("POST must not be called without an API key")

    def get(self, *args, **kwargs):
        self.gets.append(args)
        raise AssertionError("GET must not be called without an API key")


class TestOptionalLayerNoKeySkip:
    @pytest.mark.asyncio
    async def test_gsb_skips_without_key(self):
        session = _RecordingSession()
        out = await _query_gsb("example.com", "", session)
        assert out["error"] == "no API key configured"
        assert out["malicious"] is False
        assert session.posts == []

    @pytest.mark.asyncio
    async def test_phishtank_skips_without_key(self):
        session = _RecordingSession()
        out = await _query_phishtank("example.com", "", session)
        assert out["error"] == "no API key configured"
        assert out["malicious"] is False
        assert session.posts == []

    @pytest.mark.asyncio
    async def test_virustotal_skips_without_key(self):
        session = _RecordingSession()
        out = await query_virustotal("example.com", "", session)
        assert out["error"] == "no API key configured"
        assert out["malicious"] is False
        assert session.gets == []

    @pytest.mark.asyncio
    async def test_ai_skips_without_key(self):
        session = _RecordingSession()
        out = await classify_with_ai("example.com", "", session)
        assert out["error"] == "no API key"
        assert out["category"] == "other"
        assert session.posts == []
