"""V5.2 tests: DNSBL layer, all-reasons fusion + risk score, disk cache."""

import time

import pytest

from merger.models import Rule
from merger.whitelist_audit import (
    RATING_MALICIOUS,
    RATING_SAFE,
    RATING_SUSPICIOUS,
    AuditConfig,
    _disk_cache_load,
    _disk_cache_save,
    _fuse_rating,
    _query_dnsbl,
    audit_whitelist,
    parse_dnsbl_response,
)

# ── DNSBL reply parsing ─────────────────────────────────────────────


class TestDnsblParsing:
    def test_dbl_phishing_is_malicious(self):
        bad, labels = parse_dnsbl_response("SpamhausDBL", "127.0.0.11")
        assert bad is True
        assert labels == ["SpamhausDBL:phishing"]

    def test_dbl_spam_is_suspicious_only(self):
        bad, labels = parse_dnsbl_response("SpamhausDBL", "127.0.0.10")
        assert bad is False
        assert labels == ["SpamhausDBL:spam"]

    def test_surbl_bitmask_phishing_malware(self):
        # 16 (phish) | 32 (malware) = 48
        bad, labels = parse_dnsbl_response("SURBL", "127.0.0.48")
        assert bad is True
        assert "SURBL:phishing" in labels
        assert "SURBL:malware" in labels

    def test_surbl_junk_is_suspicious_only(self):
        bad, labels = parse_dnsbl_response("SURBL", "127.0.0.8")
        assert bad is False
        assert labels == ["SURBL:junk"]

    def test_non_local_answer_ignored(self):
        assert parse_dnsbl_response("SpamhausDBL", "8.8.8.8") == (False, [])

    @pytest.mark.asyncio
    async def test_query_dnsbl_nxdomain_not_listed(self, monkeypatch):
        # NXDOMAIN (gaierror) = healthy "not listed"
        import socket as _socket

        import merger.whitelist_audit as wa

        async def fake_lookup(qname, timeout):
            raise _socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(wa, "_dnsbl_lookup", fake_lookup)
        res = await _query_dnsbl("example.com")
        assert res["listed"] is False
        assert res["malicious"] is False
        assert res["error"] is None

    @pytest.mark.asyncio
    async def test_spamhaus_query_blocked_ignored(self, monkeypatch):
        # 127.255.255.x = Spamhaus "query blocked (open resolver)" — must
        # NOT be treated as a listing (would false-positive every domain).
        import merger.whitelist_audit as wa

        async def fake_lookup(qname, timeout):
            return ["127.255.255.1"]

        monkeypatch.setattr(wa, "_dnsbl_lookup", fake_lookup)
        res = await _query_dnsbl("example.com")
        assert res["listed"] is False
        assert res["malicious"] is False
        assert res["error"] is not None
        assert "blocked" in res["error"]


# ── fusion: all reasons + risk score ────────────────────────────────

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
_DNSBL_CLEAN = {"listed": False, "malicious": False, "hits": [], "error": None}


def _cfg(**kw):
    kw.setdefault("use_urlhaus", True)
    kw.setdefault("use_threatfox", True)
    kw.setdefault("use_virustotal", False)
    return AuditConfig(**kw)


class TestFusionAllReasons:
    def test_collects_all_reasons_not_just_first(self):
        dns = {"nxdomain": True, "ips": [], "error": None}
        rdap = {"is_new_domain": True, "domain_age_days": 5, "registrar": None, "error": None}
        rating, reasons, score = _fuse_rating(dns, _CLEAN, _CLEAN, rdap, _SCAM_OK, _VT_OFF, _cfg())
        assert rating == RATING_SUSPICIOUS
        # both NXDOMAIN and new-domain reasons present
        assert any("NXDOMAIN" in r for r in reasons)
        assert any("新注册" in r for r in reasons)
        assert score >= 30  # 15 + 15

    def test_ti_hit_outranks_and_keeps_reasons(self):
        dns = {"nxdomain": True, "ips": [], "error": None}
        urlhaus = {"malicious": True, "error": None}
        rating, reasons, score = _fuse_rating(
            dns, urlhaus, _CLEAN, _RDAP_OK, _SCAM_OK, _VT_OFF, _cfg()
        )
        assert rating == RATING_MALICIOUS
        assert any("URLhaus" in r for r in reasons)
        assert any("NXDOMAIN" in r for r in reasons)  # evidence kept
        assert score >= 55  # 40 + 15

    def test_dnsbl_malicious_rating_and_score(self):
        dnsbl = {"listed": True, "malicious": True, "hits": ["SpamhausDBL:phishing"], "error": None}
        rating, reasons, score = _fuse_rating(
            _DNS_OK, _CLEAN, _CLEAN, _RDAP_OK, _SCAM_OK, _VT_OFF, _cfg(), dnsbl=dnsbl
        )
        assert rating == RATING_MALICIOUS
        assert score >= 30
        assert any("DNSBL" in r for r in reasons)

    def test_dnsbl_junk_only_suspicious(self):
        dnsbl = {"listed": True, "malicious": False, "hits": ["SURBL:junk"], "error": None}
        rating, _reasons, score = _fuse_rating(
            _DNS_OK, _CLEAN, _CLEAN, _RDAP_OK, _SCAM_OK, _VT_OFF, _cfg(), dnsbl=dnsbl
        )
        assert rating == RATING_SUSPICIOUS
        assert 0 < score < 50

    def test_clean_domain_safe_zero_score(self):
        rating, reasons, score = _fuse_rating(
            _DNS_OK, _CLEAN, _CLEAN, _RDAP_OK, _SCAM_OK, _VT_OFF, _cfg()
        )
        assert rating == RATING_SAFE
        assert score == 0

    def test_score_capped_at_100(self):
        dnsbl = {"listed": True, "malicious": True, "hits": ["x"], "error": None}
        scam = {
            "is_suspicious": True,
            "is_confirmed_scam": True,
            "decision": "SCAM",
            "risk_score": 90,
            "reasons": ["r"],
            "error": None,
        }
        urlhaus = {"malicious": True, "error": None}
        threatfox = {"malicious": True, "error": None}
        vt = {"malicious": True, "error": None, "reputation_score": -50}
        rating, _reasons, score = _fuse_rating(
            {"nxdomain": True, "ips": [], "error": None},
            urlhaus,
            threatfox,
            {"is_new_domain": True, "domain_age_days": 1},
            scam,
            vt,
            _cfg(),
            dnsbl=dnsbl,
        )
        assert rating == RATING_MALICIOUS
        assert score == 100

    def test_fusion_weights_actually_affect_score(self):
        # V6: _fuse_rating must read config.fusion_weights (it used to be
        # hard-coded and the weights only fed the cache fingerprint).
        dns = {"nxdomain": True, "ips": [], "error": None}
        _r, _reasons, base = _fuse_rating(dns, _CLEAN, _CLEAN, _RDAP_OK, _SCAM_OK, _VT_OFF, _cfg())
        assert base == 15  # default dns_nxdomain weight

        cfg = _cfg()
        cfg.fusion_weights = {**cfg.fusion_weights, "dns_nxdomain": 50}
        _r2, _reasons2, boosted = _fuse_rating(
            dns, _CLEAN, _CLEAN, _RDAP_OK, _SCAM_OK, _VT_OFF, cfg
        )
        assert boosted == 50  # weight now drives the score


# ── disk cache ──────────────────────────────────────────────────────


class TestDiskCache:
    def _cfg(self, tmp_path, **kw):
        kw.setdefault("cache_results", True)
        kw.setdefault("cache_dir", str(tmp_path))
        kw.setdefault("cache_ttl_seconds", 3600)
        return AuditConfig(**kw)

    def test_roundtrip(self, tmp_path):
        cfg = self._cfg(tmp_path)
        _disk_cache_save(cfg, {"a.com": {"rating": "safe", "risk_score": 0}})
        loaded = _disk_cache_load(cfg)
        assert loaded["a.com"]["rating"] == "safe"

    def test_ttl_expiry(self, tmp_path):
        import json

        cfg = self._cfg(tmp_path)
        p = tmp_path / "whitelist_audit_cache.json"
        p.write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": {
                        "old.com": {
                            "ts": time.time() - 7200,
                            "result": {"rating": "safe"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        assert _disk_cache_load(cfg) == {}

    def test_disabled_writes_nothing(self, tmp_path):
        cfg = AuditConfig(cache_results=False, cache_dir=str(tmp_path))
        _disk_cache_save(cfg, {"a.com": {"rating": "safe"}})
        assert not (tmp_path / "whitelist_audit_cache.json").exists()
        assert _disk_cache_load(cfg) == {}


# ── end-to-end with mocked layers ───────────────────────────────────


class TestAuditEnrichment:
    @pytest.mark.asyncio
    async def test_result_fields_and_summary(self, monkeypatch, tmp_path):
        import merger.whitelist_audit as wa

        async def fake_dns(domain, timeout=5, doh_endpoint="", session=None):
            return {"nxdomain": False, "ips": ["1.2.3.4"], "error": None}

        async def fake_ti(domain, session, config, ti_sem=None):
            return ({"malicious": True, "error": None}, {"malicious": False, "error": None})

        async def fake_dnsbl(domain, timeout=6):
            return {
                "listed": True,
                "malicious": True,
                "hits": ["SpamhausDBL:malware"],
                "error": None,
            }

        monkeypatch.setattr(wa, "_dns_check", fake_dns)
        monkeypatch.setattr(wa, "_query_threat_intel", fake_ti)
        monkeypatch.setattr(wa, "_query_dnsbl", fake_dnsbl)

        rule = Rule(
            raw="@@||baddomain.example^",
            domain="baddomain.example",
            rule_type="allow",
            wildcard=False,
            modifiers=(),
            source_ids=("src1",),
        )
        cfg = AuditConfig(
            use_dns=True,
            use_urlhaus=True,
            use_threatfox=True,
            use_rdap=False,
            use_scam_check=False,
            use_dnsbl=True,
            cache_results=True,
            cache_dir=str(tmp_path),
        )
        res = await audit_whitelist([rule], config=cfg)
        r = res["rules"][0]
        assert r["rating"] == RATING_MALICIOUS
        assert r["dnsbl_malicious"] is True
        assert r["risk_score"] >= 70  # 40 TI + 30 DNSBL
        assert "URLhaus" in r["reason"] and "DNSBL" in r["reason"]
        s = res["summary"]
        assert s["layer_hits"]["urlhaus"] == 1
        assert s["layer_hits"]["dnsbl_malicious"] == 1
        assert s["risk_score_buckets"]["high(>=50)"] == 1
        assert s["top_risky"][0]["domain"] == "baddomain.example"
        assert s["disk_cache"]["enabled"] is True
        assert s["disk_cache"]["stored"] == 1

    @pytest.mark.asyncio
    async def test_one_layer_raising_falls_back_without_discarding_others(
        self, monkeypatch, tmp_path
    ):
        # C-08: inner gather uses return_exceptions=True. A single layer raising
        # must fall back to its disabled-default shape instead of propagating and
        # discarding the evidence the other layers already collected.
        import merger.whitelist_audit as wa

        async def boom_dns(domain, timeout=5, doh_endpoint="", session=None):
            raise RuntimeError("dns transport exploded")

        async def fake_ti(domain, session, config, ti_sem=None):
            return ({"malicious": True, "error": None}, {"malicious": False, "error": None})

        monkeypatch.setattr(wa, "_dns_check", boom_dns)
        monkeypatch.setattr(wa, "_query_threat_intel", fake_ti)

        rule = Rule(
            raw="@@||baddomain.example^",
            domain="baddomain.example",
            rule_type="allow",
            wildcard=False,
            modifiers=(),
            source_ids=("src1",),
        )
        cfg = AuditConfig(
            use_dns=True,
            use_urlhaus=True,
            use_threatfox=True,
            use_rdap=False,
            use_scam_check=False,
            cache_results=False,
            cache_dir=str(tmp_path),
        )
        # Must not raise despite the DNS layer exploding.
        res = await audit_whitelist([rule], config=cfg)
        r = res["rules"][0]
        # The ti layer still contributed despite the DNS layer failing.
        assert r["risk_score"] >= 40
        assert "URLhaus" in r["reason"]
        # The failed dns layer fell back to its disabled-default shape
        # (nxdomain=False, no ips) instead of propagating.
        assert r["dns_nxdomain"] is False
        assert r["dns_ips"] == []

    @pytest.mark.asyncio
    async def test_disk_cache_skips_network(self, monkeypatch, tmp_path):
        import merger.whitelist_audit as wa

        calls = {"n": 0}

        async def fake_dns(domain, timeout=5, doh_endpoint="", session=None):
            calls["n"] += 1
            return {"nxdomain": False, "ips": ["1.2.3.4"], "error": None}

        monkeypatch.setattr(wa, "_dns_check", fake_dns)

        rule = Rule(
            raw="@@||cached.example^",
            domain="cached.example",
            rule_type="allow",
            wildcard=False,
            modifiers=(),
            source_ids=("s",),
        )
        cfg = AuditConfig(
            use_dns=True,
            use_urlhaus=False,
            use_threatfox=False,
            use_rdap=False,
            use_scam_check=False,
            use_dnsbl=False,
            cache_results=True,
            cache_dir=str(tmp_path),
        )
        await audit_whitelist([rule], config=cfg)
        assert calls["n"] == 1

        # second run: the in-process cache is now per-run (V5.3), so the
        # disk cache alone must skip the network — no manual clear needed.
        res2 = await audit_whitelist([rule], config=cfg)
        assert calls["n"] == 1  # no new DNS call
        assert res2["summary"]["disk_cache"]["hits"] == 1
        assert res2["rules"][0]["disk_cache"] is True


# ── V5.3 cache fingerprint + v2 format + fixed TTL ─────────────────


class TestCacheFingerprint:
    def test_fingerprint_stable(self):
        from merger.whitelist_audit import AuditConfig, _cfg_fingerprint

        assert _cfg_fingerprint(AuditConfig()) == _cfg_fingerprint(AuditConfig())

    def test_fingerprint_sensitive_to_layers(self):
        from merger.whitelist_audit import AuditConfig, _cfg_fingerprint

        a = AuditConfig(use_dns=True)
        b = AuditConfig(use_dns=False)
        assert _cfg_fingerprint(a) != _cfg_fingerprint(b)

    def test_fingerprint_sensitive_to_weights(self):
        from merger.whitelist_audit import AuditConfig, _cfg_fingerprint

        a = AuditConfig()
        b = AuditConfig()
        b.fusion_weights = {**b.fusion_weights, "threat_intel": 99}
        assert _cfg_fingerprint(a) != _cfg_fingerprint(b)

    def test_fingerprint_sensitive_to_threshold(self):
        from merger.whitelist_audit import AuditConfig, _cfg_fingerprint

        a = AuditConfig(new_domain_threshold_days=30)
        b = AuditConfig(new_domain_threshold_days=60)
        assert _cfg_fingerprint(a) != _cfg_fingerprint(b)


class TestCacheV2Format:
    def _cfg(self, tmp_path, **kw):
        defaults = dict(
            use_dns=True,
            use_urlhaus=False,
            use_threatfox=False,
            use_rdap=False,
            use_scam_check=False,
            use_dnsbl=False,
            cache_results=True,
            cache_dir=str(tmp_path),
            cache_ttl_seconds=99999,
        )
        defaults.update(kw)
        return AuditConfig(**defaults)

    def test_v1_to_v2_migration_roundtrip(self, tmp_path):
        import json

        from merger.whitelist_audit import (
            _cfg_fingerprint,
            _disk_cache_load,
            _disk_cache_path,
            _disk_cache_save,
        )

        cfg = self._cfg(tmp_path)
        p = _disk_cache_path(cfg)
        p.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        p.write_text(
            json.dumps(
                {
                    "version": 1,
                    "entries": {"old.example": {"ts": now, "result": {"rating": "safe"}}},
                }
            ),
            encoding="utf-8",
        )
        loaded = _disk_cache_load(cfg)
        assert loaded.get("old.example", {}).get("rating") == "safe"
        _disk_cache_save(cfg, {"new.example": {"rating": "suspicious"}})
        loaded2 = _disk_cache_load(cfg)
        assert "old.example" in loaded2
        assert "new.example" in loaded2
        data = json.loads(p.read_text(encoding="utf-8"))
        assert data["version"] == 2
        assert _cfg_fingerprint(cfg) in data["configs"]

    def test_layer_switch_invalidates_cache(self, tmp_path):
        from merger.whitelist_audit import (
            _cfg_fingerprint,
            _disk_cache_load,
            _disk_cache_save,
        )

        cfg_a = self._cfg(tmp_path, use_dns=True)
        cfg_b = self._cfg(tmp_path, use_dns=False)
        assert _cfg_fingerprint(cfg_a) != _cfg_fingerprint(cfg_b)
        _disk_cache_save(cfg_a, {"a.example": {"rating": "safe"}})
        assert "a.example" not in _disk_cache_load(cfg_b)
        assert "a.example" in _disk_cache_load(cfg_a)

    def test_fixed_ttl_no_ts_refresh(self, tmp_path):
        import json

        from merger.whitelist_audit import (
            _cfg_fingerprint,
            _disk_cache_path,
            _disk_cache_save,
        )

        cfg = self._cfg(tmp_path)
        _disk_cache_save(cfg, {"old.example": {"rating": "safe"}})
        p = _disk_cache_path(cfg)
        fp = _cfg_fingerprint(cfg)
        ts1 = json.loads(p.read_text(encoding="utf-8"))["configs"][fp]["entries"]["old.example"][
            "ts"
        ]
        time.sleep(0.01)
        _disk_cache_save(cfg, {"new.example": {"rating": "suspicious"}})
        ts2 = json.loads(p.read_text(encoding="utf-8"))["configs"][fp]["entries"]["old.example"][
            "ts"
        ]
        assert ts2 == ts1

    def test_expired_entries_pruned_on_save(self, tmp_path):
        import json

        from merger.whitelist_audit import (
            _disk_cache_load,
            _disk_cache_path,
            _disk_cache_save,
        )

        cfg = self._cfg(tmp_path, cache_ttl_seconds=1)
        _disk_cache_save(cfg, {"ephemeral.example": {"rating": "safe"}})
        time.sleep(1.1)
        _disk_cache_save(cfg, {"fresh.example": {"rating": "safe"}})
        loaded = _disk_cache_load(cfg)
        assert "ephemeral.example" not in loaded
        assert "fresh.example" in loaded

    def test_different_configs_coexist(self, tmp_path):
        from merger.whitelist_audit import (
            _disk_cache_load,
            _disk_cache_save,
        )

        cfg_a = self._cfg(tmp_path, use_dns=True)
        cfg_b = self._cfg(tmp_path, use_dns=False)
        _disk_cache_save(cfg_a, {"a.example": {"rating": "safe"}})
        _disk_cache_save(cfg_b, {"b.example": {"rating": "suspicious"}})
        assert "a.example" in _disk_cache_load(cfg_a)
        assert "b.example" not in _disk_cache_load(cfg_a)
        assert "b.example" in _disk_cache_load(cfg_b)
        assert "a.example" not in _disk_cache_load(cfg_b)


# ── R2: direct call test for _query_threat_intel (no monkeypatch) ──


class TestQueryThreatIntelDirect:
    """Guard against R1 regression: _query_threat_intel must execute its
    function body (async with ti_sem + HTTP queries), not silently return
    (disabled, disabled)."""

    @pytest.mark.asyncio
    async def test_returns_tuple_of_dicts_with_error(self, monkeypatch):
        import asyncio

        import merger.whitelist_audit as wa

        async def fake_urlhaus(domain, session, timeout=8):
            return {"malicious": False, "error": None}

        async def fake_threatfox(domain, session, timeout=8):
            return {"malicious": False, "error": None}

        monkeypatch.setattr(wa, "_query_urlhaus", fake_urlhaus)
        monkeypatch.setattr(wa, "_query_threatfox", fake_threatfox)

        cfg = AuditConfig(
            use_urlhaus=True,
            use_threatfox=True,
            use_rdap=False,
            use_scam_check=False,
            use_dnsbl=False,
            use_virustotal=False,
            urlhaus_delay=0,
        )
        sem = asyncio.Semaphore(3)
        result = await wa._query_threat_intel(
            "example.com",
            session=None,
            config=cfg,
            ti_sem=sem,
        )

        assert isinstance(result, tuple)
        assert len(result) == 2
        urlhaus_r, threatfox_r = result
        assert isinstance(urlhaus_r, dict)
        assert isinstance(threatfox_r, dict)
        assert "error" in urlhaus_r
        assert "error" in threatfox_r
        assert urlhaus_r["error"] != "disabled"
        assert threatfox_r["error"] != "disabled"

    @pytest.mark.asyncio
    async def test_disabled_when_both_off(self):
        import asyncio

        import merger.whitelist_audit as wa

        cfg = AuditConfig(
            use_urlhaus=False,
            use_threatfox=False,
            use_rdap=False,
            use_scam_check=False,
            use_dnsbl=False,
            use_virustotal=False,
        )
        sem = asyncio.Semaphore(3)
        result = await wa._query_threat_intel(
            "example.com",
            session=None,
            config=cfg,
            ti_sem=sem,
        )
        assert result[0]["error"] == "disabled"
        assert result[1]["error"] == "disabled"
