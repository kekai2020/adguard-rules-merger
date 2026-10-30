"""DoH whitelist-DNS layer unit tests — fully hermetic, no network.

Covers the JSON payload parser, the DoH→system-DNS fallback in ``_dns_check``,
and the config scheme validator for ``whitelist_audit.doh_endpoint``.
"""

import pytest

import merger.whitelist_audit as wa
from merger.config import WhitelistAuditConfig

# ── payload parsing ─────────────────────────────────────────────────


def test_parse_doh_nxdomain():
    out = wa._parse_doh_json({"Status": 3, "Answer": []})
    assert out == {"nxdomain": True, "ips": [], "error": None}


def test_parse_doh_noerror_collects_a_and_aaaa_skips_cname():
    payload = {
        "Status": 0,
        "Answer": [
            {"type": 5, "data": "cdn.example.com.", "name": "example.com"},  # CNAME
            {"type": 1, "data": "93.184.216.34", "name": "example.com"},
            {"type": 28, "data": "2606:2800:220:1::1", "name": "example.com"},
        ],
    }
    out = wa._parse_doh_json(payload)
    assert out["nxdomain"] is False
    assert out["ips"] == ["93.184.216.34", "2606:2800:220:1::1"]


def test_parse_doh_servfail_falls_back():
    assert wa._parse_doh_json({"Status": 2}) is None
    assert wa._parse_doh_json({"Status": 5}) is None


def test_parse_doh_no_error_no_answers():
    out = wa._parse_doh_json({"Status": 0, "Answer": []})
    assert out == {"nxdomain": False, "ips": [], "error": None}


# ── malformed / null payloads must fall back instead of crashing ──


def test_parse_doh_null_payload_returns_none():
    # resp.json() can legitimately decode to JSON null.
    assert wa._parse_doh_json(None) is None


def test_parse_doh_non_dict_returns_none():
    assert wa._parse_doh_json(["Status", 0]) is None
    assert wa._parse_doh_json(42) is None


def test_parse_doh_missing_status_returns_none():
    assert wa._parse_doh_json({"Answer": []}) is None


def test_parse_doh_answer_missing_collects_nothing():
    out = wa._parse_doh_json({"Status": 0})
    assert out == {"nxdomain": False, "ips": [], "error": None}


def test_parse_doh_non_list_answer_ignored():
    # A dict-shaped Answer must not be iterated as a list of records.
    out = wa._parse_doh_json({"Status": 0, "Answer": {"type": 1, "data": "1.2.3.4"}})
    assert out == {"nxdomain": False, "ips": [], "error": None}


# ── _dns_check passthrough / fallback ───────────────────────────────


@pytest.mark.asyncio
async def test_dns_check_prefers_doh_result(monkeypatch):
    async def fake_doh(domain, endpoint, timeout=5.0, session=None):
        return {"nxdomain": True, "ips": [], "error": None}

    monkeypatch.setattr(wa, "_doh_lookup", fake_doh)

    # System resolver must NOT be consulted when DoH succeeds.
    async def boom(self, domain):
        raise AssertionError("system resolver should not run")

    from merger.dnsx import DnsChecker

    monkeypatch.setattr(DnsChecker, "check", boom)
    out = await wa._dns_check("expired.invalid", doh_endpoint="https://dns.nextdns.io/x")
    assert out == {"nxdomain": True, "ips": [], "error": None}


@pytest.mark.asyncio
async def test_dns_check_falls_back_when_doh_fails(monkeypatch):
    async def fake_doh(domain, endpoint, timeout=5.0, session=None):
        return None

    monkeypatch.setattr(wa, "_doh_lookup", fake_doh)

    async def fake_check(self, domain):
        return {"rcode": 0, "nxdomain": False, "ips": ["1.2.3.4"], "error_type": None}

    from merger.dnsx import DnsChecker

    monkeypatch.setattr(DnsChecker, "check", fake_check)
    out = await wa._dns_check("example.com", doh_endpoint="https://dns.nextdns.io/x")
    assert out == {"nxdomain": False, "ips": ["1.2.3.4"], "error": None}


@pytest.mark.asyncio
async def test_dns_check_empty_endpoint_uses_system(monkeypatch):
    called = {"doh": False}

    async def fake_doh(domain, endpoint, timeout=5.0, session=None):
        called["doh"] = True
        return None

    monkeypatch.setattr(wa, "_doh_lookup", fake_doh)

    async def fake_check(self, domain):
        return {"rcode": 0, "nxdomain": False, "ips": [], "error_type": None}

    from merger.dnsx import DnsChecker

    monkeypatch.setattr(DnsChecker, "check", fake_check)
    await wa._dns_check("example.com")
    assert called["doh"] is False


# ── config validator ────────────────────────────────────────────────


def test_config_rejects_non_http_doh():
    with pytest.raises(Exception, match="http"):
        WhitelistAuditConfig(doh_endpoint="dns.nextdns.io/3fef68")


def test_config_accepts_https_and_empty():
    assert WhitelistAuditConfig(doh_endpoint="https://dns.nextdns.io/3fef68").doh_endpoint
    assert WhitelistAuditConfig().doh_endpoint == ""
