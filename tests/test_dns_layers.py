"""Tests for dnsx, dns_doh, whois_audit."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from merger import dnsx, whois_audit
from merger.whitelist_audit import dns_doh

# ── dnsx ──


@pytest.mark.asyncio
async def test_dnsx_nxdomain():
    checker = dnsx.DnsChecker(timeout=1)
    # If dnspython is available, this does a real lookup; just ensure no crash.
    out = await checker.check("example.com")
    assert "rcode" in out
    assert "ips" in out


@pytest.mark.asyncio
async def test_dnsx_resolver_failure(monkeypatch):
    # Force getaddrinfo path by setting resolver to None
    checker = dnsx.DnsChecker(timeout=1)
    checker._resolver = None
    out = await checker.check("example.com")
    assert out["error_type"] in (None, "nxdomain", "servfail", "resolver_error", "timeout")


# ── dns_doh ──


@pytest.mark.asyncio
async def test_dns_doh_system_fallback():
    out = await dns_doh._dns_check("example.com", timeout=1)
    assert "nxdomain" in out
    assert "ips" in out


@pytest.mark.asyncio
async def test_dns_doh_mx_spf():
    out = await dns_doh._query_mx_spf("example.com", timeout=1)
    assert "has_mx" in out
    assert "reasons" in out


# ── whois_audit ──


def test_whois_parse_empty():
    out = whois_audit.parse_rdap_response({}, threshold_days=30)
    assert out["error"] is not None


def test_whois_parse_not_found():
    out = whois_audit.parse_rdap_response({"errorCode": 404}, threshold_days=30)
    assert "notFound" in out["error"] or "RDAP" in out["error"]


def test_whois_parse_with_events():
    data = {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
        ]
    }
    out = whois_audit.parse_rdap_response(data, threshold_days=30)
    assert out["registration_date"] == "2020-01-01T00:00:00+00:00"
    assert out["domain_age_days"] > 0
