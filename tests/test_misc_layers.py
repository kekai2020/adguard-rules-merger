"""Mock tests for ai_classifier, scam_check, heuristics, dns_doh, dnsbl."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from merger import ai_classifier, scam_check
from merger.whitelist_audit import dns_doh, dnsbl, heuristics


def _session(status=200, payload=None, exc=None):
    session = MagicMock()

    class _CM:
        async def __aenter__(self):
            if exc:
                raise exc
            resp = SimpleNamespace(status=status)
            resp.json = AsyncMock(return_value=payload or {})
            return resp

        async def __aexit__(self, *a):
            return None

    session.post = MagicMock(return_value=_CM())
    session.get = MagicMock(return_value=_CM())
    return session


# ── ai_classifier ──

@pytest.mark.asyncio
async def test_ai_no_key():
    out = await ai_classifier.classify_with_ai("example.com", "", session=_session())
    assert out["error"] == "no API key"


@pytest.mark.asyncio
async def test_ai_hit():
    payload = {"choices": [{"message": {"content": '{"category": "cdn", "confidence": 0.9, "reason": "static"}'}}]}
    out = await ai_classifier.classify_with_ai("cdn.example.com", "key", session=_session(payload=payload))
    assert out["category"] == "cdn"
    assert out["confidence"] == 0.9


@pytest.mark.asyncio
async def test_ai_http_error():
    out = await ai_classifier.classify_with_ai("example.com", "key", session=_session(status=500))
    assert out["error"] == "HTTP 500"


@pytest.mark.asyncio
async def test_ai_transport_error():
    out = await ai_classifier.classify_with_ai("boom.example.com", "key",
                                              session=_session(exc=RuntimeError("boom")))
    assert out["error"] == "transport error"


# ── scam_check ──

@pytest.mark.asyncio
async def test_scam_clean():
    payload = {"decision": "clean", "risk_score": 0, "reasons": []}
    out = await scam_check.query_scam_check("good.com", session=_session(payload=payload))
    assert out["is_suspicious"] is False
    assert out["is_confirmed_scam"] is False


@pytest.mark.asyncio
async def test_scam_confirmed():
    payload = {"decision": "scam", "risk_score": 90, "reasons": ["phishing"]}
    out = await scam_check.query_scam_check("bad.com", session=_session(payload=payload))
    assert out["is_confirmed_scam"] is True


@pytest.mark.asyncio
async def test_scam_http_error():
    out = await scam_check.query_scam_check("bad.com", session=_session(status=403))
    assert "HTTP 403" in out["error"]


# ── heuristics ──

def test_heuristics_local():
    out = heuristics.local_heuristics("example.com")
    assert isinstance(out, dict)


def test_heuristics_recycled_clue():
    out = heuristics.recycled_domain_clue({}, {})
    assert isinstance(out, bool)


# ── dnsbl ──

@pytest.mark.asyncio
async def test_dnsbl_lookup():
    # dnsbl resolves A record for reversed query; just call the entry point
    out = await dnsbl._query_dnsbl("example.com", timeout=1)
    assert isinstance(out, dict)
