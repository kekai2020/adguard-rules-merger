"""Mock-based tests for the optional external-API layers.

These exercise the request/response/error paths without touching the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from merger.whitelist_audit import online


def _fake_session(status: int = 200, payload=None, raise_exc=None):
    session = MagicMock()

    class _CM:
        async def __aenter__(self):
            if raise_exc is not None:
                raise raise_exc
            resp = SimpleNamespace(status=status)
            resp.json = AsyncMock(return_value=payload or {})
            return resp

        async def __aexit__(self, *a):
            return None

    session.post = MagicMock(return_value=_CM())
    session.get = MagicMock(return_value=_CM())
    return session


@pytest.mark.asyncio
async def test_gsb_no_api_key():
    out = await online._query_gsb("example.com", "", session=_fake_session())
    assert out["error"] == "no API key configured"
    assert out["malicious"] is False


@pytest.mark.asyncio
async def test_gsb_hit():
    session = _fake_session(payload={"matches": [{"threatType": "MALWARE"}]})
    out = await online._query_gsb("evil.com", "key", session=session)
    assert out["malicious"] is True
    assert "MALWARE" in out["threats"]


@pytest.mark.asyncio
async def test_gsb_http_error():
    session = _fake_session(status=500)
    out = await online._query_gsb("evil.com", "key", session=session)
    assert out["error"] == "HTTP 500"


@pytest.mark.asyncio
async def test_gsb_exception():
    session = _fake_session(raise_exc=RuntimeError("boom"))
    out = await online._query_gsb("evil.com", "key", session=session)
    assert "boom" in out["error"]


@pytest.mark.asyncio
async def test_phishtank_no_key():
    out = await online._query_phishtank("example.com", "", session=_fake_session())
    assert out["error"] == "no API key configured"


@pytest.mark.asyncio
async def test_phishtank_hit():
    payload = {"results": {"phish": {"phish_id": 42, "in_database": True, "valid": "yes"}}}
    session = _fake_session(payload=payload)
    out = await online._query_phishtank("phish.com", "key", session=session)
    assert out["phish_id"] == 42
    assert out["malicious"] is True


@pytest.mark.asyncio
async def test_phishtank_invalid():
    payload = {"results": {"phish": {"phish_id": 1, "in_database": True, "valid": "false"}}}
    session = _fake_session(payload=payload)
    out = await online._query_phishtank("phish.com", "key", session=session)
    assert out["malicious"] is False


@pytest.mark.asyncio
async def test_urlscan_community_malicious():
    payload = {"results": [{"verdicts": {"community": {"malicious": True}}}]}
    session = _fake_session(payload=payload)
    out = await online._query_urlscan("bad.com", "key", session=session)
    assert out["malicious"] is True
    assert out["verdict"] == "community-malicious"


@pytest.mark.asyncio
async def test_urlscan_clean():
    payload = {"results": []}
    session = _fake_session(payload=payload)
    out = await online._query_urlscan("good.com", "", session=session)
    assert out["malicious"] is False


@pytest.mark.asyncio
async def test_crtsh_entries():
    payload = [{"issuer_name": "Let's Encrypt", "not_before": "2024-01-01"}]
    session = _fake_session(payload=payload)
    out = await online._query_crtsh("example.com", session=session)
    assert len(out["entries"]) == 1
    assert out["entries"][0]["issuer"] == "Let's Encrypt"


@pytest.mark.asyncio
async def test_crtsh_error():
    session = _fake_session(status=403)
    out = await online._query_crtsh("example.com", session=session)
    assert out["error"] == "HTTP 403"
