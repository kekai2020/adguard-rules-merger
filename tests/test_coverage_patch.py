"""Coverage patch: error paths for virustotal, threat_intel."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from merger import virustotal_audit
from merger.whitelist_audit import threat_intel


def _resp(status=200, payload=None):
    r = MagicMock()
    r.status = status
    r.json = AsyncMock(return_value=payload or {})
    return r


def _session(status=200, payload=None, exc=None):
    """Return a mock session whose .get and .post both yield a context manager."""
    sess = MagicMock()
    if exc:
        # When the call itself raises, both .get(...) and .post(...) raise.
        sess.get = MagicMock(side_effect=exc)
        sess.post = MagicMock(side_effect=exc)
    else:
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=_resp(status, payload))
        cm.__aexit__ = AsyncMock(return_value=False)
        # sync mock returning the async-context-manager directly:
        # `async with session.get(url) as r:` works because session.get(url)
        # evaluates to cm without awaiting.
        sess.get = MagicMock(return_value=cm)
        sess.post = MagicMock(return_value=cm)
    return sess


# ── VirusTotal ──


@pytest.mark.asyncio
async def test_virustotal_http_error():
    out = await virustotal_audit.query_virustotal(
        "example.com", "key", session=_session(status=500)
    )
    assert out["error"] == "HTTP 500"


@pytest.mark.asyncio
async def test_virustotal_transport_error():
    out = await virustotal_audit.query_virustotal(
        "fail.example.com", "key", session=_session(exc=RuntimeError("boom"))
    )
    assert out["error"] == "transport error"


# ── URLhaus / ThreatFox ──


@pytest.mark.asyncio
async def test_urlhaus_http_error():
    out = await threat_intel._query_urlhaus("example.com", _session(status=500), timeout=1)
    assert out["error"] == "HTTP 500"


@pytest.mark.asyncio
async def test_urlhaus_transport_error():
    out = await threat_intel._query_urlhaus(
        "boom.example.com", _session(exc=RuntimeError("x")), timeout=1
    )
    assert "error" in out


@pytest.mark.asyncio
async def test_threatfox_http_error():
    out = await threat_intel._query_threatfox("example.com", _session(status=500), timeout=1)
    assert out["error"] == "HTTP 500"


@pytest.mark.asyncio
async def test_threatfox_no_hit():
    out = await threat_intel._query_threatfox(
        "clean.example.com", _session(payload={"query_status": "no_result"}), timeout=1
    )
    assert out["malicious"] is False
