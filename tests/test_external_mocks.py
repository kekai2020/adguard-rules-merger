"""Mock-based tests for virustotal, threat_intel, dns_doh, heuristics, scam_check."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from merger import virustotal_audit
from merger.whitelist_audit import dns_doh, heuristics, threat_intel


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

    session.get = MagicMock(return_value=_CM())
    session.post = MagicMock(return_value=_CM())
    return session


# ── virustotal ──

@pytest.mark.asyncio
async def test_vt_no_key():
    out = await virustotal_audit.query_virustotal("example.com", "", session=_session())
    assert out["error"] == "no API key configured"


@pytest.mark.asyncio
async def test_vt_clean():
    payload = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 0
    }}}}
    out = await virustotal_audit.query_virustotal("good.com", "key", session=_session(payload=payload))
    assert out["malicious"] is False
    assert out["total_votes"] == 70


@pytest.mark.asyncio
async def test_vt_malicious():
    payload = {"data": {"attributes": {"last_analysis_stats": {
        "malicious": 30, "suspicious": 5, "harmless": 35, "undetected": 0
    }}}}
    out = await virustotal_audit.query_virustotal("bad.com", "key", session=_session(payload=payload))
    assert out["malicious"] is True
    assert out["reputation_score"] > 0.2


@pytest.mark.asyncio
async def test_vt_404():
    out = await virustotal_audit.query_virustotal("ghost.com", "key", session=_session(status=404))
    assert out["error"] == "domain not found on VirusTotal"


@pytest.mark.asyncio
async def test_vt_429():
    out = await virustotal_audit.query_virustotal("slow.com", "key", session=_session(status=429))
    assert out["error"] == "rate limited (429)"


# ── threat_intel ──

@pytest.mark.asyncio
async def test_urlhaus_hit():
    session = _session(payload={"query_status": "ok"})
    out = await threat_intel._query_urlhaus("evil.com", session=session)
    assert out["malicious"] is True


@pytest.mark.asyncio
async def test_urlhaus_clean():
    session = _session(payload={"query_status": "no_results"})
    out = await threat_intel._query_urlhaus("good.com", session=session)
    assert out["malicious"] is False


@pytest.mark.asyncio
async def test_urlhaus_http_error():
    session = _session(status=500)
    out = await threat_intel._query_urlhaus("good.com", session=session)
    assert "HTTP 500" in out["error"]


@pytest.mark.asyncio
async def test_threatfox_hit():
    session = _session(payload={"query_status": "ok", "data": [{"ioc": "x"}]})
    out = await threat_intel._query_threatfox("evil.com", session=session)
    assert out["malicious"] is True


@pytest.mark.asyncio
async def test_threatfox_clean():
    session = _session(payload={"query_status": "ok", "data": []})
    out = await threat_intel._query_threatfox("good.com", session=session)
    assert out["malicious"] is False


@pytest.mark.asyncio
async def test_threat_intel_disabled():
    from merger.whitelist_audit.config import AuditConfig
    cfg = AuditConfig(use_urlhaus=False, use_threatfox=False)
    u, t = await threat_intel._query_threat_intel("x.com", session=_session(), config=cfg)
    assert u["error"] == "disabled"
    assert t["error"] == "disabled"


@pytest.mark.asyncio
async def test_threat_intel_dataset_hit():
    class _Feed:
        def lookup_domain(self, d):
            return {"listed": True, "source": "URLhaus"}
    u, t = await threat_intel._query_threat_intel_dataset("evil.com", feed_index=_Feed())
    assert u["malicious"] is True
    assert t["malicious"] is False


@pytest.mark.asyncio
async def test_threat_intel_dataset_miss():
    class _Feed:
        def lookup_domain(self, d):
            return {"listed": False, "source": ""}
    u, t = await threat_intel._query_threat_intel_dataset("good.com", feed_index=_Feed())
    assert u["malicious"] is False
