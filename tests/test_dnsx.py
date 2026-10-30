"""DnsChecker unit tests — mock resolver, no network access.

Covers the four paths required by C4: NXDOMAIN / servfail / timeout /
normal resolution, plus the resolver_error catch-all and the _dns_check
thin-wrapper shape contract.
"""

from unittest.mock import MagicMock

import pytest

from merger.dnsx import _DNS_AVAILABLE, DnsChecker, _Nxdomain, _Servfail, _Timeout


class TestDnsChecker:
    def _checker(self):
        """A DnsChecker with its resolver bypassed (mock _resolve directly)."""
        checker = DnsChecker(timeout=5.0)
        return checker

    @pytest.mark.asyncio
    async def test_normal_resolution_a_and_aaaa(self):
        checker = self._checker()
        checker._resolve = lambda d, t: ["1.2.3.4"] if t == "A" else ["::1"]
        r = await checker.check("example.com")
        assert r["nxdomain"] is False
        assert r["error_type"] is None
        assert r["rcode"] == 0
        assert "1.2.3.4" in r["ips"]
        assert "::1" in r["ips"]

    @pytest.mark.asyncio
    async def test_normal_resolution_a_only(self):
        checker = self._checker()
        checker._resolve = lambda d, t: ["1.2.3.4"] if t == "A" else []
        r = await checker.check("example.com")
        assert r["nxdomain"] is False
        assert r["error_type"] is None
        assert r["ips"] == ["1.2.3.4"]

    @pytest.mark.asyncio
    async def test_nxdomain(self):
        checker = self._checker()
        checker._resolve = MagicMock(side_effect=_Nxdomain)
        r = await checker.check("nonexistent.invalid")
        assert r["nxdomain"] is True
        assert r["error_type"] == "nxdomain"
        assert r["rcode"] == 3
        assert r["ips"] == []

    @pytest.mark.asyncio
    async def test_servfail(self):
        checker = self._checker()
        checker._resolve = MagicMock(side_effect=_Servfail)
        r = await checker.check("example.com")
        assert r["nxdomain"] is False
        assert r["error_type"] == "servfail"
        assert r["rcode"] == 2

    @pytest.mark.asyncio
    async def test_timeout(self):
        checker = self._checker()
        checker._resolve = MagicMock(side_effect=_Timeout)
        r = await checker.check("example.com")
        assert r["error_type"] == "timeout"
        assert r["rcode"] is None

    @pytest.mark.asyncio
    async def test_resolver_error(self):
        checker = self._checker()
        checker._resolve = MagicMock(side_effect=RuntimeError("boom"))
        r = await checker.check("example.com")
        assert r["error_type"] == "resolver_error"
        assert r["nxdomain"] is False

    def test_dnspython_available(self):
        assert _DNS_AVAILABLE is True


class TestDnsCheckWrapper:
    """Verify whitelist_audit._dns_check preserves the legacy output shape."""

    @pytest.mark.asyncio
    async def test_nxdomain_returns_no_error(self, monkeypatch):
        import merger.whitelist_audit as wa
        from merger.dnsx import DnsChecker

        async def fake_check(self, domain):
            return {"rcode": 3, "nxdomain": True, "ips": [], "error_type": "nxdomain"}

        monkeypatch.setattr(DnsChecker, "check", fake_check)
        r = await wa._dns_check("nonexistent.invalid")
        assert r == {"nxdomain": True, "ips": [], "error": None}

    @pytest.mark.asyncio
    async def test_normal_returns_ips(self, monkeypatch):
        import merger.whitelist_audit as wa
        from merger.dnsx import DnsChecker

        async def fake_check(self, domain):
            return {"rcode": 0, "nxdomain": False, "ips": ["1.2.3.4"], "error_type": None}

        monkeypatch.setattr(DnsChecker, "check", fake_check)
        r = await wa._dns_check("example.com")
        assert r == {"nxdomain": False, "ips": ["1.2.3.4"], "error": None}

    @pytest.mark.asyncio
    async def test_timeout_returns_error_string(self, monkeypatch):
        import merger.whitelist_audit as wa
        from merger.dnsx import DnsChecker

        async def fake_check(self, domain):
            return {"rcode": None, "nxdomain": False, "ips": [], "error_type": "timeout"}

        monkeypatch.setattr(DnsChecker, "check", fake_check)
        r = await wa._dns_check("slow.example")
        assert r == {"nxdomain": False, "ips": [], "error": "timeout"}
