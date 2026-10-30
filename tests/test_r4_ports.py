"""R4 thin-port offline unit tests — fully fabricated, no DNS, no HTTP, no net.

Covers fake injection of :class:`DnsPort` (5-hop cap, seen-set ring break,
empty result, end-to-end CNAME rescue), fake injection of :class:`HttpPort`
(200 body passthrough, 304 conditional request from cache, real session
never touched), the injectable audit session factory, and the default
production adapter wiring. No live network/DNS; every response and every
resolution is constructed in-test.
"""

from __future__ import annotations

import sys

import pytest

from merger.core.engine import AsyncRuleEngine
from merger.models import Rule, SourceMeta
from merger.ports import AioHttpHttpPort, DnspythonDnsPort, SourceCachePort
from merger.whitelist_audit import AuditConfig, audit_whitelist

# ── fakes ────────────────────────────────────────────────────────────────


class FakeDnsPort:
    """Scripted CNAME table; records every resolve_cname call."""

    def __init__(self, table: dict[str, list[str]]) -> None:
        self.table = table
        self.calls: list[str] = []

    def resolve_cname(self, name: str) -> list[str]:
        self.calls.append(name)
        return list(self.table.get(name, []))


class FakeResponse:
    """aiohttp-response-shaped async CM; status/headers/text() only."""

    def __init__(self, status: int = 200, text: str = "", headers: dict | None = None) -> None:
        self.status = status
        self._text = text
        self.headers = headers or {}

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def raise_for_status(self) -> None:
        if self.status >= 400:
            import aiohttp

            raise aiohttp.ClientError(f"HTTP {self.status}")

    async def text(self, encoding: str = "utf-8", errors: str = "replace") -> str:
        return self._text


class FakeHttpPort:
    """Scripted GET routes; records requests and never touches a session."""

    def __init__(self, routes: dict[str, FakeResponse]) -> None:
        self.routes = routes
        self.requests: list[tuple[str, dict | None]] = []

    def get(self, url: str, headers: dict | None = None, timeout=None):
        self.requests.append((url, headers))
        return self.routes[url]

    def post(self, *args: object, **kwargs: object):
        raise AssertionError("fetch path must not issue POST")


class _BoomSession:
    """Stand-in session that fails loudly if the real transport is reached."""

    closed = False

    def get(self, *args: object, **kwargs: object):
        raise AssertionError("real aiohttp session must not be used when fake port injected")


# ── DnsPort: 5-hop cap / seen-set ring / empty / rescue ──────────────────


def test_fake_dns_port_five_hops_cap():
    table = {f"h{i}.test": [f"h{i + 1}.test"] for i in range(1, 7)}
    port = FakeDnsPort(table)
    engine = AsyncRuleEngine(cache_dir=None, dns_port=port)
    out = engine._resolve_cname_hints_sync("h1.test")
    assert len(out) == 5
    assert out[-1] == "h6.test"
    assert "h7.test" not in out
    # exactly 5 resolves: the hop budget, not the chain length, stops the walk
    assert port.calls == [f"h{i}.test" for i in range(1, 6)]


def test_fake_dns_port_ring_broken_by_seen_set():
    port = FakeDnsPort({"a.test": ["b.test"], "b.test": ["a.test"]})
    engine = AsyncRuleEngine(cache_dir=None, dns_port=port)
    out = engine._resolve_cname_hints_sync("a.test")
    assert out == ["b.test", "a.test"]
    assert len(out) == len(set(out))


def test_fake_dns_port_empty_result_returns_list():
    port = FakeDnsPort({})
    engine = AsyncRuleEngine(cache_dir=None, dns_port=port)
    assert engine._resolve_cname_hints_sync("x.test") == []
    assert port.calls == ["x.test"]


def test_default_dns_port_missing_library_returns_empty(monkeypatch):
    # No dnspython resolvable: the lazy ImportError collapses to [].
    monkeypatch.setitem(sys.modules, "dns.resolver", None)
    engine = AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_use_cname_hints=True,
    )
    assert engine._resolve_cname_hints_sync("a.test") == []


def test_cname_rescue_through_injected_dns_port(tmp_path):
    src = tmp_path / "source.txt"
    src.write_text("||cname-marker-zone.example^\n", encoding="utf-8")
    port = FakeDnsPort({"cname-marker-zone.example": ["doubleclick.net"]})
    engine = AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_use_cname_hints=True,
        dns_port=port,
    )
    outcome = engine.run_sync([SourceMeta(name="s1", url=str(src), category="other")])
    assert outcome.reclassified == 1
    # the seam walks the chain: source hint first, then a trailing empty hop
    assert port.calls == ["cname-marker-zone.example", "doubleclick.net"]


# ── HttpPort: 200 body / 304 conditional / real session unused ──────────


@pytest.mark.asyncio
async def test_fake_http_port_200_passes_body_without_real_session():
    url = "https://example/list.txt"
    fake = FakeHttpPort({url: FakeResponse(200, "||ads.example^\n")})
    engine = AsyncRuleEngine(cache_dir=None, http_port=fake)
    engine._session = _BoomSession()  # real transport must never be reached

    text, from_cache, err, _h = await engine._fetch_text(url, retries=0)
    assert err is None
    assert from_cache is False
    assert text == "||ads.example^\n"
    assert fake.requests == [(url, {})]


@pytest.mark.asyncio
async def test_fake_http_port_304_reuses_cached_body_and_sends_validator(tmp_path):
    url = "https://example/list.txt"
    engine = AsyncRuleEngine(cache_dir=str(tmp_path / "cache"), http_port=FakeHttpPort({}))
    engine.cache.store(url=url, content="||cached.com^\n", etag='"v1"')

    fake = FakeHttpPort({url: FakeResponse(304, "", headers={})})
    engine.http_port = fake
    text, from_cache, err, _h = await engine._fetch_text(url, retries=0)
    assert err is None
    assert from_cache is True
    assert text == "||cached.com^\n"
    # conditional request carried the stored ETag validator
    _, headers = fake.requests[0]
    assert headers.get("If-None-Match") == '"v1"'


# ── audit session factory injection ──────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_uses_injected_session_factory_offline():
    calls: list[int] = []

    class _RecordingSession:
        def __init__(self) -> None:
            self.gets: list = []
            self.posts: list = []

    def factory():
        calls.append(1)

        class _CM:
            async def __aenter__(self):
                return _RecordingSession()

            async def __aexit__(self, *exc: object) -> bool:
                return False

        return _CM()

    rule = Rule(
        raw="@@||example.com^",
        domain="example.com",
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
        use_scam_check=False,
        use_virustotal=False,
        use_ai=False,
        use_dnsbl=False,
        use_gsb=False,
        use_phishtank=False,
        use_urlscan=False,
        use_crtsh=False,
        use_heuristics=False,
        use_homograph=False,
    )
    out = await audit_whitelist([rule], config=cfg, session_factory=factory)
    assert len(calls) == 1
    assert out["summary"]["total"] == 1


# ── default production adapters wired ───────────────────────────────────


def test_engine_default_ports_are_production_adapters():
    engine = AsyncRuleEngine(cache_dir=None)
    assert isinstance(engine.http_port, AioHttpHttpPort)
    assert isinstance(engine.dns_port, DnspythonDnsPort)
    assert isinstance(engine.cache_port, SourceCachePort)
