"""R2 offline unit tests for the declarative audit-layer registry.

All cases are fully fabricated / monkeypatched: no DNS, no HTTP, no feed
download. They pin (a) fixed declaration order, (b) gate decisions (keyless
layers skip, urlscan/crtsh run without a key), (c) fresh disabled fallback
shapes, and (d) that the three seam names still resolve through the package
namespace at call time so existing monkeypatch seams keep hitting.
"""

from types import SimpleNamespace

import pytest

from merger.whitelist_audit import AuditConfig
from merger.whitelist_audit.registry import (
    LAYER_REGISTRY,
    AuditLayerContext,
    specs_by_name,
)

EXPECTED_ORDER = [
    "dns",
    "ti",
    "rdap",
    "scam",
    "dnsbl",
    "vt",
    "mxspf",
    "gsb",
    "phishtank",
    "urlscan",
    "crtsh",
]


def _ctx(config: AuditConfig, feed_index=None, ti_sem=None) -> AuditLayerContext:
    return AuditLayerContext(
        domain="example.com",
        session=None,
        config=config,
        feed_index=feed_index,
        ti_sem=ti_sem,
    )


# ── declaration order ─────────────────────────────────────────────────


def test_declaration_order_is_fixed():
    assert [spec.name for spec in LAYER_REGISTRY] == EXPECTED_ORDER


def test_registry_index_matches_declaration_order():
    by_name = specs_by_name()
    assert list(by_name) == EXPECTED_ORDER
    assert set(by_name) == set(EXPECTED_ORDER)


# ── gate decisions ────────────────────────────────────────────────────


def _enabled_names(config: AuditConfig) -> list[str]:
    ctx = _ctx(config)
    return [spec.name for spec in LAYER_REGISTRY if spec.gate(ctx)]


def test_default_config_enables_only_open_layers():
    cfg = AuditConfig()
    assert _enabled_names(cfg) == ["dns", "ti", "rdap", "scam"]


def test_vt_skips_without_key_even_when_enabled():
    off = AuditConfig(use_virustotal=True, virustotal_api_key="")
    assert "vt" not in _enabled_names(off)
    on = AuditConfig(use_virustotal=True, virustotal_api_key="secret")
    assert "vt" in _enabled_names(on)


def test_gsb_skips_without_key_even_when_enabled():
    off = AuditConfig(use_gsb=True, gsb_api_key="")
    assert "gsb" not in _enabled_names(off)
    on = AuditConfig(use_gsb=True, gsb_api_key="secret")
    assert "gsb" in _enabled_names(on)


def test_phishtank_skips_without_key_even_when_enabled():
    off = AuditConfig(use_phishtank=True, phishtank_api_key="")
    assert "phishtank" not in _enabled_names(off)
    on = AuditConfig(use_phishtank=True, phishtank_api_key="secret")
    assert "phishtank" in _enabled_names(on)


def test_urlscan_runs_without_key_optional_key():
    cfg = AuditConfig(use_urlscan=True, urlscan_api_key="")
    assert "urlscan" in _enabled_names(cfg)


def test_crtsh_runs_keyless():
    cfg = AuditConfig(use_crtsh=True)
    assert "crtsh" in _enabled_names(cfg)


def test_mxspf_off_by_default_and_gated_on_flag():
    assert "mxspf" not in _enabled_names(AuditConfig())
    assert "mxspf" in _enabled_names(AuditConfig(use_dns_mx=True))


# ── fallback shapes ───────────────────────────────────────────────────


def test_every_spec_exposes_fresh_fallback_factory():
    for spec in LAYER_REGISTRY:
        a = spec.default()
        b = spec.default()
        # factories return fresh objects; mutating one must not alias another
        assert a is not b
        if isinstance(a, dict):
            a["__mutated__"] = True
            assert "__mutated__" not in b


def test_ti_fallback_is_disabled_tuple_pair():
    pair = specs_by_name()["ti"].default()
    assert isinstance(pair, tuple) and len(pair) == 2
    for part in pair:
        assert part == {"malicious": False, "error": "disabled"}


def test_plain_layer_fallback_shapes():
    by_name = specs_by_name()
    assert by_name["dns"].default() == {"nxdomain": False, "ips": [], "error": "disabled"}
    assert by_name["dnsbl"].default() == {
        "listed": False,
        "malicious": False,
        "hits": [],
        "error": "disabled",
    }
    assert by_name["crtsh"].default() == {"entries": [], "error": "disabled"}


# ── seam names still resolve through the package namespace ────────────


@pytest.mark.asyncio
async def test_dns_seam_still_patchable(monkeypatch):
    import merger.whitelist_audit as wa

    seen = {}

    async def fake_dns(domain, timeout=5, doh_endpoint="", session=None):
        seen["domain"] = domain
        seen["doh_endpoint"] = doh_endpoint
        return {"nxdomain": False, "ips": ["1.2.3.4"], "error": None}

    monkeypatch.setattr(wa, "_dns_check", fake_dns)
    ctx = _ctx(AuditConfig())
    out = await specs_by_name()["dns"].build(ctx)
    assert seen["domain"] == "example.com"
    assert out["ips"] == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_threat_intel_seam_still_patchable(monkeypatch):
    import merger.whitelist_audit as wa

    called = {}

    async def fake_ti(domain, session, config, ti_sem=None):
        called["domain"] = domain
        return ({"malicious": False, "error": None}, {"malicious": False, "error": None})

    monkeypatch.setattr(wa, "_query_threat_intel", fake_ti)
    ctx = _ctx(AuditConfig(use_urlhaus=True, use_threatfox=True))
    out = await specs_by_name()["ti"].build(ctx)
    assert called["domain"] == "example.com"
    assert isinstance(out, tuple) and len(out) == 2


@pytest.mark.asyncio
async def test_dnsbl_seam_still_patchable(monkeypatch):
    import merger.whitelist_audit as wa

    async def fake_dnsbl(domain, timeout=6):
        return {"listed": False, "malicious": False, "hits": [], "error": None}

    monkeypatch.setattr(wa, "_query_dnsbl", fake_dnsbl)
    ctx = _ctx(AuditConfig(use_dnsbl=True))
    out = await specs_by_name()["dnsbl"].build(ctx)
    assert out["listed"] is False


# ── ti feed-index branch: ready → dataset; not ready → API fallback count ─


@pytest.mark.asyncio
async def test_ti_uses_dataset_when_feed_ready(monkeypatch):
    import merger.whitelist_audit.registry as reg

    async def fake_dataset(domain, feed_index):
        return ({"malicious": False, "error": None}, {"malicious": True, "error": None})

    monkeypatch.setattr(reg, "_query_threat_intel_dataset", fake_dataset)
    feed = SimpleNamespace(ready=True, stats={"api_fallbacks": 0})
    ctx = _ctx(AuditConfig(use_urlhaus=True, use_threatfox=True), feed_index=feed)
    out = await specs_by_name()["ti"].build(ctx)
    assert out[1]["malicious"] is True
    assert feed.stats["api_fallbacks"] == 0


@pytest.mark.asyncio
async def test_ti_counts_api_fallback_when_feed_not_ready(monkeypatch):
    import merger.whitelist_audit as wa

    async def fake_ti(domain, session, config, ti_sem=None):
        return ({"malicious": False, "error": None}, {"malicious": False, "error": None})

    monkeypatch.setattr(wa, "_query_threat_intel", fake_ti)
    feed = SimpleNamespace(ready=False, stats={"api_fallbacks": 0})
    ctx = _ctx(AuditConfig(use_urlhaus=True, use_threatfox=True), feed_index=feed)
    await specs_by_name()["ti"].build(ctx)
    assert feed.stats["api_fallbacks"] == 1


# ── C-12: DoH reuses the shared session instead of opening a new one ──


class _FakeResp:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def json(self, content_type=None):
        return {"Status": 0, "Answer": [{"type": 1, "data": "9.9.9.9"}]}


class _FakeSharedSession:
    def __init__(self):
        self.gets = 0
        self.closed = False

    def get(self, url, params=None, headers=None, timeout=None):
        self.gets += 1
        return _FakeResp()


@pytest.mark.asyncio
async def test_doh_lookup_reuses_provided_session():
    from merger.whitelist_audit.dns_doh import _doh_lookup

    shared = _FakeSharedSession()
    out = await _doh_lookup("example.com", "https://doh.example/base", timeout=5.0, session=shared)
    assert shared.gets == 1
    assert shared.closed is False  # caller owns lifecycle; we must not close it
    assert out == {"nxdomain": False, "ips": ["9.9.9.9"], "error": None}
