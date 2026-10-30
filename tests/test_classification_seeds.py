"""Offline seed tables + optional CNAME-hint tests for block reclassification.

Task 1: built-in ``merger/data/category_seeds.json`` and an optional external
Shallalist/UT1-style ``seed_file`` feed the registered-domain lookup with
setdefault semantics (hand-written entries win); both only matter at
high-confidence (0.9) registered-domain exact matches.

Task 2: ``use_cname_hints`` (default off) resolves a CNAME chain via dnspython
and accepts the verdict only when a CNAME target itself hits a registered
domain at 0.9; every failure path keeps the source bucket. No real DNS: the
resolver seam is monkeypatched in every CNAME test.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from merger import AsyncRuleEngine
from merger.domain_classifier import (
    _REGISTERED_LOOKUP,
    CONFIDENCE_REGISTERED,
    _load_builtin_seeds,
    block_bucket_for,
    classify_domain_with_confidence,
    load_seed_file,
    merge_seed_map,
)
from merger.models import SourceMeta


def _run_local(tmp_path, text: str, category: str, **engine_kwargs):
    src = tmp_path / "source.txt"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(text, encoding="utf-8")
    engine = AsyncRuleEngine(cache_dir=None, **engine_kwargs)
    return engine, engine.run_sync([SourceMeta(name="s1", url=str(src), category=category)])


def _by_domain(outcome) -> dict[str, str]:
    return {r.normalized_domain: r.category for r in outcome.blocks}


# ── task 1: built-in seed table ──────────────────────────────────────


def test_builtin_seed_hit_at_high_confidence():
    # ads-twitter.com is a curated built-in seed NOT in the hand-written table.
    cat, conf, reason = classify_domain_with_confidence("ads-twitter.com")
    assert cat == "advertising"
    assert conf == CONFIDENCE_REGISTERED
    assert "registered domain match" in reason


def test_builtin_seed_moves_bucket_when_enabled(tmp_path):
    _, outcome = _run_local(
        tmp_path,
        "||ads-twitter.com^\n",
        "other",
        classification_enabled=True,
    )
    assert _by_domain(outcome)["ads-twitter.com"] == "ads"


# ── task 1: external seed_file parsing + category merge ────────────


def test_load_seed_file_shallalist_and_ut1_styles(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text(
        "# a comment line\n"
        "\n"
        "example-ad.com;Advertising\n"
        "track-example.net,TRK\n"
        "shop-example.com;Gambling\n",  # unmapped category -> dropped, not other
        encoding="utf-8",
    )
    mapping = load_seed_file(str(f))
    assert mapping["example-ad.com"] == "advertising"
    assert mapping["track-example.net"] == "analytics"
    assert "shop-example.com" not in mapping


def test_external_seed_file_merges_into_lookup(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text("ext-ad-zone.com;adv\next-trk-zone.com,tracking\n", encoding="utf-8")
    _, outcome = _run_local(
        tmp_path,
        "||ext-ad-zone.com^\n||ext-trk-zone.com^\n",
        "other",
        classification_enabled=True,
        classification_seed_file=str(f),
    )
    cats = _by_domain(outcome)
    assert cats["ext-ad-zone.com"] == "ads"
    assert cats["ext-trk-zone.com"] == "tracking"


def test_missing_seed_file_safe_skip(tmp_path):
    missing = str(tmp_path / "nope.txt")
    _, outcome = _run_local(
        tmp_path,
        "||plain-unknown-marker.example^\n",
        "other",
        classification_enabled=True,
        classification_seed_file=missing,
    )
    assert outcome.reclassified == 0
    assert _by_domain(outcome)["plain-unknown-marker.example"] == "other"


def test_bad_seed_file_safe_skip(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("\x00\xff not a parseable seed file {{{\n", encoding="utf-8", errors="ignore")
    _, outcome = _run_local(
        tmp_path,
        "||plain-unknown-marker.example^\n",
        "other",
        classification_enabled=True,
        classification_seed_file=str(bad),
    )
    assert outcome.reclassified == 0
    assert _by_domain(outcome)["plain-unknown-marker.example"] == "other"


def test_seed_file_ignored_when_disabled(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text("off-ad-zone.com;adv\n", encoding="utf-8")
    _, outcome = _run_local(
        tmp_path,
        "||off-ad-zone.com^\n",
        "other",
        classification_enabled=False,
        classification_seed_file=str(f),
    )
    assert outcome.reclassified == 0
    assert _by_domain(outcome)["off-ad-zone.com"] == "other"


# ── task 2: CNAME hints (default off, accept 0.9 target only) ────────


def test_cname_accepted_end_to_end(tmp_path, monkeypatch):
    src = tmp_path / "source.txt"
    src.write_text("||cname-marker-zone.example^\n", encoding="utf-8")
    engine = AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_use_cname_hints=True,
    )
    monkeypatch.setattr(engine, "_resolve_cname_hints_sync", lambda d: ["doubleclick.net"])
    outcome = engine.run_sync([SourceMeta(name="s1", url=str(src), category="other")])
    assert _by_domain(outcome)["cname-marker-zone.example"] == "ads"
    assert outcome.reclassified == 1


def test_cname_no_target_keeps_source(tmp_path, monkeypatch):
    src = tmp_path / "source.txt"
    src.write_text("||cname-empty-zone.example^\n", encoding="utf-8")
    engine = AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_use_cname_hints=True,
    )
    monkeypatch.setattr(engine, "_resolve_cname_hints_sync", lambda d: [])
    outcome = engine.run_sync([SourceMeta(name="s1", url=str(src), category="other")])
    assert _by_domain(outcome)["cname-empty-zone.example"] == "other"
    assert outcome.reclassified == 0


def test_cname_resolution_failure_keeps_source(tmp_path, monkeypatch):
    src = tmp_path / "source.txt"
    src.write_text("||cname-fail-zone.example^\n", encoding="utf-8")
    engine = AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_use_cname_hints=True,
    )

    def _boom(domain):
        raise RuntimeError("dns exploded")

    monkeypatch.setattr(engine, "_resolve_cname_hints_sync", _boom)
    outcome = engine.run_sync([SourceMeta(name="s1", url=str(src), category="other")])
    assert _by_domain(outcome)["cname-fail-zone.example"] == "other"
    assert outcome.reclassified == 0


def test_cname_low_confidence_target_rejected(tmp_path, monkeypatch):
    # A CNAME target that only matches a subdomain prefix (0.6) must not move.
    src = tmp_path / "source.txt"
    src.write_text("||cname-low-zone.example^\n", encoding="utf-8")
    engine = AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_use_cname_hints=True,
    )
    monkeypatch.setattr(engine, "_resolve_cname_hints_sync", lambda d: ["ads.example.com"])
    outcome = engine.run_sync([SourceMeta(name="s1", url=str(src), category="other")])
    assert _by_domain(outcome)["cname-low-zone.example"] == "other"
    assert outcome.reclassified == 0


def test_use_cname_hints_default_off(tmp_path):
    from merger.config import MergeConfig

    assert MergeConfig().classification.use_cname_hints is False
    cfg = MergeConfig()
    engine = AsyncRuleEngine.from_config(cfg)
    assert engine.classification_use_cname_hints is False


# ── classifier-level CNAME discount (0.9 → 0.72) is too weak to move ──


def test_classifier_cname_discount_072_rejected_by_bucket():
    # A CNAME hint that itself matches a registered domain at 0.9 is discounted
    # to 0.72 by the classifier; block_bucket_for refuses anything below 0.9.
    cat, conf, _reason = classify_domain_with_confidence(
        "miss.example", cname_hints=["doubleclick.net"]
    )
    assert cat == "advertising"
    assert conf == pytest.approx(0.72)
    assert block_bucket_for("advertising", conf) is None


# ── CNAME seam internals: ring / hop cap / NXDOMAIN / timeout (fake DNS) ──


class _FakeTarget:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeAnswer:
    def __init__(self, targets: list[str]) -> None:
        self._targets = targets

    def __iter__(self):
        for t in self._targets:
            yield SimpleNamespace(target=_FakeTarget(t))


class _FakeResolver:
    def __init__(self, table: dict[str, list[str]] | None, raise_exc: Exception | None = None):
        self._table = table or {}
        self._raise = raise_exc
        self.lifetime = None
        self.timeout = None

    def resolve(self, name: str, _rdtype: str):
        if self._raise is not None:
            raise self._raise
        if name not in self._table:
            raise _FakeNXDOMAIN()
        return _FakeAnswer(self._table[name])


class _FakeNXDOMAIN(Exception):
    pass


def _inject_fake_dns(monkeypatch, table=None, raise_exc=None):
    fake = SimpleNamespace(
        Resolver=lambda: _FakeResolver(table, raise_exc),
        NXDOMAIN=_FakeNXDOMAIN,
        NoAnswer=type("NoAnswer", (Exception,), {}),
    )
    # dnspython may be absent in the test env; register a stub parent package
    # plus the fake submodule so the seam's `import dns.resolver` succeeds.
    parent = SimpleNamespace(__path__=[], resolver=fake)
    monkeypatch.setitem(sys.modules, "dns", parent)
    monkeypatch.setitem(sys.modules, "dns.resolver", fake)


def _seam_engine():
    return AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_use_cname_hints=True,
    )


def test_cname_ring_is_broken_by_seen_set(monkeypatch):
    # a.test → b.test → a.test: the repeat target terminates the chain instead
    # of looping forever; each target appears at most once.
    _inject_fake_dns(monkeypatch, {"a.test": ["b.test"], "b.test": ["a.test"]})
    engine = _seam_engine()
    out = engine._resolve_cname_hints_sync("a.test")
    assert out == ["b.test", "a.test"]
    assert len(out) == len(set(out))


def test_cname_chain_stops_at_five_hops(monkeypatch):
    # h1→h2→h3→h4→h5→h6→h7: the 5-hop budget caps the recorded targets.
    chain = {f"h{i}.test": [f"h{i + 1}.test"] for i in range(1, 7)}
    _inject_fake_dns(monkeypatch, chain)
    engine = _seam_engine()
    out = engine._resolve_cname_hints_sync("h1.test")
    assert len(out) == 5
    assert out[-1] == "h6.test"
    assert "h7.test" not in out


def test_cname_nxdomain_returns_empty(monkeypatch):
    _inject_fake_dns(monkeypatch, {}, raise_exc=_FakeNXDOMAIN())
    assert _seam_engine()._resolve_cname_hints_sync("dead.test") == []


def test_cname_timeout_returns_empty(monkeypatch):
    _inject_fake_dns(monkeypatch, {}, raise_exc=TimeoutError("resolver timed out"))
    assert _seam_engine()._resolve_cname_hints_sync("slow.test") == []


def test_cname_missing_dnspython_returns_empty(monkeypatch):
    # No dnspython available at all: ImportError collapses to [].
    monkeypatch.setitem(sys.modules, "dns.resolver", None)
    assert _seam_engine()._resolve_cname_hints_sync("a.test") == []


def test_cname_seam_not_called_when_domain_already_hits(monkeypatch, tmp_path):
    # A 0.9 registered match short-circuits before CNAME rescue; the seam
    # must never be invoked (and must not blow up if it would be).
    src = tmp_path / "source.txt"
    src.write_text("||doubleclick.net^\n", encoding="utf-8")
    engine = AsyncRuleEngine(
        cache_dir=None,
        classification_enabled=True,
        classification_use_cname_hints=True,
    )

    def _boom(_domain):
        raise AssertionError("CNAME seam must not run on a 0.9 hit")

    monkeypatch.setattr(engine, "_resolve_cname_hints_sync", _boom)
    outcome = engine.run_sync([SourceMeta(name="s1", url=str(src), category="other")])
    assert _by_domain(outcome)["doubleclick.net"] == "ads"
    assert outcome.reclassified == 1


# ── external seed_file parsing edge cases ────────────────────────────


def test_seed_file_cleans_scheme_prefix_and_trailing_dot(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text(
        "# comment\n\nhttp://clean-ad.com/landing;adv\n||clean-trk.net,TRK\nclean-pay.com.;adv\n",
        encoding="utf-8",
    )
    m = load_seed_file(str(f))
    assert m["clean-ad.com"] == "advertising"
    assert m["clean-trk.net"] == "analytics"
    assert m["clean-pay.com"] == "advertising"


def test_seed_file_unknown_category_dropped(tmp_path):
    f = tmp_path / "seeds.txt"
    f.write_text("mystery.com,GAMBLING\ngood.com;adv\n", encoding="utf-8")
    m = load_seed_file(str(f))
    assert "mystery.com" not in m
    assert m["good.com"] == "advertising"


def test_seed_file_missing_returns_empty():
    assert load_seed_file("/no/such/seed-file-xyz.txt") == {}


def test_seed_file_ondir_returns_empty(tmp_path):
    # A directory path raises IsADirectoryError (OSError) → safe empty map.
    assert load_seed_file(str(tmp_path)) == {}


def test_seed_file_bad_encoding_does_not_raise(tmp_path):
    f = tmp_path / "bad.txt"
    f.write_bytes(b"\xff\x00\xfe not a seed {{{\n;adv\n")
    # errors="replace" means decode never raises; the parser must not throw.
    assert isinstance(load_seed_file(str(f)), dict)


def test_seed_file_setdefault_does_not_overwrite_handwritten():
    # hand-written registered entries win; external list cannot override them.
    prior = _REGISTERED_LOOKUP["doubleclick.net"]
    added = merge_seed_map({"doubleclick.net": "cdn"})
    assert added == 0
    assert _REGISTERED_LOOKUP["doubleclick.net"] == prior


def test_seed_file_adds_only_absent_domains():
    marker = "zzqk-seed-unique-marker.example"
    try:
        assert merge_seed_map({marker: "advertising"}) == 1
        assert _REGISTERED_LOOKUP[marker] == "advertising"
    finally:
        _REGISTERED_LOOKUP.pop(marker, None)


# ── built-in seed table metadata + scope ───────────────────────────────


def test_builtin_seed_ignores_metadata_keys():
    seeds = _load_builtin_seeds()
    assert "_comment" not in seeds
    assert all(not k.startswith("_") for k in seeds)


def test_builtin_seed_only_used_on_registered_exact_match():
    # Seed-only domain hits at 0.9; an unrelated registered domain must not
    # inherit the seed via first-label prefix.
    cat, conf, _ = classify_domain_with_confidence("ads-twitter.com")
    assert cat == "advertising"
    assert conf == CONFIDENCE_REGISTERED
    cat2, conf2, _ = classify_domain_with_confidence("ads-twitter.example.com")
    assert conf2 < CONFIDENCE_REGISTERED
    assert cat2 == "other"
