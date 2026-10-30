"""Tests for the V8 shared HTTP-hardening helpers and classifier cache."""

from __future__ import annotations

import asyncio

import pytest

from merger._http_hardening import DEFAULT_TTL, _TTLCache, with_retry
from merger.domain_classifier import ClassifierRuleSet, classify_domain


def test_ttl_cache_hit_and_miss():
    c = _TTLCache(ttl=10.0)
    assert c.get("k") is None
    c.set("k", "v")
    assert c.get("k") == "v"


def test_ttl_cache_expiry():
    c = _TTLCache(ttl=0.0)
    c.set("k", "v")
    # On the next monotonic tick the entry is past expiry.
    import time

    time.sleep(0.001)
    assert c.get("k") is None


def test_ttl_default_ttl_constant():
    assert DEFAULT_TTL == 300.0


async def test_with_retry_success_first_try():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        return "ok"

    assert await with_retry(factory, what="t") == "ok"
    assert calls["n"] == 1


async def test_with_retry_eventual_success():
    calls = {"n": 0}

    async def factory():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("boom")
        return "ok"

    assert await with_retry(factory, what="t", backoff_base=0.0) == "ok"
    assert calls["n"] == 3


async def test_with_retry_exhausts_and_reraises():
    async def factory():
        raise ConnectionError("boom")

    with pytest.raises(ConnectionError):
        await with_retry(factory, what="t", retries=2, backoff_base=0.0)


def test_classifier_cache_returns_same_result():
    rs = ClassifierRuleSet()
    a = rs.classify_with_confidence("google.com")
    b = rs.classify_with_confidence("google.com")
    assert a == b
    # cache populated
    assert any(k[0] == "google.com" for k in rs._cache)


def test_classifier_cache_cleared_on_seed_merge():
    rs = ClassifierRuleSet()
    rs.classify_with_confidence("example.com")
    assert len(rs._cache) > 0
    rs.merge_seeds({"newseed.test": "cdn"})
    assert len(rs._cache) == 0


def test_classifier_cache_key_normalized():
    rs = ClassifierRuleSet()
    # Trailing dot and case should collapse to the same cache entry.
    rs.classify_with_confidence("Google.COM.")
    rs.classify_with_confidence("google.com")
    hits = [k for k in rs._cache if k[0] == "google.com"]
    assert len(hits) == 1


def test_module_level_classify_domain_still_works():
    assert isinstance(classify_domain("example.com"), str)
