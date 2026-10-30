"""Tests for the bounded _TTLCache."""

from __future__ import annotations

import time

from merger._http_hardening import _TTLCache


def test_cache_basic_get_set():
    c = _TTLCache(ttl=60)
    c.set("a", 1)
    assert c.get("a") == 1


def test_cache_expiry():
    c = _TTLCache(ttl=0.05)
    c.set("a", 1)
    time.sleep(0.1)
    assert c.get("a") is None


def test_cache_eviction_at_maxsize():
    c = _TTLCache(ttl=60, maxsize=3)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)
    c.set("d", 4)  # evicts "a"
    assert c.get("a") is None
    assert c.get("b") == 2
    assert c.get("c") == 3
    assert c.get("d") == 4
    assert len(c._store) == 3


def test_cache_missing_key():
    c = _TTLCache(ttl=60)
    assert c.get("nope") is None
