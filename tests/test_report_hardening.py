"""Hardening regressions from the full-source audit (P0 XSS + P1/P2 fixes).

Covers:
- report.html escapes untrusted modifier VALUES and source names (P0);
- report.md survives ``|`` inside modifier values (GFM table);
- history.json is written only in timestamped mode (determinism) and atomically;
- negative-cache stale fallback returns err=None so _fetch_one consumes it;
- SourceCache.get_content_stale ignores TTL while get_content honours it;
- response bodies are capped (aiohttp.ClientPayloadError on breach);
- AI malformed payloads report a parse error without retrying.
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import aiohttp
import pytest

from merger._http_hardening import read_response_bytes
from merger.cache import SourceCache
from merger.core import AsyncRuleEngine
from merger.core.outcome import MergeOutcome
from merger.core.stats import StatsMixin
from merger.exporter import Exporter
from merger.models import Rule, SourceMeta
from merger.report.analysis import analyze_rules
from merger.report.html import _render_audit_fragments, _render_modifier_rows
from merger.report.markdown import generate_markdown_report

# ── fixtures / helpers ────────────────────────────────────────────────


def _rule_with_modifiers(domain: str, modifiers: str) -> Rule:
    return Rule(
        raw=f"||{domain}^{modifiers}",
        domain=domain,
        rule_type="block",
        wildcard=False,
        modifiers=modifiers,
    )


def _minimal_outcome(**overrides: object) -> MergeOutcome:
    """A real MergeOutcome with only the version stamped (rest defaulted)."""
    return MergeOutcome(content_version="test123", **overrides)  # type: ignore[arg-type]


# ── P0: report.html escaping ──────────────────────────────────────────


def test_html_modifier_value_escaped():
    mods = "dnsrewrite=NOERROR;CNAME;<img src=x onerror=alert(1)>"
    r = _rule_with_modifiers("x.example", mods)
    stats = StatsMixin._compute_modifier_stats([r], [])
    rows = _render_modifier_rows(stats, sum(stats.values()))
    assert "<img" not in rows, "raw HTML from an upstream modifier value reached report.html"
    assert "&lt;img" in rows


def test_html_source_names_escaped():
    outcome = SimpleNamespace(failed_sources=[])
    overlap = {
        "source_effective": {"<b>src": 3},
        "pairs": [
            {
                "source_a": "<a>src",
                "source_b": "plain-src",
                "overlap": 1,
                "rate_a": 10.0,
                "rate_b": 20.0,
                "jaccard": 5.0,
            }
        ],
    }
    frag = _render_audit_fragments(outcome, {}, overlap, overlap["pairs"], [])
    assert "<a>src" not in frag["overlap_rows"]
    assert "&lt;a&gt;src" in frag["overlap_rows"]
    assert "<b>src" not in frag["effective_rows"]
    assert "&lt;b&gt;src" in frag["effective_rows"]


# ── P2: markdown table survives pipes in modifier values ─────────────


def test_markdown_modifier_pipe_escaped():
    mods = "dnstype=A|AAAA"
    r = _rule_with_modifiers("y.example", mods)
    blocks = [r]
    analysis = analyze_rules(blocks, [])
    outcome = _minimal_outcome(modifier_stats=StatsMixin._compute_modifier_stats(blocks, []))
    md = generate_markdown_report(blocks, [], outcome, analysis, include_time=False)
    assert "`$dnstype=A\\|AAAA`" in md
    # The row still has exactly the 3 cells of the modifier table: neutralize
    # the escaped pipes first, THEN split on the real cell separators.
    row = next(line for line in md.splitlines() if "dnstype" in line)
    assert len(row.replace("\\|", "@").split("|")) == 5  # leading + 3 cells + trailing


# ── P1: history.json determinism gating ──────────────────────────────


def test_history_json_not_written_in_deterministic_mode(tmp_path):
    exp = Exporter(
        tmp_path, formats=["adguard"], tiered=False, report=False, report_timestamp=False
    )
    exp.export_all([], [], _minimal_outcome())
    assert not (tmp_path / "history.json").exists()


def test_history_json_written_and_atomic_when_timestamped(tmp_path):
    exp = Exporter(tmp_path, formats=["adguard"], tiered=False, report=False, report_timestamp=True)
    exp.export_all([], [], _minimal_outcome())
    data = json.loads((tmp_path / "history.json").read_text(encoding="utf-8"))
    assert isinstance(data, list) and len(data) == 1
    assert "timestamp" in data[0]
    assert not (tmp_path / "history.json.tmp").exists()


# ── P1: negative-cache stale fallback ────────────────────────────────


async def test_negative_cache_stale_fallback_succeeds(tmp_path):
    """_fetch_one must consume stale content from a negative-cache hit.

    Regression: _fetch_text returned the stale body WITH an error string, and
    _fetch_one's ``if err:`` discarded it — the fallback never worked.
    """
    engine = AsyncRuleEngine(
        cache_dir=str(tmp_path / "cache"),
        negative_ttl_seconds=300,
        retry_count=0,
    )
    url = "http://cached.example/list.txt"
    engine.cache.store(url=url, content="0.0.0.0 blocked.example\n")
    engine._negative_cache[url] = time.monotonic()

    text, from_cache, err, content_hash = await engine._fetch_text(url)
    assert err is None
    assert from_cache is True
    assert "blocked.example" in text
    assert content_hash

    rules, success, _fc, n, ferr = await engine._fetch_one(SourceMeta(name="t", url=url))
    assert success is True
    assert ferr is None
    assert n == 1 and rules[0].normalized_domain == "blocked.example"


# ── P1: stale fallback ignores cache TTL ─────────────────────────────


def test_get_content_stale_ignores_ttl(tmp_path):
    c = SourceCache(str(tmp_path), ttl_seconds=60)
    url = "http://x.example/l"
    c.store(url=url, content="rule-a\n")
    c._entries[url].fetched_at = time.time() - 10_000  # far past the TTL
    assert c.get_content(url) is None
    assert c.get_content_stale(url) == "rule-a\n"


# ── P2: bounded response reads ───────────────────────────────────────


class _FakeContent:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def iter_chunked(self, _n: int):
        for c in self._chunks:
            yield c


class _FakeResp:
    def __init__(self, chunks: list[bytes], content_length: int | None = None) -> None:
        self.content = _FakeContent(chunks)
        self.content_length = content_length


async def test_read_response_bytes_happy_path():
    assert await read_response_bytes(_FakeResp([b"abc", b"de"])) == b"abcde"


async def test_read_response_bytes_enforces_cap_while_streaming():
    with pytest.raises(aiohttp.ClientPayloadError):
        await read_response_bytes(_FakeResp([b"x" * 100]), limit=10)


async def test_read_response_bytes_fast_reject_on_content_length():
    with pytest.raises(aiohttp.ClientPayloadError):
        await read_response_bytes(_FakeResp([], content_length=1000), limit=10)


# ── P2: AI malformed payload — parse error, no retry ─────────────────


async def test_ai_malformed_response_no_retry():
    from merger import ai_classifier

    ai_classifier._ai_cache._store.clear()  # keep runs independent of the 5-min TTL

    calls = {"n": 0}

    class _Resp:
        status = 200

        async def json(self, content_type=None):
            return {"unexpected": "shape"}  # no choices → KeyError inside _do

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Session:
        def post(self, *a, **k):
            calls["n"] += 1
            return _Resp()

    res = await ai_classifier.classify_with_ai("malformed.example", "k", _Session())
    assert res["error"] == "malformed response"
    assert calls["n"] == 1, "parse errors must not burn retry attempts"
