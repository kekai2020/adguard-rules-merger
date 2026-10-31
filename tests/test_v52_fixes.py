"""V5.2 tests: report contribution accounting, overlap matrix, sort
determinism and the per-source fetch deadline."""

import asyncio

import pytest

from merger.cache import SourceCache
from merger.core import AsyncRuleEngine
from merger.models import Rule, SourceMeta
from merger.report import analyze_rules, generate_html_report, generate_markdown_report


def _rule(
    domain, rule_type="block", wildcard=False, sources=("s1",), category="ads", modifiers="", raw=""
):
    return Rule(
        raw=raw,
        domain=domain,
        rule_type=rule_type,
        wildcard=wildcard,
        sources=sources,
        category=category,
        modifiers=modifiers,
    )


class _FakeOutcome:
    """Minimal MergeOutcome stand-in for report rendering tests."""

    def __init__(self, blocks, allows, contributions, source_overlap):
        self.blocks = blocks
        self.allows = allows
        self.regex_blocks = []
        self.regex_allows = []
        self.raw_count = 10
        self.sources_ok = 2
        self.sources_total = 2
        self.sources_cached = 0
        self.exact_merged = 0
        self.normalized_merged = 0
        self.regex_merged = 0
        self.aggregated = 0
        self.wildcard_aggregated = 0
        self.wildcard_promoted = 0
        self.conflict_resolved = 0
        self.whitelist_blocked = 0
        self.pattern_dropped = 0
        self.quality_dropped = 0
        self.css_dropped = 0
        self.comment_dropped = 0
        self.modifier_stripped = 0
        self.badfilter_removed = 0
        self.conflicts = []
        self.failed_sources = []
        self.contributions = contributions
        self.source_overlap = source_overlap
        self.modifier_stats = {}
        self.whitelist_audit = {}
        self.added = []
        self.removed = []
        self.elapsed = 0.1
        self.content_version = "abc123"


class TestContributionAccounting:
    def test_regex_rules_counted_in_contributions(self):
        """Regex rules used to vanish from the stats (DNS Rebind case:
        raw=16 shown as 3/0/100%)."""
        regex_rules = [
            _rule("", raw=f"/^r{i}\\.(?:\\d{{1,3}})\\.$/", sources=("s1",)) for i in range(3)
        ]
        # give them empty normalized domain (regex semantics)
        for r in regex_rules:
            r._norm = ""
            r._out = ""
        blocks = [_rule("a.com", sources=("s1",))] + regex_rules
        contribs, _overlap = AsyncRuleEngine._compute_stats(blocks, [], {"s1": "Rebind"}, {"s1": 4})
        c = contribs[0]
        assert c["raw_rules"] == 4
        assert c["effective_rules"] == 4  # 1 domain + 3 regex
        assert c["unique_rules"] == 4
        assert c["coverage_rate"] == 100.0
        assert c["unique_rate"] == 100.0

    def test_coverage_rate_reflects_absorbed_rules(self):
        blocks = [_rule("a.com", sources=("s1", "s2")), _rule("b.com", sources=("s2",))]
        contribs = {
            c["name"]: c
            for c in AsyncRuleEngine._compute_stats(
                blocks, [], {"s1": "A", "s2": "B"}, {"s1": 10, "s2": 2}
            )[0]
        }
        a = contribs["A"]
        assert a["effective_rules"] == 1
        assert a["coverage_rate"] == 10.0  # 1/10 raw survived
        assert a["unique_rate"] == 0.0  # shared with B
        b = contribs["B"]
        assert b["unique_rate"] == 50.0  # 1 unique of 2 effective

    def test_overlap_matrix_includes_regex_and_jaccard(self):
        r1 = _rule("a.com", sources=("s1", "s2"))
        r2 = _rule("b.com", sources=("s2",))
        regex = _rule("", raw="/^x.*$/", sources=("s1", "s2"))
        regex._norm = ""
        regex._out = ""
        _contribs, overlap = AsyncRuleEngine._compute_stats(
            [r1, r2, regex], [], {"s1": "A", "s2": "B"}, {"s1": 2, "s2": 2}
        )
        mtx = overlap["matrix"]
        assert set(mtx["order"]) == {"A", "B"}
        cells = mtx["cells"]
        pair = cells.get("A", {}).get("B") or cells.get("B", {}).get("A")
        assert pair["overlap"] == 2  # a.com + regex
        # eff A=2, eff B=3, union=3 → jaccard 66.7
        assert pair["jaccard"] == pytest.approx(66.7, abs=0.2)


class TestReportRendering:
    def _outcome(self):
        blocks = [_rule("a.com", sources=("s1", "s2")), _rule("b.com", sources=("s1",))]
        regex = _rule("", raw="/^z.*$/", sources=("s1",))
        regex._norm = ""
        regex._out = ""
        blocks.append(regex)
        contribs, overlap = AsyncRuleEngine._compute_stats(
            blocks, [], {"s1": "A", "s2": "B"}, {"s1": 5, "s2": 10}
        )
        return _FakeOutcome(blocks, [], contribs, overlap)

    def test_html_has_new_columns_and_matrix(self):
        outcome = self._outcome()
        analysis = analyze_rules(outcome.blocks, outcome.allows)
        html = generate_html_report(outcome.blocks, outcome.allows, outcome, analysis)
        assert "输出覆盖" in html and "覆盖率" in html and "独占率" in html
        assert "源间重复矩阵" in html
        assert "重复率" in html
        assert "title=" in html  # hover tooltips on matrix cells

    def test_markdown_matrix_cells_have_count_and_rate(self):
        outcome = self._outcome()
        analysis = analyze_rules(outcome.blocks, outcome.allows)
        md = generate_markdown_report(outcome.blocks, outcome.allows, outcome, analysis)
        assert "源间重复矩阵" in md
        assert "源编号对照" in md
        # cell format: emoji + count + (rate%)
        assert "(" in md and "%" in md
        # regex contribution is no longer invisible
        assert "/^z.*$/" not in md  # not dumped raw
        assert "输出覆盖" in md

    def test_report_matrix_is_symmetric(self):
        from merger.report import _build_matrix

        r1 = _rule("a.com", sources=("s1", "s2"))
        r2 = _rule("b.com", sources=("s2", "s3"))
        r3 = _rule("c.com", sources=("s1", "s3"))
        _contribs, overlap = AsyncRuleEngine._compute_stats(
            [r1, r2, r3], [], {"s1": "A", "s2": "B", "s3": "C"}, {}
        )
        m = _build_matrix(overlap)
        order = m["order"]
        for x in order:
            for y in order:
                assert m["get"](x, y) == m["get"](y, x)
        # every pair with actual overlap must be visible from both sides
        assert m["get"]("A", "B") is not None
        assert m["get"]("B", "A") is not None

    def test_hostile_label_cannot_inject_script_tag(self):
        # XSS guard (kept from the V6 suite): a hostile regex-rule label must
        # not leak a raw closing <script> tag into the generated HTML report.
        # (The ECharts-era _json_for_script helper was removed with the
        # script-free pure-CSS renderer; the end-to-end assertion remains.)
        from merger.report import analyze_rules, generate_html_report

        outcome = self._outcome()
        outcome.blocks.append(_rule("", raw="/^z.*$/", sources=("s1",)))
        outcome.blocks[-1]._norm = ""
        outcome.blocks[-1]._out = ""
        html = generate_html_report(
            outcome.blocks, outcome.allows, outcome, analyze_rules(outcome.blocks, outcome.allows)
        )
        assert "</script><script>" not in html


class TestSortDeterminism:
    def test_regex_order_is_deterministic(self):
        def make(order):
            rules = [_rule("", raw=raw) for raw in order]
            for r in rules:
                r._norm = ""
                r._out = ""
            return rules

        import random

        base = ["/^aaa$/", "/^bbb$/", "/^ccc$/", "/^ddd$/"]
        for seed in range(5):
            shuffled = base[:]
            random.Random(seed).shuffle(shuffled)
            assert [r.sort_key() for r in sorted(make(shuffled), key=Rule.sort_key)] == [
                r.sort_key() for r in sorted(make(base), key=Rule.sort_key)
            ]

    def test_sort_key_tiebreaks_on_raw(self):
        a = _rule("", raw="/^a$/")
        b = _rule("", raw="/^b$/")
        a._norm = b._norm = ""
        a._out = b._out = ""
        assert a.sort_key() < b.sort_key()
        assert (b < a) is False


class TestStatsTieBreakDeterminism:
    """O2: equal-count ties in overlap/effective/modifier stats must resolve to
    a stable key order instead of async completion/insertion order."""

    def _tied_blocks(self):
        # s1 and s2 each contribute 2 effective rules; exactly one shared pair.
        a = _rule("a.com", sources=("s1", "s2"))
        b = _rule("b.com", sources=("s1",))
        c = _rule("c.com", sources=("s2",))
        return [a, b, c]

    def test_effective_and_pair_order_independent_of_input_order(self):
        src_names = {"s1": "A", "s2": "B"}
        raw = {"s1": 2, "s2": 2}
        _, ov1 = AsyncRuleEngine._compute_stats(self._tied_blocks(), [], src_names, raw)
        _, ov2 = AsyncRuleEngine._compute_stats(
            list(reversed(self._tied_blocks())), [], src_names, raw
        )
        assert list(ov1["source_effective"]) == list(ov2["source_effective"])
        assert ov1["matrix"]["order"] == ov2["matrix"]["order"]
        assert [p["overlap"] for p in ov1["pairs"]] == [p["overlap"] for p in ov2["pairs"]]

    def test_modifier_stats_tie_sorted_by_modifier_name(self):
        # One $important and one $badfilter rule, equal count; tie must break
        # alphabetically rather than follow input order.
        r1 = _rule("m1.com", modifiers="important")
        r2 = _rule("m2.com", modifiers="badfilter")
        stats = AsyncRuleEngine._compute_modifier_stats([r1, r2], [])
        assert list(stats) == ["badfilter", "important"]
        reversed_stats = AsyncRuleEngine._compute_modifier_stats([r2, r1], [])
        assert list(reversed_stats) == ["badfilter", "important"]


class _HangAndTimeout:
    """aiohttp-style request handle: async context manager that hangs then
    times out (mirrors ``async with session.get(...) as resp``)."""

    async def __aenter__(self):
        await asyncio.sleep(0.25)
        raise asyncio.TimeoutError()

    async def __aexit__(self, *exc):
        return False


class _StubSession:
    """Session whose requests always hang then time out."""

    closed = False

    def __init__(self):
        self.calls = 0

    def get(self, url, headers=None, timeout=None):
        self.calls += 1
        return _HangAndTimeout()


class TestSourceDeadline:
    @pytest.mark.asyncio
    async def test_deadline_caps_retries_and_uses_stale_cache(self, tmp_path):
        engine = AsyncRuleEngine(
            cache_dir=str(tmp_path / "cache"),
            source_deadline=0.6,
            retry_count=10,
            retry_delay=0.01,
            timeout=30,
        )
        url = "https://dead.example/list.txt"
        engine.cache.store(url=url, content="||cached.com^\n")
        engine._session = _StubSession()

        text, from_cache, err, _h = await engine._fetch_text(url, retries=10)
        assert text == "||cached.com^\n"  # stale-cache fallback
        assert from_cache is True
        assert err is None
        # without the deadline this would be 11 attempts × 0.25s+
        assert engine._session.calls <= 4

    @pytest.mark.asyncio
    async def test_deadline_without_cache_reports_error(self, tmp_path):
        engine = AsyncRuleEngine(
            cache_dir=str(tmp_path / "cache"),
            source_deadline=0.6,
            retry_count=10,
            retry_delay=0.01,
            timeout=30,
        )
        engine._session = _StubSession()
        text, from_cache, err, _h = await engine._fetch_text(
            "https://dead.example/list.txt", retries=10
        )
        assert text == ""
        assert err is not None and "deadline" in err


class TestSidecarCounterRestore:
    @pytest.mark.asyncio
    async def test_counters_survive_parsed_cache(self, tmp_path):
        engine = AsyncRuleEngine(cache_dir=str(tmp_path / "cache"), strip_www=False)
        text = "||ads.example.com^\n! comment\n"
        h = SourceCache.hash_text(text)
        engine.cache.store(url="u://x", content=text, content_hash=h)
        # first fetch: full parse, counters recorded + stored
        meta = SourceMeta(name="x", url="u://x", category="ads", timeout=5)

        class _LocalSession:
            closed = False

        engine._session = _LocalSession()

        # _fetch_text short-circuits for local paths only; simulate 304 path by
        # monkeypatching it to return the cached text directly.
        async def fake_fetch(source, retries=2, timeout=None):
            return text, True, None, h

        engine._fetch_text = fake_fetch

        rules, ok, _cached, _n, _err = await engine._fetch_one(meta)
        assert ok and len(rules) == 1
        assert engine.comment_dropped == 1

        # second engine: sidecar hit must restore the comment counter too
        engine2 = AsyncRuleEngine(cache_dir=str(tmp_path / "cache"), strip_www=False)
        engine2._session = _LocalSession()
        engine2._fetch_text = fake_fetch
        rules2, ok2, _c2, _n2, _e2 = await engine2._fetch_one(meta)
        assert ok2 and len(rules2) == 1
        assert engine2.comment_dropped == 1  # restored from sidecar
        assert engine2.pattern_dropped == 0
