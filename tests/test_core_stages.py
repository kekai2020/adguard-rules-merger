"""R1 offline unit tests for the pure stage kernels in ``merger.core.stages``.

All rules are constructed in-process (no fetch, no DNS, no file IO). The
delegation tests assert the module-level helpers return exactly what the
existing ``StatsMixin`` class/static methods return, so counts, overlap
shape and deterministic tie-breaks are unchanged.
"""

import hashlib

from merger.core import AsyncRuleEngine
from merger.core.stages import (
    compute_content_version,
    compute_contributions,
    compute_modifier_stats,
    sort_merged,
)
from merger.models import Rule


def _rule(
    domain,
    rule_type="block",
    wildcard=False,
    sources=("s1",),
    category="ads",
    modifiers="",
    raw="",
):
    r = Rule(
        raw=raw,
        domain=domain,
        rule_type=rule_type,
        wildcard=wildcard,
        sources=sources,
        category=category,
        modifiers=modifiers,
    )
    # Regex rules carry an empty normalized domain and keep their raw form.
    if domain == "":
        r._norm = ""
        r._out = ""
    return r


class TestSortMerged:
    def test_blocks_match_reference_sort(self):
        blocks = [_rule("b.com"), _rule("a.com")]
        regex_blocks = [
            _rule("", raw="/^z\\./", sources=("s1",)),
            _rule("", raw="/^a\\./", sources=("s1",)),
        ]
        final_blocks, final_allows = sort_merged(blocks, regex_blocks, [], [])

        ref_blocks = sorted(list(blocks) + list(regex_blocks), key=Rule.sort_key)
        assert [r.raw for r in final_blocks] == [r.raw for r in ref_blocks]
        assert final_allows == []
        # Regex rules share an empty normalized domain and tie-break by raw.
        rx = [r.raw for r in final_blocks if r.normalized_domain == ""]
        assert rx == ["/^a\\./", "/^z\\./"]
        domains = [r.normalized_domain for r in final_blocks if r.normalized_domain]
        assert domains == sorted(domains) == ["a.com", "b.com"]

    def test_allows_sorted_independently(self):
        allows = [_rule("b.com", rule_type="allow"), _rule("a.com", rule_type="allow")]
        regex_allows = [_rule("", raw="@@/^r\\./", rule_type="allow", sources=("s1",))]
        _final_blocks, final_allows = sort_merged([], [], allows, regex_allows)

        ref_allows = sorted(list(allows) + list(regex_allows), key=Rule.sort_key)
        assert [r.raw for r in final_allows] == [r.raw for r in ref_allows]
        domains = [r.normalized_domain for r in final_allows if r.normalized_domain]
        assert domains == ["a.com", "b.com"]

    def test_stable_for_equal_sort_key(self):
        # Two identical regex rules share every key field; stable sort keeps
        # their input order (network completion order must not leak).
        rx1 = _rule("", raw="/^dup\\./", sources=("s1",))
        rx2 = _rule("", raw="/^dup\\./", sources=("s1",))
        final_blocks, _ = sort_merged([], [rx1, rx2], [], [])
        assert final_blocks == [rx1, rx2]

    def test_does_not_mutate_input_lists(self):
        blocks = [_rule("b.com"), _rule("a.com")]
        regex_blocks = [_rule("", raw="/^z\\./", sources=("s1",))]
        before = [id(r) for r in blocks] + [id(r) for r in regex_blocks]
        sort_merged(blocks, regex_blocks, [], [])
        after = [id(r) for r in blocks] + [id(r) for r in regex_blocks]
        assert before == after


class TestComputeContentVersion:
    def test_deterministic_12_hex(self):
        blocks = [_rule("a.com"), _rule("b.com", modifiers="important")]
        allows = [_rule("allow.com", rule_type="allow")]
        v1 = compute_content_version(blocks, allows)
        v2 = compute_content_version(blocks, allows)
        assert v1 == v2
        assert len(v1) == 12
        int(v1, 16)  # raises if not hex

    def test_matches_manual_sha256_loop(self):
        blocks = [_rule("a.com"), _rule("b.com", modifiers="important")]
        allows = [_rule("allow.com", rule_type="allow")]
        h = hashlib.sha256()
        for r in blocks + allows:
            h.update(r.output_raw.encode("utf-8", errors="replace"))
            h.update(b"\n")
        assert compute_content_version(blocks, allows) == h.hexdigest()[:12]

    def test_order_sensitive(self):
        v1 = compute_content_version([_rule("a.com"), _rule("b.com")], [])
        v2 = compute_content_version([_rule("b.com"), _rule("a.com")], [])
        assert v1 != v2

    def test_empty_inputs_hashes_empty_buffer(self):
        assert compute_content_version([], []) == hashlib.sha256().hexdigest()[:12]


class TestComputeContributions:
    def test_matches_classmethod_delegation(self):
        blocks = [
            _rule("a.com", sources=("s1", "s2")),
            _rule("b.com", sources=("s2",)),
        ]
        allows = [_rule("allow.com", rule_type="allow", sources=("s1",))]
        source_names = {"s1": "A", "s2": "B"}
        raw_counts = {"s1": 3, "s2": 2}

        contribs, overlap = compute_contributions(blocks, allows, source_names, raw_counts)
        ref_contribs, ref_overlap = AsyncRuleEngine._compute_stats(
            blocks, allows, source_names, raw_counts
        )
        assert contribs == ref_contribs
        assert overlap == ref_overlap

    def test_contribution_row_shape(self):
        blocks = [_rule("a.com", sources=("s1", "s2")), _rule("b.com", sources=("s2",))]
        contribs, overlap = compute_contributions(
            blocks, [], {"s1": "A", "s2": "B"}, {"s1": 2, "s2": 2}
        )
        row = contribs[0]
        assert set(row) == {
            "name",
            "url",
            "raw_rules",
            "unique_rules",
            "shared_rules",
            "effective_rules",
            "coverage_rate",
            "unique_rate",
            "rule_categories",
        }
        assert set(overlap) == {"pairs", "source_effective", "matrix"}


class TestComputeModifierStats:
    def test_matches_staticmethod_delegation(self):
        r1 = _rule("a.com", modifiers="important")
        r2 = _rule("b.com", modifiers="important")
        r3 = _rule("c.com", modifiers="badfilter")
        stats = compute_modifier_stats([r1, r2, r3], [])
        ref = AsyncRuleEngine._compute_modifier_stats([r1, r2, r3], [])
        assert stats == ref
        assert stats == {"important": 2, "badfilter": 1}

    def test_equal_counts_tie_break_by_name(self):
        r1 = _rule("a.com", modifiers="zmod")
        r2 = _rule("b.com", modifiers="amod")
        stats = compute_modifier_stats([r1, r2], [])
        # Both count 1; deterministic tie-break sorts by modifier name.
        assert list(stats) == ["amod", "zmod"]
        assert stats == AsyncRuleEngine._compute_modifier_stats([r1, r2], [])
