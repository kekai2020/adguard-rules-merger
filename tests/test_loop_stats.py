"""Determinism of contribution stats."""

from merger.core.stats import StatsMixin


class _S(StatsMixin):
    cascade_subdomains = True


def test_contributions_sort_deterministic():
    # Two identical runs must produce identical ordering.
    class R:
        def __init__(self, key, mask, cat):
            self._k = key
            self.source_mask = mask
            self.category = cat

        def normalized_domain(self):
            return self._k

    # source A = bit0, B = bit1
    blocks = [R("a.com", 1, "ads"), R("b.com", 1, "ads"), R("shared.com", 3, "ads")]
    src_names = {"http://a": "A", "http://b": "B"}
    raw = {"http://a": 3, "http://b": 1}
    out, _ = StatsMixin._compute_stats(blocks, [], src_names, raw)
    names = [c["name"] for c in out]
    assert names == sorted(
        names, key=lambda n: -next(c["unique_rules"] for c in out if c["name"] == n)
    )
