"""Lock the v7 conflict policy: block rules kept on whitelist overlap."""

from merger.core.conflicts import ConflictMixin


class _Dummy(ConflictMixin):
    cascade_subdomains = True


class R:
    def __init__(self, n, raw, wildcard=False, cat="ads"):
        self.normalized_domain = n
        self.output_raw = raw
        self.wildcard = wildcard
        self.category = cat
        self.source_ids = ()


def test_conflict_keeps_block_and_records():
    eng = _Dummy()
    blocks = [R("ads.example.com", "||ads.example.com^")]
    allows = [R("ads.example.com", "@@||ads.example.com^")]
    kept, removed, conflicts = eng._resolve_conflicts(blocks, allows, {})
    # block survives, nothing removed
    assert len(kept) == 1
    assert removed == 0
    assert conflicts[0]["action"] == "kept_block"
    assert conflicts[0]["conflict_type"] == "exact"


def test_conflict_cascade_subdomain():
    eng = _Dummy()
    blocks = [R("sub.ads.example.com", "||sub.ads.example.com^")]
    allows = [R("ads.example.com", "@@||ads.example.com^")]
    kept, _, conflicts = eng._resolve_conflicts(blocks, allows, {})
    assert len(kept) == 1
    assert conflicts[0]["conflict_type"] == "cascade"
