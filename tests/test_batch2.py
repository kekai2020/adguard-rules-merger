"""Batch2 P1 golden cases."""

from merger.parser import RuleParser, canonicalize_modifiers


def test_badfilter_cancel_order_invariant():
    # The parser emits the same canonical modifier string regardless of source
    # token order, so _apply_badfilter can find its target.
    a = canonicalize_modifiers("client=1.2.3.4,important")
    b = canonicalize_modifiers("important,client=1.2.3.4")
    assert a == b


def test_canonicalize_order():
    assert canonicalize_modifiers("client=1.2.3.4,important") == "important,client=1.2.3.4"


# NOTE(M-4, deferred): the release package drops infix wildcards
# (||ad*.example.com^ -> []); the development line KEEPS them. That divergence
# is a separate product decision, so the release-side
# test_infix_wildcard_still_dropped is not carried over here.


def test_hosts_badfilter_ignored():
    r = RuleParser().parse_text("0.0.0.0 example.com$badfilter", source="s", category="ads")
    # hosts line yields the host but badfilter modifier is stripped (KB:
    # badfilter does not apply to hosts-style rules).
    assert [x.normalized_domain for x in r] == ["example.com"]
    assert all("badfilter" not in (x.modifiers or []) for x in r)


def test_w1_zero_coverage_no_safe():
    from merger.whitelist_audit.config import AuditConfig
    from merger.whitelist_audit.constants import RATING_UNKNOWN
    from merger.whitelist_audit.fusion import _fuse_rating

    cfg = AuditConfig(
        use_heuristics=False,
        use_homograph=False,
        use_urlhaus=False,
        use_threatfox=False,
        use_rdap=False,
        use_scam_check=False,
        use_dnsbl=False,
        use_dns=False,
    )
    rating, _, _ = _fuse_rating({}, {}, {}, {}, {}, {}, cfg)
    assert rating == RATING_UNKNOWN
