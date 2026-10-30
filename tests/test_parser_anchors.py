"""P-1/P-2 parser edge cases ported: single-pipe anchors, out-of-range hosts IP."""

from merger.parser import RuleParser


def parse(text: str):
    return [(r.output_raw, r.normalized_domain) for r in RuleParser().parse_text(text)]


def test_separator_anchor_kept():
    # ||example^| — the trailing '^|' is an end anchor, must not be dropped.
    out = parse("||example.com^|")
    assert ("||example.com^", "example.com") in out


def test_both_single_anchors_kept():
    out = parse("|example.com|")
    assert out == [("||example.com^", "example.com")]


def test_allow_start_anchor():
    out = parse("@@|example.com")
    assert out == [("@@||example.com^", "example.com")]


def test_hosts_out_of_range_octet_dropped():
    out = parse("999.999.999.999 a.com")
    assert out == []


def test_embedded_wildcard_preserved():
    # M-4: infix wildcard ||ad*.example.com^ is preserved verbatim.
    out = parse("||ad*.example.com^")
    assert out == [("||ad*.example.com^", "")]
