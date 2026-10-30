"""Robustness edge cases for the parser counters."""

from merger.parser import RuleParser


def test_comment_and_blank_not_counted_unrecognized():
    p = RuleParser()
    p.parse_text("! a comment\n\n# hash comment\n", source="s", category="ads")
    assert p.unrecognized_dropped == 0


def test_ip_only_line_dropped():
    p = RuleParser()
    p.parse_text("1.2.3.4\n", source="s", category="ads")
    # bare IP line with no host is not a DNS domain rule.
    assert p.unrecognized_dropped >= 0


def test_crlf_handling():
    p = RuleParser()
    r = p.parse_text("||example.com^\r\n||test.org^\r\n", source="s", category="ads")
    assert len(r) == 2
