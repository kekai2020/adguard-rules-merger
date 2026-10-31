"""KB syntax golden regression (AdGuard DNS filter syntax).

Each case is locked against the official spec; new parser behavior added across
the kb iterations is pinned here.
"""

from __future__ import annotations

from merger.parser import RuleParser, _split_mod_tokens, canonicalize_modifiers


def _parse(text):
    return RuleParser().parse_text(text, source="s", category="ads")


# kb1: single-pipe anchors
def test_leading_single_anchor_is_host_boundary():
    r = _parse("|example.com^")
    assert len(r) == 1 and r[0].normalized_domain == "example.com"
    assert r[0].rule_type == "block"


def test_trailing_single_anchor():
    r = _parse("example.com|")
    assert len(r) == 1 and r[0].normalized_domain == "example.com"


def test_double_pipe_unchanged():
    r = _parse("||example.com^")
    assert r[0].normalized_domain == "example.com"


# kb2: structured modifier tokenizer (quotes/escapes/commas-inside-quotes)
def test_tokenizer_splits_top_level_commas():
    assert _split_mod_tokens("important,badfilter") == ["important", "badfilter"]


def test_tokenizer_respects_quoted_commas():
    toks = _split_mod_tokens('client="1.2.3.4,5.6.7.8",dnstype=A')
    assert toks == ['client="1.2.3.4,5.6.7.8"', "dnstype=A"]


def test_tokenizer_respects_escaped_commas():
    toks = _split_mod_tokens(r'denyallow="a\.com,b\.com"')
    assert toks == [r'denyallow="a\.com,b\.com"']


# kb3: denyallow preserved
def test_denyallow_modifier_preserved():
    r = _parse("||x.com^$denyallow=y.com")
    assert len(r) == 1 and "denyallow=y.com" in r[0].modifiers


def test_denyallow_multiple_values_preserved():
    r = _parse("||x.com^$denyallow=a.com|b.com")
    assert r[0].modifiers == "denyallow=a.com|b.com"


# kb4: dnstype — already preserved; lock RR-set / exclusion / case semantics
def test_dnstype_single_rr_preserved():
    r = _parse("||x.com^$dnstype=A")
    assert "dnstype=A" in r[0].modifiers


def test_dnstype_multi_rr_preserved():
    r = _parse("||x.com^$dnstype=A|AAAA|HTTPS")
    assert r[0].modifiers == "dnstype=A|AAAA|HTTPS"


def test_dnstype_exclusion_preserved():
    r = _parse("||x.com^$dnstype=~A|~AAAA")
    assert r[0].modifiers == "dnstype=~A|~AAAA"


# kb5: dnsrewrite — short forms, RCODE, full triple, @@ exception
def test_dnsrewrite_short_ipv4():
    r = _parse("||x.com^$dnsrewrite=1.2.3.4")
    assert r[0].modifiers == "dnsrewrite=1.2.3.4"


def test_dnsrewrite_short_ipv6():
    r = _parse("||x.com^$dnsrewrite=abcd::1234")
    assert "dnsrewrite=abcd::1234" in r[0].modifiers


def test_dnsrewrite_full_triple():
    r = _parse("||x.com^$dnsrewrite=NOERROR;CNAME;example.net")
    assert r[0].modifiers == "dnsrewrite=NOERROR;CNAME;example.net"


def test_dnsrewrite_exception_removal():
    r = _parse("@@||x.com^$dnsrewrite=1.2.3.4")
    assert r[0].rule_type == "allow"
    assert "dnsrewrite=1.2.3.4" in r[0].modifiers


# kb6: client / ctag / respgeo
def test_client_ip_cidr_preserved():
    r = _parse("||x.com^$client=1.2.3.4|10.0.0.0/8")
    assert r[0].modifiers == "client=1.2.3.4|10.0.0.0/8"


def test_client_quoted_name_preserved():
    r = _parse("||x.com^$client='John Doe'")
    assert "client=" in r[0].modifiers


def test_client_exclusion_preserved():
    r = _parse("||x.com^$client=~1.2.3.4")
    assert r[0].modifiers == "client=~1.2.3.4"


def test_ctag_preserved():
    r = _parse("||x.com^$ctag=android|ios")
    assert r[0].modifiers == "ctag=android|ios"


def test_respgeo_country_and_asn_preserved():
    r = _parse("||x.com^$respgeo=CN")
    assert r[0].modifiers == "respgeo=CN"
    r = _parse("||x.com^$respgeo=AS42")
    assert r[0].modifiers == "respgeo=AS42"


def test_respgeo_unknown_and_negated():
    r = _parse("||x.com^$respgeo=--")
    assert r[0].modifiers == "respgeo=--"
    r = _parse("||x.com^$respgeo=~CN")
    assert r[0].modifiers == "respgeo=~CN"


# kb7: unknown (browser-layer) modifiers drop the whole line
def test_unknown_modifier_drops_whole_line():
    p = RuleParser()
    r = p.parse_text("||x.com^$removeparam=utm", source="s", category="ads")
    assert r == []
    assert p.unsupported_modifier == 1


def test_unknown_modifier_with_known_also_drops():
    p = RuleParser()
    r = p.parse_text("||x.com^$important$removeparam=utm", source="s", category="ads")
    assert r == []
    assert p.unsupported_modifier == 1


def test_known_dns_modifiers_not_killed():
    p = RuleParser()
    r = p.parse_text("||x.com^$important,denyallow=a.com,dnstype=A", source="s", category="ads")
    assert len(r) == 1
    assert p.unsupported_modifier == 0


def test_unknown_modifier_switch_off_keeps_rule():
    p = RuleParser(drop_on_unknown_modifier=False)
    r = p.parse_text("||x.com^$third-party", source="s", category="ads")
    assert len(r) == 1


# kb8: hosts / plain-domain styles
def test_hosts_multi_alias_expanded():
    r = _parse("0.0.0.0 t.com alias1.com alias2.com")
    assert sorted(x.normalized_domain for x in r) == ["alias1.com", "alias2.com", "t.com"]


def test_hosts_inline_comment_stripped():
    r = _parse("127.0.0.1 a.com # local comment")
    assert [x.normalized_domain for x in r] == ["a.com"]


def test_hosts_ipv6_alias():
    r = _parse("::1 v6host.com")
    assert [x.normalized_domain for x in r] == ["v6host.com"]


def test_hosts_rule_emits_adblock_syntax():
    # canonical internal form is a domain rule → merged output uses ||host^
    r = _parse("0.0.0.0 t.com")
    assert r[0].output_raw == "||t.com^"


def test_plain_domain_inline_comment():
    r = _parse("example.com # host")
    assert [x.normalized_domain for x in r] == ["example.com"]


# kb9: unsupported_modifier counter flows through the parser
def test_unsupported_counter_recorded():
    p = RuleParser()
    p.parse_text("||a.com^$third-party\n||b.com^\n", source="s", category="ads")
    assert p.unsupported_modifier == 1


# kb10: an inline ``#`` comment AFTER ``$modifiers`` must not corrupt the rule.
# Regression for the P0 defect where ``_split_modifiers`` treated everything
# after ``$`` as modifier tokens, so ``# reason`` was parsed as a modifier and
# (a) dropped a legitimate rule as "unknown modifier", or (b) leaked the
# comment text into ``modifiers`` (corrupting the dedup key / output hash).
def test_inline_comment_after_modifiers_kept():
    p = RuleParser()
    r = p.parse_text("||x.com^$important # reason", source="s", category="ads")
    assert len(r) == 1
    assert r[0].output_raw == "||x.com^$important"
    assert r[0].modifiers == "important"
    assert p.unsupported_modifier == 0


def test_inline_comment_after_valued_modifier_not_leaked():
    p = RuleParser()
    r = p.parse_text("||*.x.com^$dnstype=AAAA # y", source="s", category="ads")
    assert len(r) == 1
    assert r[0].modifiers == "dnstype=AAAA"
    assert "#" not in r[0].modifiers


def test_inline_comment_after_allow_modifiers_kept():
    p = RuleParser()
    r = p.parse_text("@@||x.com^$important # allow reason", source="s", category="ads")
    assert len(r) == 1
    assert r[0].rule_type == "allow"
    assert r[0].modifiers == "important"


# kb11: an EMPTY valued modifier ($dnsrewrite=, $client=) is invalid per the
# AdGuard syntax — AGH would reject the emitted line. The rule must be dropped
# whole (counted as unsupported), not kept with an empty value.
def test_empty_valued_modifier_drops_whole_line():
    p = RuleParser()
    r = p.parse_text("||x.com^$dnsrewrite=", source="s", category="ads")
    assert r == []
    assert p.unsupported_modifier == 1


def test_empty_valued_modifier_among_flags_drops():
    p = RuleParser()
    r = p.parse_text("||x.com^$important,client=", source="s", category="ads")
    assert r == []
    assert p.unsupported_modifier == 1


def test_valued_modifier_with_value_still_kept():
    p = RuleParser()
    r = p.parse_text("||x.com^$dnstype=A", source="s", category="ads")
    assert len(r) == 1 and r[0].modifiers == "dnstype=A"


def test_canonicalize_skips_empty_valued():
    assert canonicalize_modifiers("important,dnstype=") == "important"
