"""iter6 (final-review v2) — parser-coverage regression probes.

Locks the *measured* classification of representative real-list syntax
(uBlock / AdGuard / Hagezi style). Where a line is currently dropped, the test
pins that behaviour; support additions are listed as「需用户决策」in the review
doc because they would change rule output bytes.
"""

from __future__ import annotations

from merger.parser import RuleParser


def _p():
    return RuleParser()


def test_dns_valued_modifiers_kept():
    r = _p().parse_text("||x.com^$dnsrewrite=1.2.3.4\n||y.com^$dnstype=~A\n", source="s")
    mods = sorted(x.modifiers for x in r)
    assert mods == ["dnsrewrite=1.2.3.4", "dnstype=~A"]


def test_url_layer_modifiers_drop_whole_line():
    # kb7: removeparam / csp are browser-layer → whole-line drop per spec.
    p = _p()
    r = p.parse_text("||x.com^$removeparam=a\n||y.com^$csp=script-src 'self'\n", source="s")
    assert r == []
    assert p.unsupported_modifier == 2


def test_cidr_dnscrypt_rpz_are_unrecognized():
    # Doubao Item3: CIDR and DNSCrypt standalone lines are preserved verbatim
    # instead of being dropped; only RPZ RR-like lines (no sdns://, no CIDR)
    # still fall through to the unrecognized bucket.
    for line in ["1.2.3.0/24", "sdns://abcdef"]:
        p = _p()
        out = p.parse_text(line, source="s")
        assert len(out) == 1
        assert out[0].raw == line
        assert p.unrecognized_dropped == 0
    p = _p()
    assert p.parse_text("localdata example.com CNAME rpz.x", source="s") == []
    assert p.unrecognized_dropped == 1


def test_hosts_localhost_filtered_not_unrecognized():
    p = _p()
    p.parse_text("127.0.0.1 localhost\n", source="s")
    # localhost hosts lines are dropped in the hosts branch (neither quality
    # nor unrecognized bucket) — they are not classified as garbage.
    assert p.parse_text("127.0.0.1 localhost\n", source="s") == []
    assert p.unrecognized_dropped == 0


def test_bom_and_crlf_handled():
    text = "||a.com^\r\n||b.com^\n"
    r = _p().parse_text(text, source="s")
    assert sorted(x.normalized_domain for x in r) == ["a.com", "b.com"]


def test_local_file_bom_is_stripped_by_fetch(tmp_path):
    # The fetch layer reads local files as utf-8-sig so a leading BOM does not
    # void the first rule. (Parser itself does not strip BOM.)
    import asyncio

    from merger.core.engine import AsyncRuleEngine

    f = tmp_path / "bom.txt"
    f.write_bytes("﻿||a.com^\n".encode())
    eng = AsyncRuleEngine(cache_dir=None)
    text, _, err, _ = asyncio.run(eng._fetch_text(str(f)))
    assert err is None
    r = RuleParser().parse_text(text, source="s")
    assert r and r[0].normalized_domain == "a.com"
