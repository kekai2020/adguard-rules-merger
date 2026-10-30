"""Probe: how the parser classifies representative real-list syntax.
Read-only; prints a table. Run: python scripts/probe_syntax.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from merger.parser import RuleParser

CASES = [
    # (label, line)
    ("block basic", "||ads.example.com^"),
    ("allow basic", "@@||ads.example.com^"),
    ("hosts ipv4", "0.0.0.0 ads.example.com"),
    ("hosts ipv6", "::1 v6.example.com"),
    ("hosts localhost", "127.0.0.1 localhost"),
    ("plain domain", "example.com"),
    ("wildcard star-domain", "||*.example.com^"),
    ("regex", "/ads-[a-z]+/"),
    ("regex allow", "@@/track-[a-z]+/"),
    ("mod important", "||x.com^$important"),
    ("mod badfilter", "||x.com^$badfilter"),
    ("mod removeparam", "||x.com^$removeparam=utm"),
    ("mod csp", "||x.com^$csp=script-src 'self'"),
    ("mod dnsrewrite", "||x.com^$dnsrewrite=1.2.3.4"),
    ("mod dnstype", "||x.com^$dnstype=~A"),
    ("mod denyallow", "||x.com^$denyallow=y.com"),
    ("mod redirect", "||x.com^$redirect=rule"),
    ("mod third-party (cosmetic)", "||x.com^$third-party"),
    ("mod script (cosmetic)", "||x.com^$script"),
    ("css cosmetic", "example.com##.ad"),
    ("css exception", "example.com#@#.ad"),
    ("urlbar http", "https://example.com/path"),
    ("comment bang", "! comment"),
    ("comment hash", "# comment"),
    ("ipv4 bare", "1.2.3.4"),
    ("cidr", "1.2.3.0/24"),
    ("dnscrypt", "sdns://abcdef"),
    ("RPZ", "localdata example.com CNAME rpz.example.com"),
    ("empty", ""),
    ("spaces", "   ||pad.example.com^   "),
    ("case upper", "||X.Example.COM^"),
    ("trailing dot", "||example.com.^"),
]

p = RuleParser()
for label, line in CASES:
    p2 = RuleParser()
    rules = p2.parse_text(line, source="s", category="ads")
    kind = rules[0].rule_type if rules else "DROP"
    dom = rules[0].normalized_domain if rules else ""
    mod = rules[0].modifiers if rules else ""
    flags = (
        f"unrec={p2.unrecognized_dropped} css={p2.css_dropped} "
        f"qual={p2.quality_dropped} comment={p2.comment_dropped} "
        f"modstrip={p2.modifier_stripped} pat={p2.pattern_dropped}"
    )
    print(f"{label:28s} -> {kind:6s} dom={dom:24s} mod={mod:18s} | {flags}")
