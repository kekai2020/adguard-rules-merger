"""Dedup-equivalence normalization tests (literal equivalence only).

Guards that ``normalize_domain`` / ``Rule`` fold only *literally identical*
domain shapes — case, edge dots, the ``*.`` literal prefix, optional www, and
surplus whitespace around label separators — while keeping semantically
distinct rules apart: exact vs wildcard, different ``$`` modifiers, block vs
allow. Punycode (``xn--`` labels) stays in its ASCII form and is NEVER decoded
to Unicode here; homograph folding belongs to the whitelist audit layer.
"""

from merger.models import Rule, normalize_domain

# ── literal-equivalence folding (strip_www=True) ─────────────────────


def test_case_edge_dot_star_prefix_www_all_normalize_equal():
    """WWW.Example.COM / example.com. / .example.com / *.example.com collapse."""
    variants = [
        "WWW.Example.COM",
        "EXAMPLE.COM",
        "example.com.",
        ".example.com",
        "*.example.com",
        "www.example.com.",
        "  example.com  ",
        "  *.Example.COM  ",
    ]
    expected = "example.com"
    for v in variants:
        assert normalize_domain(v, strip_www=True) == expected, v


def test_strip_www_false_keeps_www_label():
    """Without strip_www, www. is a distinct label and must not be folded."""
    assert normalize_domain("www.example.com", strip_www=False) == "www.example.com"
    assert normalize_domain("WWW.Example.COM", strip_www=False) == "www.example.com"
    assert normalize_domain("www.example.com", strip_www=True) == "example.com"


def test_inter_label_whitespace_removed():
    """Surplus whitespace around a separator (not inside a label) is cleaned."""
    assert normalize_domain("example .com") == "example.com"
    assert normalize_domain("example.com ") == "example.com"
    assert normalize_domain(" example.com") == "example.com"
    assert normalize_domain("*. example.com") == "example.com"


def test_repeated_edge_dots_collapsed():
    """Consecutive leading/trailing dots are literal noise, not labels."""
    assert normalize_domain("example.com..") == "example.com"
    assert normalize_domain("..example.com") == "example.com"
    assert normalize_domain("...example.com...") == "example.com"


# ── semantic distinctions preserved (must NOT merge) ────────────────


def test_exact_and_wildcard_are_distinct_keys():
    exact = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    wild = Rule(
        raw="||*.example.com^",
        domain="*.example.com",
        rule_type="block",
        wildcard=True,
    )
    assert exact.normalized_domain == wild.normalized_domain == "example.com"
    assert exact != wild
    assert hash(exact) != hash(wild)


def test_modifiers_are_distinct_keys():
    """||x.com^ and ||x.com^$important must NOT dedup-merge."""
    plain = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    important = Rule(
        raw="||example.com^$important",
        domain="example.com",
        rule_type="block",
        wildcard=False,
        modifiers="important",
    )
    badfilter = Rule(
        raw="||example.com^$badfilter",
        domain="example.com",
        rule_type="block",
        wildcard=False,
        modifiers="badfilter",
    )
    assert plain != important
    assert important != badfilter
    assert hash(plain) != hash(important)


def test_block_and_allow_are_distinct_keys():
    block = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    allow = Rule(raw="@@||example.com^", domain="example.com", rule_type="allow", wildcard=False)
    assert block != allow
    assert hash(block) != hash(allow)


def test_equivalent_forms_share_dedup_key():
    """Literal variants build the same 4-tuple key and collapse in a map."""
    forms = [
        Rule(
            raw="||example.com^",
            domain="Example.COM",
            rule_type="block",
            wildcard=False,
            strip_www=True,
        ),
        Rule(
            raw="||example.com^",
            domain="www.example.com.",
            rule_type="block",
            wildcard=False,
            strip_www=True,
        ),
        Rule(
            raw="||example.com^",
            domain="*.example.com",
            rule_type="block",
            wildcard=False,
            strip_www=True,
        ),
    ]
    first = forms[0]
    for other in forms[1:]:
        assert other == first
        assert hash(other) == hash(first)

    # Mirror core._load_dedup's block_map key exactly.
    merged = {}
    for r in forms:
        key = (r.normalized_domain, r.wildcard, r.modifiers)
        merged[key] = r
    assert len(merged) == 1


# ── punycode: ASCII stable, never decoded ────────────────────────────


def test_punycode_case_folds_and_stays_ascii():
    upper = "XN--80AK6AA92E.COM"
    lower_dot = "xn--80ak6aa92e.com."
    assert normalize_domain(upper) == "xn--80ak6aa92e.com"
    assert normalize_domain(lower_dot) == "xn--80ak6aa92e.com"
    # The xn-- prefix survives verbatim; nothing decodes it to Unicode.
    assert normalize_domain(upper).startswith("xn--")


def test_punycode_not_decoded_to_unicode():
    norm = normalize_domain("xn--80ak6aa92e.com")
    # Literal ASCII form only; must not be replaced by a Unicode lookalike.
    assert norm == "xn--80ak6aa92e.com"
    assert norm != "пример.com"


def test_unicode_label_not_homograph_folded():
    """A Cyrillic lookalike label must not collide with the ASCII domain."""
    cyrillic = "еxample.com"  # first letter is U+0435, not ASCII 'e'
    assert normalize_domain(cyrillic) == cyrillic
    assert normalize_domain(cyrillic) != normalize_domain("example.com")


# ── output_raw behavior preserved ───────────────────────────────────


def test_output_raw_unchanged_for_canonical_rules():
    plain = Rule(raw="||example.com^", domain="example.com", rule_type="block", wildcard=False)
    assert plain.output_raw == "||example.com^"

    wild = Rule(
        raw="||*.example.com^",
        domain="*.example.com",
        rule_type="block",
        wildcard=True,
    )
    assert wild.output_raw == "||*.example.com^"

    important = Rule(
        raw="||example.com^$important",
        domain="example.com",
        rule_type="block",
        wildcard=False,
        modifiers="important",
    )
    assert important.output_raw == "||example.com^$important"

    allow = Rule(raw="@@||example.com^", domain="example.com", rule_type="allow", wildcard=False)
    assert allow.output_raw == "@@||example.com^"
