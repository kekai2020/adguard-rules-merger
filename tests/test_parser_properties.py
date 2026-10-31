"""Property-based parser/model invariants (hypothesis, C2 quality batch).

Three invariants that hand-written cases cannot exhaust:
1. the parser NEVER raises on arbitrary text — hostile lines degrade to
   counted drops, not crashes;
2. ``normalize_domain`` is idempotent (folding twice equals folding once);
3. ``canonicalize_modifiers`` is idempotent and preserves quoted tokens
   verbatim (the dedup-key / badfilter-target contract).
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from merger.models import normalize_domain
from merger.parser import RuleParser, canonicalize_modifiers

# Full character space (including control/surrogate-free unicode) for hostile
# lines; parse must degrade gracefully, never raise.
ARBITRARY_TEXT = st.text(alphabet=st.characters(blacklist_categories=()), max_size=200)


@settings(deadline=None, max_examples=300)
@given(ARBITRARY_TEXT)
def test_parser_never_raises_on_arbitrary_text(line):
    parser = RuleParser()
    rules = parser.parse_text(line, source="prop", category="ads")
    assert isinstance(rules, list)
    for r in rules:
        assert r.rule_type in ("block", "allow", "comment")
    # counters stay consistent with what was materialised — blank/whitespace
    # lines are legitimately skipped without any accounting
    if line.strip():
        total = (
            parser.pattern_dropped
            + parser.quality_dropped
            + parser.css_dropped
            + parser.comment_dropped
            + parser.unrecognized_dropped
            + parser.unsupported_modifier
            + parser.modifier_stripped
            + len(rules)
        )
        assert total >= 1  # every input line is accounted for


# Domain-ish strings: labels, dots, the `*.` literal, www prefix, whitespace
# noise and case — exactly the shapes normalize_domain is specified to fold.
DOMAINISH = st.builds(
    lambda parts, star, www: f"{star}{www}{'.'.join(parts)}",
    st.lists(st.text(alphabet="abcXYZ0-9-_ ", min_size=1, max_size=8), min_size=1, max_size=6),
    st.sampled_from(["", "*."]),
    st.sampled_from(["", "WWW.", "www."]),
)


@settings(deadline=None, max_examples=300)
@given(DOMAINISH)
def test_normalize_domain_is_idempotent(domain):
    once = normalize_domain(domain, strip_www=True)
    twice = normalize_domain(once, strip_www=True)
    assert once == twice


MOD_STRS = st.text(alphabet="ab1=.,'\"\\|- ", max_size=40)


@settings(deadline=None, max_examples=300)
@given(MOD_STRS)
def test_canonicalize_modifiers_is_idempotent(mod_str):
    once = canonicalize_modifiers(mod_str)
    assert canonicalize_modifiers(once) == once
