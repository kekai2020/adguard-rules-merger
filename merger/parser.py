"""V5.1 streaming parser for DNS-layer AdGuard / Hosts / plain-domain lists.

Parsing rules (strict DNS-layer only):
  - AdGuard block:  ``||domain^``            -> block
  - AdGuard allow:  ``@@||domain^``         -> allow
  - Wildcard:       ``||*.domain^``         -> block, wildcard=True
  - Hosts:          ``0.0.0.0 domain``      -> block
  - IPv6 hosts:     ``::1 domain`` / ``:: domain``
  - Plain domain:  ``example.com``          -> block
  - Comment:        ``! ...`` / ``# ...``   -> skipped (not materialised)
  - Regex:          ``/regex/``             -> kept as-is (AGH supports it)
  - ``$ modifiers``: DNS-meaningful flags kept (important, badfilter,
    dnstype, dnsrewrite, client, ctag, ipset, resolver). Cosmetic
    modifiers (script, third-party, popup, ...) are stripped so AGH DNS
    does not ignore the rule.

V5.1:
  - Comments are counted, not turned into Rule objects.
  - Cosmetic $ modifiers stripped; DNS modifiers preserved.
  - IPv6 hosts lines accepted.
  - Per-parse drop counters (thread-safe if each parse uses its own parser).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from .models import CATEGORY_OTHER, Rule

# DNS-layer modifiers AdGuard Home honours. Everything else is cosmetic
# (script/third-party/popup/...) and would make AGH skip or warn on the rule.
_DNS_FLAG_MODS = frozenset({"important", "badfilter"})
_DNS_VALUED_PREFIXES = (
    "dnstype=",
    "dnsrewrite=",
    "client=",
    "ctag=",
    "ipset=",
    "resolver=",
    "denyallow=",
    "respgeo=",
)


def _split_mod_tokens(mod_str: str) -> list[str]:
    """Split a `$modifier=...,...` string on top-level commas only.

    Per AdGuard spec, a value wrapped in single/double quotes may contain
    commas, pipes and escaped chars — those must NOT be treated as modifier
    separators. Quotes are preserved verbatim in the returned token so the
    caller keeps the original spelling.

    Fast path: without quotes/backslashes nothing can shield a comma, so a
    plain ``str.split`` is exactly equivalent to the character state machine
    below (strip per token + drop empties matches its behaviour).
    """
    if "'" not in mod_str and '"' not in mod_str and "\\" not in mod_str:
        return [t for t in (tok.strip() for tok in mod_str.split(",")) if t]
    tokens: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    escaped = False
    for ch in mod_str:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            cur.append(ch)
            escaped = True
            continue
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            cur.append(ch)
            continue
        if ch == ",":
            tok = "".join(cur).strip()
            if tok:
                tokens.append(tok)
            cur = []
            continue
        cur.append(ch)
    tok = "".join(cur).strip()
    if tok:
        tokens.append(tok)
    return tokens


def canonicalize_modifiers(mod_str: str) -> str:
    """Single source of truth for modifier ordering used by both the parser and
    ``aggregation._apply_badfilter`` (flags first sorted, then valued sorted).

    Sharing this keeps the badfilter target key identical to the parser's
    emitted modifier string - otherwise ``important,client=x`` vs
    ``client=x,important`` would fail cancellation.
    """
    flags: list[str] = []
    valued: list[str] = []
    for m in _split_mod_tokens(mod_str):
        if "=" in m:
            key, _, val = m.partition("=")
            combined = f"{key.strip().lower()}={val.strip()}"
            if val.strip() and combined.startswith(_DNS_VALUED_PREFIXES):
                valued.append(combined)
        elif m.lower() in _DNS_FLAG_MODS:
            flags.append(m.lower())
    return ",".join(sorted(set(flags)) + sorted(set(valued)))


class RuleParser:
    """High-performance streaming parser with drop counters."""

    # ── pre-compiled patterns ──────────────────────────────────
    # ^ is optional when $ modifiers follow directly: ||domain$important
    RE_BLOCK = re.compile(r"^\|\|([^/^\s$]+)\^?")
    RE_ALLOW = re.compile(r"^@@\|\|([^/^\s$]+)\^?")
    RE_HOSTS = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}\s+(\S+)")
    RE_HOSTS_V6 = re.compile(r"^(?:(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}|::1?)\s+(\S+)")
    # D2: labels may contain a leading/embedded underscore (e.g. _dmarc,
    # _service); the TLD stays letters-only and arbitrary characters are not
    # allowed.
    RE_DOMAIN = re.compile(r"^([_a-zA-Z0-9][-_a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_WILD_DOMAIN = re.compile(r"^\*\.([_a-zA-Z0-9][-_a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$")
    RE_CSS = re.compile(r"#@?#|#%#")  # CSS/JS: ##, #@#, #%# (may be domain-prefixed)
    RE_REGEX = re.compile(r"^(?:@@)?/.+/\$?[a-z,]*$")
    RE_URLBAR = re.compile(r"^\|?https?://")
    RE_COMMENT_HASH = re.compile(r"^#(?!#|@#|%)")

    LOCALHOST: frozenset[str] = frozenset(
        {
            "localhost",
            "localhost.localdomain",
            "localhost6",
            "localhost6.localdomain6",
            "local",
            "localdomain",
        }
    )

    def __init__(
        self,
        strip_www: bool = False,
        quality_filter: bool = True,
        min_domain_length: int = 4,
        max_domain_length: int = 253,
        filter_localhost: bool = True,
        filter_ip_rules: bool = False,
        drop_on_unknown_modifier: bool = True,
    ) -> None:
        self.pattern_dropped = 0
        self.quality_dropped = 0
        self.css_dropped = 0
        self.comment_dropped = 0
        self.modifier_stripped = 0
        self.unsupported_modifier = 0
        self.unrecognized_dropped = 0
        self.strip_www = strip_www
        self.quality_filter_enabled = quality_filter
        self.min_domain_length = min_domain_length
        self.max_domain_length = max_domain_length
        self.filter_localhost = filter_localhost
        self.filter_ip_rules = filter_ip_rules
        self.drop_on_unknown_modifier = drop_on_unknown_modifier

    # ── helpers ────────────────────────────────────────────────

    @staticmethod
    def _clean(domain: str) -> str:
        d = domain.lower().strip()
        if d.endswith("."):
            d = d[:-1]
        if d.startswith("."):
            d = d[1:]
        return d

    @staticmethod
    def _is_ip(text: str) -> bool:
        parts = text.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False

    @staticmethod
    def _split_modifiers(s: str) -> tuple[str, str, bool]:
        """Return (line_without_$section, normalized_modifiers_str, stripped).

        Cosmetic (non-DNS) modifiers are dropped; ``stripped`` is True when
        at least one cosmetic flag was removed.
        """
        i = s.find("$")
        if i == -1:
            return s, "", False
        body = s[:i].strip()
        mod_str = s[i + 1 :].strip()
        if not mod_str:
            return body, "", False
        flags = []
        valued = []
        stripped = False
        for m in _split_mod_tokens(mod_str):
            if "=" in m:
                key, _, val = m.partition("=")
                key = key.strip().lower()
                combined = f"{key}={val.strip()}"
                if not val.strip():
                    # A valued DNS modifier with an EMPTY value ($dnsrewrite=,
                    # $client=, ...) is invalid per the AdGuard syntax and AGH
                    # would reject the line — treat it like an unknown modifier
                    # so the rule is dropped whole (counted, not silently kept).
                    stripped = True
                elif combined.startswith(_DNS_VALUED_PREFIXES):
                    valued.append(combined)
                else:
                    stripped = True
            else:
                flag = m.lower()
                if flag in _DNS_FLAG_MODS:
                    flags.append(flag)
                else:
                    stripped = True
        flags = sorted(set(flags))
        valued = sorted(set(valued))
        normalized = ",".join(flags + valued)
        return body, normalized, stripped

    @staticmethod
    def _normalize_regex(raw: str) -> str:
        """Normalize regex rules: strip whitespace + sort trailing $flags.

        Ensures ``/regex/$b,a`` and ``/regex/$a,b`` produce identical output
        (deterministic ordering), which helps dedup and byte-stable diffs.
        """
        s = raw.strip()
        prefix = ""
        body = s
        if body.startswith("@@"):
            prefix = "@@"
            body = body[2:]
        m = re.match(r"^(.+/)\$([a-z,]+)$", body)
        if m:
            flags = sorted(set(f for f in m.group(2).split(",") if f))
            return prefix + m.group(1) + "$" + ",".join(flags)
        return s

    def _valid_dns_domain(self, d: str) -> bool:
        if "*" not in d:
            return True
        return d.startswith("*.") and "*" not in d[2:]

    def _quality_check(self, d: str) -> bool:
        if not self.quality_filter_enabled:
            return True
        check_d = d[2:] if d.startswith("*.") else d
        if len(check_d) < self.min_domain_length:
            return False
        if len(check_d) > self.max_domain_length:
            return False
        if self.filter_localhost:
            if (
                check_d in self.LOCALHOST
                or check_d.endswith(".localhost")
                or check_d.endswith(".local")
            ):
                return False
        if self.filter_ip_rules:
            if self._is_ip(check_d):
                return False
        if "." not in check_d:
            return False
        # `_clean` already stripped leading/trailing dots, so an empty label
        # can only come from a CONSECUTIVE dot — check it without allocating
        # the split list (this runs once per parsed rule).
        if ".." in check_d:
            return False
        return True

    def _make_rule(
        self,
        d: str,
        rule_type: str,
        wildcard: bool,
        source: str,
        category: str,
        modifiers: str = "",
    ) -> Rule | None:
        if not d:
            return None
        # Mid-word '*' wildcard (e.g. ``||ad*.example.com^``) is valid per the
        # AdGuard DNS syntax (``*`` = any character run) but is not a foldable
        # domain. Preserve it verbatim on the regex path (domain == "") so it is
        # never dropped and never aggregated; ``output_raw`` keeps the original
        # ``||...*...^`` spelling.
        if "*" in d and not (d.startswith("*.") and "*" not in d[2:]):
            if not self._quality_check(d):
                self.quality_dropped += 1
                return None
            raw = self._render_rule(d, rule_type, modifiers)
            return Rule(
                raw=raw,
                domain="",
                rule_type=rule_type,
                wildcard=False,
                sources=source,
                category=category,
                strip_www=self.strip_www,
                modifiers=modifiers,
            )
        if not self._valid_dns_domain(d):
            if d and "*" in d:
                self.pattern_dropped += 1
            return None
        if not self._quality_check(d):
            self.quality_dropped += 1
            return None
        raw = self._render_rule(d, rule_type, modifiers)
        return Rule(
            raw=raw,
            domain=d,
            rule_type=rule_type,
            wildcard=wildcard,
            sources=source,
            category=category,
            strip_www=self.strip_www,
            modifiers=modifiers,
        )

    @staticmethod
    def _render_rule(d: str, rule_type: str, modifiers: str = "") -> str:
        """Render a domain rule body (O-6, single source for the three inline
        ``||...`` / ``@@||...`` spellings in ``_make_rule``)."""
        mod = f"${modifiers}" if modifiers else ""
        prefix = "@@||" if rule_type == "allow" else "||"
        return f"{prefix}{d}^{mod}"

    @staticmethod
    def _drop_badfilter(modifiers: str) -> str:
        """Drop a ``badfilter`` modifier from a rule body.

        Per the AdGuard DNS syntax, ``$badfilter`` does not apply to
        ``/etc/hosts``-style rules, so a hosts line must not be converted into
        a cancellation of ``||domain^``.
        """
        if not modifiers:
            return ""
        rest = [m.strip() for m in modifiers.split(",") if m.strip() and m.strip() != "badfilter"]
        return ",".join(rest)

    # ── streaming parse ─────────────────────────────────────────

    def parse_stream(
        self,
        lines: Iterator[str],
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> Iterator[Rule]:
        re_block = self.RE_BLOCK.match
        re_allow = self.RE_ALLOW.match
        re_hosts = self.RE_HOSTS.match
        re_hosts_v6 = self.RE_HOSTS_V6.match
        re_plain = self.RE_DOMAIN.match
        re_wild_plain = self.RE_WILD_DOMAIN.match
        re_css = self.RE_CSS.search
        re_regex = self.RE_REGEX.match
        re_urlbar = self.RE_URLBAR.match
        re_hash_comment = self.RE_COMMENT_HASH.match
        clean = self._clean
        is_ip = self._is_ip
        localhost = self.LOCALHOST
        split_mod = self._split_modifiers
        norm_regex = self._normalize_regex
        RuleCls = Rule
        strip_www = self.strip_www

        for line in lines:
            if not line:
                continue
            s = line.strip()
            if not s:
                continue

            # comments: ! or # (but not ## / #@#) — counted, not materialised
            if s.startswith("!") or re_hash_comment(s):
                self.comment_dropped += 1
                continue

            is_css = re_css(s)
            if is_css or (s.startswith("|") and re_urlbar(s)):
                if is_css:
                    self.css_dropped += 1
                continue

            # regex rules — kept as-is (light whitespace normalization)
            if (s.startswith("/") or s.startswith("@@/")) and re_regex(s):
                s = norm_regex(s)
                rule_type = "allow" if s.startswith("@@") else "block"
                yield RuleCls(
                    raw=s,
                    domain="",
                    rule_type=rule_type,
                    wildcard=False,
                    sources=source,
                    category=category,
                    strip_www=strip_www,
                )
                continue

            # Single-pipe anchors (AdGuard): |host = anchor at start, host| =
            # anchor at end; both may appear on the same rule (|host|). For DNS
            # filtering these are host-boundary rules, equivalent to ||host^
            # after stripping the anchor pipe(s).
            # P-2: the old if/elif only ran ONE branch, so |host| kept a stray
            # '|' in the domain (→ "host|"), and a redundant '^|' tail (the ^
            # already ends the match) or an '@@|' start-anchor were mishandled.
            if s.startswith("@@|") and not s.startswith("@@||"):
                s = "@@" + "||" + s[3:]
            elif s.startswith("|") and not s.startswith("||"):
                s = "||" + s[1:]
            if s.endswith("^|"):
                s = s[:-1]
            elif s.endswith("|"):
                s = s[:-1]

            # Inline comment: any ``#`` to end-of-line after the body starts a
            # comment (AdGuard syntax). Strip it BEFORE splitting ``$``
            # modifiers so (a) ``||x.com^$dnstype=AAAA # y`` does not leak the
            # trailing comment into the modifier string (corrupting the dedup
            # key and byte-stable hashes), and (b) ``||x.com^$important # why``
            # does not mis-parse ``# why`` as extra modifier tokens that turn
            # an otherwise-kept rule into an unknown-modifier drop.
            if "#" in s:
                s = s.split("#", 1)[0].rstrip()

            s2, modifiers, stripped_mods = split_mod(s)
            if stripped_mods:
                # AdGuard spec: a rule carrying an unlisted (browser-layer)
                # modifier must be dropped whole, not kept with the mod stripped.
                if self.drop_on_unknown_modifier:
                    self.unsupported_modifier += 1
                    continue
                self.modifier_stripped += 1
            if not s2:
                continue

            # allow: @@||domain^
            m = re_allow(s2)
            if m:
                # Anything after the domain + optional ^ (a /path, | anchor, or
                # trailing text) is a URL-layer rule — drop it, don't silently
                # widen to the bare domain (over-blocking).
                if s2[m.end() :]:
                    self.pattern_dropped += 1
                    continue
                d = clean(m.group(1))
                r = self._make_rule(
                    d, "allow", d.startswith("*."), source, category, modifiers=modifiers
                )
                if r:
                    yield r
                continue

            # block: ||domain^
            m = re_block(s2)
            if m:
                if s2[m.end() :]:
                    self.pattern_dropped += 1
                    continue
                d = clean(m.group(1))
                r = self._make_rule(
                    d, "block", d.startswith("*."), source, category, modifiers=modifiers
                )
                if r:
                    yield r
                continue

            # hosts: IPv4 hostname(s) — expand `IP host1 host2 ...` aliases
            # P-1: the RE_HOSTS pattern allows \d{1,3} octets, so 999.999.999.999
            # would otherwise be accepted as a hosts IP. Validate the octets are
            # 0–255 (reuse _is_ip) so an out-of-range IP is NOT parsed as a
            # hostname list (fall through and get dropped as unparsed).
            m = re_hosts(s2)
            if m:
                # Single split for both the IP validation and the alias walk —
                # hosts lines with thousands of aliases paid for it twice.
                parts = s2.split()
                if is_ip(parts[0]):
                    host_mods = self._drop_badfilter(modifiers)
                    for d in (clean(x) for x in parts[1:]):
                        if not d:
                            continue
                        if d in localhost or "*" in d:
                            if "*" in d:
                                self.pattern_dropped += 1
                            continue
                        r = self._make_rule(
                            d, "block", False, source, category, modifiers=host_mods
                        )
                        if r:
                            yield r
                    continue
                # not a valid IPv4 host line: fall through to the next branch
                # (unchanged P-1 behaviour — out-of-range octets are unparsed)

            # hosts: IPv6 hostname(s)
            m = re_hosts_v6(s2)
            if m:
                tail = s2[m.end(0) - len(m.group(1)) :]
                host_mods = self._drop_badfilter(modifiers)
                for d in (clean(x) for x in tail.split()):
                    if not d:
                        continue
                    if d in localhost or "*" in d:
                        if "*" in d:
                            self.pattern_dropped += 1
                        continue
                    r = self._make_rule(d, "block", False, source, category, modifiers=host_mods)
                    if r:
                        yield r
                continue

            # plain wildcard domain: *.example.com
            if re_wild_plain(s2) and not is_ip(s2):
                d = clean(s2)
                r = self._make_rule(d, "block", True, source, category, modifiers=modifiers)
                if r:
                    yield r
                continue

            # plain domain (hosts-style `#` trailing comment allowed)
            dom = s2.split("#", 1)[0].strip() if not s2.startswith("#") else s2
            if re_plain(dom) and not is_ip(dom):
                d = clean(dom)
                r = self._make_rule(dom, "block", False, source, category, modifiers=modifiers)
                if r:
                    yield r
                continue

            # Item3 (Doubao): preserve non-domain standalone lines verbatim
            # instead of dropping them: DNSCrypt sdns://, CIDR, RPZ RR-like.
            if s2.startswith("sdns://") or ("/" in s2 and is_ip(s2.split("/")[0])):
                yield RuleCls(
                    raw=s2,
                    domain="",
                    rule_type="block",
                    wildcard=False,
                    sources=source,
                    category=category,
                    strip_www=self.strip_www,
                )
                continue

            # No known pattern matched — count the dropped line so silent drops
            # are visible in stats/report instead of vanishing silently.
            self.unrecognized_dropped += 1

    # ── bulk ────────────────────────────────────────────────────

    def parse_text(
        self,
        text: str,
        source: str = "",
        category: str = CATEGORY_OTHER,
    ) -> list[Rule]:
        # O1: str.splitlines() handles \n, \r and \r\n (universal newlines)
        # without an extra full-text copy that io.StringIO(text) would make.
        return list(self.parse_stream(iter(text.splitlines()), source, category))

    @staticmethod
    def compact_records(rules: list[Rule]) -> list[tuple]:
        """Serializable tuples for the parsed-rule sidecar cache."""
        recs = []
        for r in rules:
            recs.append(
                (
                    r.rule_type,
                    r.normalized_domain,
                    r.wildcard,
                    r.modifiers,
                    r.category,
                    r.raw if r.normalized_domain == "" else "",
                )
            )
        return recs

    @staticmethod
    def rules_from_records(
        records: list[tuple], source: str, strip_www: bool = False
    ) -> list[Rule]:
        rules: list[Rule] = []
        for rule_type, domain, wildcard, modifiers, category, raw in records:
            rules.append(
                Rule(
                    raw=raw or "",
                    domain=domain,
                    rule_type=rule_type,
                    wildcard=wildcard,
                    sources=source,
                    category=category,
                    strip_www=strip_www,
                    modifiers=modifiers,
                )
            )
        return rules
