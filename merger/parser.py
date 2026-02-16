"""Parser for AdGuard filter rules."""

import re
from typing import Optional

from .models import Rule


class RuleParser:
    """High-performance parser for AdGuard filter rules and other formats."""

    # Pre-compiled regex patterns for performance
    BLOCK_PATTERN = re.compile(r'^\|\|([^/^\s]+)\^')
    ALLOW_PATTERN = re.compile(r'^@@\|\|([^/^\s]+)\^')
    COMMENT_PATTERN = re.compile(r'^!')
    WILDCARD_PATTERN = re.compile(r'^\*\.')
    
    # Additional patterns for other formats
    HOSTS_PATTERN = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)$')
    PLAIN_DOMAIN_PATTERN = re.compile(r'^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$')
    HTML_FILTER_PATTERN = re.compile(r'^##')
    CSS_RULE_PATTERN = re.compile(r'^#@?#')

    def __init__(self, skip_unsupported: bool = True):
        """
        Initialize the parser.
        
        Args:
            skip_unsupported: If True, skip unsupported rule types instead of returning None
        """
        self.skip_unsupported = skip_unsupported

    def parse_line(self, line: str, source: str = "unknown") -> Optional[Rule]:
        """
        Parse a single line from an AdGuard filter list or hosts file.

        Supports multiple formats:
        - AdGuard: ||domain.com^, @@||domain.com^, ! comment
        - Hosts: 0.0.0.0 domain.com, 127.0.0.1 domain.com
        - Plain domains: domain.com (auto-converted to block rule)

        Args:
            line: Raw line from the filter list
            source: Identifier for the source of this rule

        Returns:
            Rule object if the line is a valid rule, None otherwise
        """
        # Fast path: skip empty lines
        if not line:
            return None

        original_line = line.strip()
        if not original_line:
            return None

        # Cache pattern methods for faster lookup
        comment_match = self.COMMENT_PATTERN.match
        allow_match = self.ALLOW_PATTERN.match
        block_match = self.BLOCK_PATTERN.match
        wildcard_match = self.WILDCARD_PATTERN.match
        hosts_match = self.HOSTS_PATTERN.match
        plain_domain_match = self.PLAIN_DOMAIN_PATTERN.match
        html_filter_match = self.HTML_FILTER_PATTERN.match
        css_rule_match = self.CSS_RULE_PATTERN.match

        # Check for comments first
        if comment_match(original_line):
            return Rule(
                raw=original_line,
                domain="",
                type="comment",
                wildcard=False,
                source=source
            )

        # Skip HTML/CSS filter rules (not supported)
        if html_filter_match(original_line) or css_rule_match(original_line):
            if self.skip_unsupported:
                return None
            # Return as comment for preservation
            return Rule(
                raw=original_line,
                domain="",
                type="comment",
                wildcard=False,
                source=source
            )

        # Check for AdGuard allow rules (whitelist)
        allow_m = allow_match(original_line)
        if allow_m:
            domain = allow_m.group(1)
            return Rule(
                raw=original_line,
                domain=domain,
                type="allow",
                wildcard=wildcard_match(domain) is not None,
                source=source
            )

        # Check for AdGuard block rules
        block_m = block_match(original_line)
        if block_m:
            domain = block_m.group(1)
            return Rule(
                raw=original_line,
                domain=domain,
                type="block",
                wildcard=wildcard_match(domain) is not None,
                source=source
            )

        # Check for hosts file format: 0.0.0.0 domain.com
        hosts_m = hosts_match(original_line)
        if hosts_m:
            domain = hosts_m.group(1)
            # Skip localhost entries
            if domain.lower() in ('localhost', 'localhost.localdomain'):
                return None
            return Rule(
                raw=original_line,
                domain=domain,
                type="block",
                wildcard=wildcard_match(domain) is not None,
                source=source
            )

        # Check for plain domain format (convert to block rule)
        # Only if it looks like a valid domain and isn't an IP address
        plain_m = plain_domain_match(original_line)
        if plain_m and not self._is_ip_address(original_line):
            domain = original_line.lower()
            # Convert to AdGuard format
            raw = f"||{domain}^"
            return Rule(
                raw=raw,
                domain=domain,
                type="block",
                wildcard=False,
                source=source
            )

        # Line doesn't match any known pattern
        return None

    def _is_ip_address(self, text: str) -> bool:
        """Check if text is an IP address."""
        # Quick check for IPv4 pattern
        parts = text.split('.')
        if len(parts) == 4:
            try:
                for p in parts:
                    num = int(p)
                    if num < 0 or num > 255:
                        return False
                return True
            except ValueError:
                pass
        return False

    def parse_lines(self, lines: list[str], source: str = "unknown") -> list[Rule]:
        """
        Parse multiple lines from an AdGuard filter list.

        Uses list comprehension with walrus operator for better performance.

        Args:
            lines: List of raw lines from the filter list
            source: Identifier for the source of these rules

        Returns:
            List of valid Rule objects
        """
        return [rule for line in lines if (rule := self.parse_line(line, source)) is not None]

    def parse_lines_optimized(self, lines: list[str], source: str = "unknown") -> list[Rule]:
        """
        Optimized version for very large datasets using batch processing.
        
        This method avoids the overhead of walrus operator in list comprehension
        for maximum performance with large datasets.

        Args:
            lines: List of raw lines from the filter list
            source: Identifier for the source of these rules

        Returns:
            List of valid Rule objects
        """
        if not lines:
            return []

        rules: list[Rule] = []
        rules_append = rules.append

        # Local references for faster access
        comment_match = self.COMMENT_PATTERN.match
        allow_match = self.ALLOW_PATTERN.match
        block_match = self.BLOCK_PATTERN.match
        wildcard_match = self.WILDCARD_PATTERN.match
        hosts_match = self.HOSTS_PATTERN.match
        plain_domain_match = self.PLAIN_DOMAIN_PATTERN.match
        html_filter_match = self.HTML_FILTER_PATTERN.match
        css_rule_match = self.CSS_RULE_PATTERN.match

        for line in lines:
            # Fast path: skip empty lines
            if not line:
                continue

            original_line = line.strip()
            if not original_line:
                continue

            # Check for comments first
            if comment_match(original_line):
                rules_append(Rule(
                    raw=original_line,
                    domain="",
                    type="comment",
                    wildcard=False,
                    source=source
                ))
                continue

            # Skip HTML/CSS filter rules
            if html_filter_match(original_line) or css_rule_match(original_line):
                continue

            # Check for allow rules (whitelist)
            allow_m = allow_match(original_line)
            if allow_m:
                domain = allow_m.group(1)
                rules_append(Rule(
                    raw=original_line,
                    domain=domain,
                    type="allow",
                    wildcard=wildcard_match(domain) is not None,
                    source=source
                ))
                continue

            # Check for block rules
            block_m = block_match(original_line)
            if block_m:
                domain = block_m.group(1)
                rules_append(Rule(
                    raw=original_line,
                    domain=domain,
                    type="block",
                    wildcard=wildcard_match(domain) is not None,
                    source=source
                ))
                continue

            # Check for hosts file format
            hosts_m = hosts_match(original_line)
            if hosts_m:
                domain = hosts_m.group(1)
                if domain.lower() not in ('localhost', 'localhost.localdomain'):
                    rules_append(Rule(
                        raw=original_line,
                        domain=domain,
                        type="block",
                        wildcard=wildcard_match(domain) is not None,
                        source=source
                    ))
                continue

            # Check for plain domain
            if plain_domain_match(original_line) and not self._is_ip_address(original_line):
                domain = original_line.lower()
                rules_append(Rule(
                    raw=f"||{domain}^",
                    domain=domain,
                    type="block",
                    wildcard=False,
                    source=source
                ))
                continue

        return rules

    def parse_text(self, text: str, source: str = "unknown") -> list[Rule]:
        """
        Parse text content from an AdGuard filter list.

        Uses splitlines() which is faster than split('\n') and handles
        different line endings.

        Args:
            text: Full text content of the filter list
            source: Identifier for the source of these rules

        Returns:
            List of valid Rule objects
        """
        lines = text.splitlines()
        return self.parse_lines_optimized(lines, source)
