"""Optimized parser for AdGuard filter rules with improved performance."""

import re
from typing import Optional, Pattern, List

from .models import Rule


class OptimizedRuleParser:
    """High-performance parser for AdGuard filter rules."""

    # Pre-compiled regex patterns for performance
    BLOCK_PATTERN: Pattern = re.compile(r'^\|\|([^/^\s]+)\^')
    ALLOW_PATTERN: Pattern = re.compile(r'^@@\|\|([^/^\s]+)\^')
    COMMENT_PATTERN: Pattern = re.compile(r'^!')
    WILDCARD_PATTERN: Pattern = re.compile(r'^\*\.')

    def __init__(self):
        """Initialize the parser."""
        pass

    def parse_line(self, line: str, source: str = "unknown") -> Optional[Rule]:
        """
        Parse a single line from an AdGuard filter list.

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

        # Check for comments
        if comment_match(original_line):
            return Rule(
                raw=original_line,
                domain="",
                type="comment",
                wildcard=False,
                source=source
            )

        # Check for allow rules (whitelist)
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

        # Check for block rules (blacklist)
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

        # Line doesn't match any known pattern, treat as invalid/unsupported
        return None

    def parse_lines(self, lines: List[str], source: str = "unknown") -> List[Rule]:
        """
        Parse multiple lines from an AdGuard filter list.

        Uses list comprehension for better performance.

        Args:
            lines: List of raw lines from the filter list
            source: Identifier for the source of these rules

        Returns:
            List of valid Rule objects
        """
        # Use list comprehension with walrus operator for better performance
        return [rule for line in lines if (rule := self.parse_line(line, source)) is not None]

    def parse_lines_optimized(self, lines: List[str], source: str = "unknown") -> List[Rule]:
        """
        Optimized version for very large datasets using batch processing.

        Args:
            lines: List of raw lines from the filter list
            source: Identifier for the source of these rules

        Returns:
            List of valid Rule objects
        """
        if not lines:
            return []

        rules: List[Rule] = []
        rules_append = rules.append

        # Local references for faster access
        comment_match = self.COMMENT_PATTERN.match
        allow_match = self.ALLOW_PATTERN.match
        block_match = self.BLOCK_PATTERN.match
        wildcard_match = self.WILDCARD_PATTERN.match

        for line in lines:
            # Fast path: skip empty lines
            if not line:
                continue

            original_line = line.strip()
            if not original_line:
                continue

            # Check for comments first (most common in filter lists)
            if comment_match(original_line):
                rules_append(Rule(
                    raw=original_line,
                    domain="",
                    type="comment",
                    wildcard=False,
                    source=source
                ))
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

            # Check for block rules (blacklist)
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

        return rules

    def parse_text(self, text: str, source: str = "unknown") -> List[Rule]:
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
        # splitlines() is faster and handles \r\n, \r, \n
        lines = text.splitlines()
        return self.parse_lines_optimized(lines, source)
