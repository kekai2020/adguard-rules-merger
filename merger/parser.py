"""Parser for AdGuard filter rules."""

import re
from typing import Optional, Pattern

from .models import Rule


class RuleParser:
    """Parser for AdGuard filter rules."""

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

        # Strip once and reuse
        original_line = line.strip()
        if not original_line:
            return None

        # Cache pattern matches for performance
        comment_match = self.COMMENT_PATTERN.match
        allow_pattern = self.ALLOW_PATTERN.match
        block_pattern = self.BLOCK_PATTERN.match
        wildcard_pattern = self.WILDCARD_PATTERN.match

        # Check for comments first (most common in filter lists)
        if comment_match(original_line):
            return Rule(
                raw=original_line,
                domain="",
                type="comment",
                wildcard=False,
                source=source
            )

        # Check for allow rules (whitelist)
        allow_match = allow_pattern(original_line)
        if allow_match:
            domain = allow_match.group(1)
            return Rule(
                raw=original_line,
                domain=domain,
                type="allow",
                wildcard=wildcard_pattern(domain) is not None,
                source=source
            )

        # Check for block rules (blacklist)
        block_match = block_pattern(original_line)
        if block_match:
            domain = block_match.group(1)
            return Rule(
                raw=original_line,
                domain=domain,
                type="block",
                wildcard=wildcard_pattern(domain) is not None,
                source=source
            )

        # Line doesn't match any known pattern, treat as invalid/unsupported
        return None

    def parse_lines(self, lines: list[str], source: str = "unknown") -> list[Rule]:
        """
        Parse multiple lines from an AdGuard filter list.

        Uses list comprehension for better performance.

        Args:
            lines: List of raw lines from the filter list
            source: Identifier for the source of these rules

        Returns:
            List of valid Rule objects
        """
        # Use list comprehension with filter for better performance
        return [rule for line in lines if (rule := self.parse_line(line, source)) is not None]

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
        # splitlines() is faster and handles \r\n, \r, \n
        lines = text.splitlines()
        return self.parse_lines(lines, source)
