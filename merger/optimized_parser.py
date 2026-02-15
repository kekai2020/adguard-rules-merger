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
        if not line or not line.strip():
            return None
        
        original_line = line.strip()
        
        # Skip empty lines
        if not original_line:
            return None
        
        # Check for comments
        if self.COMMENT_PATTERN.match(original_line):
            return Rule(
                raw=original_line,
                domain="",
                type="comment",
                wildcard=False,
                source=source
            )
        
        # Check for allow rules (whitelist)
        allow_match = self.ALLOW_PATTERN.match(original_line)
        if allow_match:
            domain = allow_match.group(1)
            return Rule(
                raw=original_line,
                domain=domain,
                type="allow",
                wildcard=self.WILDCARD_PATTERN.match(domain) is not None,
                source=source
            )
        
        # Check for block rules (blacklist)
        block_match = self.BLOCK_PATTERN.match(original_line)
        if block_match:
            domain = block_match.group(1)
            return Rule(
                raw=original_line,
                domain=domain,
                type="block",
                wildcard=self.WILDCARD_PATTERN.match(domain) is not None,
                source=source
            )
        
        # Line doesn't match any known pattern, treat as invalid/unsupported
        return None
    
    def parse_lines(self, lines: list[str], source: str = "unknown") -> list[Rule]:
        """
        Parse multiple lines from an AdGuard filter list.
        
        Args:
            lines: List of raw lines from the filter list
            source: Identifier for the source of these rules
            
        Returns:
            List of valid Rule objects
        """
        if not lines:
            return []
        
        # Pre-allocate list for better performance
        rules = []
        rules_append = rules.append  # Local reference for faster access
        
        # Process lines in batches for better memory efficiency
        for line in lines:
            rule = self.parse_line(line, source)
            if rule is not None:
                rules_append(rule)
        
        return rules
    
    def parse_lines_optimized(self, lines: list[str], source: str = "unknown") -> list[Rule]:
        """
        Optimized version for very large datasets.
        
        Args:
            lines: List of raw lines from the filter list
            source: Identifier for the source of these rules
            
        Returns:
            List of valid Rule objects
        """
        if not lines:
            return []
        
        rules = []
        rules_append = rules.append
        
        # Local references for faster access
        comment_pattern = self.COMMENT_PATTERN
        allow_pattern = self.ALLOW_PATTERN
        block_pattern = self.BLOCK_PATTERN
        wildcard_pattern = self.WILDCARD_PATTERN
        
        for line in lines:
            if not line or not line.strip():
                continue
            
            original_line = line.strip()
            if not original_line:
                continue
            
            # Check for comments
            if comment_pattern.match(original_line):
                rules_append(Rule(
                    raw=original_line,
                    domain="",
                    type="comment",
                    wildcard=False,
                    source=source
                ))
                continue
            
            # Check for allow rules (whitelist)
            allow_match = allow_pattern.match(original_line)
            if allow_match:
                domain = allow_match.group(1)
                rules_append(Rule(
                    raw=original_line,
                    domain=domain,
                    type="allow",
                    wildcard=wildcard_pattern.match(domain) is not None,
                    source=source
                ))
                continue
            
            # Check for block rules (blacklist)
            block_match = block_pattern.match(original_line)
            if block_match:
                domain = block_match.group(1)
                rules_append(Rule(
                    raw=original_line,
                    domain=domain,
                    type="block",
                    wildcard=wildcard_pattern.match(domain) is not None,
                    source=source
                ))
                continue
        
        return rules
    
    def parse_text(self, text: str, source: str = "unknown") -> list[Rule]:
        """
        Parse text content from an AdGuard filter list.
        
        Args:
            text: Full text content of the filter list
            source: Identifier for the source of these rules
            
        Returns:
            List of valid Rule objects
        """
        lines = text.split('\n')
        return self.parse_lines_optimized(lines, source)