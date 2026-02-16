"""Unit tests for the core functionality."""

import pytest
import time
from merger.models import Rule
from merger.parser import RuleParser
from merger.core import RuleEngine


class TestRule:
    """Test cases for the Rule dataclass."""
    
    def test_rule_creation(self):
        """Test basic rule creation."""
        rule = Rule(
            raw="||ads.com^",
            domain="ads.com",
            type="block",
            wildcard=False,
            source="test"
        )
        
        assert rule.raw == "||ads.com^"
        assert rule.domain == "ads.com"
        assert rule.type == "block"
        assert rule.wildcard is False
        assert rule.source == "test"
    
    def test_wildcard_normalization(self):
        """Test domain normalization for wildcard rules."""
        wildcard_rule = Rule(
            raw="||*.ads.com^",
            domain="*.ads.com",
            type="block",
            wildcard=True,
            source="test"
        )
        
        normal_rule = Rule(
            raw="||ads.com^",
            domain="ads.com",
            type="block",
            wildcard=False,
            source="test"
        )
        
        # Both should have the same normalized domain
        assert wildcard_rule.normalized_domain == "ads.com"
        assert normal_rule.normalized_domain == "ads.com"
    
    def test_equivalence_check(self):
        """Test rule equivalence checking."""
        rule1 = Rule(
            raw="||*.ads.com^",
            domain="*.ads.com",
            type="block",
            wildcard=True,
            source="test"
        )
        
        rule2 = Rule(
            raw="||ads.com^",
            domain="ads.com",
            type="block",
            wildcard=False,
            source="test"
        )
        
        rule3 = Rule(
            raw="@@||ads.com^",
            domain="ads.com",
            type="allow",
            wildcard=False,
            source="test"
        )
        
        # rule1 and rule2 should be equivalent (same domain, same type)
        assert rule1.is_equivalent_to(rule2) is True
        assert rule2.is_equivalent_to(rule1) is True
        
        # rule1 and rule3 should not be equivalent (different types)
        assert rule1.is_equivalent_to(rule3) is False
        
        # rule2 and rule3 should not be equivalent (different types)
        assert rule2.is_equivalent_to(rule3) is False
    
    def test_subdomain_check(self):
        """Test subdomain relationship checking."""
        wildcard_rule = Rule(
            raw="||*.example.com^",
            domain="*.example.com",
            type="block",
            wildcard=True,
            source="test"
        )
        
        subdomain_rule = Rule(
            raw="||ads.example.com^",
            domain="ads.example.com",
            type="block",
            wildcard=False,
            source="test"
        )
        
        unrelated_rule = Rule(
            raw="||other.com^",
            domain="other.com",
            type="block",
            wildcard=False,
            source="test"
        )
        
        # subdomain_rule should be a subdomain of wildcard_rule
        assert subdomain_rule.is_subdomain_of(wildcard_rule) is True
        
        # wildcard_rule should not be a subdomain of subdomain_rule
        assert wildcard_rule.is_subdomain_of(subdomain_rule) is False
        
        # unrelated_rule should not be a subdomain of wildcard_rule
        assert unrelated_rule.is_subdomain_of(wildcard_rule) is False


class TestRuleParser:
    """Test cases for the RuleParser."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.parser = RuleParser()
    
    def test_parse_block_rule(self):
        """Test parsing of block rules."""
        rule = self.parser.parse_line("||ads.com^", "test")
        
        assert rule is not None
        assert rule.domain == "ads.com"
        assert rule.type == "block"
        assert rule.wildcard is False
        assert rule.raw == "||ads.com^"
    
    def test_parse_allow_rule(self):
        """Test parsing of allow rules."""
        rule = self.parser.parse_line("@@||whitelist.com^", "test")
        
        assert rule is not None
        assert rule.domain == "whitelist.com"
        assert rule.type == "allow"
        assert rule.wildcard is False
        assert rule.raw == "@@||whitelist.com^"
    
    def test_parse_wildcard_rule(self):
        """Test parsing of wildcard rules."""
        rule = self.parser.parse_line("||*.ads.com^", "test")
        
        assert rule is not None
        assert rule.domain == "*.ads.com"
        assert rule.type == "block"
        assert rule.wildcard is True
        assert rule.raw == "||*.ads.com^"
    
    def test_parse_comment(self):
        """Test parsing of comments."""
        rule = self.parser.parse_line("! This is a comment", "test")
        
        assert rule is not None
        assert rule.type == "comment"
        assert rule.domain == ""
        assert rule.raw == "! This is a comment"
    
    def test_parse_empty_line(self):
        """Test parsing of empty lines."""
        rule = self.parser.parse_line("", "test")
        assert rule is None
        
        rule = self.parser.parse_line("   ", "test")
        assert rule is None
    
    def test_parse_invalid_line(self):
        """Test parsing of invalid lines."""
        rule = self.parser.parse_line("invalid rule format", "test")
        assert rule is None
        
        rule = self.parser.parse_line("some random text", "test")
        assert rule is None
    
    def test_parse_multiple_lines(self):
        """Test parsing multiple lines."""
        lines = [
            "||ads.com^",
            "@@||whitelist.com^",
            "! This is a comment",
            "",
            "invalid line",
            "||*.tracker.com^"
        ]
        
        rules = self.parser.parse_lines(lines, "test")
        
        # Should parse 4 valid rules (excluding empty and invalid lines)
        assert len(rules) == 4
        
        # Check types
        types = [rule.type for rule in rules]
        assert "block" in types
        assert "allow" in types
        assert "comment" in types
    
    def test_performance_parsing(self):
        """Test parsing performance with 1000 lines."""
        # Generate 1000 test lines
        test_lines = []
        for i in range(1000):
            if i % 3 == 0:
                test_lines.append(f"||ads{i}.com^")
            elif i % 3 == 1:
                test_lines.append(f"@@||whitelist{i}.com^")
            else:
                test_lines.append(f"! Comment {i}")
        
        start_time = time.time()
        rules = self.parser.parse_lines(test_lines, "performance_test")
        end_time = time.time()
        
        # Should parse all 1000 lines
        assert len(rules) == 1000
        
        # Should complete in less than 1 second
        parsing_time = end_time - start_time
        assert parsing_time < 1.0, f"Parsing took {parsing_time:.2f}s, expected < 1.0s"


class TestRuleEngine:
    """Test cases for the RuleEngine."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.engine = RuleEngine()
    
    def test_deduplicate_exact_duplicates(self):
        """Test deduplication of exact duplicate rules."""
        rules = [
            Rule("||ads.com^", "ads.com", "block", False, "source1"),
            Rule("||ads.com^", "ads.com", "block", False, "source2"),
            Rule("||tracker.com^", "tracker.com", "block", False, "source1"),
        ]
        
        deduped = self.engine.deduplicate_rules(rules)
        
        # Should remove exact duplicates
        assert len(deduped) == 2
        
        # Check that we have the right domains
        domains = [rule.domain for rule in deduped]
        assert "ads.com" in domains
        assert "tracker.com" in domains
    
    def test_deduplicate_wildcard_equivalents(self):
        """Test deduplication of equivalent wildcard and non-wildcard rules."""
        rules = [
            Rule("||*.ads.com^", "*.ads.com", "block", True, "source1"),
            Rule("||ads.com^", "ads.com", "block", False, "source2"),
            Rule("||tracker.com^", "tracker.com", "block", False, "source3"),
        ]
        
        deduped = self.engine.deduplicate_rules(rules)
        
        # Should keep only the wildcard version as it's more general
        assert len(deduped) == 2
        
        # Check that we have the wildcard version for ads.com
        ads_rules = [r for r in deduped if "ads" in r.domain]
        assert len(ads_rules) == 1
        assert ads_rules[0].wildcard is True
    
    def test_deduplicate_subdomain_redundancy(self):
        """Test removal of redundant subdomain rules."""
        rules = [
            Rule("||*.example.com^", "*.example.com", "block", True, "source1"),
            Rule("||ads.example.com^", "ads.example.com", "block", False, "source2"),
            Rule("||tracker.example.com^", "tracker.example.com", "block", False, "source3"),
            Rule("||other.com^", "other.com", "block", False, "source4"),
        ]
        
        deduped = self.engine.deduplicate_rules(rules)
        
        # Should remove subdomain rules covered by wildcard
        assert len(deduped) == 2
        
        # Check that we have the wildcard rule and the unrelated rule
        domains = [rule.domain for rule in deduped]
        assert "*.example.com" in domains
        assert "other.com" in domains
        assert "ads.example.com" not in domains
        assert "tracker.example.com" not in domains
    
    def test_deduplicate_mixed_types(self):
        """Test deduplication with mixed rule types."""
        rules = [
            Rule("||ads.com^", "ads.com", "block", False, "source1"),
            Rule("@@||ads.com^", "ads.com", "allow", False, "source2"),
            Rule("! Comment about ads.com", "", "comment", False, "source3"),
        ]
        
        deduped = self.engine.deduplicate_rules(rules)
        
        # Should keep all rules as they have different types
        assert len(deduped) == 3
        
        # Verify types
        types = [rule.type for rule in deduped]
        assert "block" in types
        assert "allow" in types
        assert "comment" in types
    
    def test_merge_empty_sources(self):
        """Test merge with empty source list."""
        result = self.engine.merge([])
        assert result == []
    
    def test_merge_single_source(self):
        """Test merge with a single source using local file."""
        import tempfile
        import os
        
        # Create a temporary file with test rules
        test_content = """||ads1.com^
||ads2.com^
@@||whitelist.com^
||*.tracker.com^
! This is a comment
||malware.com^"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(test_content)
            temp_path = f.name
        
        try:
            # Test merge with single local file source
            result = self.engine.merge([temp_path])
            
            # Should have parsed 6 rules (5 valid rules + 1 comment)
            assert len(result) == 6, f"Expected 6 rules, got {len(result)}"
            
            # Check rule types
            types = [rule.type for rule in result]
            assert 'block' in types
            assert 'allow' in types
            assert 'comment' in types
            
            # Check domains
            domains = [rule.domain for rule in result if rule.type == 'block']
            assert 'ads1.com' in domains
            assert 'ads2.com' in domains
            
        finally:
            os.unlink(temp_path)