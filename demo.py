#!/usr/bin/env python3
"""
Demo script showing the AdGuard Rules Merger capabilities.

This demonstrates the core functionality implemented in Tasks S1 and S2.
"""

import time
from merger import RuleEngine
from merger.models import Rule
from merger.parser import RuleParser


def demo_basic_functionality():
    """Demonstrate basic parsing and rule creation."""
    print("🎯 Demo 1: Basic Rule Parsing")
    print("-" * 40)
    
    parser = RuleParser()
    
    # Test various rule formats
    test_lines = [
        "||ads.com^",
        "@@||whitelist.com^", 
        "||*.tracker.com^",
        "! This is a comment",
        "invalid line format"
    ]
    
    for line in test_lines:
        rule = parser.parse_line(line, "demo")
        if rule:
            print(f"✅ '{line}' -> {rule.type} rule for '{rule.domain}'")
        else:
            print(f"❌ '{line}' -> Invalid/unsupported")
    
    print()


def demo_rule_equivalence():
    """Demonstrate rule equivalence and deduplication logic."""
    print("🎯 Demo 2: Rule Equivalence and Deduplication")
    print("-" * 50)
    
    # Create equivalent rules
    rule1 = Rule("||*.example.com^", "*.example.com", "block", True, "source1")
    rule2 = Rule("||example.com^", "example.com", "block", False, "source2")
    
    print(f"Rule 1: {rule1.raw}")
    print(f"Rule 2: {rule2.raw}")
    print(f"Are they equivalent? {rule1.is_equivalent_to(rule2)}")
    print(f"Normalized domains: '{rule1.normalized_domain}' == '{rule2.normalized_domain}'")
    print()
    
    # Test subdomain relationship
    subdomain_rule = Rule("||ads.example.com^", "ads.example.com", "block", False, "source3")
    print(f"Subdomain rule: {subdomain_rule.raw}")
    print(f"Is subdomain of wildcard? {subdomain_rule.is_subdomain_of(rule1)}")
    print()


def demo_deduplication():
    """Demonstrate the deduplication engine."""
    print("🎯 Demo 3: Rule Deduplication Engine")
    print("-" * 42)
    
    engine = RuleEngine()
    
    # Create a set of rules with duplicates and redundancies
    test_rules = [
        Rule("||*.example.com^", "*.example.com", "block", True, "source1"),
        Rule("||ads.example.com^", "ads.example.com", "block", False, "source2"),
        Rule("||tracker.example.com^", "tracker.example.com", "block", False, "source3"),
        Rule("||other.com^", "other.com", "block", False, "source4"),
        Rule("||example.com^", "example.com", "block", False, "source5"),  # Equivalent to wildcard
        Rule("@@||whitelist.com^", "whitelist.com", "allow", False, "source6"),
        Rule("@@||*.whitelist.com^", "*.whitelist.com", "allow", True, "source7"),
        Rule("! Comment 1", "", "comment", False, "source8"),
        Rule("! Comment 1", "", "comment", False, "source9"),  # Duplicate comment
    ]
    
    print(f"Original rules: {len(test_rules)}")
    print("Rules before deduplication:")
    for i, rule in enumerate(test_rules, 1):
        print(f"  {i:2d}. {rule.raw:<30} (from {rule.source})")
    
    print("\nRunning deduplication...")
    deduped_rules = engine.deduplicate_rules(test_rules)
    
    print(f"\nAfter deduplication: {len(deduped_rules)} rules")
    print("Final rules:")
    for i, rule in enumerate(deduped_rules, 1):
        print(f"  {i:2d}. {rule.raw:<30} (type: {rule.type})")
    
    dedup_rate = (1 - len(deduped_rules) / len(test_rules)) * 100
    print(f"\nDeduplication rate: {dedup_rate:.1f}%")
    print()


def demo_performance():
    """Demonstrate parsing performance."""
    print("🎯 Demo 4: Performance Test")
    print("-" * 32)
    
    parser = RuleParser()
    
    # Generate 1000 test rules
    test_lines = []
    for i in range(1000):
        if i % 4 == 0:
            test_lines.append(f"||ads{i}.com^")
        elif i % 4 == 1:
            test_lines.append(f"@@||whitelist{i}.com^")
        elif i % 4 == 2:
            test_lines.append(f"||*.tracker{i}.com^")
        else:
            test_lines.append(f"! Comment {i}")
    
    print(f"Parsing {len(test_lines)} rules...")
    
    start_time = time.time()
    rules = parser.parse_lines(test_lines, "performance_test")
    end_time = time.time()
    
    parsing_time = end_time - start_time
    rate = len(test_lines) / parsing_time
    
    print(f"✅ Parsed {len(rules)} valid rules in {parsing_time:.3f} seconds")
    print(f"✅ Parsing rate: {rate:,.0f} rules/second")
    print(f"✅ Performance requirement: {'PASSED' if parsing_time < 1.0 else 'FAILED'}")
    print()


def main():
    """Run all demos."""
    print("🚀 AdGuard Rules Merger - Interactive Demo")
    print("=" * 50)
    print("This demo showcases the core functionality implemented in Tasks S1 and S2.\n")
    
    demo_basic_functionality()
    demo_rule_equivalence()
    demo_deduplication()
    demo_performance()
    
    print("=" * 50)
    print("🎉 Demo completed successfully!")
    print("\nNext steps:")
    print("  - Task S3: Implement conflict detection system")
    print("  - Task S4: Add statistical reporting")
    print("  - Task S5: Set up CI/CD pipeline")


if __name__ == "__main__":
    main()