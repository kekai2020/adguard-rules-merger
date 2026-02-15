#!/usr/bin/env python3
"""Performance test script for AdGuard Rules Merger."""

import time
from merger.parser import RuleParser
from merger.optimized_parser import OptimizedRuleParser


def test_parsing_performance():
    """Test parsing performance with different scales and parsers."""
    parser = RuleParser()
    optimized_parser = OptimizedRuleParser()
    
    # Test multiple scales with both parsers
    test_scales = [1000, 10000, 50000]  # Reduced max scale for reasonable testing
    all_passed = True
    
    for scale in test_scales:
        # Generate test lines with various formats
        test_lines = []
        for i in range(scale):
            if i % 4 == 0:
                test_lines.append(f"||ads{i}.com^")
            elif i % 4 == 1:
                test_lines.append(f"@@||whitelist{i}.com^")
            elif i % 4 == 2:
                test_lines.append(f"||*.tracker{i}.com^")
            else:
                test_lines.append(f"! Comment {i}")
        
        print(f"\nTesting parsing performance with {len(test_lines)} lines...")
        
        # Test original parser
        start_time = time.time()
        rules = parser.parse_lines(test_lines, "performance_test")
        end_time = time.time()
        
        parsing_time = end_time - start_time
        rate = len(test_lines) / parsing_time
        print(f"Original parser: {len(rules)} rules in {parsing_time:.3f}s ({rate:.0f} lines/sec)")
        
        # Test optimized parser
        start_time = time.time()
        optimized_rules = optimized_parser.parse_lines_optimized(test_lines, "performance_test")
        end_time = time.time()
        
        optimized_time = end_time - start_time
        optimized_rate = len(test_lines) / optimized_time
        print(f"Optimized parser: {len(optimized_rules)} rules in {optimized_time:.3f}s ({optimized_rate:.0f} lines/sec)")
        
        # Verify both parsers produce the same results
        assert len(rules) == len(optimized_rules), "Parsers should produce same number of rules"
        
        # Performance improvement
        improvement = (parsing_time - optimized_time) / parsing_time * 100
        print(f"Performance improvement: {improvement:.1f}%")
        
        # Set reasonable performance requirements based on scale
        if scale == 1000:
            requirement = 1.0  # 1000 rules should complete in < 1 second
            requirement_desc = "1 second"
        elif scale == 10000:
            requirement = 3.0  # 10000 rules should complete in < 3 seconds
            requirement_desc = "3 seconds"
        else:  # 50000
            requirement = 10.0  # 50000 rules should complete in < 10 seconds
            requirement_desc = "10 seconds"
        
        # Use the faster (optimized) parser for pass/fail determination
        if optimized_time < requirement:
            print(f"✅ Performance test PASSED - completed in less than {requirement_desc}")
        else:
            print(f"❌ Performance test FAILED - took more than {requirement_desc}")
            all_passed = False
    
    return all_passed


def test_rule_formats():
    """Test that all required rule formats are handled correctly."""
    parser = RuleParser()
    
    test_cases = [
        ("||ads.com^", "block", "ads.com", False),
        ("@@||whitelist.com^", "allow", "whitelist.com", False),
        ("! This is a comment", "comment", "", False),
        ("||*.example.com^", "block", "*.example.com", True),
        ("@@||*.whitelist.com^", "allow", "*.whitelist.com", True),
    ]
    
    print("\nTesting rule format parsing...")
    all_passed = True
    
    for raw_line, expected_type, expected_domain, expected_wildcard in test_cases:
        rule = parser.parse_line(raw_line, "test")
        
        if rule is None:
            print(f"❌ Failed to parse: {raw_line}")
            all_passed = False
            continue
        
        if (rule.type == expected_type and 
            rule.domain == expected_domain and 
            rule.wildcard == expected_wildcard):
            print(f"✅ Correctly parsed: {raw_line}")
        else:
            print(f"❌ Incorrect parsing of: {raw_line}")
            print(f"   Expected: type={expected_type}, domain='{expected_domain}', wildcard={expected_wildcard}")
            print(f"   Got:      type={rule.type}, domain='{rule.domain}', wildcard={rule.wildcard}")
            all_passed = False
    
    return all_passed


if __name__ == "__main__":
    print("AdGuard Rules Merger - Performance and Format Tests")
    print("=" * 50)
    
    performance_passed = test_parsing_performance()
    formats_passed = test_rule_formats()
    
    print("\n" + "=" * 50)
    if performance_passed and formats_passed:
        print("🎉 ALL TESTS PASSED!")
    else:
        print("❌ Some tests failed!")
        exit(1)
