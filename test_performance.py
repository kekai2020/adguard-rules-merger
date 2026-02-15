#!/usr/bin/env python3
"""Performance test script for AdGuard Rules Merger."""

import time
from merger.parser import RuleParser


def test_parsing_performance():
    """Test parsing performance with 1000 lines."""
    parser = RuleParser()
    
    # Generate 1000 test lines with various formats
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
    
    print(f"Testing parsing performance with {len(test_lines)} lines...")
    
    start_time = time.time()
    rules = parser.parse_lines(test_lines, "performance_test")
    end_time = time.time()
    
    parsing_time = end_time - start_time
    print(f"Parsed {len(rules)} valid rules in {parsing_time:.3f} seconds")
    print(f"Parsing rate: {len(test_lines) / parsing_time:.0f} lines/second")
    
    # Verify performance requirement (< 1 second)
    if parsing_time < 1.0:
        print("✅ Performance test PASSED - parsing completed in less than 1 second")
    else:
        print("❌ Performance test FAILED - parsing took more than 1 second")
    
    return parsing_time < 1.0


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