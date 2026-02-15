#!/usr/bin/env python3
"""
核心功能单元测试脚本
测试 merger.py 的核心功能
"""

import sys
import os

# 添加项目目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from merger import RuleType, RuleCategory, Rule, RuleNormalizer, RuleMerger


def test_normalization():
    """测试规则标准化"""
    print("\n📋 测试: 规则标准化")
    
    test_cases = [
        ("example.com", "example.com", RuleType.DOMAIN),
        ("||example.com^", "example.com", RuleType.WILDCARD),
        ("|example.com|", "example.com", RuleType.WILDCARD),
        ("*.example.com", "example.com", RuleType.WILDCARD),
        ("# 注释", "# 注释", RuleType.COMMENT),
        ("! 注释", "! 注释", RuleType.COMMENT),
        ("", "", RuleType.EMPTY),
        ("   ", "", RuleType.EMPTY),
        ("0.0.0.0 example.com", "example.com", RuleType.HOSTS),
        ("/regex pattern/", "/regex pattern/", RuleType.REGEX),
        ("example.com$important", "example.com$important", RuleType.WILDCARD),
    ]
    
    passed = 0
    failed = 0
    
    for input_rule, expected_norm, expected_type in test_cases:
        result_norm, result_type = RuleNormalizer.normalize(input_rule)
        if result_norm == expected_norm and result_type == expected_type:
            passed += 1
        else:
            print(f"   ❌ '{input_rule[:30]}'")
            print(f"      期望: '{expected_norm}' ({expected_type.value})")
            print(f"      实际: '{result_norm}' ({result_type.value})")
            failed += 1
    
    print(f"   结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_whitelist_detection():
    """测试白名单检测"""
    print("\n📋 测试: 白名单检测")
    
    test_cases = [
        ("@@example.com", True),
        ("example.com", False),
        ("@@||example.com^", True),
        ("||example.com^", False),
        ("  @@example.com  ", True),
    ]
    
    passed = 0
    failed = 0
    
    for rule_text, expected in test_cases:
        result = RuleNormalizer.is_whitelist(rule_text)
        if result == expected:
            passed += 1
        else:
            print(f"   ❌ '{rule_text.strip()}'")
            failed += 1
    
    print(f"   结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_category_detection():
    """测试分类检测"""
    print("\n📋 测试: 分类检测")
    
    test_cases = [
        ("ad.example.com", "", RuleCategory.ADS),
        ("tracker.example.com", "", RuleCategory.PRIVACY),
        ("malware.example.com", "", RuleCategory.MALWARE),
        ("phishing.example.com", "", RuleCategory.PHISHING),
        ("example.com", "https://phishing.com/list.txt", RuleCategory.PHISHING),
        ("example.com", "", RuleCategory.GENERAL),
    ]
    
    passed = 0
    failed = 0
    
    for rule_text, source_url, expected in test_cases:
        result = RuleNormalizer.detect_category(rule_text, source_url)
        if result == expected:
            passed += 1
        else:
            print(f"   ❌ '{rule_text}' -> {result.value} (期望: {expected.value})")
            failed += 1
    
    print(f"   结果: {passed} 通过, {failed} 失败")
    return failed == 0


def test_duplicate_detection():
    """测试去重检测"""
    print("\n📋 测试: 去重检测")
    
    merger = RuleMerger(timeout=10)
    merger.rules = {}
    merger.duplicates = []
    
    rule1 = Rule(
        raw="||example.com^",
        normalized="example.com",
        rule_type=RuleType.WILDCARD,
        category=RuleCategory.ADS,
        source="test1.txt",
        line_num=1,
        is_whitelist=False
    )
    
    rule2 = Rule(
        raw="*.example.com",
        normalized="example.com",
        rule_type=RuleType.WILDCARD,
        category=RuleCategory.ADS,
        source="test2.txt",
        line_num=2,
        is_whitelist=False
    )
    
    # 测试添加规则
    result1 = merger.add_rule(rule1)
    result2 = merger.add_rule(rule2)
    
    passed = 0
    if result1 == True:
        passed += 1
    else:
        print("   ❌ 第一条规则应该被添加")
    
    if result2 == False:
        passed += 1
    else:
        print("   ❌ 第二条规则应该被检测为重复")
    
    if len(merger.duplicates) == 1:
        passed += 1
    else:
        print(f"   ❌ 应该有 1 个重复，实际有 {len(merger.duplicates)}")
    
    print(f"   结果: {passed}/3 通过")
    return passed == 3


def test_conflict_detection():
    """测试冲突检测"""
    print("\n📋 测试: 冲突检测")
    
    merger = RuleMerger(timeout=10)
    merger.rules = {}
    merger.conflicts = []
    
    blacklist_rule = Rule(
        raw="||example.com^",
        normalized="example.com",
        rule_type=RuleType.WILDCARD,
        category=RuleCategory.ADS,
        source="blacklist.txt",
        line_num=1,
        is_whitelist=False
    )
    
    whitelist_rule = Rule(
        raw="@@sub.example.com",
        normalized="sub.example.com",
        rule_type=RuleType.DOMAIN,
        category=RuleCategory.ADS,
        source="whitelist.txt",
        line_num=1,
        is_whitelist=True
    )
    
    # 测试 is_conflict
    is_conflict = merger.is_conflict(blacklist_rule, whitelist_rule)
    
    passed = 0
    if is_conflict == True:
        passed += 1
        print("   ✅ 正确检测到冲突")
    else:
        print("   ❌ 应该检测到冲突")
    
    print(f"   结果: {passed}/1 通过")
    return passed == 1


def main():
    """运行所有测试"""
    print("=" * 60)
    print("核心功能单元测试")
    print("=" * 60)
    
    results = []
    
    results.append(("规则标准化", test_normalization()))
    results.append(("白名单检测", test_whitelist_detection()))
    results.append(("分类检测", test_category_detection()))
    results.append(("去重检测", test_duplicate_detection()))
    results.append(("冲突检测", test_conflict_detection()))
    
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"   {status}: {name}")
    
    print(f"\n总计: {passed}/{total} 测试通过")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
