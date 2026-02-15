#!/usr/bin/env python3
"""
AdGuard Rules Merger - 核心功能单元测试
"""

import os
import sys
import tempfile
import unittest
from merger import RuleNormalizer, RuleMerger, RuleType, RuleCategory, load_sources


class TestRuleNormalizer(unittest.TestCase):
    """测试规则标准化器"""

    def test_normalize_empty(self):
        """测试空行处理"""
        result, rule_type = RuleNormalizer.normalize("")
        self.assertEqual(result, "")
        self.assertEqual(rule_type, RuleType.EMPTY)

    def test_normalize_comment(self):
        """测试注释行处理"""
        test_cases = [
            "# This is a comment",
            "! AdGuard comment",
        ]
        for case in test_cases:
            result, rule_type = RuleNormalizer.normalize(case)
            self.assertEqual(rule_type, RuleType.COMMENT, f"Failed for: {case}")

    def test_normalize_domain(self):
        """测试普通域名处理"""
        test_cases = [
            ("example.com", "example.com"),
            ("sub.example.com", "sub.example.com"),
            ("EXAMPLE.COM", "example.com"),
        ]
        for input_val, expected in test_cases:
            result, rule_type = RuleNormalizer.normalize(input_val)
            self.assertEqual(rule_type, RuleType.DOMAIN)
            self.assertEqual(result, expected)

    def test_normalize_wildcard(self):
        """测试通配符规则处理"""
        test_cases = [
            ("||example.com^", "example.com"),
            ("||sub.example.com^", "sub.example.com"),
            ("*.example.com", "example.com"),
        ]
        for input_val, expected in test_cases:
            result, rule_type = RuleNormalizer.normalize(input_val)
            self.assertEqual(rule_type, RuleType.WILDCARD)
            self.assertEqual(result, expected)

    def test_normalize_adguard_modifier(self):
        """测试AdGuard修饰符规则"""
        result, rule_type = RuleNormalizer.normalize("||example.com$important")
        self.assertEqual(rule_type, RuleType.WILDCARD)
        self.assertEqual(result, "example.com$important")

    def test_normalize_hosts(self):
        """测试Hosts格式"""
        result, rule_type = RuleNormalizer.normalize("127.0.0.1 example.com")
        self.assertEqual(rule_type, RuleType.HOSTS)
        self.assertEqual(result, "example.com")

    def test_normalize_regex(self):
        """测试正则表达式规则"""
        result, rule_type = RuleNormalizer.normalize("/ads?\\d+\\.example\\.com/")
        self.assertEqual(rule_type, RuleType.REGEX)

    def test_is_whitelist(self):
        """测试白名单检测"""
        self.assertTrue(RuleNormalizer.is_whitelist("@@example.com"))
        self.assertTrue(RuleNormalizer.is_whitelist("@@||example.com$important"))
        self.assertFalse(RuleNormalizer.is_whitelist("example.com"))

    def test_detect_category(self):
        """测试分类检测"""
        self.assertEqual(
            RuleNormalizer.detect_category("test", "https://phishing.com/list.txt"),
            RuleCategory.PHISHING
        )
        self.assertEqual(
            RuleNormalizer.detect_category("test", "https://malware.com/list.txt"),
            RuleCategory.MALWARE
        )
        self.assertEqual(
            RuleNormalizer.detect_category("ad-banner.example.com", ""),
            RuleCategory.ADS
        )
        self.assertEqual(
            RuleNormalizer.detect_category("tracker.example.com", ""),
            RuleCategory.PRIVACY
        )


class TestRuleMerger(unittest.TestCase):
    """测试规则合并器"""

    def setUp(self):
        """测试前准备"""
        self.merger = RuleMerger(timeout=10)

    def test_add_rule(self):
        """测试添加规则"""
        from merger import Rule
        
        rule = Rule(
            raw="example.com",
            normalized="example.com",
            rule_type=RuleType.DOMAIN,
            source="test.txt",
            is_whitelist=False
        )
        
        self.assertTrue(self.merger.add_rule(rule))
        self.assertFalse(self.merger.add_rule(rule))  # 重复添加

    def test_is_duplicate(self):
        """测试重复检测"""
        from merger import Rule
        
        rule1 = Rule(
            raw="example.com",
            normalized="example.com",
            rule_type=RuleType.DOMAIN,
            source="test1.txt",
            is_whitelist=False
        )
        
        rule2 = Rule(
            raw="*.example.com",
            normalized="*.example.com",
            rule_type=RuleType.WILDCARD,
            source="test2.txt",
            is_whitelist=False
        )
        
        self.merger.add_rule(rule1)
        self.assertTrue(self.merger.is_duplicate_fast(rule2))

    def test_merge_files(self):
        """测试合并多个文件"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("example.com\ntest.com\n")
            temp_path1 = f.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("example.com\nother.com\n")
            temp_path2 = f.name

        try:
            stats = self.merger.merge_files([temp_path1, temp_path2])
            
            self.assertEqual(stats['total_files'], 2)
            self.assertEqual(stats['successful_files'], 2)
        finally:
            os.unlink(temp_path1)
            os.unlink(temp_path2)


class TestLoadSources(unittest.TestCase):
    """测试加载订阅源列表"""

    def test_load_sources(self):
        """测试从文件加载订阅源"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# Comment\n")
            f.write("https://example1.com/list.txt\n")
            f.write("\n")
            f.write("https://example2.com/list.txt\n")
            temp_path = f.name

        try:
            sources = load_sources(temp_path)
            self.assertEqual(len(sources), 2)
            self.assertIn("https://example1.com/list.txt", sources)
            self.assertIn("https://example2.com/list.txt", sources)
        finally:
            os.unlink(temp_path)

    def test_load_sources_not_exist(self):
        """测试文件不存在的情况"""
        sources = load_sources("/nonexistent/file.txt")
        self.assertEqual(sources, [])


class TestIntegration(unittest.TestCase):
    """集成测试"""

    def test_full_workflow(self):
        """测试完整工作流程"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# Source 1\n")
            f.write("example.com\n")
            f.write("||test.com^\n")
            temp_path = f.name

        with tempfile.TemporaryDirectory() as output_dir:
            merger = RuleMerger(timeout=10)
            
            stats = merger.merge_files([temp_path])
            
            self.assertEqual(stats['total_rules'], 2)
            
            rules_file = merger.generate_output(output_dir)
            self.assertTrue(os.path.exists(rules_file))

        os.unlink(temp_path)


def run_tests():
    """运行所有测试"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestRuleNormalizer))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleMerger))
    suite.addTests(loader.loadTestsFromTestCase(TestLoadSources))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_tests())
