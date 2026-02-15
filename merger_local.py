#!/usr/bin/env python3
"""
AdGuard Home 规则合并工具 - 本地版本
功能：合并本地规则文件，实现去重和优化
"""

import re
import os
import sys
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


class RuleType(Enum):
    """规则类型枚举"""
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    REGEX = "regex"
    HOSTS = "hosts"
    COMMENT = "comment"
    EMPTY = "empty"
    INVALID = "invalid"


@dataclass
class Rule:
    """规则数据类"""
    raw: str
    normalized: str
    rule_type: RuleType
    source: str
    line_num: int
    is_whitelist: bool = False

    def __hash__(self):
        return hash(self.normalized)

    def __eq__(self, other):
        if not isinstance(other, Rule):
            return False
        return self.normalized == other.normalized


class RuleNormalizer:
    """规则标准化器"""

    DOMAIN_PATTERN = re.compile(
        r'^(?:\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )

    @classmethod
    def normalize(cls, rule_text: str) -> Tuple[str, RuleType]:
        """标准化规则文本"""
        original = rule_text.strip()

        if not original:
            return "", RuleType.EMPTY

        if original.startswith('#') or original.startswith('!') or original.startswith('//'):
            return original, RuleType.COMMENT

        rule = original.split('#')[0].split('!')[0].strip()
        if not rule:
            return original, RuleType.COMMENT

        # Hosts 格式
        hosts_match = re.match(r'^(\d{1,3}\.){3}\d{1,3}\s+(.+)$', rule)
        if hosts_match:
            domain = hosts_match.group(2).strip()
            return cls._normalize_domain(domain), RuleType.HOSTS

        # 正则表达式
        if rule.startswith('/') and rule.endswith('/'):
            return rule, RuleType.REGEX

        # AdGuard 修饰符规则
        if '$' in rule:
            parts = rule.split('$', 1)
            domain_part = parts[0].strip()
            if '@@' in domain_part:
                domain_part = domain_part.lstrip('@')
            normalized_domain = cls._normalize_domain(domain_part)
            return f"{normalized_domain}${parts[1].strip()}", RuleType.WILDCARD

        # 通配符域名
        if rule.startswith('*.') or rule.startswith('||') or rule.startswith('|'):
            if rule.startswith('||'):
                domain = rule[2:].rstrip('^').rstrip('|')
            elif rule.startswith('|'):
                domain = rule[1:].rstrip('^').rstrip('|')
            else:
                domain = rule[2:]
            return cls._normalize_domain(domain), RuleType.WILDCARD

        # 普通域名
        normalized = cls._normalize_domain(rule)
        if normalized:
            return normalized, RuleType.DOMAIN

        return original, RuleType.INVALID

    @classmethod
    def _normalize_domain(cls, domain: str) -> str:
        """标准化域名"""
        if not domain:
            return ""
        domain = re.sub(r'^(https?://)', '', domain, flags=re.IGNORECASE)
        domain = domain.rstrip('/').rstrip(':').strip().lower()
        if cls.DOMAIN_PATTERN.match(domain):
            return domain
        return domain

    @classmethod
    def is_whitelist(cls, rule_text: str) -> bool:
        """检测是否为白名单规则"""
        return '@@' in rule_text


class LocalRuleMerger:
    """本地规则合并器"""

    def __init__(self):
        self.rules: Dict[str, Rule] = {}
        self.duplicates: List[Tuple[Rule, Rule]] = []
        self.conflicts: List[Tuple[Rule, Rule]] = []

    def read_local_file(self, file_path: str) -> Tuple[str, bool]:
        """读取本地文件"""
        try:
            logger.info(f"读取本地文件: {file_path}")
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            logger.info(f"成功读取: {file_path} ({len(content)} 字符)")
            return content, True
        except Exception as e:
            logger.error(f"读取失败: {file_path} - {str(e)}")
            return "", False

    def parse_rules(self, content: str, source_name: str) -> List[Rule]:
        """解析规则内容"""
        rules = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            normalized, rule_type = RuleNormalizer.normalize(line)

            if rule_type in (RuleType.EMPTY, RuleType.COMMENT):
                continue

            if rule_type == RuleType.INVALID:
                continue

            is_whitelist = RuleNormalizer.is_whitelist(line)

            rule = Rule(
                raw=line.strip(),
                normalized=normalized,
                rule_type=rule_type,
                source=source_name,
                line_num=line_num,
                is_whitelist=is_whitelist
            )
            rules.append(rule)

        return rules

    def is_duplicate(self, new_rule: Rule, existing_rule: Rule) -> bool:
        """检测重复规则"""
        if new_rule.normalized == existing_rule.normalized:
            return True

        new_norm = new_rule.normalized
        exist_norm = existing_rule.normalized

        if new_norm.startswith('*.'):
            new_base = new_norm[2:]
            if new_base == exist_norm or exist_norm.endswith('.' + new_base):
                return True

        if exist_norm.startswith('*.'):
            exist_base = exist_norm[2:]
            if exist_base == new_norm or new_norm.endswith('.' + exist_base):
                return True

        if new_norm.endswith('.' + exist_norm) or exist_norm.endswith('.' + new_norm):
            return True

        return False

    def is_conflict(self, rule1: Rule, rule2: Rule) -> bool:
        """检测冲突规则"""
        if rule1.is_whitelist == rule2.is_whitelist:
            return False
        if rule1.normalized == rule2.normalized:
            return True
        if rule1.normalized in rule2.normalized or rule2.normalized in rule1.normalized:
            return True
        return False

    def add_rule(self, rule: Rule) -> bool:
        """添加规则"""
        normalized = rule.normalized

        if normalized in self.rules:
            existing = self.rules[normalized]
            self.duplicates.append((rule, existing))
            return False

        for exist_norm, exist_rule in self.rules.items():
            if self.is_duplicate(rule, exist_rule):
                self.duplicates.append((rule, exist_rule))
                return False

            if self.is_conflict(rule, exist_rule):
                self.conflicts.append((rule, exist_rule))

        self.rules[normalized] = rule
        return True

    def merge_files(self, file_paths: List[str]) -> Dict:
        """合并多个本地文件"""
        stats = {
            'total_files': len(file_paths),
            'successful_files': 0,
            'failed_files': [],
            'total_rules': 0,
            'unique_rules': 0,
            'duplicates': 0,
            'conflicts': 0,
            'by_source': defaultdict(int),
        }

        for file_path in file_paths:
            content, success = self.read_local_file(file_path)
            if not success:
                stats['failed_files'].append(file_path)
                continue

            stats['successful_files'] += 1
            rules = self.parse_rules(content, os.path.basename(file_path))
            stats['by_source'][file_path] = len(rules)

            for rule in rules:
                stats['total_rules'] += 1
                if self.add_rule(rule):
                    stats['unique_rules'] += 1

        stats['duplicates'] = len(self.duplicates)
        stats['conflicts'] = len(self.conflicts)

        return stats

    def generate_output(self, output_dir: str = "output") -> str:
        """生成合并后的规则文件"""
        os.makedirs(output_dir, exist_ok=True)
        rules_file = os.path.join(output_dir, "merged_rules.txt")

        with open(rules_file, 'w', encoding='utf-8') as f:
            f.write("! AdGuard Home 合并规则 (本地)\n")
            f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 规则总数: {len(self.rules)}\n")
            f.write("! ==========================================\n\n")

            # 白名单优先
            whitelist_rules = [r for r in self.rules.values() if r.is_whitelist]
            blacklist_rules = [r for r in self.rules.values() if not r.is_whitelist]

            if whitelist_rules:
                f.write("! ===== 白名单规则 =====\n")
                for rule in sorted(whitelist_rules, key=lambda r: r.normalized):
                    f.write(f"{rule.raw}\n")
                f.write("\n")

            if blacklist_rules:
                f.write("! ===== 黑名单规则 =====\n")
                for rule in sorted(blacklist_rules, key=lambda r: r.normalized):
                    f.write(f"{rule.raw}\n")

        logger.info(f"规则文件已生成: {rules_file}")
        return rules_file

    def generate_report(self, stats: Dict, output_dir: str = "output") -> str:
        """生成合并报告"""
        os.makedirs(output_dir, exist_ok=True)
        report_file = os.path.join(output_dir, "merge_report.md")

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# AdGuard Home 本地规则合并报告\n\n")
            f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## 📊 摘要\n\n")
            f.write(f"- **文件总数**: {stats['total_files']}\n")
            f.write(f"- **成功读取**: {stats['successful_files']}\n")
            f.write(f"- **读取失败**: {len(stats['failed_files'])}\n")
            f.write(f"- **原始规则总数**: {stats['total_rules']:,}\n")
            f.write(f"- **去重后规则**: {stats['unique_rules']:,}\n")
            f.write(f"- **去重数量**: {stats['duplicates']:,}\n")
            f.write(f"- **冲突检测**: {stats['conflicts']}\n")
            f.write(f"- **去重率**: {(stats['duplicates'] / max(stats['total_rules'], 1) * 100):.2f}%\n\n")

            f.write("## 📁 来源统计\n\n")
            f.write("| 来源 | 规则数量 |\n")
            f.write("|------|----------|\n")
            for source, count in sorted(stats['by_source'].items(), key=lambda x: -x[1]):
                f.write(f"| `{source}` | {count:,} |\n")
            f.write("\n")

            if stats['failed_files']:
                f.write("## ❌ 读取失败的文件\n\n")
                for file_path in stats['failed_files']:
                    f.write(f"- `{file_path}`\n")
                f.write("\n")

        logger.info(f"报告已生成: {report_file}")
        return report_file


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='AdGuard Home 本地规则合并工具')
    parser.add_argument('files', nargs='+', help='要合并的规则文件路径')
    parser.add_argument('-o', '--output', default='output', help='输出目录')

    args = parser.parse_args()

    merger = LocalRuleMerger()

    logger.info("开始合并本地规则...")
    stats = merger.merge_files(args.files)

    rules_file = merger.generate_output(args.output)
    report_file = merger.generate_report(stats, args.output)

    print("\n" + "="*50)
    print("合并完成!")
    print("="*50)
    print(f"规则文件: {rules_file}")
    print(f"统计报告: {report_file}")
    print(f"总规则数: {stats['total_rules']:,}")
    print(f"去重后: {stats['unique_rules']:,}")
    print(f"去重率: {(stats['duplicates'] / max(stats['total_rules'], 1) * 100):.2f}%")
    print("="*50)


if __name__ == "__main__":
    main()
