#!/usr/bin/env python3
"""
AdGuard Home 规则合并工具 - 高性能优化版本
功能：合并规则文件，实现高效去重和优化
优化点：
1. 使用集合存储规则，O(1)查找复杂度
2. 批量处理减少函数调用开销
3. 延迟加载和生成器减少内存占用
4. 优化的重复检测算法
"""

import re
import os
import sys
import logging
import time
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional, Iterator
from dataclasses import dataclass, field
from enum import Enum

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


class RuleCategory(Enum):
    """规则分类枚举"""
    ADS = "广告拦截"
    MALWARE = "恶意软件"
    PHISHING = "钓鱼网站"
    PRIVACY = "隐私保护"
    SOCIAL = "社交媒体"
    ADULT = "成人内容"
    GAMBLING = "赌博"
    TRACKERS = "跟踪器"
    CRYPTOMINING = "加密货币挖矿"
    GENERAL = "通用"


@dataclass(frozen=True)
class Rule:
    """规则数据类（不可变，可哈希）"""
    raw: str
    normalized: str
    rule_type: RuleType
    source: str
    is_whitelist: bool = False
    category: RuleCategory = RuleCategory.GENERAL


class RuleNormalizer:
    """规则标准化器 - 优化版本"""

    # 预编译正则表达式
    DOMAIN_PATTERN = re.compile(
        r'^(?:\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )
    HOSTS_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}\s+(.+)$')
    PROTOCOL_PATTERN = re.compile(r'^(https?://)', re.IGNORECASE)

    # 分类关键词映射（预编译为集合加速查找）
    CATEGORY_KEYWORDS = {
        RuleCategory.ADS: {'ad', 'ads', 'advert', 'advertisement', 'banner', 'popup', 'pop-up'},
        RuleCategory.MALWARE: {'malware', 'virus', 'trojan', 'malicious', 'botnet'},
        RuleCategory.PHISHING: {'phishing', 'phish', 'scam', 'fraud'},
        RuleCategory.PRIVACY: {'privacy', 'tracking', 'tracker', 'analytics', 'telemetry', 'metrics'},
        RuleCategory.SOCIAL: {'social', 'facebook', 'twitter', 'instagram', 'tiktok', 'snapchat'},
        RuleCategory.ADULT: {'adult', 'porn', 'xxx', 'sex', 'nsfw'},
        RuleCategory.GAMBLING: {'gambling', 'casino', 'bet', 'poker', 'lottery'},
        RuleCategory.CRYPTOMINING: {'crypto', 'mining', 'coin', 'monero', 'bitcoin', 'miner'},
    }

    @classmethod
    def normalize(cls, rule_text: str) -> Tuple[str, RuleType]:
        """标准化规则文本 - 优化版本"""
        original = rule_text.strip()

        if not original:
            return "", RuleType.EMPTY

        # 快速检查注释行
        first_char = original[0]
        if first_char in '#!/':
            if first_char == '/' and original.endswith('/'):
                return original, RuleType.REGEX
            return original, RuleType.COMMENT

        # 移除行内注释
        if '#' in original:
            rule = original.split('#')[0].strip()
        elif '!' in original:
            rule = original.split('!')[0].strip()
        else:
            rule = original
            
        if not rule:
            return original, RuleType.COMMENT

        # 检测 Hosts 格式
        hosts_match = cls.HOSTS_PATTERN.match(rule)
        if hosts_match:
            domain = hosts_match.group(2).strip()
            normalized = cls._normalize_domain(domain)
            return (normalized, RuleType.HOSTS) if normalized else (original, RuleType.INVALID)

        # 检测 AdGuard 修饰符规则
        if '$' in rule:
            parts = rule.split('$', 1)
            domain_part = parts[0].strip()
            modifiers = parts[1].strip()

            if domain_part.startswith('@@'):
                domain_part = domain_part[2:]
            
            if domain_part.startswith('||'):
                domain_part = domain_part[2:].rstrip('^')
            elif domain_part.startswith('|'):
                domain_part = domain_part[1:].rstrip('^')

            normalized_domain = cls._normalize_domain(domain_part)
            if normalized_domain:
                return f"{normalized_domain}${modifiers}", RuleType.WILDCARD
            return rule, RuleType.WILDCARD

        # 处理白名单规则
        if rule.startswith('@@'):
            domain = rule[2:].rstrip('^')
            normalized = cls._normalize_domain(domain)
            return (normalized, RuleType.DOMAIN) if normalized else (domain, RuleType.DOMAIN)

        # 处理通配符域名
        if rule.startswith('*.') or rule.startswith('||') or rule.startswith('|'):
            if rule.startswith('||'):
                domain = rule[2:].rstrip('^').rstrip('|')
            elif rule.startswith('|'):
                domain = rule[1:].rstrip('^').rstrip('|')
            else:
                domain = rule[2:]
            normalized = cls._normalize_domain(domain)
            return (normalized, RuleType.WILDCARD) if normalized else (original, RuleType.INVALID)

        # 普通域名
        normalized = cls._normalize_domain(rule)
        return (normalized, RuleType.DOMAIN) if normalized else (original, RuleType.INVALID)

    @classmethod
    def _normalize_domain(cls, domain: str) -> str:
        """标准化域名"""
        if not domain:
            return ""

        # 移除协议前缀
        domain = cls.PROTOCOL_PATTERN.sub('', domain)
        domain = domain.rstrip('/').rstrip(':').strip().lower()

        # 验证域名格式
        if cls.DOMAIN_PATTERN.match(domain):
            return domain
        return ""

    @classmethod
    def detect_category(cls, rule_text: str, source_url: str = "") -> RuleCategory:
        """检测规则分类 - 优化版本"""
        text_lower = rule_text.lower()
        source_lower = source_url.lower()

        # 根据来源URL判断
        source_keywords = {
            'phishing': RuleCategory.PHISHING,
            'malware': RuleCategory.MALWARE,
            'scam': RuleCategory.PHISHING,
            'coin': RuleCategory.CRYPTOMINING,
            'crypto': RuleCategory.CRYPTOMINING,
            'ad': RuleCategory.ADS,
            'track': RuleCategory.PRIVACY,
            'privacy': RuleCategory.PRIVACY,
            'social': RuleCategory.SOCIAL,
            'adult': RuleCategory.ADULT,
            'gambling': RuleCategory.GAMBLING,
        }

        for keyword, category in source_keywords.items():
            if keyword in source_lower:
                return category

        # 根据规则内容判断（使用集合查找）
        text_set = set(text_lower.split('.'))
        for category, keywords in cls.CATEGORY_KEYWORDS.items():
            if text_set & keywords:  # 集合交集
                return category

        return RuleCategory.GENERAL

    @classmethod
    def is_whitelist(cls, rule_text: str) -> bool:
        """检测是否为白名单规则"""
        return '@@' in rule_text


class OptimizedRuleMerger:
    """优化的规则合并器"""

    def __init__(self):
        # 使用集合存储规则，O(1)查找
        self.rules: Set[Rule] = set()
        self.domain_index: Set[str] = set()  # 域名索引，加速重复检测
        self.duplicate_count = 0
        self.conflict_count = 0

    def read_file_lines(self, file_path: str) -> Iterator[str]:
        """流式读取文件行"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield line
        except Exception as e:
            logger.error(f"读取文件失败: {file_path} - {e}")

    def parse_rules_stream(self, file_path: str) -> Iterator[Rule]:
        """流式解析规则"""
        source_name = os.path.basename(file_path)
        
        for line_num, line in enumerate(self.read_file_lines(file_path), 1):
            normalized, rule_type = RuleNormalizer.normalize(line)

            if rule_type in (RuleType.EMPTY, RuleType.COMMENT, RuleType.INVALID):
                continue

            category = RuleNormalizer.detect_category(line, source_name)
            is_whitelist = RuleNormalizer.is_whitelist(line)

            yield Rule(
                raw=line.strip(),
                normalized=normalized,
                rule_type=rule_type,
                source=source_name,
                is_whitelist=is_whitelist,
                category=category
            )

    def is_duplicate_fast(self, rule: Rule) -> bool:
        """快速重复检测"""
        normalized = rule.normalized
        
        # 检查完全匹配
        if normalized in self.domain_index:
            return True
        
        # 检查通配符等价性
        if normalized.startswith('*.'):
            base = normalized[2:]
            if base in self.domain_index:
                return True
        else:
            wildcard_form = '*.' + normalized
            if wildcard_form in self.domain_index:
                return True
        
        return False

    def add_rule(self, rule: Rule) -> bool:
        """添加规则 - 优化版本"""
        if self.is_duplicate_fast(rule):
            self.duplicate_count += 1
            return False

        self.rules.add(rule)
        self.domain_index.add(rule.normalized)
        return True

    def merge_files(self, file_paths: List[str]) -> Dict:
        """合并多个文件 - 优化版本"""
        stats = {
            'total_files': len(file_paths),
            'successful_files': 0,
            'failed_files': [],
            'total_rules': 0,
            'unique_rules': 0,
            'duplicates': 0,
            'by_source': defaultdict(int),
            'by_category': defaultdict(int),
        }

        for file_path in file_paths:
            if not os.path.exists(file_path):
                stats['failed_files'].append(file_path)
                continue

            file_rules = 0
            try:
                for rule in self.parse_rules_stream(file_path):
                    stats['total_rules'] += 1
                    file_rules += 1
                    stats['by_category'][rule.category.value] += 1
                    
                    if self.add_rule(rule):
                        stats['unique_rules'] += 1

                stats['successful_files'] += 1
                stats['by_source'][file_path] = file_rules
                logger.info(f"已处理: {os.path.basename(file_path)} - {file_rules:,} 条规则")
                
            except Exception as e:
                logger.error(f"处理文件失败: {file_path} - {e}")
                stats['failed_files'].append(file_path)

        stats['duplicates'] = self.duplicate_count
        return stats

    def generate_output(self, output_dir: str = "output") -> str:
        """生成合并后的规则文件"""
        os.makedirs(output_dir, exist_ok=True)
        rules_file = os.path.join(output_dir, "merged_rules.txt")

        # 分类和排序
        whitelist_rules = []
        blacklist_rules = []
        
        for rule in self.rules:
            if rule.is_whitelist:
                whitelist_rules.append(rule)
            else:
                blacklist_rules.append(rule)

        # 按分类分组
        categories = defaultdict(list)
        for rule in blacklist_rules:
            categories[rule.category].append(rule)

        with open(rules_file, 'w', encoding='utf-8') as f:
            # 文件头
            f.write("! AdGuard Home 合并规则\n")
            f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 规则总数: {len(self.rules)}\n")
            f.write("! 工具版本: 2.0.0 (Optimized)\n")
            f.write("! ==========================================\n\n")

            # 白名单
            if whitelist_rules:
                f.write("! ===== 白名单规则 =====\n")
                for rule in sorted(whitelist_rules, key=lambda r: r.normalized):
                    f.write(f"{rule.raw}\n")
                f.write("\n")

            # 按分类输出黑名单
            for category in sorted(categories.keys(), key=lambda c: c.value):
                rules = categories[category]
                f.write(f"\n! ===== {category.value} ({len(rules)} 条) =====\n")
                for rule in sorted(rules, key=lambda r: r.normalized):
                    f.write(f"{rule.raw}\n")

        logger.info(f"规则文件已生成: {rules_file}")
        return rules_file

    def generate_report(self, stats: Dict, output_dir: str = "output") -> str:
        """生成合并报告"""
        os.makedirs(output_dir, exist_ok=True)
        report_file = os.path.join(output_dir, "merge_report.md")

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("# AdGuard Home 规则合并报告\n\n")
            f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## 📊 摘要\n\n")
            f.write(f"- **文件总数**: {stats['total_files']}\n")
            f.write(f"- **成功读取**: {stats['successful_files']}\n")
            f.write(f"- **读取失败**: {len(stats['failed_files'])}\n")
            f.write(f"- **原始规则总数**: {stats['total_rules']:,}\n")
            f.write(f"- **去重后规则**: {stats['unique_rules']:,}\n")
            f.write(f"- **去重数量**: {stats['duplicates']:,}\n")
            f.write(f"- **去重率**: {(stats['duplicates'] / max(stats['total_rules'], 1) * 100):.2f}%\n\n")

            f.write("## 📁 分类统计\n\n")
            f.write("| 分类 | 数量 |\n")
            f.write("|------|------|\n")
            for category, count in sorted(stats['by_category'].items(), key=lambda x: -x[1]):
                f.write(f"| {category} | {count:,} |\n")
            f.write("\n")

            f.write("## 📥 来源统计\n\n")
            f.write("| 来源 | 规则数量 |\n")
            f.write("|------|----------|\n")
            for source, count in sorted(stats['by_source'].items(), key=lambda x: -x[1]):
                f.write(f"| `{os.path.basename(source)}` | {count:,} |\n")
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

    parser = argparse.ArgumentParser(description='AdGuard Home 规则合并工具 (优化版)')
    parser.add_argument('files', nargs='+', help='要合并的规则文件路径')
    parser.add_argument('-o', '--output', default='output', help='输出目录')

    args = parser.parse_args()

    merger = OptimizedRuleMerger()

    logger.info("开始合并规则...")
    start_time = time.time()
    
    stats = merger.merge_files(args.files)
    
    elapsed_time = time.time() - start_time

    rules_file = merger.generate_output(args.output)
    report_file = merger.generate_report(stats, args.output)

    print("\n" + "="*60)
    print("合并完成!")
    print("="*60)
    print(f"处理时间: {elapsed_time:.2f} 秒")
    print(f"规则文件: {rules_file}")
    print(f"统计报告: {report_file}")
    print(f"总规则数: {stats['total_rules']:,}")
    print(f"去重后: {stats['unique_rules']:,}")
    print(f"去重率: {(stats['duplicates'] / max(stats['total_rules'], 1) * 100):.2f}%")
    print("="*60)


if __name__ == "__main__":
    main()
