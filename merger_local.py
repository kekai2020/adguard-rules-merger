#!/usr/bin/env python3
"""
AdGuard Home 规则合并去重工具
功能：自动合并多个 AdGuard Home 拦截规则订阅源，实现去重和优化
作者：AI Assistant
版本：1.0.0
"""

import re
import os
import sys
import json
import hashlib
import logging
import requests
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict
from typing import Set, Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import fnmatch

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('merger.log', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)


class RuleType(Enum):
    """规则类型枚举"""
    DOMAIN = "domain"           # 普通域名
    WILDCARD = "wildcard"       # 通配符规则
    REGEX = "regex"             # 正则表达式
    HOSTS = "hosts"             # Hosts 格式
    COMMENT = "comment"         # 注释
    EMPTY = "empty"             # 空行
    INVALID = "invalid"         # 无效规则


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


@dataclass
class Rule:
    """规则数据类"""
    raw: str                    # 原始规则文本
    normalized: str             # 标准化后的规则
    rule_type: RuleType         # 规则类型
    category: RuleCategory      # 规则分类
    source: str                 # 来源URL
    line_num: int               # 在源文件中的行号
    is_whitelist: bool          # 是否为白名单
    priority: int = 0           # 优先级
    metadata: Dict = field(default_factory=dict)  # 元数据

    def __hash__(self):
        return hash(self.normalized)

    def __eq__(self, other):
        if not isinstance(other, Rule):
            return False
        return self.normalized == other.normalized


class RuleNormalizer:
    """规则标准化器"""

    # 正则表达式模式
    DOMAIN_PATTERN = re.compile(
        r'^(?:\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )

    # 分类关键词映射
    CATEGORY_KEYWORDS = {
        RuleCategory.ADS: ['ad', 'ads', 'advert', 'advertisement', 'banner', 'popup', 'pop-up'],
        RuleCategory.MALWARE: ['malware', 'virus', 'trojan', 'malicious', 'botnet'],
        RuleCategory.PHISHING: ['phishing', 'phish', 'scam', 'fraud'],
        RuleCategory.PRIVACY: ['privacy', 'tracking', 'tracker', 'analytics', 'telemetry', 'metrics'],
        RuleCategory.SOCIAL: ['social', 'facebook', 'twitter', 'instagram', 'tiktok', 'snapchat'],
        RuleCategory.ADULT: ['adult', 'porn', 'xxx', 'sex', 'nsfw'],
        RuleCategory.GAMBLING: ['gambling', 'casino', 'bet', 'poker', 'lottery'],
        RuleCategory.CRYPTOMINING: ['crypto', 'mining', 'coin', 'monero', 'bitcoin', 'miner'],
    }

    @classmethod
    def normalize(cls, rule_text: str) -> Tuple[str, RuleType]:
        """
        标准化规则文本
        返回: (标准化后的规则, 规则类型)
        """
        original = rule_text.strip()

        # 空行
        if not original:
            return "", RuleType.EMPTY

        # 注释行
        if original.startswith('#') or original.startswith('!') or original.startswith('//'):
            return original, RuleType.COMMENT

        # 移除行内注释
        rule = original.split('#')[0].split('!')[0].strip()
        if not rule:
            return original, RuleType.COMMENT

        # 检测 Hosts 格式 (IP 域名)
        hosts_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+(.+)$', rule)
        if hosts_match:
            domain = hosts_match.group(1).strip()
            return cls._normalize_domain(domain), RuleType.HOSTS

        # 检测正则表达式
        if rule.startswith('/') and rule.endswith('/'):
            return rule, RuleType.REGEX

        # 检测 AdGuard 修饰符规则
        if '$' in rule:
            # 分离域名和修饰符
            parts = rule.split('$', 1)
            domain_part = parts[0].strip()
            modifiers = parts[1].strip()

            # 检查是否为白名单
            if '@@' in modifiers or domain_part.startswith('@@'):
                domain_part = domain_part.lstrip('@')

            normalized_domain = cls._normalize_domain(domain_part)
            return f"{normalized_domain}${modifiers}", RuleType.WILDCARD

        # 处理通配符域名
        if rule.startswith('*.') or rule.startswith('||') or rule.startswith('|'):
            # AdGuard 格式
            if rule.startswith('||'):
                domain = rule[2:].rstrip('^').rstrip('|')
                return cls._normalize_domain(domain), RuleType.WILDCARD
            elif rule.startswith('|'):
                domain = rule[1:].rstrip('^').rstrip('|')
                return cls._normalize_domain(domain), RuleType.WILDCARD
            else:
                # *.example.com 格式
                domain = rule[2:] if rule.startswith('*.') else rule
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

        # 移除协议前缀
        domain = re.sub(r'^(https?://)', '', domain, flags=re.IGNORECASE)
        domain = domain.rstrip('/').rstrip(':').strip().lower()

        # 验证域名格式
        if cls.DOMAIN_PATTERN.match(domain):
            return domain

        return domain

    @classmethod
    def detect_category(cls, rule_text: str, source_url: str = "") -> RuleCategory:
        """检测规则分类"""
        text_lower = rule_text.lower()
        source_lower = source_url.lower()

        # 根据来源URL判断
        source_category_map = {
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
            'stalkerware': RuleCategory.MALWARE,
        }

        for keyword, category in source_category_map.items():
            if keyword in source_lower:
                return category

        # 根据规则内容判断
        for category, keywords in cls.CATEGORY_KEYWORDS.items():
            for keyword in keywords:
                if keyword in text_lower:
                    return category

        return RuleCategory.GENERAL

    @classmethod
    def is_whitelist(cls, rule_text: str) -> bool:
        """检测是否为白名单规则"""
        return rule_text.strip().startswith('@@') or '@@' in rule_text


class RuleMerger:
    """规则合并器"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.rules: Dict[str, Rule] = {}  # normalized -> Rule
        self.duplicates: List[Tuple[Rule, Rule]] = []
        self.conflicts: List[Tuple[Rule, Rule]] = []
        self.failed_sources: List[Tuple[str, str]] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AdGuard-Rule-Merger/1.0 (Automated Tool)'
        })

    def fetch_source(self, url: str) -> Tuple[str, bool]:
        """
        获取规则源内容
        返回: (内容, 是否成功)
        """
        # 支持本地文件
        if url.startswith('file://'):
            local_path = url[7:]
            try:
                logger.info(f"正在读取本地文件: {local_path}")
                with open(local_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                logger.info(f"成功读取: {local_path} ({len(content)} 字符)")
                return content, True
            except Exception as e:
                logger.error(f"读取本地文件失败: {local_path} - {e}")
                return "", False

        try:
            logger.info(f"正在获取: {url}")
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            response.raise_for_status()

            # 检测编码
            if response.encoding is None:
                response.encoding = 'utf-8'

            content = response.text
            logger.info(f"成功获取: {url} ({len(content)} 字符)")
            return content, True

        except requests.exceptions.Timeout:
            error_msg = f"请求超时: {url}"
            logger.error(error_msg)
            return "", False
        except requests.exceptions.ConnectionError:
            error_msg = f"连接错误: {url}"
            logger.error(error_msg)
            return "", False
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP错误 {e.response.status_code}: {url}"
            logger.error(error_msg)
            return "", False
        except Exception as e:
            error_msg = f"未知错误: {url} - {str(e)}"
            logger.error(error_msg)
            return "", False

    def parse_rules(self, content: str, source_url: str) -> List[Rule]:
        """解析规则内容"""
        rules = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            normalized, rule_type = RuleNormalizer.normalize(line)

            if rule_type in (RuleType.EMPTY, RuleType.COMMENT):
                continue

            if rule_type == RuleType.INVALID:
                logger.debug(f"无效规则 [{source_url}:{line_num}]: {line}")
                continue

            category = RuleNormalizer.detect_category(line, source_url)
            is_whitelist = RuleNormalizer.is_whitelist(line)

            rule = Rule(
                raw=line.strip(),
                normalized=normalized,
                rule_type=rule_type,
                category=category,
                source=source_url,
                line_num=line_num,
                is_whitelist=is_whitelist
            )
            rules.append(rule)

        return rules

    def is_duplicate(self, new_rule: Rule, existing_rule: Rule) -> bool:
        """
        检测两条规则是否重复（考虑通配符等价性）
        """
        # 完全相同的规则
        if new_rule.normalized == existing_rule.normalized:
            return True

        # 检查通配符等价性
        new_norm = new_rule.normalized
        exist_norm = existing_rule.normalized

        # *.example.com 与 example.com 等价
        if new_norm.startswith('*.'):
            new_base = new_norm[2:]
            if new_base == exist_norm or exist_norm.endswith('.' + new_base):
                return True

        if exist_norm.startswith('*.'):
            exist_base = exist_norm[2:]
            if exist_base == new_norm or new_norm.endswith('.' + exist_base):
                return True

        # 检查子域关系
        if new_norm.endswith('.' + exist_norm) or exist_norm.endswith('.' + new_norm):
            return True

        return False

    def is_conflict(self, rule1: Rule, rule2: Rule) -> bool:
        """检测两条规则是否冲突（白名单与黑名单）"""
        if rule1.is_whitelist == rule2.is_whitelist:
            return False

        # 检查是否针对同一域名
        if rule1.normalized == rule2.normalized:
            return True

        # 检查通配符覆盖
        if rule1.normalized in rule2.normalized or rule2.normalized in rule1.normalized:
            return True

        return False

    def add_rule(self, rule: Rule) -> bool:
        """
        添加规则到合并集合
        返回: 是否为新增规则
        """
        normalized = rule.normalized

        # 检查是否已存在
        if normalized in self.rules:
            existing = self.rules[normalized]
            self.duplicates.append((rule, existing))
            logger.debug(f"发现重复规则: {rule.raw} (来自 {rule.source})")
            return False

        # 检查与其他规则的重复和冲突
        for exist_norm, exist_rule in self.rules.items():
            if self.is_duplicate(rule, exist_rule):
                self.duplicates.append((rule, exist_rule))
                logger.debug(f"发现通配符等价: {rule.raw} ~= {exist_rule.raw}")
                return False

            if self.is_conflict(rule, exist_rule):
                self.conflicts.append((rule, exist_rule))
                logger.warning(f"发现冲突规则: {rule.raw} vs {exist_rule.raw}")

        self.rules[normalized] = rule
        return True

    def merge_sources(self, source_urls: List[str]) -> Dict:
        """
        合并多个规则源
        返回: 统计信息
        """
        stats = {
            'total_sources': len(source_urls),
            'successful_sources': 0,
            'failed_sources': [],
            'total_rules': 0,
            'unique_rules': 0,
            'duplicates': 0,
            'conflicts': 0,
            'by_category': defaultdict(int),
            'by_type': defaultdict(int),
            'by_source': defaultdict(int),
        }

        for url in source_urls:
            url = url.strip()
            if not url or url.startswith('#'):
                continue

            content, success = self.fetch_source(url)
            if not success:
                self.failed_sources.append((url, "Failed to fetch"))
                stats['failed_sources'].append(url)
                continue

            stats['successful_sources'] += 1
            rules = self.parse_rules(content, url)
            stats['by_source'][url] = len(rules)

            for rule in rules:
                stats['total_rules'] += 1
                stats['by_category'][rule.category.value] += 1
                stats['by_type'][rule.rule_type.value] += 1

                if self.add_rule(rule):
                    stats['unique_rules'] += 1

        stats['duplicates'] = len(self.duplicates)
        stats['conflicts'] = len(self.conflicts)

        return stats

    def generate_output(self, output_dir: str = "output") -> Tuple[str, str]:
        """
        生成合并后的规则文件
        返回: (规则文件路径, 报告文件路径)
        """
        os.makedirs(output_dir, exist_ok=True)

        # 生成规则文件
        rules_file = os.path.join(output_dir, "merged_rules.txt")

        with open(rules_file, 'w', encoding='utf-8') as f:
            # 写入文件头
            f.write("! AdGuard Home 合并规则\n")
            f.write(f"! 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"! 规则总数: {len(self.rules)}\n")
            f.write("! 工具版本: 1.0.0\n")
            f.write("! ==========================================\n\n")

            # 按分类分组写入
            categories = defaultdict(list)
            for rule in self.rules.values():
                categories[rule.category].append(rule)

            for category in sorted(categories.keys(), key=lambda c: c.value):
                rules_in_category = categories[category]
                f.write(f"\n! ===== {category.value} ({len(rules_in_category)} 条) =====\n")

                # 按类型排序：白名单优先，然后是域名、通配符、正则
                sorted_rules = sorted(
                    rules_in_category,
                    key=lambda r: (
                        not r.is_whitelist,
                        r.rule_type != RuleType.DOMAIN,
                        r.rule_type != RuleType.WILDCARD,
                        r.rule_type != RuleType.REGEX
                    )
                )

                for rule in sorted_rules:
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

            # 摘要
            f.write("## 📊 摘要\n\n")
            f.write(f"- **订阅源总数**: {stats['total_sources']}\n")
            f.write(f"- **成功获取**: {stats['successful_sources']}\n")
            f.write(f"- **获取失败**: {len(stats['failed_sources'])}\n")
            f.write(f"- **原始规则总数**: {stats['total_rules']:,}\n")
            f.write(f"- **去重后规则**: {stats['unique_rules']:,}\n")
            f.write(f"- **去重数量**: {stats['duplicates']:,}\n")
            f.write(f"- **冲突检测**: {stats['conflicts']}\n")
            f.write(f"- **去重率**: {(stats['duplicates'] / max(stats['total_rules'], 1) * 100):.2f}%\n\n")

            # 按分类统计
            f.write("## 📁 规则分类统计\n\n")
            f.write("| 分类 | 数量 | 占比 |\n")
            f.write("|------|------|------|\n")
            for category, count in sorted(stats['by_category'].items(), key=lambda x: -x[1]):
                percentage = count / max(stats['total_rules'], 1) * 100
                f.write(f"| {category} | {count:,} | {percentage:.2f}% |\n")
            f.write("\n")

            # 按类型统计
            f.write("## 🔧 规则类型统计\n\n")
            f.write("| 类型 | 数量 | 占比 |\n")
            f.write("|------|------|------|\n")
            for rule_type, count in sorted(stats['by_type'].items(), key=lambda x: -x[1]):
                percentage = count / max(stats['total_rules'], 1) * 100
                f.write(f"| {rule_type} | {count:,} | {percentage:.2f}% |\n")
            f.write("\n")

            # 来源统计
            f.write("## 📥 来源统计\n\n")
            f.write("| 来源 | 规则数量 |\n")
            f.write("|------|----------|\n")
            for source, count in sorted(stats['by_source'].items(), key=lambda x: -x[1]):
                f.write(f"| `{source}` | {count:,} |\n")
            f.write("\n")

            # 失败来源
            if stats['failed_sources']:
                f.write("## ❌ 获取失败的来源\n\n")
                for source in stats['failed_sources']:
                    f.write(f"- `{source}`\n")
                f.write("\n")

            # 冲突详情
            if self.conflicts:
                f.write("## ⚠️ 规则冲突详情\n\n")
                f.write("| 规则1 | 来源1 | 规则2 | 来源2 |\n")
                f.write("|-------|-------|-------|-------|\n")
                for rule1, rule2 in self.conflicts[:50]:  # 只显示前50个
                    f.write(f"| `{rule1.raw[:50]}` | {rule1.source[:30]} | `{rule2.raw[:50]}` | {rule2.source[:30]} |\n")
                if len(self.conflicts) > 50:
                    f.write(f"\n*还有 {len(self.conflicts) - 50} 个冲突未显示*\n")
                f.write("\n")

            # 使用说明
            f.write("## 🚀 使用说明\n\n")
            f.write("### 在 AdGuard Home 中添加规则\n\n")
            f.write("1. 打开 AdGuard Home 管理界面\n")
            f.write("2. 进入 `过滤器` -> `DNS 拦截列表`\n")
            f.write("3. 点击 `添加阻止列表`\n")
            f.write("4. 输入以下 URL:\n")
            f.write("   ```\n")
            f.write("   https://raw.githubusercontent.com/YOUR_USERNAME/adguard-rules-merger/main/output/merged_rules.txt\n")
            f.write("   ```\n\n")

            f.write("### 推荐配置\n\n")
            f.write("- **保守模式**: 仅启用 `GENERAL` 和 `ADS` 分类\n")
            f.write("- **平衡模式**: 启用除 `ADULT` 和 `GAMBLING` 外的所有分类\n")
            f.write("- **激进模式**: 启用所有分类\n\n")

        logger.info(f"报告已生成: {report_file}")
        return report_file


def load_sources(sources_file: str = "sources.txt") -> List[str]:
    """从文件加载订阅源列表"""
    if not os.path.exists(sources_file):
        logger.error(f"订阅源文件不存在: {sources_file}")
        return []

    with open(sources_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

    logger.info(f"从 {sources_file} 加载了 {len(urls)} 个订阅源")
    return urls


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='AdGuard Home 规则合并工具')
    parser.add_argument('-s', '--sources', default='sources.txt', help='订阅源文件路径')
    parser.add_argument('-o', '--output', default='output', help='输出目录')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='请求超时时间(秒)')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细日志')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 加载订阅源
    sources = load_sources(args.sources)
    if not sources:
        logger.error("没有可用的订阅源，退出")
        sys.exit(1)

    # 创建合并器
    merger = RuleMerger(timeout=args.timeout)

    # 执行合并
    logger.info("开始合并规则...")
    stats = merger.merge_sources(sources)

    # 生成输出
    rules_file = merger.generate_output(args.output)
    report_file = merger.generate_report(stats, args.output)

    # 输出摘要
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
