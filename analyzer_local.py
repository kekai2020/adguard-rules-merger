#!/usr/bin/env python3
"""
AdGuard Home 订阅源本地分析工具
使用本地 sources.txt 进行分析
"""

import os
import re
import logging
import requests
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class FilterSource:
    name: str
    url: str
    category: str = ""
    rules_count: int = 0
    rules: Set[str] = field(default_factory=set)


class LocalSourceAnalyzer:
    """本地订阅源分析器"""

    CATEGORY_KEYWORDS = {
        '广告': ['ad', 'ads', 'advert', 'banner', 'popup'],
        '隐私': ['privacy', 'tracking', 'tracker', 'telemetry'],
        '恶意软件': ['malware', 'virus', 'malicious', 'threat'],
        '钓鱼': ['phishing', 'phish', 'scam', 'fraud'],
        '加密货币': ['crypto', 'coin', 'mining', 'bitcoin'],
        '中文': ['chn', 'china', 'chinese', 'anti-ad'],
        '通用': ['dns', 'filter', 'general', 'oisd'],
    }

    def __init__(self, sources_file: str = "sources.txt", timeout: int = 30):
        self.sources_file = sources_file
        self.timeout = timeout
        self.sources: List[FilterSource] = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'AdGuard-Analyzer/1.0'})

    def load_sources(self) -> List[FilterSource]:
        """从 sources.txt 加载订阅源"""
        sources = []
        
        predefined_sources = [
            ("AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "通用"),
            ("AdAway Default Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt", "广告"),
            ("1Hosts (Lite)", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt", "通用"),
            ("OISD Blocklist Small", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt", "通用"),
            ("CHN: AdRules DNS List", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt", "中文"),
            ("CHN: anti-AD", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt", "中文"),
            ("Phishing URL Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt", "钓鱼"),
            ("Malicious URL Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt", "恶意软件"),
            ("HaGeZi's Threat Intelligence", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt", "恶意软件"),
            ("NoCoin Filter List", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt", "加密货币"),
            ("Phishing Army", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt", "钓鱼"),
            ("Scam Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt", "钓鱼"),
            ("ShadowWhisperer's Malware List", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt", "恶意软件"),
            ("HaGeZi's Ultimate Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt", "通用"),
        ]
        
        for name, url, category in predefined_sources:
            sources.append(FilterSource(name=name, url=url, category=category))
        
        self.sources = sources
        logger.info(f"加载了 {len(sources)} 个订阅源")
        return sources

    def fetch_and_parse(self, source: FilterSource) -> bool:
        """获取并解析订阅源"""
        try:
            logger.info(f"获取: {source.name}")
            response = self.session.get(source.url, timeout=self.timeout)
            response.raise_for_status()
            
            content = response.text
            rules = self.parse_rules(content)
            source.rules = rules
            source.rules_count = len(rules)
            
            logger.info(f"{source.name}: {len(rules)} 条规则")
            return True
            
        except Exception as e:
            logger.error(f"获取 {source.name} 失败: {e}")
            return False

    def parse_rules(self, content: str) -> Set[str]:
        """解析规则"""
        rules = set()
        
        for line in content.split('\n'):
            line = line.strip()
            
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            normalized = self.normalize_rule(line)
            if normalized:
                rules.add(normalized)
        
        return rules

    def normalize_rule(self, rule: str) -> str:
        """标准化规则"""
        rule = rule.lower().strip()
        
        rule = re.sub(r'^(https?://)', '', rule)
        rule = rule.split('/')[0]
        rule = rule.split(':')[0]
        
        if rule.startswith('||'):
            rule = rule[2:].rstrip('^')
        elif rule.startswith('|'):
            rule = rule[1:].rstrip('^')
        elif rule.startswith('*.'):
            rule = rule[2:]
        
        parts = rule.split()
        if len(parts) >= 2:
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                rule = parts[1]
        
        if re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', rule):
            return rule
        
        return ""

    def analyze_all(self) -> Dict:
        """分析所有订阅源"""
        self.load_sources()
        
        for source in self.sources:
            self.fetch_and_parse(source)
        
        self.sources = [s for s in self.sources if s.rules_count > 0]
        
        stats = {
            'total_sources': len(self.sources),
            'total_rules': sum(s.rules_count for s in self.sources),
            'avg_rules': sum(s.rules_count for s in self.sources) / max(len(self.sources), 1),
            'by_category': defaultdict(int),
        }
        
        for source in self.sources:
            stats['by_category'][source.category] += source.rules_count
        
        return stats

    def calculate_overlap(self) -> Tuple[list, List[str]]:
        """计算重合率矩阵"""
        n = len(self.sources)
        if n == 0:
            return [], []
        
        matrix = [[0.0 for _ in range(n)] for _ in range(n)]
        names = [s.name[:25] for s in self.sources]
        
        for i in range(n):
            for j in range(n):
                if i == j:
                    matrix[i][j] = 100.0
                    continue
                
                set_i = self.sources[i].rules
                set_j = self.sources[j].rules
                
                if len(set_i) == 0 or len(set_j) == 0:
                    matrix[i][j] = 0.0
                    continue
                
                intersection = len(set_i & set_j)
                overlap = (intersection / min(len(set_i), len(set_j))) * 100
                matrix[i][j] = round(overlap, 1)
        
        return matrix, names

    def generate_report(self, output_path: str = "analysis/analysis_report.md"):
        """生成分析报告"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        matrix, names = self.calculate_overlap()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# AdGuard Home 订阅源深度分析报告\n\n")
            f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## 📊 分析概述\n\n")
            f.write(f"- **分析订阅源数量**: {len(self.sources)}\n")
            f.write(f"- **总规则数量**: {sum(s.rules_count for s in self.sources):,}\n")
            f.write(f"- **平均规则数**: {sum(s.rules_count for s in self.sources) / max(len(self.sources), 1):.0f}\n")
            f.write(f"- **分析维度**: 重合率、覆盖领域、规则数量\n\n")
            
            f.write("## 📋 订阅源详情\n\n")
            f.write("| 名称 | 分类 | 规则数 |\n")
            f.write("|------|------|--------|\n")
            
            for source in sorted(self.sources, key=lambda s: s.rules_count, reverse=True):
                f.write(f"| {source.name} | {source.category} | {source.rules_count:,} |\n")
            
            f.write("\n")
            
            if len(matrix) > 0:
                f.write("## 🔗 重合率分析\n\n")
                f.write("### 高重合率组合 (>30%)\n\n")
                high_overlap = []
                
                for i in range(len(self.sources)):
                    for j in range(i+1, len(self.sources)):
                        if matrix[i][j] > 30:
                            high_overlap.append((self.sources[i].name, self.sources[j].name, matrix[i][j]))
                
                if high_overlap:
                    f.write("| 订阅源 A | 订阅源 B | 重合率 | 建议 |\n")
                    f.write("|----------|----------|--------|------|\n")
                    for name1, name2, overlap in sorted(high_overlap, key=lambda x: -x[2]):
                        suggestion = "⚠️ 建议只选其一" if overlap > 50 else "ℹ️ 可同时启用"
                        f.write(f"| {name1} | {name2} | {overlap:.1f}% | {suggestion} |\n")
                else:
                    f.write("未发现高重合率组合。\n")
                
                f.write("\n")
            
            f.write("## 🎯 推荐配置方案\n\n")
            
            f.write("### 保守模式 (Conservative)\n\n")
            conservative = [s for s in self.sources if s.category in ['通用']][:2]
            conservative += [s for s in self.sources if 'AdGuard DNS' in s.name]
            conservative = list({s.name: s for s in conservative}.values())[:3]
            
            total_rules = sum(s.rules_count for s in conservative)
            for source in conservative:
                f.write(f"- ✅ **{source.name}** ({source.rules_count:,} 条)\n")
            f.write(f"\n**总计**: {total_rules:,} 条规则\n\n")
            
            f.write("### 平衡模式 (Balanced) - 推荐\n\n")
            balanced = []
            balanced += [s for s in self.sources if s.category == '通用'][:2]
            balanced += [s for s in self.sources if s.category == '中文'][:2]
            balanced += [s for s in self.sources if s.category in ['恶意软件', '钓鱼']][:3]
            balanced = list({s.name: s for s in balanced}.values())
            
            total_rules = sum(s.rules_count for s in balanced)
            for source in balanced:
                f.write(f"- ✅ **{source.name}** ({source.category}, {source.rules_count:,} 条)\n")
            f.write(f"\n**总计**: {total_rules:,} 条规则\n\n")
            
            f.write("### 激进模式 (Aggressive)\n\n")
            aggressive = sorted(self.sources, key=lambda s: s.rules_count, reverse=True)[:10]
            total_rules = sum(s.rules_count for s in aggressive)
            
            for source in aggressive:
                f.write(f"- ✅ **{source.name}** ({source.category}, {source.rules_count:,} 条)\n")
            f.write(f"\n**总计**: {total_rules:,} 条规则\n\n")
            
            f.write("## 💡 优化建议\n\n")
            f.write("### 1. 避免重复订阅\n\n")
            f.write("高重合率的规则源同时启用会浪费资源，建议根据重合率选择其一。\n\n")
            f.write("### 2. 按需求选择\n\n")
            f.write("- **日常家用**: 平衡模式即可\n")
            f.write("- **企业环境**: 建议启用更多安全相关规则\n")
            f.write("- **开发者**: 可添加 GitHub520 加速访问\n\n")
            f.write("### 3. 性能考虑\n\n")
            f.write("- 规则数量与 DNS 查询延迟正相关\n")
            f.write("- 建议总规则数控制在 500,000 以内\n")
            f.write("- 定期清理不用的规则源\n\n")
            
            f.write("## 📎 附录\n\n")
            f.write("### 数据来源\n\n")
            f.write("- [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry)\n\n")
        
        logger.info(f"分析报告已生成: {output_path}")


def main():
    analyzer = LocalSourceAnalyzer(timeout=60)
    
    stats = analyzer.analyze_all()
    analyzer.generate_report()
    
    print("\n" + "="*60)
    print("分析完成!")
    print("="*60)
    print(f"成功分析: {stats['total_sources']} 个订阅源")
    print(f"总规则数: {stats['total_rules']:,}")
    print(f"平均规则数: {stats['avg_rules']:.0f}")
    print("="*60)


if __name__ == "__main__":
    main()
