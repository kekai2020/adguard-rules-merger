#!/usr/bin/env python3
"""
AdGuard Home 订阅源本地分析工具
使用本地 sources.txt 进行分析
"""

import os
import re
import json
import logging
import requests
import numpy as np
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass, field
import matplotlib.pyplot as plt
import seaborn as sns

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

    # 分类关键词映射
    CATEGORY_KEYWORDS = {
        '广告': ['ad', 'ads', 'advert', 'banner', 'popup', '乘风'],
        '隐私': ['privacy', 'tracking', 'tracker', 'telemetry', 'metrics'],
        '恶意软件': ['malware', 'virus', 'malicious', 'threat', 'shadowwhisperer'],
        '钓鱼': ['phishing', 'phish', 'scam', 'fraud', 'phish', 'army'],
        '加密货币': ['crypto', 'coin', 'mining', 'bitcoin', 'nocoin'],
        '中文': ['chn', 'china', 'chinese', 'anti-ad', 'adrules'],
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
        
        # 用户提供的订阅源列表
        predefined_sources = [
            ("AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "通用"),
            ("AdAway Default Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt", "广告"),
            ("1Hosts (Lite)", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_24.txt", "通用"),
            ("OISD Blocklist Small", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_5.txt", "通用"),
            ("CHN: AdRules DNS List", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt", "中文"),
            ("CHN: anti-AD", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_21.txt", "中文"),
            ("GitHub520", "https://raw.hellogithub.com/hosts", "通用"),
            ("乘风广告过滤规则", "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/refs/heads/master/rule.txt", "中文"),
            ("乘风视频广告过滤规则", "https://raw.githubusercontent.com/xinggsf/Adblock-Plus-Rule/refs/heads/master/mv.txt", "中文"),
            ("Phishing URL Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt", "钓鱼"),
            ("Malicious URL Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_11.txt", "恶意软件"),
            ("HaGeZi's Threat Intelligence", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_44.txt", "恶意软件"),
            ("NoCoin Filter List", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt", "加密货币"),
            ("Phishing Army", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_18.txt", "钓鱼"),
            ("Scam Blocklist", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt", "钓鱼"),
            ("ShadowWhisperer's Malware List", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_42.txt", "恶意软件"),
            ("Stalkerware Indicators", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_31.txt", "恶意软件"),
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
            
            # 跳过空行和注释
            if not line or line.startswith('#') or line.startswith('!'):
                continue
            
            # 标准化
            normalized = self.normalize_rule(line)
            if normalized:
                rules.add(normalized)
        
        return rules

    def normalize_rule(self, rule: str) -> str:
        """标准化规则"""
        rule = rule.lower().strip()
        
        # 移除协议
        rule = re.sub(r'^(https?://)', '', rule)
        rule = rule.split('/')[0]
        rule = rule.split(':')[0]
        
        # 处理 AdGuard 格式
        if rule.startswith('||'):
            rule = rule[2:].rstrip('^')
        elif rule.startswith('|'):
            rule = rule[1:].rstrip('^')
        elif rule.startswith('*.'):
            rule = rule[2:]
        
        # 处理 hosts 格式
        parts = rule.split()
        if len(parts) >= 2:
            # 可能是 IP + 域名
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                rule = parts[1]
        
        # 验证域名
        if re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', rule):
            return rule
        
        return ""

    def analyze_all(self) -> Dict:
        """分析所有订阅源"""
        self.load_sources()
        
        for source in self.sources:
            self.fetch_and_parse(source)
        
        # 过滤掉失败的
        self.sources = [s for s in self.sources if s.rules_count > 0]
        
        # 计算统计
        stats = {
            'total_sources': len(self.sources),
            'total_rules': sum(s.rules_count for s in self.sources),
            'avg_rules': np.mean([s.rules_count for s in self.sources]) if self.sources else 0,
            'by_category': defaultdict(int),
        }
        
        for source in self.sources:
            stats['by_category'][source.category] += source.rules_count
        
        return stats

    def calculate_overlap(self) -> Tuple[np.ndarray, List[str]]:
        """计算重合率矩阵"""
        n = len(self.sources)
        if n == 0:
            return np.array([]), []
        
        matrix = np.zeros((n, n))
        names = [s.name[:25] for s in self.sources]
        
        for i in range(n):
            for j in range(n):
                if i == j:
                    matrix[i, j] = 100.0
                    continue
                
                set_i = self.sources[i].rules
                set_j = self.sources[j].rules
                
                if len(set_i) == 0 or len(set_j) == 0:
                    matrix[i, j] = 0.0
                    continue
                
                intersection = len(set_i & set_j)
                overlap = (intersection / min(len(set_i), len(set_j))) * 100
                matrix[i, j] = round(overlap, 1)
        
        return matrix, names

    def create_visualizations(self, output_dir: str = "analysis"):
        """创建可视化"""
        os.makedirs(output_dir, exist_ok=True)
        
        # 设置样式
        sns.set_style("whitegrid")
        
        # 1. 重合率热力图
        matrix, names = self.calculate_overlap()
        if len(matrix) > 0:
            fig, ax = plt.subplots(figsize=(16, 14))
            
            sns.heatmap(
                matrix,
                annot=True,
                fmt='.1f',
                cmap='RdYlGn_r',
                xticklabels=names,
                yticklabels=names,
                ax=ax,
                vmin=0,
                vmax=100,
                cbar_kws={'label': '重合率 (%)'},
                annot_kws={'size': 8}
            )
            
            plt.title('AdGuard Home 订阅源重合率热力图', fontsize=16, fontweight='bold', pad=20)
            plt.xticks(rotation=45, ha='right', fontsize=9)
            plt.yticks(rotation=0, fontsize=9)
            plt.tight_layout()
            plt.savefig(f"{output_dir}/overlap_heatmap.png", dpi=150, bbox_inches='tight')
            plt.close()
            logger.info(f"热力图已保存: {output_dir}/overlap_heatmap.png")
        
        # 2. 规则数量对比
        fig, ax = plt.subplots(figsize=(14, 10))
        
        sorted_sources = sorted(self.sources, key=lambda s: s.rules_count, reverse=True)
        names = [s.name[:30] for s in sorted_sources]
        counts = [s.rules_count for s in sorted_sources]
        colors = plt.cm.viridis(np.linspace(0.2, 0.8, len(names)))
        
        bars = ax.barh(range(len(names)), counts, color=colors)
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=10)
        ax.set_xlabel('规则数量', fontsize=12)
        ax.set_title('各订阅源规则数量对比', fontsize=14, fontweight='bold')
        ax.set_xlim(0, max(counts) * 1.1)
        
        # 添加数值标签
        for i, (bar, count) in enumerate(zip(bars, counts)):
            ax.text(bar.get_width() + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                   f'{count:,}', va='center', fontsize=9)
        
        ax.grid(axis='x', alpha=0.3)
        plt.tight_layout()
        plt.savefig(f"{output_dir}/rules_count.png", dpi=150, bbox_inches='tight')
        plt.close()
        logger.info(f"规则数量图已保存: {output_dir}/rules_count.png")
        
        # 3. 分类分布
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        category_counts = defaultdict(int)
        for source in self.sources:
            category_counts[source.category] += source.rules_count
        
        categories = list(category_counts.keys())
        counts = list(category_counts.values())
        colors = plt.cm.Set3(np.linspace(0, 1, len(categories)))
        
        # 条形图
        bars = ax1.barh(categories, counts, color=colors)
        ax1.set_xlabel('规则数量', fontsize=12)
        ax1.set_title('各分类规则数量', fontsize=14, fontweight='bold')
        
        for bar, count in zip(bars, counts):
            ax1.text(bar.get_width() + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                    f'{count:,}', va='center', fontsize=10)
        
        # 饼图
        ax2.pie(counts, labels=categories, autopct='%1.1f%%', colors=colors, startangle=90)
        ax2.set_title('分类分布占比', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/category_distribution.png", dpi=150, bbox_inches='tight')
        plt.close()
        logger.info(f"分类分布图已保存: {output_dir}/category_distribution.png")
        
        # 4. 重合率分布
        if len(matrix) > 0:
            fig, ax = plt.subplots(figsize=(12, 6))
            
            # 获取上三角矩阵（不含对角线）
            upper_tri = matrix[np.triu_indices_from(matrix, k=1)]
            
            ax.hist(upper_tri, bins=20, color='steelblue', edgecolor='black', alpha=0.7)
            ax.set_xlabel('重合率 (%)', fontsize=12)
            ax.set_ylabel('组合数量', fontsize=12)
            ax.set_title('订阅源重合率分布', fontsize=14, fontweight='bold')
            ax.axvline(x=np.mean(upper_tri), color='red', linestyle='--', 
                      label=f'平均值: {np.mean(upper_tri):.1f}%')
            ax.legend()
            ax.grid(axis='y', alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(f"{output_dir}/overlap_distribution.png", dpi=150, bbox_inches='tight')
            plt.close()
            logger.info(f"重合率分布图已保存: {output_dir}/overlap_distribution.png")

    def generate_report(self, output_path: str = "analysis/analysis_report.md"):
        """生成分析报告"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        matrix, names = self.calculate_overlap()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# AdGuard Home 订阅源深度分析报告\n\n")
            f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # 概述
            f.write("## 📊 分析概述\n\n")
            f.write(f"- **分析订阅源数量**: {len(self.sources)}\n")
            f.write(f"- **总规则数量**: {sum(s.rules_count for s in self.sources):,}\n")
            f.write(f"- **平均规则数**: {np.mean([s.rules_count for s in self.sources]):.0f}\n")
            f.write(f"- **分析维度**: 重合率、覆盖领域、规则数量\n\n")
            
            # 订阅源详情
            f.write("## 📋 订阅源详情\n\n")
            f.write("| 名称 | 分类 | 规则数 |\n")
            f.write("|------|------|--------|\n")
            
            for source in sorted(self.sources, key=lambda s: s.rules_count, reverse=True):
                f.write(f"| {source.name} | {source.category} | {source.rules_count:,} |\n")
            
            f.write("\n")
            
            # 重合率分析
            if len(matrix) > 0:
                f.write("## 🔗 重合率分析\n\n")
                
                # 高重合率
                f.write("### 高重合率组合 (>30%)\n\n")
                high_overlap = []
                
                for i in range(len(self.sources)):
                    for j in range(i+1, len(self.sources)):
                        if matrix[i, j] > 30:
                            high_overlap.append((self.sources[i].name, self.sources[j].name, matrix[i, j]))
                
                if high_overlap:
                    f.write("| 订阅源 A | 订阅源 B | 重合率 | 建议 |\n")
                    f.write("|----------|----------|--------|------|\n")
                    for name1, name2, overlap in sorted(high_overlap, key=lambda x: -x[2]):
                        suggestion = "⚠️ 建议只选其一" if overlap > 50 else "ℹ️ 可同时启用"
                        f.write(f"| {name1} | {name2} | {overlap:.1f}% | {suggestion} |\n")
                else:
                    f.write("未发现高重合率组合。\n")
                
                f.write("\n")
                
                # 低重合率推荐组合
                f.write("### 互补性强的组合 (<10%)\n\n")
                low_overlap = []
                
                for i in range(len(self.sources)):
                    for j in range(i+1, len(self.sources)):
                        if matrix[i, j] < 10:
                            low_overlap.append((self.sources[i].name, self.sources[j].name, matrix[i, j]))
                
                if low_overlap:
                    f.write("| 订阅源 A | 订阅源 B | 重合率 | 建议 |\n")
                    f.write("|----------|----------|--------|------|\n")
                    for name1, name2, overlap in sorted(low_overlap, key=lambda x: x[2])[:10]:
                        f.write(f"| {name1} | {name2} | {overlap:.1f}% | ✅ 推荐组合 |\n")
                
                f.write("\n")
            
            # 推荐配置
            f.write("## 🎯 推荐配置方案\n\n")
            
            # 保守模式
            f.write("### 保守模式 (Conservative)\n\n")
            f.write("适合追求稳定性的用户，仅启用核心拦截:\n\n")
            conservative = [s for s in self.sources if s.category in ['通用']][:2]
            conservative += [s for s in self.sources if 'AdGuard DNS' in s.name]
            conservative = list({s.name: s for s in conservative}.values())[:3]
            
            total_rules = sum(s.rules_count for s in conservative)
            for source in conservative:
                f.write(f"- ✅ **{source.name}** ({source.rules_count:,} 条)\n")
            f.write(f"\n**总计**: {total_rules:,} 条规则\n\n")
            
            # 平衡模式
            f.write("### 平衡模式 (Balanced) - 推荐\n\n")
            f.write("适合大多数用户，平衡拦截效果与性能:\n\n")
            
            balanced = []
            # 通用规则
            balanced += [s for s in self.sources if s.category == '通用'][:2]
            # 中文规则
            balanced += [s for s in self.sources if s.category == '中文'][:2]
            # 安全规则
            balanced += [s for s in self.sources if s.category in ['恶意软件', '钓鱼']][:3]
            # 去重
            balanced = list({s.name: s for s in balanced}.values())
            
            total_rules = sum(s.rules_count for s in balanced)
            for source in balanced:
                f.write(f"- ✅ **{source.name}** ({source.category}, {source.rules_count:,} 条)\n")
            f.write(f"\n**总计**: {total_rules:,} 条规则\n\n")
            
            # 激进模式
            f.write("### 激进模式 (Aggressive)\n\n")
            f.write("适合追求极致拦截的用户:\n\n")
            
            aggressive = sorted(self.sources, key=lambda s: s.rules_count, reverse=True)[:10]
            total_rules = sum(s.rules_count for s in aggressive)
            
            for source in aggressive:
                f.write(f"- ✅ **{source.name}** ({source.category}, {source.rules_count:,} 条)\n")
            f.write(f"\n**总计**: {total_rules:,} 条规则\n\n")
            
            # 配置决策树
            f.write("## 🌳 配置决策树\n\n")
            f.write("```\n")
            f.write("是否需要中文网站拦截?\n")
            f.write("├── 是 -> 启用 CHN: anti-AD + CHN: AdRules DNS List\n")
            f.write("│   └── 是否需要视频广告拦截?\n")
            f.write("│       ├── 是 -> 额外添加乘风视频广告过滤规则\n")
            f.write("│       └── 否 -> 保持当前配置\n")
            f.write("└── 否\n")
            f.write("    ├── 主要关注安全威胁?\n")
            f.write("    │   ├── 是 -> 启用 Malicious URL + Phishing URL + Threat Intelligence\n")
            f.write("    │   └── 否\n")
            f.write("    │       ├── 需要隐私保护 (防跟踪)?\n")
            f.write("    │       │   ├── 是 -> 启用隐私相关规则\n")
            f.write("    │       │   └── 否 -> 使用 AdGuard DNS filter (默认推荐)\n")
            f.write("    │       └── 需要加密货币挖矿防护?\n")
            f.write("    │           ├── 是 -> 启用 NoCoin Filter List\n")
            f.write("    │           └── 否 -> 完成配置\n")
            f.write("```\n\n")
            
            # 优化建议
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
            
            f.write("### 4. 白名单配合\n\n")
            f.write("- 适当配置白名单避免误拦截\n")
            f.write("- 推荐白名单源:\n")
            f.write("  - https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/ok.txt\n")
            f.write("  - https://raw.githubusercontent.com/Goooler/1024_hosts/refs/heads/master/whitelist\n\n")
            
            # 可视化
            f.write("## 📈 可视化分析\n\n")
            f.write("### 重合率热力图\n\n")
            f.write("![重合率热力图](overlap_heatmap.png)\n\n")
            f.write("### 规则数量对比\n\n")
            f.write("![规则数量对比](rules_count.png)\n\n")
            f.write("### 分类分布\n\n")
            f.write("![分类分布](category_distribution.png)\n\n")
            f.write("### 重合率分布\n\n")
            f.write("![重合率分布](overlap_distribution.png)\n\n")
            
            # 附录
            f.write("## 📎 附录\n\n")
            f.write("### 数据来源\n\n")
            f.write("- [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry)\n")
            f.write("- [乘风广告过滤规则](https://github.com/xinggsf/Adblock-Plus-Rule)\n")
            f.write("- [HaGeZi's DNS Blocklists](https://github.com/hagezi/dns-blocklists)\n\n")
            
            f.write("### 分析工具\n\n")
            f.write("- Python 3.11+\n")
            f.write("- NumPy, Matplotlib, Seaborn\n")
            f.write("- Requests\n\n")
        
        logger.info(f"分析报告已生成: {output_path}")


def main():
    analyzer = LocalSourceAnalyzer(timeout=60)
    
    # 分析
    stats = analyzer.analyze_all()
    
    # 可视化
    analyzer.create_visualizations()
    
    # 报告
    analyzer.generate_report()
    
    # 输出摘要
    print("\n" + "="*60)
    print("分析完成!")
    print("="*60)
    print(f"成功分析: {stats['total_sources']} 个订阅源")
    print(f"总规则数: {stats['total_rules']:,}")
    print(f"平均规则数: {stats['avg_rules']:.0f}")
    print("="*60)


if __name__ == "__main__":
    main()
