#!/usr/bin/env python3
"""
AdGuard Home 订阅源分析工具
功能：分析默认订阅源的重合率、覆盖领域、质量评分等
"""

import os
import re
import json
import logging
import requests
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field, asdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class FilterSource:
    """过滤源数据类"""
    id: int
    name: str
    url: str
    description: str = ""
    category: str = ""
    rules_count: int = 0
    rules: Set[str] = field(default_factory=set)
    update_frequency: str = "unknown"
    maintainer: str = ""
    homepage: str = ""
    license: str = ""


@dataclass
class AnalysisResult:
    """分析结果数据类"""
    sources: List[FilterSource] = field(default_factory=list)
    overlap_matrix: list = field(default_factory=list)
    category_coverage: Dict[str, List[str]] = field(default_factory=dict)
    quality_scores: Dict[str, float] = field(default_factory=dict)
    recommendations: Dict[str, List[str]] = field(default_factory=dict)


class AdGuardSourceAnalyzer:
    """AdGuard 订阅源分析器"""

    REGISTRY_URL = "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/filters.json"
    
    CATEGORY_MAP = {
        'ads': '广告拦截',
        'privacy': '隐私保护',
        'malware': '恶意软件',
        'phishing': '钓鱼网站',
        'social': '社交媒体',
        'adult': '成人内容',
        'gambling': '赌博',
        'regional': '区域规则',
        'security': '安全',
        'general': '通用',
    }

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AdGuard-Source-Analyzer/1.0'
        })
        self.sources: Dict[int, FilterSource] = {}
        self.analysis_result = AnalysisResult()

    def fetch_registry(self) -> bool:
        """从 AdGuard Registry 获取过滤源信息"""
        try:
            logger.info(f"正在获取 Registry: {self.REGISTRY_URL}")
            response = self.session.get(self.REGISTRY_URL, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            for filter_data in data.get('filters', []):
                source = FilterSource(
                    id=filter_data.get('id', 0),
                    name=filter_data.get('name', 'Unknown'),
                    url=filter_data.get('sourceUrl', ''),
                    description=filter_data.get('description', ''),
                    category=filter_data.get('category', 'general'),
                    homepage=filter_data.get('homepage', ''),
                    license=filter_data.get('license', '')
                )
                self.sources[source.id] = source
            
            logger.info(f"成功获取 {len(self.sources)} 个过滤源信息")
            return True
            
        except Exception as e:
            logger.error(f"获取 Registry 失败: {e}")
            return False

    def fetch_source_rules(self, source: FilterSource) -> bool:
        """获取单个订阅源的规则"""
        if not source.url:
            logger.warning(f"跳过 {source.name}: 无 URL")
            return False

        try:
            logger.info(f"正在获取: {source.name}")
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
        """解析规则内容"""
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
        """标准化规则文本"""
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
        
        if re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$', rule):
            return rule
        
        return ""

    def analyze_all_sources(self) -> None:
        """分析所有订阅源"""
        for source_id, source in list(self.sources.items()):
            success = self.fetch_source_rules(source)
            if not success:
                del self.sources[source_id]
        
        logger.info(f"成功获取 {len(self.sources)} 个订阅源的规则")

    def calculate_overlap_matrix(self) -> list:
        """计算重合率矩阵"""
        source_list = list(self.sources.values())
        n = len(source_list)
        
        if n == 0:
            return []
        
        overlap_matrix = [[0.0 for _ in range(n)] for _ in range(n)]
        
        for i in range(n):
            for j in range(n):
                if i == j:
                    overlap_matrix[i][j] = 100.0
                    continue
                
                set_i = source_list[i].rules
                set_j = source_list[j].rules
                
                if len(set_i) == 0 or len(set_j) == 0:
                    overlap_matrix[i][j] = 0.0
                    continue
                
                intersection = len(set_i & set_j)
                overlap = (intersection / min(len(set_i), len(set_j))) * 100
                overlap_matrix[i][j] = round(overlap, 2)
        
        self.analysis_result.overlap_matrix = overlap_matrix
        return overlap_matrix

    def analyze_category_coverage(self) -> Dict[str, List[str]]:
        """分析分类覆盖"""
        coverage = defaultdict(list)
        
        for source in self.sources.values():
            category = self.CATEGORY_MAP.get(source.category, '其他')
            coverage[category].append(source.name)
        
        self.analysis_result.category_coverage = dict(coverage)
        return dict(coverage)

    def calculate_quality_scores(self) -> Dict[str, float]:
        """计算质量评分"""
        scores = {}
        
        for source in self.sources.values():
            score = 0.0
            
            if source.rules_count > 100000:
                score += 30
            elif source.rules_count > 50000:
                score += 25
            elif source.rules_count > 10000:
                score += 20
            elif source.rules_count > 1000:
                score += 15
            else:
                score += 10
            
            if 'daily' in source.name.lower() or 'updated' in source.name.lower():
                score += 30
            else:
                score += 20
            
            if source.homepage:
                score += 20
            else:
                score += 10
            
            if source.license:
                score += 20
            else:
                score += 15
            
            scores[source.name] = round(score, 1)
        
        self.analysis_result.quality_scores = scores
        return scores

    def generate_recommendations(self) -> Dict[str, List[str]]:
        """生成配置建议"""
        recommendations = {
            'conservative': [],
            'balanced': [],
            'aggressive': [],
        }
        
        sorted_sources = sorted(
            self.sources.values(),
            key=lambda s: self.analysis_result.quality_scores.get(s.name, 0),
            reverse=True
        )
        
        for source in sorted_sources:
            if source.category in ['general', 'ads'] and len(recommendations['conservative']) < 3:
                recommendations['conservative'].append(source.name)
        
        recommendations['balanced'] = recommendations['conservative'].copy()
        for source in sorted_sources:
            if source.category in ['security', 'privacy', 'malware', 'phishing']:
                if source.name not in recommendations['balanced']:
                    recommendations['balanced'].append(source.name)
            if len(recommendations['balanced']) >= 8:
                break
        
        recommendations['aggressive'] = [s.name for s in sorted_sources]
        
        self.analysis_result.recommendations = recommendations
        return recommendations

    def generate_report(self, output_path: str = "analysis/recommendations.md") -> str:
        """生成分析报告"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# AdGuard Home 订阅源深度分析报告\n\n")
            f.write(f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("## 📊 分析概述\n\n")
            f.write(f"- **分析订阅源数量**: {len(self.sources)}\n")
            f.write(f"- **总规则数量**: {sum(s.rules_count for s in self.sources.values()):,}\n")
            f.write(f"- **平均规则数**: {sum(s.rules_count for s in self.sources.values()) / max(len(self.sources), 1):.0f}\n")
            f.write(f"- **分析维度**: 重合率、覆盖领域、质量评分\n\n")
            
            f.write("## 📋 订阅源详情\n\n")
            f.write("| 名称 | 分类 | 规则数 | 质量评分 |\n")
            f.write("|------|------|--------|----------|\n")
            
            sorted_sources = sorted(
                self.sources.values(),
                key=lambda s: self.analysis_result.quality_scores.get(s.name, 0),
                reverse=True
            )
            
            for source in sorted_sources:
                score = self.analysis_result.quality_scores.get(source.name, 0)
                category = self.CATEGORY_MAP.get(source.category, source.category)
                f.write(f"| {source.name} | {category} | {source.rules_count:,} | {score:.1f} |\n")
            
            f.write("\n")
            
            f.write("## 🔗 重合率分析\n\n")
            f.write("### 高重合率组合 (>50%)\n\n")
            
            source_list = list(self.sources.values())
            high_overlap = []
            
            for i in range(len(source_list)):
                for j in range(i+1, len(source_list)):
                    if self.analysis_result.overlap_matrix and i < len(self.analysis_result.overlap_matrix) and j < len(self.analysis_result.overlap_matrix[i]):
                        overlap = self.analysis_result.overlap_matrix[i][j]
                        if overlap > 50:
                            high_overlap.append((source_list[i].name, source_list[j].name, overlap))
            
            if high_overlap:
                f.write("| 订阅源 A | 订阅源 B | 重合率 |\n")
                f.write("|----------|----------|--------|\n")
                for name1, name2, overlap in sorted(high_overlap, key=lambda x: -x[2]):
                    f.write(f"| {name1} | {name2} | {overlap:.1f}% |\n")
            else:
                f.write("未发现高重合率组合。\n")
            
            f.write("\n")
            
            f.write("## 📁 分类覆盖\n\n")
            for category, sources in self.analysis_result.category_coverage.items():
                f.write(f"### {category}\n\n")
                for source_name in sources:
                    f.write(f"- {source_name}\n")
                f.write("\n")
            
            f.write("## 🎯 推荐配置\n\n")
            
            f.write("### 保守模式 (Conservative)\n\n")
            f.write("适合追求稳定性的用户，仅启用核心拦截:\n\n")
            for name in self.analysis_result.recommendations.get('conservative', []):
                f.write(f"- ✅ {name}\n")
            f.write("\n")
            
            f.write("### 平衡模式 (Balanced) - 推荐\n\n")
            f.write("适合大多数用户，平衡拦截效果与性能:\n\n")
            for name in self.analysis_result.recommendations.get('balanced', []):
                f.write(f"- ✅ {name}\n")
            f.write("\n")
            
            f.write("### 激进模式 (Aggressive)\n\n")
            f.write("适合追求极致拦截的用户，启用所有可用规则:\n\n")
            for name in self.analysis_result.recommendations.get('aggressive', [])[:15]:
                f.write(f"- ✅ {name}\n")
            if len(self.analysis_result.recommendations.get('aggressive', [])) > 15:
                f.write(f"- ... 还有 {len(self.analysis_result.recommendations['aggressive']) - 15} 个规则\n")
            f.write("\n")
            
            f.write("## 💡 优化建议\n\n")
            f.write("1. **避免重复订阅**: 高重合率的规则源同时启用会浪费资源\n")
            f.write("2. **按需求选择**: 根据实际需求选择合适的分类\n")
            f.write("3. **定期更新**: 保持规则源更新以获得最新保护\n")
            f.write("4. **监控性能**: 规则过多可能影响 DNS 查询性能\n")
            f.write("5. **白名单配合**: 适当配置白名单避免误拦截\n\n")
            
            f.write("## 📎 附录\n\n")
            f.write("### 数据来源\n\n")
            f.write(f"- [AdGuard Hostlists Registry]({self.REGISTRY_URL})\n\n")
        
        logger.info(f"分析报告已生成: {output_path}")
        return output_path

    def run_full_analysis(self) -> AnalysisResult:
        """运行完整分析"""
        logger.info("开始完整分析...")
        
        if not self.fetch_registry():
            logger.error("无法获取 Registry，分析终止")
            return self.analysis_result
        
        self.analyze_all_sources()
        
        logger.info("计算重合率矩阵...")
        self.calculate_overlap_matrix()
        
        logger.info("分析分类覆盖...")
        self.analyze_category_coverage()
        
        logger.info("计算质量评分...")
        self.calculate_quality_scores()
        
        logger.info("生成配置建议...")
        self.generate_recommendations()
        
        logger.info("生成分析报告...")
        self.generate_report()
        
        logger.info("分析完成!")
        return self.analysis_result


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AdGuard Home 订阅源分析工具')
    parser.add_argument('-o', '--output', default='analysis', help='输出目录')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='请求超时时间')
    
    args = parser.parse_args()
    
    analyzer = AdGuardSourceAnalyzer(timeout=args.timeout)
    result = analyzer.run_full_analysis()
    
    print("\n" + "="*60)
    print("分析完成!")
    print("="*60)
    print(f"分析订阅源: {len(result.sources)}")
    print(f"总规则数: {sum(s.rules_count for s in result.sources):,}")
    print(f"报告位置: {args.output}/recommendations.md")
    print("="*60)


if __name__ == "__main__":
    main()
