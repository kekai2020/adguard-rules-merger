# AdGuard Home 订阅源深度分析报告

**生成时间**: 2026-02-14 20:30:31

## 📊 分析概述

- **分析订阅源数量**: 0
- **总规则数量**: 0
- **平均规则数**: nan
- **分析维度**: 重合率、覆盖领域、质量评分

## 📋 订阅源详情

| 名称 | 分类 | 规则数 | 质量评分 |
|------|------|--------|----------|

## 🔗 重合率分析

### 高重合率组合 (>50%)

未发现高重合率组合。

## 📁 分类覆盖

## 🎯 推荐配置

### 保守模式 (Conservative)

适合追求稳定性的用户，仅启用核心拦截:


### 平衡模式 (Balanced) - 推荐

适合大多数用户，平衡拦截效果与性能:


### 激进模式 (Aggressive)

适合追求极致拦截的用户，启用所有可用规则:


## 🌳 配置决策树

```
是否需要中文网站拦截?
├── 是 -> 启用 CHN: anti-AD + CHN: AdRules DNS List
└── 否
    ├── 主要关注安全?
    │   ├── 是 -> 启用 Malicious URL + Phishing URL + Threat Intelligence
    │   └── 否
    │       ├── 需要隐私保护?
    │       │   ├── 是 -> 启用隐私相关规则
    │       │   └── 否 -> 使用 AdGuard DNS filter (默认)
```

## 📈 可视化分析

### 重合率热力图

![重合率热力图](overlap_analysis.png)

### 分类覆盖

![分类覆盖](category_coverage.png)

### 质量评分

![质量评分](quality_scores.png)

## 💡 优化建议

1. **避免重复订阅**: 高重合率的规则源同时启用会浪费资源
2. **按需求选择**: 根据实际需求选择合适的分类
3. **定期更新**: 保持规则源更新以获得最新保护
4. **监控性能**: 规则过多可能影响 DNS 查询性能
5. **白名单配合**: 适当配置白名单避免误拦截

## 📎 附录

### 数据来源

- [AdGuard Hostlists Registry](https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/assets/filters.json)

### 分析工具

- Python 3.11+
- NumPy, Matplotlib, Seaborn
- Requests

