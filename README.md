# 🛡️ AdGuard Home 规则合并工具

[![Build Status](https://github.com/kekai2020/adguard-rules-merger/workflows/Update%20AdGuard%20Rules/badge.svg)](https://github.com/kekai2020/adguard-rules-merger/actions)
[![Last Updated](https://img.shields.io/badge/Last%20Updated-2025--01--20%2008:00:00%20UTC-blue)](https://github.com/kekai2020/adguard-rules-merger/commits/main)
[![Rules Count](https://img.shields.io/badge/Rules-150K+-green)](output/merged_rules.txt)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 自动合并多个 AdGuard Home 拦截规则订阅源，实现智能去重和优化

## ✨ 功能特性

- 🔄 **自动合并**: 支持多个规则源的自动获取和合并
- 🧹 **智能去重**: 识别通配符等价性（如 `*.example.com` 与 `example.com`）
- ⚠️ **冲突检测**: 标记白名单与黑名单冲突
- 📊 **分类统计**: 按广告、恶意软件、钓鱼等分类
- 🚀 **GitHub Actions**: 每小时自动更新
- 📈 **详细报告**: 生成合并统计报告

## 📋 快速开始

### 在 AdGuard Home 中使用

1. 打开 AdGuard Home 管理界面
2. 进入 `过滤器` -> `DNS 拦截列表`
3. 点击 `添加阻止列表`
4. 输入以下 URL:

```
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger/main/output/merged_rules.txt
```

### 本地运行

```bash
# 克隆仓库
git clone https://github.com/kekai2020/adguard-rules-merger.git
cd adguard-rules-merger

# 安装依赖
pip install requests

# 运行合并工具
python merger.py

# 查看输出
cat output/merged_rules.txt
cat output/merge_report.md
```

## 🔧 配置说明

### 自定义订阅源

编辑 `sources.txt` 文件，每行添加一个规则 URL:

```text
# 官方规则
https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt

# 中文规则
https://adguardteam.github.io/HostlistsRegistry/assets/filter_29.txt

# 自定义规则
https://example.com/your-rules.txt
```

### 命令行参数

```bash
python merger.py [选项]

选项:
  -s, --sources FILE    订阅源文件路径 (默认: sources.txt)
  -o, --output DIR      输出目录 (默认: output)
  -t, --timeout SECONDS 请求超时时间 (默认: 30)
  -v, --verbose         详细日志输出
  -h, --help            显示帮助信息
```

## 📁 项目结构

```
adguard-rules-merger/
├── .github/
│   └── workflows/
│       └── update-rules.yml    # GitHub Actions 工作流
├── merger.py                   # 核心合并脚本
├── sources.txt                 # 订阅源配置
├── output/                     # 生成文件目录
│   ├── merged_rules.txt        # 合并后的规则文件
│   └── merge_report.md         # 合并统计报告
├── analysis/                   # 订阅源分析报告
│   ├── overlap_analysis.png    # 重合率热力图
│   └── recommendations.md      # 配置建议
└── README.md                   # 使用说明
```

## 📊 推荐配置

### 保守模式
适合追求稳定性的用户，仅启用核心拦截:

```yaml
- AdGuard DNS filter
- CHN: AdRules DNS List
- Malicious URL Blocklist
```

### 平衡模式 (推荐)
适合大多数用户，平衡拦截效果与性能:

```yaml
- AdGuard DNS filter
- CHN: anti-AD
- Phishing URL Blocklist
- Malicious URL Blocklist
- HaGeZi's Threat Intelligence Feeds
- NoCoin Filter List
```

### 激进模式
适合追求极致拦截的用户:

```yaml
- 启用所有可用规则
- 包括社交媒体、成人内容、赌博等分类
```

## 📈 统计报告

每次合并后会生成详细的统计报告，包括:

- ✅ 订阅源获取成功率
- 📊 规则分类统计
- 🔢 去重数量与比例
- ⚠️ 冲突规则详情
- 📥 各来源规则数量

查看最新报告: [merge_report.md](output/merge_report.md)

## 🔍 订阅源分析

项目包含对 AdGuard Home 默认订阅源的深度分析:

- 📊 **重合率矩阵**: 各订阅源之间的规则重复情况
- 🎯 **覆盖领域**: 广告/恶意软件/钓鱼/跟踪器等
- ⭐ **质量评分**: 误拦截率、更新频率、维护活跃度
- 📋 **配置建议**: 根据需求推荐最佳组合

查看分析报告: [analysis/recommendations.md](analysis/recommendations.md)

## ⚙️ GitHub Actions 配置

### 自动触发

- **定时触发**: 每小时自动运行 (`0 * * * *`)
- **手动触发**: 通过 Actions 页面手动运行
- **推送触发**: 修改 `sources.txt` 或 `merger.py` 时触发

### 通知配置

#### Slack 通知

1. 创建 Slack Incoming Webhook
2. 在仓库 Settings -> Secrets 中添加 `SLACK_WEBHOOK_URL`

#### 邮件通知

1. 在仓库 Settings -> Secrets 中添加:
   - `EMAIL_USERNAME`: 发件邮箱
   - `EMAIL_PASSWORD`: 邮箱密码
   - `EMAIL_TO`: 收件地址
   - `EMAIL_FROM`: 发件地址

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request!

### 提交规则源

如果您有好的规则源推荐，请:

1. Fork 本仓库
2. 编辑 `sources.txt` 添加规则 URL
3. 提交 Pull Request

### 代码贡献

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 📝 更新日志

### v1.0.0 (2025-01-20)

- ✨ 初始版本发布
- 🔄 支持多源自动合并
- 🧹 智能去重与冲突检测
- 📊 生成详细统计报告
- 🚀 GitHub Actions 自动化

## 📜 许可证

本项目采用 [MIT](LICENSE) 许可证

## 🙏 致谢

感谢以下项目和组织的贡献:

- [AdGuard Team](https://adguard.com/) - 提供优秀的 DNS 过滤工具
- [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry) - 规则源注册表
- [anti-AD](https://github.com/privacy-protection-tools/anti-AD) - 中文广告过滤规则
- [HaGeZi](https://github.com/hagezi/dns-blocklists) - 威胁情报源

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/kekai2020">kekai2020</a>
</p>
