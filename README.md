# 🛡️ AdGuard Home 规则合并工具

[![Update Rules](https://github.com/kekai2020/adguard-rules-merger/actions/workflows/update-rules.yml/badge.svg)](https://github.com/kekai2020/adguard-rules-merger/actions/workflows/update-rules.yml)
[![Last Commit](https://img.shields.io/github/last-commit/kekai2020/adguard-rules-merger)](https://github.com/kekai2020/adguard-rules-merger/commits/main)
[![License](https://img.shields.io/github/license/kekai2020/adguard-rules-merger)](LICENSE)

自动合并多个 AdGuard Home 拦截规则订阅源，实现智能去重和优化

## ✨ 功能特性

- 🔄 **自动合并**: 支持多个规则源的自动获取和合并
- 🧹 **智能去重**: 识别通配符等价性（如 `*.example.com` 与 `example.com`）
- ⚠️ **冲突检测**: 标记白名单与黑名单冲突
- 📊 **分类统计**: 按广告、恶意软件、钓鱼等分类
- 🚀 **GitHub Actions**: 每6小时自动更新
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

### 本地使用

```bash
# 克隆仓库
git clone https://github.com/kekai2020/adguard-rules-merger.git
cd adguard-rules-merger

# 安装依赖
pip install -r requirements.txt

# 运行合并
python merger.py

# 查看输出
cat output/merged_rules.txt
```

## 🔧 配置说明

### 自定义订阅源

编辑 `sources.txt` 文件，每行添加一个规则源 URL:

```
# 注释以 # 开头
https://example1.com/rules.txt
https://example2.com/rules.txt
```

### 命令行参数

```bash
python merger.py -h
# 输出:
# -s, --sources    订阅源文件路径 (默认: sources.txt)
# -o, --output     输出目录 (默认: output)
# -t, --timeout    请求超时时间(秒) (默认: 30)
# -v, --verbose    详细日志
```

## 📁 项目结构

```
adguard-rules-merger/
├── .github/
│   └── workflows/
│       └── update-rules.yml    # GitHub Actions 自动更新
├── merger.py                    # 核心合并工具
├── merger_local.py              # 本地文件合并工具
├── analyzer.py                  # 订阅源分析工具
├── analyzer_local.py            # 本地分析工具
├── sources.txt                  # 订阅源列表
├── requirements.txt             # Python 依赖
├── test_core.py                 # 单元测试
├── output/                      # 输出目录
│   ├── merged_rules.txt         # 合并后的规则
│   └── merge_report.md          # 合并报告
└── README.md                    # 本文件
```

## 🧪 测试

```bash
# 运行单元测试
python test_core.py

# 详细输出
python test_core.py -v
```

## 📊 性能优化

### 合并操作优化

1. **使用集合去重**: O(1) 复杂度的规则查找
2. **延迟加载**: 按需获取规则源内容
3. **流式处理**: 大文件分块读取
4. **超时控制**: 防止单个源阻塞

### GitHub Actions 优化

1. **定时调度**: 每6小时运行一次（避免过于频繁）
2. **超时设置**: 30分钟工作流超时
3. **pip缓存**: 加速依赖安装
4. **条件提交**: 无变化时不提交

## 📝 规则格式支持

| 格式 | 示例 | 说明 |
|------|------|------|
| 普通域名 | `example.com` | 标准域名格式 |
| AdGuard | `\|\|example.com^` | AdGuard 格式 |
| 通配符 | `*.example.com` | 通配符匹配 |
| Hosts | `127.0.0.1 example.com` | Hosts 格式 |
| 正则 | `/ads?\d+\.example\.com/` | 正则表达式 |
| 白名单 | `@@example.com` | 白名单规则 |

## 🎯 推荐配置

### 保守模式
- 仅启用 `GENERAL` 和 `ADS` 分类
- 适合追求稳定性的用户

### 平衡模式（推荐）
- 启用除 `ADULT` 和 `GAMBLING` 外的所有分类
- 适合大多数用户

### 激进模式
- 启用所有分类
- 适合追求极致拦截的用户

## 🤝 贡献指南

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

## 📄 许可证

本项目采用 [MIT](LICENSE) 许可证

## 🙏 致谢

- [AdGuard Team](https://adguard.com/) - 提供优秀的广告拦截工具
- [AdGuard Hostlists Registry](https://github.com/AdguardTeam/HostlistsRegistry) - 规则源注册表
- 所有规则源维护者

## 📞 联系方式

如有问题或建议，欢迎提交 [Issue](https://github.com/kekai2020/adguard-rules-merger/issues)
