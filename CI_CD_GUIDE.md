# GitHub Actions CI/CD 配置指南

## 📋 工作流概览

本项目配置了三个主要的工作流：

| 工作流 | 文件名 | 触发条件 | 用途 |
|--------|--------|----------|------|
| **Tests** | `test.yml` | PR/Push | 代码测试和验证 |
| **Merge Rules** | `merge.yml` | 定时/手动 | 自动合并规则 |
| **Daily Release** | `release.yml` | 每日定时 | 创建发布版本 |

## 🔧 工作流详情

### 1. Tests (test.yml)

**触发条件：**
- 推送到 `main` 或 `develop` 分支
- 创建 Pull Request
- 修改了相关代码文件

**执行内容：**
- 多版本 Python 测试 (3.9, 3.10, 3.11, 3.12)
- 代码风格检查 (flake8)
- 单元测试 (pytest)
- 性能测试
- 并发测试
- 集成测试（真实数据源）
- 覆盖率报告

**使用方式：**
```bash
# 查看测试状态
gh run list --workflow=test.yml

# 重新运行失败的测试
gh run rerun <run-id>
```

### 2. Merge Rules (merge.yml)

**触发条件：**
- 每小时自动执行 (`0 * * * *`)
- 手动触发 (workflow_dispatch)
- 推送修改了配置或核心代码

**执行内容：**
- 从配置的源获取规则
- 合并和去重
- 生成统计报告
- 提交到 `output/` 目录
- 上传构建产物

**手动触发参数：**
- `sources`: 自定义源 URL（逗号分隔）
- `output_file`: 输出文件名

**使用方式：**
```bash
# GitHub CLI 手动触发
gh workflow run merge.yml

# 带参数触发
gh workflow run merge.yml -f sources="url1,url2" -f output_file="custom.txt"
```

### 3. Daily Release (release.yml)

**触发条件：**
- 每天 UTC 00:00 执行
- 手动触发

**执行内容：**
- 合并规则
- 创建 Release
- 上传规则文件
- 更新 `latest` 标签

**发布格式：**
- 标签: `vYYYY-MM-DD`
- 包含: `merged_rules.txt`, `stats.txt`

## 🚀 快速开始

### 启用 GitHub Actions

1. **推送到 GitHub：**
   ```bash
   git remote add origin https://github.com/yourusername/adguard-rules-merger.git
   git push -u origin main
   ```

2. **查看 Actions：**
   访问 `https://github.com/yourusername/adguard-rules-merger/actions`

3. **验证运行：**
   - 创建测试 PR 验证 `test.yml`
   - 手动触发 `merge.yml` 验证合并功能

### 配置 Secrets（可选）

如果需要访问私有源或发送通知：

1. 进入 Settings → Secrets and variables → Actions
2. 添加所需的 secrets:
   - `PRIVATE_SOURCE_TOKEN`: 私有源的访问令牌
   - `NOTIFICATION_WEBHOOK`: 通知 Webhook URL

## 📊 状态徽章

在 README.md 中添加状态徽章：

```markdown
[![Tests](https://github.com/yourusername/adguard-rules-merger/actions/workflows/test.yml/badge.svg)](https://github.com/yourusername/adguard-rules-merger/actions/workflows/test.yml)
[![Merge Rules](https://github.com/yourusername/adguard-rules-merger/actions/workflows/merge.yml/badge.svg)](https://github.com/yourusername/adguard-rules-merger/actions/workflows/merge.yml)
[![Daily Release](https://github.com/yourusername/adguard-rules-merger/actions/workflows/release.yml/badge.svg)](https://github.com/yourusername/adguard-rules-merger/releases)
```

## 🧪 本地测试

### 使用 act 工具

```bash
# 安装 act
brew install act  # macOS
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash  # Linux

# 运行测试工作流
act -j test

# 运行合并工作流（需要 secrets）
act -j merge --secret-file .secrets

# 列出可用任务
act -l
```

### 创建工作流测试环境

```bash
# 创建 .secrets 文件（不要提交到 git）
echo "GITHUB_TOKEN=your_token_here" > .secrets

# 运行完整测试
act push --secret-file .secrets
```

## 🔍 故障排查

### 常见问题

**1. 工作流未触发**
- 检查文件路径是否正确
- 确认分支名称匹配
- 查看 Actions 是否已启用

**2. 权限错误**
```
Error: Resource not accessible by integration
```
- 进入 Settings → Actions → General
- 设置 Workflow permissions 为 "Read and write permissions"

**3. 依赖安装失败**
```yaml
# 在 workflow 中添加缓存
- uses: actions/setup-python@v5
  with:
    python-version: '3.11'
    cache: 'pip'  # 启用缓存
```

**4. 合并提交失败**
- 检查 GITHUB_TOKEN 权限
- 确认分支保护规则允许 Actions 提交

### 调试工作流

```yaml
# 在 workflow 中添加调试步骤
- name: Debug
  run: |
    echo "Current directory: $(pwd)"
    echo "Directory contents:"
    ls -la
    echo "Environment variables:"
    env | grep GITHUB
```

## 📝 自定义配置

### 修改定时触发

编辑 `.github/workflows/merge.yml`：

```yaml
on:
  schedule:
    # 每30分钟
    - cron: '*/30 * * * *'
    # 每天上午8点
    - cron: '0 8 * * *'
```

Cron 表达式格式：
```
* * * * *
│ │ │ │ └─── 星期 (0-7, 0和7都是周日)
│ │ │ └───── 月份 (1-12)
│ │ └─────── 日期 (1-31)
│ └───────── 小时 (0-23)
└─────────── 分钟 (0-59)
```

### 添加通知

在 workflow 末尾添加：

```yaml
- name: Notify on success
  if: success()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "✅ Rules merged successfully! Total: ${{ steps.merge.outputs.total_rules }}"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### 多环境部署

```yaml
jobs:
  deploy-staging:
    if: github.ref == 'refs/heads/develop'
    environment: staging
    
  deploy-production:
    if: github.ref == 'refs/heads/main'
    environment: production
    needs: deploy-staging
```

## 🔒 安全建议

1. **不要硬编码敏感信息**
   - 使用 GitHub Secrets
   - 使用环境变量

2. **限制权限**
   ```yaml
   permissions:
     contents: write
     actions: read
   ```

3. **审计依赖**
   ```yaml
   - name: Audit dependencies
     run: pip audit
   ```

## 📚 相关文档

- [GitHub Actions 文档](https://docs.github.com/en/actions)
- [Workflow 语法参考](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [Events 触发器](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows)
- [官方 Actions 市场](https://github.com/marketplace?type=actions)

## ✅ 验证清单

部署前检查：

- [ ] 工作流文件已提交到 `.github/workflows/`
- [ ] YAML 语法正确（可用在线工具验证）
- [ ] Secrets 已配置（如需要）
- [ ] 权限设置正确
- [ ] README 已添加状态徽章
- [ ] 本地测试通过（如有 act）
- [ ] 首次运行成功

---

**遇到问题？** 查看 Actions 页面的日志输出，或提交 Issue 获取帮助。