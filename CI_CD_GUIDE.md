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
