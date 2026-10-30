# 部署指南（Deployment）

介绍如何把 AdGuard Rules Merger V7 部署到 GitHub Actions（推荐）、自建服务器、
cron、或 Docker，并验证产物可被 AdGuard Home 订阅。

## 1. GitHub Actions 自动更新（推荐）

仓库已包含工作流，无需自建服务器。

### 1.1 首次发布到 GitHub

```bash
# 在本地仓库根目录
git init
git add .
git commit -m "feat: AdGuard Rules Merger V7"
git branch -M main
git remote add origin https://github.com/<owner>/adguard-rules-merger-v7.git
git push -u origin main
```

> 使用 gh CLI 可直接建仓：`gh repo create <owner>/adguard-rules-merger-v7 --public --push`。

### 1.2 工作流说明

| 工作流 | 触发 | 产物 |
|---|---|---|
| `ci.yml` | push / PR / 手动 | 质量门禁、矩阵测试、wheel/sdist（artifact） |
| `merge.yml` | 每日 UTC 0 点、手动、配置相关代码变更 | 运行合并并把 `output/` 提交回 `main` |
| `release.yml` | 推送 `v*` 标签 | wheel/sdist 上传到 GitHub Release |

`merge.yml` 使用 `GITHUB_TOKEN`（`contents: write`）自动提交；`rebase` 重试
三次以避免并发冲突。任务间用 `concurrency` 串行化，避免重复运行互相覆盖。

### 1.3 可选 Secrets

- `VIRUSTOTAL_API_KEY`：启用 VirusTotal 层。
- `OPENAI_API_KEY`：启用 AI 分类层。

不设置时二者自动关闭，其余 6 层免费、无需密钥。

### 1.4 手动触发

仓库 Actions 页面 → **Merge Rules (V7)** → **Run workflow**。

### 1.5 AdGuard Home 订阅

```
https://raw.githubusercontent.com/<owner>/adguard-rules-merger-v7/main/output/merged_rules.txt
```

## 2. 自建服务器 / cron

适用于希望把产物分发到自有 CDN 或对象存储的场景。

### 2.1 安装（推荐 uv）

```bash
git clone https://github.com/<owner>/adguard-rules-merger-v7.git
cd adguard-rules-merger
uv sync --extra dev
uv run python -m merger validate config/sources.yaml
```

### 2.2 定时任务（每天 0 点）

```cron
0 0 * * * cd /opt/adguard-rules-merger && \
  /usr/bin/env bash -lc 'uv run python -m merger merge --config config/sources.yaml' \
  >> /var/log/adguard-merger.log 2>&1
```

pip 安装方式：

```cron
0 0 * * * cd /opt/adguard-rules-merger && /opt/adguard-rules-merger/.venv/bin/adguard-rules-merger merge >> /var/log/adguard-merger.log 2>&1
```

### 2.3 分发

合并完成后 `output/` 即为静态文件目录，可由 nginx / Caddy / 对象存储直接托管：

```nginx
location /adguard/ {
    root /var/www;          # 即 /var/www/adguard/output/...
    autoindex off;
    add_header Cache-Control "public, max-age=3600";
}
```

## 3. Docker

仓库根目录提供多阶段 `Dockerfile`，构建产物为不含构建工具的精简镜像。

```bash
# 构建
docker build -t adguard-rules-merger:7.0.0 .

# 运行（挂载 output / cache / config）
docker run --rm \
  -v "$PWD/output:/app/output" \
  -v "$PWD/cache:/app/cache" \
  -v "$PWD/config:/app/config:ro" \
  adguard-rules-merger:7.0.0 merge --config config/sources.yaml --no-audit
```

镜像默认工作目录 `/app`，入口即 `adguard-rules-merger` 控制台命令。
启用网络审计时去掉 `--no-audit`，并用 `-e` 注入 API key。

## 4. 部署验收清单

合并完成后，在 CI 的 “Verify output” 步骤或本地依次确认：

- `output/merged_rules.txt`、`output/whitelist.txt`、`output/stats.json` 存在且非空；
- `merged_rules.txt` 含 `! Version:` 头且标题为 `(V7)`；
- 各格式文件按需生成（`hosts.txt` / `domains.txt` / `clash.yaml` /
  `surge.list` / `smartdns.conf`）；
- 分层文件 `merged_ads.txt` 等存在；
- 同一规则集合重复运行时，`merged_rules.txt` / `whitelist.txt` /
  `report.html` / `report.md` / `stats.json` 字节级一致（默认确定性）。

可在本地快速验证确定性：

```bash
uv run python -m merger merge --no-audit --output /tmp/out1
uv run python -m merger merge --no-audit --output /tmp/out2
diff -r /tmp/out1 /tmp/out2    # 应无差异（两次抓取的源内容一致时）
```

## 5. 常见故障

| 现象 | 排查 |
|---|---|
| 多个源失败导致任务中止 | `fail_threshold` 触发；查看 `stats.json` 的 `failed_sources`，确认网络/代理与源可用性 |
| 合并很慢 | 确认 `ti_mode: auto`（避免逐域名情报调用）；适当调低 `max_concurrency` 或调大 `source_deadline` |
| 每次都产生新提交 | 确认没有把 `output.report_timestamp` 设为 `true`；确认规则文件无墙钟时间 |
| 白名单评级不符合预期 | 删除 `cache/whitelist_audit_cache.json` 强制重审；调整 `fusion_weights`；检查各层是否被网络环境阻断 |
| DNSBL 层无结果 | 自建环境需放行对 `*.spamhaus.org` / `*.surbl.org` 的 UDP/53 查询 |
| 本地中文输出乱码 | Windows 终端设置 `PYTHONIOENCODING=utf-8` 或使用 PowerShell 7 + UTF-8 代码页 |
| wheel 安装后找不到命令 | 确认安装的是 `adguard-rules-merger`（脚本入口），或改用 `python -m merger` |

## 6. 升级到 V7（来自 V6）

- 配置 schema 向后兼容；新增项都有默认值，可直接沿用旧 `sources.yaml`。
- 建议在 YAML 中显式加入 `ti_mode: auto` 与 `output.report_timestamp: false`
  （仓库内的 `config/sources.yaml` 已更新）。
- 旧缓存可继续使用（磁盘格式版本未变）；CI 缓存键前缀改为 `rule-cache-v7-`，
  首次运行会重建缓存。
- 旧文档中的 `python merge_rules.py` 仍可用；新文档统一为
  `adguard-rules-merger` / `python -m merger`。
