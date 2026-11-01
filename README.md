# adguard-rules-merger

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Version](https://img.shields.io/badge/Version-8.0.1-blue)
![Tests](https://img.shields.io/badge/Tests-743-green)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://github.com/kekai2020/adguard-rules-merger/actions/workflows/ci.yml/badge.svg)

从 **18 个上游订阅源**自动下载、合并、去重、聚合、审计并输出 AdGuard Home 规则。
生产就绪：确定性产物（相同规则字节级一致）、`uv` 可复现构建、ruff/mypy/vulture
三重门禁、GitHub Actions 全自动每日发布。

---

## 功能特性

- **多源合并**：18 个维护良好的订阅源（AdGuard DNS / anti-AD / HaGeZi 系列 /
  OISD / URLHaus / Phishing Army 等），并发下载，ETag/304 增量 + 4s 负缓存。
- **四层去重**：精确 → 规范化 → 正则 → 向上聚合（含 `$badfilter` 成对取消、
  PSL 守卫、通配提升）。
- **blocks-preserved 冲突政策**：白名单覆盖的拦截规则**保留不删**，重叠明细
  记入 `conflicts.json`，放行交给 AdGuard Home 的 allow 优先语义。
- **白名单多层审计（16 层纵深）**：本地 DNS/DoH、离线启发式、同形字
  typosquat 检测 + URLhaus/ThreatFox/RDAP/MarketNow/DNSBL + 可选
  VirusTotal/AI/GSB/PhishTank/urlscan，证据加权融合，24h 配置指纹磁盘缓存。
- **DNS 可达性审计**（`scripts/dns_coverage_audit.py`）：多 DoH 解析器并发、
  通道自诊断、延时加权两轮分片、判定缓存增量模式——自动找出"已死亡"的
  白名单/拦截域名并写入报告。
- **确定性产物**：提交的规则/报告/stats 默认不含墙钟时间（相同规则集 ⇒
  字节级一致）；设 `report_timestamp: true` 或环境变量
  `MERGER_REPORT_TIMESTAMP=1` 后输出 `! Generated:` 与合并时间、阶段耗时、
  历史波动。
- **专业分析报告**：自包含交互式 HTML + Markdown 双格式——优化漏斗、
  按源贡献、源间重复矩阵、白名单审计详情、**与上次合并的三级对比
  （规则级 + 源级）**、**历史波动趋势**、**DNS 可达性附录**。
- **质量门禁**：743 项测试（4 Python 版本矩阵）、ruff、mypy
  （check_untyped_defs）、vulture 零死代码、依赖无环（AST 实证）。

---

## 快速开始

### 方式一：uv（推荐，可复现）

```bash
git clone https://github.com/kekai2020/adguard-rules-merger.git
cd adguard-rules-merger
uv sync --extra dev        # 运行依赖 + 开发/测试依赖（锁定版本）
uv run adguard-rules-merger merge --config config/sources.yaml
```

### 方式二：pip

```bash
python -m venv .venv && .venv\Scripts\activate   # Linux: source .venv/bin/activate
pip install -r requirements.txt
python merge_rules.py merge --config config/sources.yaml
```

### 方式三：Docker

```bash
docker build -t adguard-rules-merger:8.0.1 .
docker run --rm -v "$PWD/output:/app/output" -v "$PWD/cache:/app/cache" \
  adguard-rules-merger:8.0.1 merge --config config/sources.yaml
```

---

## 命令行用法

```bash
uv run adguard-rules-merger merge --config config/sources.yaml   # 主命令
uv run adguard-rules-merger validate config/sources.yaml         # 校验配置（不联网）
uv run adguard-rules-merger sources [--all]                      # 源清单
uv run adguard-rules-merger cache stats | cache clear --yes      # 缓存管理
uv run adguard-rules-merger version                              # 版本
```

常用选项：`--output` / `--cache-dir` / `--timeout` / `--concurrency` /
`--no-audit` / `--verbose`。

---

## 输出文件

| 文件 | 说明 |
|---|---|
| `merged_rules.txt` | 合并后的 AdGuard block 规则（头部含内容哈希版本；timestamped 模式含 `! Generated:`） |
| `whitelist.txt` | 白名单（`@@||domain^`，与拦截规则分离输出） |
| `whitelist_safe/suspicious/malicious.txt` | 白名单多层审计分级 |
| `whitelist_by_category/*.txt` | 按用途分类的白名单 |
| `merged_ads/malware/tracking/phishing/mining/other.txt` | 按类别分层 |
| `hosts.txt` `domains.txt` `clash.yaml` `surge.list` `smartdns.conf` | 其它格式 |
| `stats.json` | 机器可读优化报告（timestamped 模式含 `generated_at`/`stage_timings`） |
| `conflicts.json` `contributions.json` | 冲突明细 / 按源贡献统计 |
| `history.json` | 运行趋势日志（timestamped 模式） |
| `report.html` `report.md` | 交互式分析报告（漏斗/贡献/矩阵/审计/对比/趋势/DNS 附录） |

---

## 确定性产物与合并时间戳

默认（`report_timestamp: false`）：相同规则集产生**字节级一致**的产物，
CI 只在规则真正变化时提交。

需要时间信息时（二选一）：

```yaml
output:
  report_timestamp: true   # 配置开启
```

```bash
MERGER_REPORT_TIMESTAMP=1 uv run adguard-rules-merger merge   # 环境变量开启
```

开启后：规则文件头 `! Generated:`、`stats.json.generated_at`、
`report.html/md` 的「合并时间」卡片与概览行、阶段耗时表、`history.json`
趋势日志、报告「与上次合并对比」源级增减全部激活。遵循 `SOURCE_DATE_EPOCH`
可复现构建。

---

## DNS 可达性审计（离线工具）

```bash
# 抽样 20,000 条（等距无偏，覆盖全部 18 源），约 5 分钟
uv run python scripts/dns_coverage_audit.py --blocks-sample 20000

# 全量 277 万逐域核验（约 3-4 小时；判定缓存使重复运行只扫增量）
uv run python scripts/dns_coverage_audit.py --blocks-sample 2000000 \
  --concurrency 150 --checkpoint-every 200000
```

- 10 个**无过滤** DoH 端点并发（阿里/DNSPod/360/Cloudflare/Google/Quad9
  unfiltered/AdGuard unfiltered/DNS.SB），通道自诊断门控——存活解析器不足
  时自动中止，绝不产出假判定；
- 三值判定：可达（任一成功）/ 已死亡（≥min_live 个 NXDOMAIN 权威应答）/
  未判定（超时永不判死）；
- 输出 `dns_audit.{json,md}` 并把统计、按源归因、**白名单清理建议**写入
  `report.md/html` §16。

---

## GitHub Actions 自动化

| 工作流 | 触发 | 作用 |
|---|---|---|
| `ci.yml` | push / PR | ruff + 4×Python 版本矩阵测试 + wheel/sdist 构建验证 |
| `merge.yml` | **每日 00:00 UTC** / 手动 / 配置变更 | 合并 + 白名单审计 + DNS 抽样审计 + 校验产物 + 自动提交发布 |
| `dns-audit.yml` | 手动 dispatch | 独立 DNS 审计（dispatch 可传全量样本参数） |

订阅地址（首次 `merge.yml` 成功后可用）：

```
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger/main/output/merged_rules.txt
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger/main/output/whitelist.txt
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger/main/output/domains.txt
```

可选 Secrets：`VIRUSTOTAL_API_KEY` / `OPENAI_API_KEY`（对应审计层自动启用）。

---

## 本地开发

```bash
uv sync --extra dev
uv run pytest                          # 743 项测试（默认跳过 3 个 slow）
uv run pytest -m slow                  # 含网络/基准慢测试
uv run ruff check merger merge_rules.py config_loader.py tests
uv run mypy merger                     # check_untyped_defs
uvx vulture merger --min-confidence 80 # 死代码
```

架构与数据流详见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)（含 Mermaid
架构图），开发规范见 [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)，
部署与 CI 细节见 [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)。

---

## 项目结构

```
adguard-rules-merger/
├── merger/                  # 核心包（51 模块，依赖无环）
│   ├── core/                # engine 编排 · fetch 组合式抓取 · stats · stages
│   ├── whitelist_audit/     # 16 层审计：registry/fusion/缓存/信号层
│   ├── report/              # analysis 共享层 + html/md 双渲染
│   ├── domain_classifier/   # 域名用途分类（规则表/种子/规则集）
│   ├── parser · models · cache · exporter · config · cli · ports
│   └── version.py           # 版本唯一事实源
├── scripts/dns_coverage_audit.py   # DNS 可达性审计（离线工具）
├── config/sources.yaml      # 源与管线配置
├── tests/                   # 743 项测试（含 hypothesis 属性测试）
└── .github/workflows/       # ci / merge / dns-audit
```

---

## License

[MIT](LICENSE)
