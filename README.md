# AdGuard Rules Merger V8

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Version](https://img.shields.io/badge/Version-8.0.0-blue)
![Tests](https://img.shields.io/badge/Tests-703-green)
![License](https://img.shields.io/badge/License-MIT-green)
![CI](https://github.com/kekai2020/adguard-rules-merger-v8/actions/workflows/ci.yml/badge.svg)

从 18 个上游订阅源自动下载、合并、去重、聚合、消解冲突并输出 AdGuard Home 规则。

V8 是一个**生产就绪（production-ready）**的重构版本：包内 CLI 与可安装的控制台命令、
确定性产物（相同规则即字节级一致）、`uv` 可复现构建、ruff 质量门禁、矩阵 CI、
一键 Release 工作流、以及更完善的配置校验与白名单审计接线。

---

## 功能特性

- **多源合并**：18 个维护良好的订阅源（AdGuard DNS / anti-AD / HaGeZi 系列 / OISD / NoCoin / URLHaus / Phishing Army 等），统一下载。
- **四层去重**：
  - 精确去重（原始行完全一致）
  - 规范化去重（大小写归一化、去除末尾点、可选去除 `www.`）
  - 正则去重（相同正则表达式保留一份）
  - 向上聚合（`a.example.com` + `b.example.com` 收敛为 `||*.example.com^`）。
- **冲突消解**：`@@||example.com^` 白名单规则自动覆盖 block 规则并级联删除其子域名。
- **白名单多层审计**：DNS / URLhaus / ThreatFox / RDAP 域名年龄 / MarketNow 诈骗检测 /
  Spamhaus DBL + SURBL DNSBL / VirusTotal / AI 分类，共 8 层纵深防御，输出安全/可疑/
  恶意分级文件。
- **多格式输出**：AdGuard、Hosts、纯域名、Clash、Surge、SmartDNS，以及按类别拆分的分层文件。
- **增量缓存**：HTTP ETag / Last-Modified / SHA-256 内容哈希 + 解析结果 sidecar，
  304 不重下、内容不变不重解析。
- **确定性产物**：提交的规则 / 报告 / `stats.json` 默认不含墙钟时间与运行耗时，
  相同输入产生字节级一致的输出，CI 只在规则真正变化时提交。
- **GitHub Actions 自动更新**：每日 UTC 0 点运行，自动提交到 `output/` 目录，无需服务器。
- **并发下载**：`aiohttp` 异步，50 并发，硬超时 + 指数退避（deadline 兜底）。
- **内存优化**：来源溯源用整数位掩码、通配符流式聚合、解析结果缓存，百万级规则低内存。
- **专业分析报告**：交互式 HTML 仪表盘（ECharts）+ Markdown 报告，含优化漏斗、分类分布、
  按源贡献、源间重复矩阵、白名单审计、性能指标。

---

## 快速开始

### 环境要求

- Python 3.10+（开发环境推荐 3.12/3.13）
- 推荐使用 [uv](https://docs.astral.sh/uv/)（项目已带 `uv.lock`），也可用 pip / conda。

### 方式一：uv（推荐，可复现）

```bash
git clone https://github.com/kekai2020/adguard-rules-merger-v8.git
cd adguard-rules-merger-v8
uv sync --extra dev        # 安装运行依赖 + 开发/测试/ruff 依赖（锁定版本）
uv run adguard-rules-merger merge --config config/sources.yaml
```

`uv sync` 会自动按 `.python-version` 创建虚拟环境并把项目以可编辑方式安装，
随后直接可用控制台命令 `adguard-rules-merger`。

### 方式二：pip 安装

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python merge_rules.py merge --config config/sources.yaml
```

### 方式三：构建并安装 wheel

```bash
uv sync --extra dev
uv run python -m build
pip install dist/adguard_rules_merger-8.0.0-py3-none-any.whl
adguard-rules-merger version
```

### 方式四：Docker（可选）

```bash
docker build -t adguard-rules-merger:8.0.0 .
docker run --rm -v "$PWD/output:/app/output" -v "$PWD/cache:/app/cache" \
  adguard-rules-merger:8.0.0 merge --config config/sources.yaml
```

---

## 命令行用法

安装后提供控制台命令 `adguard-rules-merger`（等价于 `python -m merger` 或
传统入口 `python merge_rules.py`）：

```bash
# 执行合并（主命令）
uv run adguard-rules-merger merge --config config/sources.yaml

# 校验配置（不联网）
uv run adguard-rules-merger validate config/sources.yaml
uv run adguard-rules-merger validate config/sources.yaml --json

# 查看配置的源清单
uv run adguard-rules-merger sources                 # 仅启用的源
uv run adguard-rules-merger sources --all           # 含已停用的源

# 查看 / 清理本地缓存
uv run adguard-rules-merger cache stats
uv run adguard-rules-merger cache clear --yes

# 版本
uv run adguard-rules-merger version
```

`merge` 常用选项：

| 选项 | 说明 |
|---|---|
| `--config, -c` | 源配置 YAML 路径 |
| `--output, -o` | 覆盖输出目录 |
| `--cache-dir` | 覆盖缓存目录 |
| `--timeout` | 覆盖单源超时（秒） |
| `--concurrency` | 覆盖并发数 |
| `--no-audit` | 跳过白名单多层审计（离线快速合并） |
| `--verbose, -v` / `--quiet, -q` | 调试日志 / 仅错误 |

---

## 输出文件

| 文件 | 说明 |
|---|---|
| `merged_rules.txt` | 合并后的 AdGuard block 规则（含 `||domain^` 与 `/regex/`） |
| `whitelist.txt` | AdGuard allow 白名单（`@@||domain^`） |
| `whitelist_safe.txt` / `whitelist_suspicious.txt` / `whitelist_malicious.txt` | 白名单分级（来自多层审计） |
| `whitelist_by_category/*.txt` | 按 CDN / 分析 / 广告跟踪 / 公共网站等用途分类 |
| `merged_ads.txt` / `merged_malware.txt` / `merged_tracking.txt` / `merged_phishing.txt` / `merged_mining.txt` / `merged_other.txt` | 按类别拆分的分层文件 |
| `hosts.txt` | `0.0.0.0 domain` 主机格式 |
| `domains.txt` | 纯域名列表（每行一个） |
| `clash.yaml` | Clash `DOMAIN-SUFFIX` 规则集 |
| `surge.list` | Surge `DOMAIN-SUFFIX` 规则集 |
| `smartdns.conf` | SmartDNS `address /domain/#` 屏蔽配置 |
| `stats.json` | 机器可读的优化报告（确定性：默认不含运行耗时） |
| `conflicts.json` | 被白名单覆盖的 block 规则明细 |
| `contributions.json` | 每个源的独占/共享规则贡献统计 |
| `report.html` | 交互式分析仪表盘 |
| `report.md` | Markdown 分析报告 |
| `added.txt` / `removed.txt` | 相对上次的域名增减（需启用 `diff_against`） |

---

## 确定性产物（V8 重点）

所有**提交到仓库**的文件都以内容哈希作为 `Version`，且默认不写入墙钟时间：

- `merged_rules.txt` / `whitelist.txt` / 分层文件：相同规则即字节级一致；
- `report.html` / `report.md` / `stats.json`：默认不包含生成时间与运行耗时，
  改为显示**内容版本**。

因此 GitHub Actions 的「仅在规则变化时提交」逻辑不会再被每次都变化的时间戳/耗时
干扰。若需要在报告里看到人类可读的生成时间与耗时，在 `config/sources.yaml` 中设置：

```yaml
output:
  report_timestamp: true   # 默认 false（确定性）
```

该模式也遵循可复现构建环境变量 `SOURCE_DATE_EPOCH`（设置后用它作为报告时间）。

---

## AdGuard Home 订阅

GitHub Actions 运行后，将以下 raw URL 填入 AdGuard Home → DNS 设置 → 过滤名单：

```
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger-v8/main/output/merged_rules.txt
```

白名单：

```
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger-v8/main/output/whitelist.txt
```

纯域名（Pi-hole / 其他工具）：

```
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger-v8/main/output/domains.txt
```

分级白名单：

```
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger-v8/main/output/whitelist_safe.txt
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger-v8/main/output/whitelist_suspicious.txt
https://raw.githubusercontent.com/kekai2020/adguard-rules-merger-v8/main/output/whitelist_malicious.txt
```

---

## 配置说明

配置文件为 `config/sources.yaml`，关键段落：

### 合并与下载

```yaml
timeout: 120
max_concurrency: 50
fail_threshold: 0.5      # 超过该比例的源失败则中止（防止产出空规则）
download:
  retry_count: 2
  retry_delay: 1.5
  source_deadline: 120   # 单源硬超时预算（含全部重试），到期回退陈旧缓存
  backoff: linear        # linear | exponential（V8 校验拼写）
```

### 去重 / 质量过滤 / 聚合

```yaml
dedup:
  strip_www: true
quality_filter:
  enabled: true
  min_domain_length: 4
  max_domain_length: 253
  filter_localhost: true
  filter_ip_rules: false
aggregation:
  enabled: true
  wildcard_child_aggregation: true
  wildcard_promotion_threshold: 0     # 0 关闭；N 个精确兄弟升级为一个通配符
  promotion_mode: count              # count | pattern
  psl_guard: true
```

### 块规则分类（可选离线重判，默认关闭）

默认块规则类别只来自各源在 `sources:` 声明。开启后，引擎对块规则做离线高置信
重判：仅当注册域精确匹配已知广告/分析/追踪库（置信度 0.9）时才把规则归入
`ads`/`tracking`；`cdn`、支付、隐私安全、`other` 一律保留来源类别，来源已声明的
`malware`/`phishing`/`mining` 安全桶永不被降级。默认关闭，关闭时产物字节与默认完全一致。

```yaml
classification:
  enabled: false                    # 总开关，默认关闭
  rejudge_registered_only: true    # 仅高置信注册域精确匹配覆盖（false 放宽到中置信前缀）
  seed_file: ""                    # 可选离线外部种子文件（Shallalist `域;类` / UT1 `域,ID`）；缺失/损坏安全跳过
  use_cname_hints: false           # 可选 CNAME 线索（dnspython，2s 超时）；仅当 CNAME 目标自身 0.9 精确命中才接受，默认关
```

- 内置精选种子表 `merger/data/category_seeds.json`（`{注册域: 9 类}`）以 setdefault 补缺，手写表永远优先；种子与外部表都只在 0.9 注册域精确匹配时参与，不放宽到中置信(0.6)。
- 外部 `seed_file` 的类别 ID/名称经 `EXTERNAL_CATEGORY_MAP` 归并到现有 9 类，归并不上（赌博/色情/恶意等）丢弃为 `other`，绝不强行入桶；文件缺失/OSError/解析异常只记 warning 并返回空，不中断合并。
- `use_cname_hints` 开启且注册域未命中时，用系统 resolver 解析短 CNAME 链（包在 executor，超时/NXDOMAIN/无 CNAME/任何异常均回退）；只有 CNAME 目标自身命中注册域精确(0.9)才采纳该结论，仍走 `BLOCK_BUCKET_MAP`、仍受安全桶不降级约束；中/低置信 CNAME 保留来源类。默认 False（DNS 结果有环境相关性，不进确定性默认路径）。

### 白名单多层审计

```yaml
whitelist_audit:
  enabled: true
  ti_mode: auto          # auto（CI 推荐，整包离线匹配）| api（逐域名实时，慢）
  use_dns: true
  # 可选 DNS-over-HTTPS JSON 解析器（如 NextDNS 个人配置）；留空用系统解析器。
  # 失败自动回退系统 DNS，并参与审计缓存指纹。例：https://dns.nextdns.io/<id>
  doh_endpoint: ""
  use_urlhaus: true
  use_threatfox: true
  use_rdap: true
  use_scam_check: true
  use_dnsbl: true
  use_heuristics: true
  # 离线同形字/typosquat 层（零网络，默认开启）：西里尔/希腊形近字折叠 +
  # 编辑距离对标常见品牌注册域，识别 google / paypal / alipay 等仿冒域名。
  use_homograph: true
  # MX/SPF 缺失线索（需要 DNS，默认关闭）。
  use_dns_mx: false
  # 可选在线情报层（默认关闭，缺 key 即跳过；任一失败回退 error，不阻断其它层）。
  use_gsb: false
  gsb_api_key: ""          # Google Safe Browsing
  use_phishtank: false
  phishtank_api_key: ""    # PhishTank
  use_urlscan: false
  urlscan_api_key: ""      # urlscan（key 可选）
  use_crtsh: false         # 证书透明度（crt.sh），仅接口
  fusion_weights:        # 可选：覆盖各层证据的融合权重（浅合并，未列键保持默认）
    threat_intel: 40
    dnsbl_malicious: 30
    scam_confirmed: 30
    scam_suspicious: 20
    dns_nxdomain: 15
    rdap_new_domain: 15
    heuristics: 10
    # homograph: 12 / dns_mx_missing: 8 / gsb_malicious: 35
    # phishtank_malicious: 30 / urlscan_suspicious: 20 / dns_private_ip: 20
    # dnsbl_listed: 15
    # ...
  use_virustotal: false
  virustotal_api_key: ""
  ai:
    enabled: false
    api_key: ""
```

API key 也可通过环境变量提供（不写进配置；在线层仍需在 YAML 显式开启）：

```bash
export VIRUSTOTAL_API_KEY="your-key"
export OPENAI_API_KEY="sk-..."
export GSB_API_KEY="..."
export PHISHTANK_API_KEY="..."
export URLSCAN_API_KEY="..."
```

### 输出

```yaml
output:
  directory: output
  formats: [adguard, whitelist, hosts, domains, clash, surge, smartdns]
  tiered: true
  report: true
  report_timestamp: false  # V8：默认确定性
```

---

## GitHub Actions 自动更新

仓库包含三个工作流：

| 工作流 | 触发 | 作用 |
|---|---|---|
| `.github/workflows/ci.yml` | push / PR / 手动 | ruff 检查 + 格式校验、Python 3.11/3.13 矩阵测试、构建 wheel/sdist 并验证控制台命令 |
| `.github/workflows/merge.yml` | 每日 UTC 0 点 / 手动 / 配置变更 | 跑测试后执行合并、校验产物、把 `output/` 提交回 `main` |
| `.github/workflows/release.yml` | 推送 `v*` 标签 | 构建 wheel/sdist 并发布到 GitHub Release |

缓存使用 `actions/cache`（缓存键前缀 `rule-cache-v8-`），可显著减少重复下载。

发布一个版本：

```bash
git tag v8.0.0
git push origin v8.0.0   # release.yml 自动构建并发布 Release
```

---

## 本地开发

```bash
uv sync --extra dev

# 运行测试（默认跳过带 slow 标记的网络/基准测试）
uv run pytest

# 包含性能基准
uv run pytest -m slow

# 代码风格检查与格式化
uv run ruff check merger merge_rules.py config_loader.py tests
uv run ruff format merger merge_rules.py config_loader.py tests

# 构建产物
uv run python -m build
```

更多内容见：

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — 架构、管线、模块与数据模型
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) — 开发、测试、代码规范与版本约定
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — 部署、GitHub Actions、Docker、故障排查
- [`CHANGELOG.md`](CHANGELOG.md) — 版本变更记录

---

## 项目结构

```
adguard-rules-merger/
├── merger/                  # 核心包
│   ├── cli.py / __main__.py # 包内 CLI（控制台命令 / python -m merger）
│   ├── config.py            # 配置模型与校验（pydantic）
│   ├── parser.py            # 流式解析器
│   ├── models.py            # Rule / SourceMeta（整数位掩码溯源）
│   ├── cache.py / feed_cache.py  # ETag/内容哈希/sidecar 缓存 + 情报源 blob 缓存
│   ├── exporter.py          # 多格式流式导出
│   ├── ports.py             # IO 薄端口（HTTP/DNS/Cache seam）
│   ├── domain_classifier/    # 域名用途分类（高置信可映射块规则桶；v8.2 拆为子包）
│   │   ├── api.py / rules.py / ruleset.py / seeds.py
│   ├── homograph.py         # 离线同形字/typosquat 品牌对标
│   ├── threat_feeds.py      # 威胁情报源下载/索引
│   ├── dnsx.py / scam_check.py / whois_audit.py / virustotal_audit.py / ai_classifier.py
│   ├── version.py           # 版本号唯一事实源
│   ├── core/                # 合并内核
│   │   ├── engine.py        #   异步引擎：调度、去重、聚合、冲突、审计编排
│   │   ├── fetch.py / stages.py / stats.py / outcome.py
│   │   ├── aggregation.py / conflicts.py
│   ├── report/               # 报告渲染（HTML/Markdown，确定性）
│   │   ├── html.py / markdown.py / render.py / analysis.py
│   └── whitelist_audit/     # 多层白名单威胁情报审计
│       ├── engine.py / fusion.py / registry.py / seam.py
│       ├── config.py / constants.py / disk_cache.py
│       ├── dns_doh.py / dnsbl.py / rdap.py / online.py / threat_intel.py / heuristics.py
├── config/sources.yaml      # 源配置
├── merge_rules.py           # 兼容启动器（旧入口，委托给 merger.cli）
├── config_loader.py         # 兼容垫片（重导出 merger.config）
├── tests/                   # 703 个单元/集成测试（默认；另有 3 个 slow 网络/基准测试，共 706）
├── .github/workflows/       # ci / merge / release
├── Dockerfile
└── pyproject.toml + uv.lock # 打包与可复现依赖
```

---

## License

[MIT](LICENSE)
