# AdGuard Rules Merger V7.0.0 — 优化改进建议分析书

> 分析对象：`adguard-rules-merger-v7-7.0.0`（Python 3.10+，uv/pip 双栈）
> 方法：逐模块阅读源码 + 静态检查（ruff）+ 全量单测 + 端到端离线合并 + 针对性探针复现
> 分析日期：2026-10-27
>
> **🛠️ 修复执行**：第 9/12/13 章的 P0/P1 缺陷已按[修复执行与验证报告](FIX_REPORT.md)落地（`pytest` 557 passed，`ruff` 全绿）；下文表格中已修复项标注 `✅ 已修`。

---

## 0. 摘要

| 维度 | 结论 |
|---|---|
| 架构质量 | **高**。分层清晰（fetch→parse→dedup→aggregate→conflict→classify→stats→export→report），确定性产物、位掩码溯源、IO 端口 seam、渲染与写盘分离等设计成熟 |
| 测试 | **557 passed / 3 slow deselected**（实际收集 560 个），但 `cache clear()` 路径**无测试**，导致一个真实 bug 逃逸 |
| 静态检查 | `ruff check` 与 `ruff format --check` 全绿（84 文件） |
| 已复现缺陷 | **2 个 P0**：①`SourceCache.clear()` 引用未定义属性；②Windows GBK 控制台 CLI 崩溃 |
| 主要瓶颈 | 分类器逐条 + 每域一次 PSL 解析；统计两两配对 O(n²)；缓存索引全量落盘；对规则列表约 10 次全量遍历 |
| 改进优先级 | P0 缺陷修复 → P1 分类正确性/性能与引擎接线 → P2 工程化门禁 → P3 体验打磨 |

---

## 1. 已落地的工程化基线

| 项 | 结果 |
|---|---|
| 虚拟环境 | `uv sync --extra dev` 创建 `.venv`（Python 3.12.14），安装 40 包，项目以可编辑方式安装 |
| 测试 | `pytest` → **557 passed, 3 deselected in 33s** |
| 静态检查 | `ruff check` 全过；`ruff format --check` → 84 files already formatted |
| 校验 | `python -m merger validate config/sources.yaml` → 18/18 源启用 |
| 端到端 | 本地文件源离线合并：parse→dedup→aggregate→conflict→export→report 全通，二次运行走 parsed-cache 且**字节一致**（确定性成立） |
| 版本控制 | `git init -b main`，基线提交含 134 文件；`release/pkg/`、`release/bench/` 已加入 `.gitignore` |

---

## 2. 架构与设计评估（亮点）

1. **确定性产物**：`stages.compute_content_version`（`core/stages.py:43`）以 SHA-256 前 12 位作为版本号；报告/stat 在 `report_timestamp=False` 时剔除墙钟时间与耗时（`exporter.py:126-132, 352-355`），使「相同规则 → 字节一致」，CI 只在真正变化时提交。
2. **位掩码溯源**：`Rule.source_mask` 用整数 bitmask 记录来源（`models.py:88-149`），`merge_from` 是 O(1) 的 `|=`，百万级规则下内存平坦；`iter_source_keys` 惰性遍历避免每规则分配元组。
3. **IO 端口 seam**：`ports.py` 用 Protocol + 默认适配器隔离 HTTP/DNS/Cache，离线测试可注入 fake，且生产行为不变。
4. **渲染/写盘分离（R5）**：`report/render.py` 只产出 `(html, md)` 字符串，`Exporter.write_report` 只负责原子写盘，避免渲染逻辑与 IO 耦合。
5. **缓存分层**：ETag/Last-Modified 条件请求 + SHA-256 内容哈希 + 解析结果 sidecar（pickle），304 不重下、内容不变不重解析（`cache.py`）。
6. **配置即校验**：pydantic 模型 + `Literal` 枚举，拼写错误在加载期 fail-fast（`config.py`）。
7. **安全默认**：分类重判、白名单审计、威胁情报层默认关闭；缺 key 安静跳过，绝不阻断合并。
8. **XSS 防护**：报告内嵌 JSON 对 `</` 做转义，防止恶意域名注入 `<script>`（`report/analysis.py:105-113`）。

---

## 3. 缺陷清单（已复现，按严重度）

### 3.1 【P0】`SourceCache.clear()` 引用未定义属性 —— `cache clear` 必然失败

- **位置**：`merger/cache.py:356` 与 `merger/cache.py:361`
  ```python
  feeds = self._dir / "feeds"
  audit_cache = self._dir / "whitelist_audit_cache.json"
  ```
- **根因**：`SourceCache.__init__` 只定义 `self.cache_dir`（`cache.py:69`），`self._dir` 是 `FeedCache` 的属性（`feed_cache.py:25`），此处误用。
- **实测**：
  ```
  clear() RAISED: AttributeError 'SourceCache' object has no attribute '_dir'
  ```
- **影响**：`merger cache clear` 会先删掉 index/content/parsed，再在 feeds 处抛异常 → **半清理 + CLI 报错退出 1**（`cli.py:290-294` 捕获后打印 `✗ Unable to clear cache`）。feeds/audit 缓存永远清不掉。
- **修复**：改为 `self.cache_dir / "feeds"`、`self.cache_dir / "whitelist_audit_cache.json"`。
- **测试缺口**：`tests/test_cache.py` 只测 get/store/evict/conditional，**没有任何 `clear()` 用例**，故 560 个测试全绿仍放行。

### 3.2 【P0】Windows GBK 控制台 UnicodeEncodeError —— CLI 在中文 Windows 崩溃

- **位置**：`cli.py` 多处 `typer.secho("✓ ...")` / `typer.secho("✗ ...")`（如 `cli.py:160, 176, 208`），使用 U+2713/U+2717。
- **实测**：`python -m merger validate config/sources.yaml` 在 cp936 控制台抛
  ```
  UnicodeEncodeError: 'gbk' codec can't encode character '\u2713' in position 0
  ```
- **影响**：`merge/validate/sources/cache` 全部在**结尾横幅**处崩溃（`merge` 更糟：产物已写出后才退出 1）。
- **修复（任选）**：CLI 入口 `sys.stdout.reconfigure(encoding="utf-8", errors="replace")`；或把 `✓/✗` 换成 ASCII；或文档要求 `set PYTHONIOENCODING=utf-8`。
- **验证**：`PYTHONIOENCODING=utf-8` 后 `validate` 正常输出（已实测）。

### 3.3 【P1】`config/sources.yaml` 硬编码 NextDNS DoH endpoint

- **位置**：`config/sources.yaml:87` → `doh_endpoint: "https://dns.nextdns.io/3fef68"`
- **风险**：NextDNS profile ID 属半敏感配置，随仓库/CI 公开可被外部查询。与其它 API key「环境变量注入」的约定不一致。
- **修复**：留空默认系统解析器，或从环境变量注入（复用 `resolve_api_keys` 模式）。

### 3.4 【P2】类型注解与实际不符（2 处）

| 位置 | 注解 | 实际 |
|---|---|---|
| `core/fetch.py:201-216` `_parse_text` | `tuple[list[Rule], int×6]`（7 元） | **8 元**（rules + 7 计数器，含 `unsupported_modifier`） |
| `core/aggregation.py:103` `_aggregate` | `dict[tuple[str, bool], Rule]`（2 元 key） | **3 元 key** `(normalized_domain, wildcard, modifiers)`（见 `fetch.py:346`） |

运行时因解包位置一致未崩，但会误导调用方，且若接入 mypy 会直接报错。

---

## 4. 性能瓶颈分析

### 4.1 【P1】分类器逐条分类、无批量/记忆化

- **位置**：`core/stats.py:217-258` `_rejudge_block_categories`
  ```python
  for r in blocks:
      ...
      offline_cat, confidence, _ = classify_domain_with_confidence(domain, ruleset=ruleset)
  ```
- **问题**：每条规则独立调用分类器，每次内部执行 `tldextract.extract`（`domain_classifier.py:995`）+ 字典查找。几十万规则下 `tldextract` 是主开销，且大量规则共享同一注册域（如 `*.googlevideo.com` 下数百子域）。
- **改进**：按 `normalized_domain` 分组 → 对**唯一域名集合**分类一次建 `{domain: (bucket, conf)}` 映射 → 套用到规则；CNAME 救援同样按唯一域去重。

### 4.2 【P2】`_compute_stats` 的成对重叠 O(n²)

- **位置**：`core/stats.py:75-83`
  ```python
  for i in range(n):
      for j in range(i + 1, n):
          pair_overlap[(lo, hi)] += 1
  ```
- **问题**：对每条规则遍历其来源集合的两两组合；18 源高度共享的规则单条就要算 `C(18,2)=153` 对。规则数 × 来源数² 增长。
- **改进**：相同 `source_mask` 的规则只算一次（`Counter(mask)` 后按 mask 组合展开），把 O(R·S²) 降到 O(U·S²)，U=唯一 mask 数（≤ `2^S`，实际远小于 R）。

### 4.3 【P2】缓存索引每次 store 全量落盘

- **位置**：`cache.py:224-263 store()` 置 `_dirty=True`；`fetch.py:165-173` 每次 store 后立即 `save_if_dirty()`。
- **问题**：18 源并发下载 → 最多 18 次全量 `json.dumps(index)` + 原子替换，索引随缓存增长线性变大。
- **改进**：节流（如按时间/条数批量 flush），或 `close()` 时统一落盘；304/负缓存场景同理。

### 4.4 【P2】对最终规则列表约 10 次全量遍历

- 依次为：`sort_merged` → `_rejudge_block_categories`（可选）→ `compute_contributions`（2 遍）→ `compute_modifier_stats`（1 遍）→ `compute_content_version`（1 遍）→ `write_adguard` → `write_tiered` → `write_stats` 的 `Counter` → `_domain_rules`（1 遍，已缓存）→ `analyze_rules`（2 遍）。
- 百万级规则下每遍数秒。**改进**：合并 `write_stats` 的 category 计数（复用 `export_all` 已算的 `cat_counts`，见 `exporter.py:487` 与 `exporter.py:287` 重复计算），其余保留可读性。

### 4.5 【P3】`fetch_all` 一次性构建全部协程

- **位置**：`fetch.py:313` `asyncio.as_completed([bounded(s) for s in sources])`
- 18 源无碍；但若源数量上千，会一次性创建上千协程对象。可用 `asyncio.TaskGroup`/池化信号量迭代提交。

---

## 5. 正确性与健壮性

### 5.1 【P1】子域名只匹配「首个标签」→ 大量漏判（已实测）

- **位置**：`domain_classifier.py:915-919` `_first_subdomain_label` 只取 `ext.subdomain.split(".")[0]`；`classify_with_confidence:1009-1013` 只查该标签。
- **实测**：
  | 域名 | 结果 |
  |---|---|
  | `api.tracking.example.com` | **other / 无匹配**（tracking 在第 2 个标签） |
  | `img.ads.example.com` | **other / 无匹配**（ads 在第 2 个标签） |
  | `cdn.example.com` | cdn 0.6 ✓ |
- **改进**：遍历子域名全部标签（或「首标签 + 注册域相邻标签」），任一命中即可，并给邻接标签更高权重。

### 5.2 【P2】多类别冲突「先到先得」不确定

- **位置**：`domain_classifier.py:941-950` 用 `setdefault` 依次灌入 `REGISTERED_DOMAIN_RULES` 与 `category_seeds.json`。
- **问题**：同一域名若出现在多个类别，静默取**列表顺序**决定者，不可预测、难审计。
- **改进**：为每类加显式优先级（或置信度/特异性评分），冲突时确定性裁决。

### 5.3 【P2】子域名前缀规则过度泛化 → 0.6 误判（已实测）

- **位置**：`domain_classifier.py:580-638`，`cdn` 含 `file/files/media/content/resource/static/edge/proxy/mirror/download/cache`；`analytics` 含 `report/event/beacon/monitor/stats/trace/logging`。
- **实测**：`content.example.com`、`file.example.com`、`media.example.com`、`edge.example.com` → 全判 `cdn`(0.6)；`report.example.com` → `analytics`(0.6)。
- **改进**：移出过度泛化的词，或要求「≥2 个标签同时命中」才给 0.6；保留 `cdn./ads./analytics./tracking.` 等强信号。

### 5.4 【P3】CNAME 置信度语义不一致

- `classify_with_confidence` 对 CNAME 返回 `conf×0.8`（≤0.72），但引擎重判（`stats.py:243-248`）直接用 CNAME 目标自身 0.9。两处对「可接受阈值」理解不同，易踩坑。建议统一并写入 docstring。

### 5.5 【P3】`_extract_suffix` 用硬编码二级后缀表，非 PSL

- **位置**：`report/analysis.py:74-81`，`second_level_cc = {"co","com","net","org","gov","edu"}`。
- **问题**：这是对 PSL 的近似，`example.com.au`、`example.co.jp` 等会归错后缀桶（仅影响报告 Top 后缀统计，不影响规则）。
- **改进**：直接用已依赖的 `tldextract`（`domain_classifier.py:41` 已有离线实例），或明确注释为启发式。

### 5.6 【P3】`_resolve_cname_hints` 的 `except Exception`

- **位置**：`stats.py:209-215`。设计上「never raises」合理，但会吞掉非预期异常；可收窄到 `(OSError, RuntimeError)` 并记 debug 日志。

---

## 6. 可维护性与工程化

| # | 项 | 位置 | 建议 |
|---|---|---|---|
| 1 | **引擎 ~70 个构造参数** + `from_config` 手写接线 | `engine.py:43-123, 224-298` | 引入单一配置 dataclass / 复用 `MergeConfig`，减少新增配置项「5 处同步」的漏接风险 |
| 2 | **分类种子数据内联在 1101 行代码**（476 注册域 + 113 前缀） | `domain_classifier.py:48-724` | 抽成数据文件（与 `category_seeds.json` 同构），便于审阅/扩展 |
| 3 | **`category_seeds.json` 仅 40 条**，`microsoft_telemetry`/`cdn` 近乎空壳 | `merger/data/category_seeds.json` | 扩大覆盖面或改用外部 `seed_file`（Shallalist/UT1） |
| 4 | **`requirements.txt` 与 pyproject 重复** | `requirements.txt` | 用 `uv export --format requirements-txt` 生成，或注明仅 pip 兼容 |
| 5 | **CI 无类型检查** | `.github/workflows/ci.yml` | 加 `mypy`（或 pyright）到 dev 依赖与 CI，可拦住 §3.4 类问题 |
| 6 | **CI 矩阵无 3.14** | `ci.yml:40` | 加 `'3.14'`，classifiers 同步 |
| 7 | **README 陈旧** | `README.md:5,333,406` | 徽章 `Tests-268`→560；「487/490」→560；「3.11/3.13」→3.10–3.14 |
| 8 | **Dockerfile 用 `uv:latest`** | `Dockerfile:16` | pin 具体版本以求可复现 |
| 9 | **无 pre-commit** | — | 加 `.pre-commit-config.yaml`（ruff check + format） |
| 10 | **HTML 报告依赖 CDN 且无 SRI** | `report/html.py:308` | 加 `integrity`+`crossorigin`；或提供内联开关（离线场景） |

---

## 7. 优化路线图

### P0 — 立即修复（影响可用性）
1. `cache.py:356,361` 修 `self._dir` → `self.cache_dir`，并补 `tests/test_cache.py` 的 `clear()` 用例（覆盖「清 feeds/audit」断言）。
2. `cli.py` 入口重配 stdout/stderr 为 UTF-8，或替换 `✓/✗` 为 ASCII。

### P1 — 近期（正确性 + 关键性能）
3. 分类器：子域名**全标签**匹配；`_rejudge_block_categories` 按唯一域**批量分类**。
4. `config/sources.yaml` 移除硬编码 NextDNS ID（环境变量注入）。
5. 引擎参数收敛为配置对象，降低接线成本。

### P2 — 中期（性能 + 工程化）
6. `_compute_stats` 按唯一 `source_mask` 聚合，消除 O(n²) 热点。
7. 缓存索引节流落盘；`write_stats` 复用 `cat_counts`。
8. 分类多类别冲突确定性裁决；泛化前缀收紧。
9. CI 加 mypy + 3.14；README 数字/矩阵校正。
10. 主分类表外置为数据文件；补充种子覆盖。

### P3 — 长期（打磨）
11. 报告后缀统计改用 `tldextract`。
12. CNAME 置信度语义统一；`_resolve_cname_hints` 异常收窄。
13. HTML 报告 SRI / 内联开关；pre-commit；Dockerfile pin。

---

## 8. 结论

本项目**工程质量已属上乘**：确定性、可复现、分层清晰、测试充分（560 个）。当前最值得投入的是：

- **两个 P0 缺陷**（`cache clear` 崩溃、Windows 控制台崩溃）——直接损害日常使用；
- **分类逻辑三处**（首标签漏判、多类别先到先得、泛化前缀误判）——决定了「离线重判」这条可选链路的实际价值；
- **两处性能热点**（逐条分类、成对重叠 O(n²)）——决定了百万级规则下的可扩展性。

以上改动均不触碰默认确定性产物路径（分类/审计默认关闭），可按 P0→P3 渐进落地、每步补测。

---

## 附录：关键代码位置索引

| 主题 | 文件:行 |
|---|---|
| `clear()` 缺陷 | `merger/cache.py:356, 361` |
| 缓存索引落盘 | `merger/cache.py:114-125` |
| 逐条分类 | `merger/core/stats.py:217-258` |
| 成对重叠 O(n²) | `merger/core/stats.py:75-83` |
| CNAME 0.9 判定 | `merger/core/stats.py:243-248` |
| `_parse_text` 注解 | `merger/core/fetch.py:201-216` |
| `as_completed` 列表 | `merger/core/fetch.py:313` |
| `_aggregate` 注解 | `merger/core/aggregation.py:103` |
| 首标签匹配 | `merger/domain_classifier.py:915-919, 1009-1013` |
| setdefault 冲突 | `merger/domain_classifier.py:941-950` |
| 泛化前缀 | `merger/domain_classifier.py:580-638` |
| 引擎参数/接线 | `merger/core/engine.py:43-123, 224-298` |
| CLI ✓/✗ | `merger/cli.py:160, 176, 208` |
| NextDNS ID | `config/sources.yaml:87` |
| 两次 `list()` | `merger/core/stages.py:51` |
| 域缓存 | `merger/exporter.py:189-200` |
| `write_tiered` | `merger/exporter.py:262-284` |
| 后缀启发式 | `merger/report/analysis.py:74-81` |
| 报告 CDN | `merger/report/html.py:308` |
| README 陈旧计数 | `README.md:5, 333, 406` |

---

## 9. 功能模块缺陷清单（功能级）

> 本节按「功能模块」组织，聚焦**具体功能失效/契约不符**，与第 3 节的缺陷清单互补。
> 标注 ⚠️ 者为本次新增、此前未收录。

### 9.1 下载层 `core/fetch.py`

| # | 缺陷 | 位置 | 现象 | 建议 | 级别 |
|---|---|---|---|---|---|
| F-1 | ⚠️ **`file://` 源契约违约** | `config.py:251-254` 放行 `file` scheme；`fetch.py:70-71` 只用 `Path(url).exists()` 判本地文件 | `file:///C:/x/rules.txt` 被当相对路径 → `exists()=False` → 走 aiohttp → `NonHttpUrlClientError` 失败（已实测） | `_fetch_text` 先 `urlparse(url).scheme=="file"` 转本地路径；或从 `valid_url` 移除 `file` | P2 |
| F-2 | 线程池共享瓶颈 | `fetch.py:262` `run_in_executor(None, ...)` | 默认线程池 `min(32, cpu+4)`，大源并发解析时排队 | 专用 `ThreadPoolExecutor(max_workers=concurrency)` | P3 |
| F-3 | 负缓存不复位 | `fetch.py:187-188` | 同一 URL 先失败后（同进程内）不会重试成功 | CLI 一次性场景无碍；库场景需 `clear_negative()` | P3 |

### 9.2 解析层 `parser.py`

| # | 缺陷 | 位置 | 现象 | 建议 | 级别 |
|---|---|---|---|---|---|
| P-1 | hosts 不校验 octet | `parser.py:97` `RE_HOSTS` 用 `\d{1,3}` | `999.999.999.999 a.com` 仍被当 hosts 行解析出 `a.com` | 复用 `_is_ip` 校验 0–255 | P3 |
| P-2 | 单竖线锚点边界 | `parser.py:348-351` | `||domain^|` 等混合锚点分支较脆 | 补边界用例 | P3 |

### 9.3 聚合 / 冲突层

| # | 缺陷 | 位置 | 现象 | 建议 | 级别 |
|---|---|---|---|---|---|
| A-1 | 提升规则双写两份容器 | `aggregation.py:182-183` | `wild_map[parent]` 与 `block_map[(parent,True,"")]` 同一对象；后续 `block_map.values()` 会重复计入 | 保留单一权威容器或注明 | P3 |
| C-1 | `id()` 作集合键 | `conflicts.py:43,69`、`aggregation.py:190,239` | 依赖对象存活期，`id()` 复用有理论风险 | 改用 `Rule.__hash__`（已是稳定 4 元组键） | P3 |

### 9.4 分类层 `domain_classifier.py`

| # | 缺陷 | 位置 | 现象 | 建议 | 级别 |
|---|---|---|---|---|---|
| G-1 | 首标签漏判 | `domain_classifier.py:915-919` | `api.tracking.example.com` 无匹配（实测） | 遍历全部子域标签 | P1 |
| G-2 | ⚠️ **审计与重判规则集不一致** | 审计 `whitelist_audit/engine.py:156` 调**默认单例**；重判 `core/stats.py:240` 用 `self.classification_ruleset`（可带 `seed_file`） | 配置 `classification.seed_file` 后，白名单分类**不**使用该种子，两条链路结论可能不同 | 把同一 ruleset 传入 `audit_whitelist` | P2 |
| G-3 | setdefault 先到先得 | `domain_classifier.py:941-950` | 同域多类取列表顺序 | 显式类别优先级 | P2 |
| G-4 | 泛化前缀误判 | `domain_classifier.py:580-638` | `content/report/file.example.com` 误判 cdn/analytics（实测） | 收紧或要求 ≥2 标签 | P2 |

### 9.5 审计层 `whitelist_audit/`

| # | 缺陷 | 位置 | 现象 | 建议 | 级别 |
|---|---|---|---|---|---|
| W-1 | ⚠️ **SAFE 语义过强** | `fusion.py:168-189` | 所有 TI 层关闭、DNS 正常时直接 `RATING_SAFE`，reason「无威胁情报标记」——**根本没查情报** | SAFE 要求至少一个 TI 层有有效覆盖，否则 `UNKNOWN` | P2 |
| W-2 | ⚠️ **计数并发非原子** | `engine.py:277-308` `layer_hits[k] += 1` | `gather` 并发下读-改-写可丢更新，统计偏低 | 改为局部计数后汇总，或 `Counter.update` 单线程归并 | P2 |
| W-3 | 协程无界创建 | `engine.py:364` `gather(*[_audit_one(r) ...])` | 白名单大时一次性建 N 协程 | 池化提交 / `TaskGroup` 分批 | P2 |
| W-4 | 磁盘缓存末尾才落盘 | `engine.py:421` `_disk_cache_save` 仅在全部完成后 | 中途崩溃丢失本次审计 | 分批落盘 | P3 |
| W-5 | VT 阈值偏激进 | `virustotal_audit.py:28` `MALICIOUS_THRESHOLD=0.10` | 70 引擎中 ~7 家标记即 malicious | 提阈值或分级 | P3 |
| W-6 | 冗余判定 | `fusion.py:173-178` `ti_disabled` ⊆ `ti_all_errors` | 逻辑重复 | 简化 | P3 |

### 9.6 导出 / 报告

| # | 缺陷 | 位置 | 现象 | 建议 | 级别 |
|---|---|---|---|---|---|
| E-1 | 重复全量遍历 | `analysis.py:84-102` 又一遍；`exporter.py:287` 再 `Counter` | 与 `export_all` 的 `cat_counts` 重复 | 复用已算计数 | P2 |
| E-2 | JSON 转义不全 | `analysis.py:105-113` 只转义 `</` | U+2028/U+2029 理论可破坏内联脚本 | 一并转义 | P3 |
| E-3 | CDN 无 SRI | `html.py:308` | 供应链/隐私；离线无图 | 加 `integrity`+`crossorigin` | P3 |

### 9.7 配置层 `config.py`

| # | 缺陷 | 位置 | 现象 | 建议 | 级别 |
|---|---|---|---|---|---|
| K-1 | ⚠️ **未知键静默忽略** | `config.py:283-287` `MergeConfig(**raw)`；pydantic v2 默认 `extra='ignore'` | YAML 写成 `whitelist_audit.us_dns`（少个 `e`）不会报错、开关静默失效（已实测） | `model_config = ConfigDict(extra="forbid")`（或至少对 `whitelist_audit` 等子模型） | P2 |
| K-2 | ⚠️ **环境变量隐式开启在线层** | `config.py:374-391` | `VIRUSTOTAL_API_KEY`/`OPENAI_API_KEY` 存在即 `use_virustotal=True`/`ai.enabled=True`，与 README「在线层仍需 YAML 显式开启」矛盾 | 只填 key，不改开关；或文档同步 | P2 |

### 9.8 CLI / 缓存层

| # | 缺陷 | 位置 | 现象 | 建议 | 级别 |
|---|---|---|---|---|---|
| C-1 | GBK 控制台崩溃 | `cli.py:160,176,208` | `✓/✗` 抛 `UnicodeEncodeError`（实测） | 入口 `reconfigure(encoding="utf-8")` | P0 |
| C-2 | `clear()` 未定义属性 | `cache.py:356,361` | `AttributeError`，半清理（实测） | `self.cache_dir`，并补 `clear()` 测试 | P0 |
| C-3 | ⚠️ `clear()` 残留空目录 | `cache.py:348-363` | 只 `unlink` 文件，不删 `content/`、`parsed/`、`feeds/` 目录；`feeds` 分支本就有 bug 未执行 | 用 `shutil.rmtree(subdir)` | P3 |

---

## 10. 设计缺陷与架构优化建议

> 本节是**跨模块的设计级问题**：不是某个函数写错，而是「契约/边界/状态」层面的结构性风险。

### D-1 配置「fail-fast」只对值、不对键（最重要）
`README.md:86`/`DEVELOPMENT.md:86` 承诺「拼写错误在加载阶段即失败」，但实际只对 `Literal` **取值**（如 `backoff`）生效；**键名拼错被 `extra='ignore'` 静默吞掉**（实测未报错）。
- **优化**：`MergeConfig` 及各子模型加 `ConfigDict(extra="forbid")`；`validate_config` 额外比对各已知段落的键集合，输出「未知键」告警。

### D-2 两套分类「权威源」
- `domain_classifier._DEFAULT_RULESET`（模块级单例）与 `AsyncRuleEngine.classification_ruleset`（每实例）并存；审计走前者、重判走后者（G-2）。
- **优化**：把 ruleset 作为显式参数贯穿 `audit_whitelist` 与 `_rejudge_block_categories`，消除隐式单例路径。

### D-3 审计「SAFE」不等于「已验证安全」
`fusion.py` 在无任何 TI 覆盖时仍给 SAFE（W-1）。这会误导订阅者把危险域名列入白名单。
- **优化**：引入「覆盖度」概念——`coverage = 启用的 TI 层数`；`coverage==0` 时最高只到 `UNKNOWN`，并在 summary 暴露 `coverage`。

### D-4 环境变量与开关的「隐式耦合」
`resolve_api_keys` 见到 key 就打开层（K-2），造成「配了环境变量但没开 YAML 也联网」的意外行为。
- **优化**：key 只做填充；开关只认 YAML（或在日志中明确提示「已因环境变量启用」）。

### D-5 端口 seam 半接线
`ports.SourceCachePort.__getattr__` 透明代理，但注释自承「fetch 仍直接调 `self.cache`」（`ports.py:150-153`）。端口存在但未真正路由，注入 fake cache 不生效。
- **优化**：完成 `fetch.py` 的 `self.cache → self.cache_port` 迁移，或在 README 标注「占位」。

### D-6 引擎配置靠 70 个 kwargs 手写接线
`engine.py:43-123` + `from_config:224-298`。新增一个配置项要同步 5 处（DEVELOPMENT.md 自述），漏接风险高。
- **优化**：`AsyncRuleEngine(config: MergeConfig)` 单参构造，内部 `self._cfg = config`；mixin 从 `self._cfg` 读，`from_config` 退化为一行。

### D-7 模块级可变全局 `_SOURCE_TO_BIT` 无界增长
`models.py:91-103`：进程内每见一个新 source key 就永久分配 bit，长驻进程/测试里会持续累积且无锁。
- **优化**：提供 `reset_source_registry()`（测试用）；或改为 `WeakValueDictionary`/显式注册表；至少注明「仅 CLI 单次运行」。

### D-8 确定性产物与缓存的隐式耦合
`stats.json` 在确定性模式下把 `cached` 设为 `null`（`exporter.py:300`），下游按 int 解析会踩空。
- **优化**：改为 `cached: 0` 或 `"cached": null` 并在 schema/README 注明可空。

### D-9 报告对外部 CDN 的硬依赖
`html.py:308` 引 `cdn.jsdelivr.net`（有降级 guard，但离线无图、且有供应链面）。
- **优化**：加 SRI；或提供 `output.report_self_contained: true` 内联 ECharts（体积换自主）。

### D-10 `cache clear` 的「全清」承诺未兑现
`clear()` 文档称删除全部缓存，但因 C-2 / C-3 实际残留 `feeds/`、空目录甚至中断在半途。
- **优化**：先整体 `shutil.rmtree(cache_dir)` 再重建，或按子目录逐个 `rmtree` 并写单测。

---

## 11. 增量修复路线（本节新增项）

| 优先级 | 项 | 理由 | 状态 |
|---|---|---|---|
| **P0** | C-1 GBK、C-2 `_dir` | 直接导致命令失败 | ✅ 已修 |
| **P1** | G-1 全标签、K-1 `extra="forbid"`、W-1 SAFE 覆盖度、F-1 `file://` | 正确性 / 契约 | ✅ 已修 |
| **P1** | M-1/M-2 语义扩宽、M-4 中缀 `*`、M-7 hosts badfilter、badfilter 规范化、K-2 开关解耦、hosts 内联注释 | 第 12 章语法对齐 | ✅ 已修 |
| **P1** | R-1/R-3/R-4/R-8 口径、U-1 执行摘要 | 第 13 章报告修正 | ✅ 已修 |
| **P2** | W-3 分批协程、G-2 ruleset 统一 | 稳定性 / 一致性 | ✅ 已修 |
| **P2** | W-2 原子计数 | 复核为非缺陷（无 await 块原子） | ✅ 复核 |
| **P2** | 泛化前缀调参、`_extract_suffix` 换 PSL | 需评审/回归 | ⬜ 待办 |
| **P3** | P-1/P-2/C-3/W-6/E-2/D-10 | 边界 / 清理 | ✅ 已修 |
| **P3** | W-4/W-5/E-1/E-3/D-7/D-8/D-9 | 打磨 | ✅ 已修 |
| **P2** | D-5 端口接线、D-6 配置映射 | 可维护性 | ✅ 已修 |
| **对齐** | 冲突 blocks-preserved、verdict_cache、canonicalize_modifiers、cli 别名、契约测试、ARCHITECTURE-REVIEW | 发布包对齐（第六轮） | ✅ 已修 |
| **待决** | M-4 infix 通配符（开发线保留 / 发布包丢弃） | 产品决策 | ⬜ 未决 |

> 注：以上修改均落在「非默认确定性路径」或纯健壮性范畴；C-1/C-2/K-1 已补对应回归测试（`test_parser.py` 更新 + `clear()`/UTF-8/未知键均已验证）。详见 [FIX_REPORT.md](FIX_REPORT.md)。

---

## 附录 B：新增缺陷源码索引

| 主题 | 文件:行 |
|---|---|
| `file://` 契约 | `merger/core/fetch.py:70-71`；`merger/config.py:251-254` |
| 审计 ruleset 不一致 | `merger/whitelist_audit/engine.py:156`；`merger/core/stats.py:240` |
| SAFE 语义 | `merger/whitelist_audit/fusion.py:168-189` |
| layer_hits 并发 | `merger/whitelist_audit/engine.py:277-308` |
| 审计 gather | `merger/whitelist_audit/engine.py:364-367` |
| 未知键忽略 | `merger/config.py:283-287` |
| 环境变量开启 | `merger/config.py:374-391` |
| `clear()` 残留 | `merger/cache.py:348-363` |
| 端口占位 | `merger/ports.py:147-160` |
| 全局源注册表 | `merger/models.py:91-103` |

---

## 12. 智能合并 / 去重逻辑 vs AdGuard DNS 语法规范

> 对照基准：[AdGuard DNS 过滤规则语法](https://adguard-dns.io/kb/zh-CN/general/dns-filtering-syntax/)（以下简称 KB）。
> 结论先行：**聚合/冲突主流程与 KB 一致**；主要问题集中在「输入归一化扩宽拦截范围」「合法语法被丢弃」「badfilter 语义」「修饰符保留策略」四类。

### 12.1 语义扩宽（over-blocking，最需决策）

| # | 现象 | KB 语义 | 当前行为 | 影响 | 建议 | 级别 |
|---|---|---|---|---|---|---|
| M-1 | hosts 行 `0.0.0.0 example.org` | 仅拦截 `example.org`，`www.example.org` 仍放行 | 归一化为 `||example.org^`（实测），**连带拦截所有子域** | 输出比上游激进，可能误杀 | 增加 `hosts_scope: exact\|subdomains`；exact 输出 `\|example.org^` | P1 |
| M-2 | domains-only `example.org` | 仅拦截该域，不含子域 | 同上 → `||example.org^` | 同上 | 同 M-1 | P1 |
| M-3 | 单竖线尾锚 `ample.org\|` | 匹配 `example.org`，不匹配 `example.org.com` | 去尾 `\|` → `\|\|ample.org^`（实测） | 扩宽到 `ample.org` 的子域 | 保留锚点语义，或文档声明 | P2 |

> 说明：若「扩宽到子域」是产品有意为之（多数黑名单确实想要子域覆盖），应在 README/报告显式声明，而非静默改变语义。

### 12.2 合法语法被丢弃（under-blocking）

| # | 现象 | KB 依据 | 实测 | 建议 | 级别 |
|---|---|---|---|---|---|
| M-4 | 中缀通配符 `\|\|ad*.example.com^` 被丢弃 | `*` 可表示任意字符集，位置不限 | `pattern_dropped=1`，无输出 | 支持中缀 `*`（转正则或保留原样） | P1 |
| M-5 | 裸 IP 行 `8.8.8.8` 被丢弃 | domains-only 要求是域名；`\|\|8.8.8.8^` 可解析 | `\|\|8.8.8.8^` → 保留；裸 IP → `unrecognized` | 报告/文档区分两种写法 | P3 |
| M-6 | Unicode/IDN 域被 `[a-zA-Z]{2,}` TLD 正则丢弃 | 主机名可为 IDN | 静默计入 `unrecognized` | 先 `idna` 编码再解析 | P2 |
| M-7 | `\|\|domain^\$badfilter` 取消的是 block；hosts 行 `$badfilter` 被转成 `\|\|domain^$badfilter` | badfilter **不适用于** `/etc/hosts` 规则 | 会把 hosts 行也变成可取消规则 | hosts 分支忽略 `$badfilter` | P2 |

### 12.3 badfilter 规范化不一致（功能性缺陷）

- **现象**：目标规则 `||example.com^$important,client=1.2.3.4`，取消规则 `||example.com^$client=1.2.3.4,important,badfilter`。
- **实测**：`_apply_badfilter` `removed=1`（只删了 badfilter 自身），**目标规则存活**。
- **根因**：parser 归一化为 `flags+valued` 顺序（`important,client=...`）；`_apply_badfilter` 用 `sorted(全 token)`（`client=...,important`），两套顺序不一致 → 查不到目标。
- **建议**：统一为「flags 与 valued 各自排序后拼接」的单一 canonicalize 函数，parser 与 badfilter 共用。
- **级别**：P1（badfilter 是上游列表常用的“撤回”机制，失效会导致本应被撤回的规则继续生效）。

### 12.4 修饰符保留策略（设计）

| # | 修饰符 | KB 适用范围 | 当前 | 建议 |
|---|---|---|---|---|
| M-8 | `client=` | 仅 AdGuard Home / AdGuard DNS | 保留进公共 `merged_rules.txt`（实测） | 默认丢弃或分离到 `merged_client_scoped.txt` |
| M-9 | `ctag=` | 仅 AdGuard Home | 保留 | 同上 |
| M-10 | `respgeo=` | 仅 AdGuard DNS | 保留 | 同上 |
| M-11 | `dnsrewrite=` | 响应重写，**优先级最高**；HostlistsRegistry 自动过滤 | 保留（实测） | 默认剥离（否则订阅端解析行为被改写） |
| M-12 | `ipset=` / `resolver=` | 不在 DNS 语法 KB 中 | 被当作 DNS 修饰符保留 | 确认归属（AH 专有？）并在文档标注 |

> 共同理由：公共合并列表面向所有订阅者，客户端/标签/地理位置/响应重写类修饰符在订阅端语义不成立，保留会产生「规则存在但永不命中」或「意外改写解析」两类问题。

### 12.5 与 KB **一致**的部分（无需改）

- `\|\|example.org^` 覆盖子域 → 聚合把 `sub.parent` 折进 `||parent^` **正确**。
- `@@||parent^` 级联解锁子域 → 冲突消解级联 **正确**。
- `$important` 不被白名单覆盖 → `_resolve_conflicts` 跳过 **正确**。
- `@@||*.example.com^` 不解除 `||example.com^`（只覆盖子域）→ **正确**。
- 提升 `||*.parent^` 不覆盖 parent 本身 → **正确**。
- 未知修饰符整条丢弃 → 与 KB「必须忽略整条规则」**一致**（`drop_on_unknown_modifier=True`）。
- `||domain` 与 `||domain^` 归一化合并 → 语义等价，**正确**。

### 12.6 去重键的细粒度问题

- `denyallow=a|b` 与 `denyallow=b|a` 语义等价但**不合并**（值内 `|` 顺序未 canonicalize）。
- `client=~A|~B` 同理。
- 建议：对 `|` 分隔的值做集合序化后再入 dedup 键。

---

## 13. 报告数据准确性与体验评估

> 对象：`report.html`（`report/html.py`）与 `report.md`（`report/markdown.py`）。
> 总体：**结构完整、信息量大、HTML 体验优秀**（目录/打印/响应式/热力 tooltip/图例/离线降级）；但**若干指标口径与标签不一致**，会让人误读「去重/安全」的真实含义。

### 13.1 数据准确性问题

| # | 问题 | 位置 | 说明 | 建议 |
|---|---|---|---|---|
| R-1 | 「综合去重率」实为「整体压缩率」 | `html.py:45`、`markdown.py:39` | 公式用 `1-(block+allow)/raw`，含**去重+badfilter+聚合+冲突**四步；与漏斗「去重」步不是同一量 | 改名「整体压缩率」，并单列「纯去重率 = dedup/raw」 |
| R-2 | MD 同一数字出现两次 | `markdown.py:77,79` | 「综合去重率」与「最终压缩」同公式 | 合并为一行 |
| R-3 | 「聚合精简」卡片是 **gross** | `html.py:409`、`markdown.py:82` | 未减 `promoted_groups`，与漏斗「净」不一致，**高估**节省量 | 统一用 `agg_net` |
| R-4 | 「带 $ 修饰符规则」= **token 数** | `html.py:411`、`markdown.py:85` | 实测 2 条规则（含 `$important,client=…`）显示为 **3** | 改为「带修饰符规则数」另列「修饰符 token 数」 |
| R-5 | 「原始规则（Raw）」≠ 原始行 | 漏斗首行 | 实为「已解析候选规则」，不含注释/丢弃行 | 改标签为「解析候选（不含注释/丢弃）」 |
| R-6 | 「自去重率」名不符实 | `html.py:206`、`markdown.py:229` | 公式含聚合/冲突，非「源内自重复」 | 改名「原始→输出保留率（损失含聚合/冲突）」 |
| R-7 | 「🟢 安全 可放心放行」高估 | `html.py:508` | 叠加 §9 W-1（无 TI 覆盖也给 SAFE） | 先修 W-1，再在报告标注「安全=已查 N 层情报」 |
| R-8 | 冲突表截断 50 条未标注 | `html.py:93`、`markdown.py:244` | `conflict_resolved` 可能 > 50，读者误以为全部 | 标注「仅显示前 50 / 共 N 条」，或折叠+下载 |
| R-9 | `top_suffixes` 用启发式 | `analysis.py:74-81` | 非 PSL；`bar.co.uk` 等按硬编码 cc 表推 eTLD+1，异见 TLD 会偏 | 改用 `tldextract`（已依赖） |
| R-10 | `added/removed` 恒 0 未说明 | 两报告性能段 | 仅 `diff_against` 启用时非 0 | 标注「需启用 output.write_diff / diff_against」 |
| R-11 | 类别图顺序=插入序 | `html.py:51` | 非按数量排序 | 按 count 降序 |
| R-12 | 漏斗无自校验 | `html.py:415-423` | 「Raw − 各步 = 最终」未断言，计数漂移会静默错 | 末尾加一致性校验，偏差时显示警告 |

### 13.2 人性化 / 合理性评估

**做得好的**
- HTML：可折叠目录、打印样式、移动端响应式、粘性表头、热力 tooltip、重复率图例、CDN 缺失降级提示。
- 数据冗余展示（表格 + 图表 + tooltip），色盲用户有文字百分比/emoji 兜底。
- 确定性模式下用「内容版本」替代时间戳，产物可复现。
- 审计分级（恶意/可疑/安全/未知）+ 建议动作 + 风险分，可操作性强。

**可改进**
1. **缺「执行摘要」**：读者需读 13 节才知道「本次变了什么、健康度如何」。建议顶部加 3–5 条结论（新增/移除、冲突数、失败源、安全告警、聚合节省）。
2. **缺「本次变化清单」**：只有计数，无样例；建议内嵌 `added/removed` 前 N 条与 `diff` 开关状态。
3. **术语重叠**：去重率 / 压缩率 / 自去重率 / 聚合精简 含义交叉 → 建议加「术语表」小节统一口径（对应 R-1/R-3/R-6）。
4. **Markdown 无目录**：12 节长文，建议加 TOC（GitHub 支持锚点）。
5. **审计表无上限**：大 whitelist 会输出数千行；建议 Top-N 默认 + 「展开全部」/导出 CSV。
6. **确定性模式缺脚注**：`总耗时 — / 缓存 —` 应注明「确定性模式不记录，`report_timestamp: true` 可开启」。
7. **订阅快捷块缺失**：报告内可直接列出 AdGuard Home 订阅 URL（README 有），减少跳转。
8. **可访问性**：表头补 `scope="col"`、表格加 `<caption>`；热力格已有 tooltip，可再补 `aria-label`。
9. **离线图表**：CDN 不可达时仅文字占位；可加轻量 SVG 条形兜底，或提供 `report_self_contained` 内联 ECharts。
10. **深色模式**（低优先级）：CSS 变量化即可。

### 13.3 报告改进优先级

| 优先级 | 项 |
|---|---|
| **P1** | R-1/R-3/R-4 口径与标签修正；R-8 截断标注；加「执行摘要」 |
| **P2** | R-6 改名、R-5 标签、术语表、MD TOC、审计表 Top-N、R-9 改 PSL、R-10 标注、R-12 自校验 |
| **P3** | R-11 排序、订阅块、a11y、深色模式、离线 SVG 兜底 |

> 注：R-1/R-3/R-4 属「同一份数据两种口径」，改动只在渲染层，不影响产物字节；建议与 `tests/test_report_layers.py` / `test_p2_report_ux.py` 同步断言。
