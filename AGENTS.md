# AGENTS.md — adguard-rules-merger

AdGuard Home 规则合并器：从 18 个上游订阅源异步下载、四层去重、向上聚合、
白名单冲突消解、8 层白名单威胁审计，输出 AdGuard/Hosts/Clash/Surge/SmartDNS 等多格式产物。
Python 3.10+，uv 管理，pydantic 配置，Typer CLI，aiohttp 异步。

注意：本工作区是解压出的源码树（无 `.git`），git 历史与提交流程不适用于本地。

## 常用命令

```bash
uv sync --extra dev                                  # 安装依赖（可复现，读 uv.lock）
uv run pytest                                        # 测试（默认经 pyproject addopts 跳过 slow）
uv run pytest tests/test_v7.py -q                    # 单文件
uv run pytest -k "fusion"                            # 按关键字
uv run pytest -m slow                                # 网络/基准慢测试（默认不跑）
uv run ruff check merger merge_rules.py config_loader.py tests
uv run ruff format merger merge_rules.py config_loader.py tests   # CI 校验 format --check
uv run python -m merger validate config/sources.yaml # 离线校验配置
uv run python -m merger merge --no-audit --output tmp/out --cache-dir tmp/cache  # 本地快速合并
uv run python -m build                               # wheel/sdist
```

mypy 已配置但为非阻塞 advisory（`packages = ["merger"]`）。CI 矩阵跑 Python 3.10–3.13。

## 架构与分层

- 入口等价三种：控制台命令 `adguard-rules-merger`（= `merger.cli:app`）、`python -m merger`、
  旧入口 `merge_rules.py`；`config_loader.py` 是重导出 `merger.config` 的兼容垫片。
  **新功能一律放 `merger/` 包内**，不要加顶层模块。
- 管线（`merger/core/engine.py` 的 `AsyncRuleEngine.run()`）：
  fetch（并发+三级缓存+硬超时）→ parse（流式）→ dedup（精确/规范化/正则）→
  aggregate（通配符向上聚合）→ block/allow 分流 → 冲突消解 → 白名单审计 → 稳定排序。
- CLI 只做装配：加载配置 → 调引擎 → 调导出器；不要在 CLI 层写业务逻辑。
- 子包：`merger/core/`（引擎与阶段）、`merger/whitelist_audit/`（多层审计，含 fusion/registry/seam）、
  `merger/report/`（HTML/MD 渲染）、`merger/domain_classifier/`（子包，含 seeds/rules/ruleset）。
- 外部 IO（HTTP/DNS/缓存）走 `merger/ports.py` 薄端口，便于测试替身。
- 导出为原子写（`*.tmp` → replace）。
- ⚠️ `docs/ARCHITECTURE.md` 模块表部分陈旧（写 `merger/core.py`、`domain_classifier.py`），
  以实际目录 `merger/core/`、`merger/domain_classifier/` 为准。

## 硬性约定（改动前必读）

- **确定性**：提交到仓库的产物（规则文件/报告/stats.json）不得含墙钟时间与运行耗时，
  相同输入必须字节级一致（遵守 `SOURCE_DATE_EPOCH`）。任何改去重/聚合/冲突/排序的 PR
  必须保持 `test_determinism.py` / `test_integration.py` 两次运行字节一致；改变默认输出需
  同步更新规则文件头版本与相关测试。
- **版本号唯一事实源**是 `merger/version.py`；同步改 `pyproject.toml`、README 徽章、
  `CHANGELOG.md`、CI 缓存键（`tests/test_version_consistency.py` 会拦截遗漏）。
  磁盘格式版本（`SIDECAR_VERSION`/`CACHE_VERSION`/`AUDIT_CACHE_VERSION`）不随产品版本走，
  仅在序列化布局变化时提升。
- **新增配置项五处同步**：pydantic 模型（`merger/config.py`，枚举用 `Literal[...]` fail-fast）→
  `AsyncRuleEngine.from_config` 传参 → 引擎构造参数 → `config/sources.yaml` 注释示例 → 测试。
- **API key 绝不写进 YAML**：走环境变量 `VIRUSTOTAL_API_KEY` / `OPENAI_API_KEY` /
  `GSB_API_KEY` / `PHISHTANK_API_KEY` / `URLSCAN_API_KEY`（`resolve_api_keys`）。
- **新的网络/情报层**必须无网络、无 key 时安全降级（默认 disabled），且可被 `monkeypatch` 替身。

## 代码与测试规范

- ruff 是唯一强制门禁：规则 `E/F/I/UP`，line-length 100，双引号；`E501`/`E402` 有意放宽。
- Python 3.10+，标准库优先；`from __future__ import annotations` + 内建泛型（`list[...]`）。
- 测试放 `tests/test_*.py`；用 `tmp_path` 隔离输出与缓存，**绝不写真实 `output/`、`cache/`**。
- 异步测试靠 pytest-asyncio `asyncio_mode = "auto"`，无需装饰器。
- 网络/大体积基准测试标 `@pytest.mark.slow`。

## 调试

- `-v` 开 DEBUG 日志，`-q` 仅错误；源失败看 `stats.json` 的 `failed_sources`，
  覆盖/重复看 `conflicts.json`、`contributions.json`。
- 排查白名单审计：先 `--no-audit` 验证纯合并管线；审计结果有 24h 缓存，
  改逻辑后删 `cache/whitelist_audit_cache.json` 强制重审。

## 文档

改敏感区域（引擎/审计/缓存/导出）前先读：`docs/ARCHITECTURE.md`（管线与数据模型）、
`docs/DEVELOPMENT.md`（规范与版本约定）、`docs/DEPLOYMENT.md`（CI/发布/Docker）、
`CHANGELOG.md`。
