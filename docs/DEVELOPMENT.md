# 开发指南（Development）

面向开发者：环境搭建、测试、代码规范、配置与版本约定。

## 1. 环境准备

推荐使用 [uv](https://docs.astral.sh/uv/)。仓库提供 `uv.lock` 与 `.python-version`。

```bash
# 安装全部运行依赖 + 开发依赖（pytest / ruff / build）
uv sync --extra dev

# 等价于激活虚拟环境后运行
uv run python -m merger version
```

也可用 conda 或 venv：

```bash
# conda
conda create -n adguard-merger python=3.12 -y
conda activate adguard-merger
pip install -r requirements.txt
pip install pytest pytest-asyncio ruff build

# 或 venv
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

> 说明：项目根目录是包目录（flat layout，包名 `merger`），同时保留两个顶层
> 兼容模块 `merge_rules.py` / `config_loader.py`。新增功能请放进 `merger/` 包内。

## 2. 常用命令

```bash
# 测试（默认通过 pyproject 的 addopts 跳过 slow 标记）
uv run pytest

# 跑全部（含网络/基准慢测试）
uv run pytest -m slow

# 只跑某个文件 / 某个关键字
uv run pytest tests/test_v7.py -q
uv run pytest -k "fusion"

# 静态检查与格式化
uv run ruff check merger merge_rules.py config_loader.py tests
uv run ruff format merger merge_rules.py config_loader.py tests

# 校验配置
uv run python -m merger validate config/sources.yaml

# 离线快速合并（跳过白名单网络审计，便于本地调试）
uv run python -m merger merge --no-audit --output tmp/out --cache-dir tmp/cache

# 构建 wheel / sdist
uv run python -m build
```

## 3. 代码规范

- **ruff** 是唯一强制的静态检查器，配置在 `pyproject.toml` 的 `[tool.ruff]`。
  - 启用规则：`E`/`F`（pycodestyle + pyflakes）、`I`（isort）、`UP`（pyupgrade）。
  - `E501`（行长）与 `E402`（模块级导入位置）有意放宽。
  - 提交前请确保 `ruff check` 与 `ruff format --check` 均通过（CI 会拦截）。
- 目标 Python 3.10+，标准库优先；类型标注用 `from __future__ import annotations`
  与内建泛型（`list[...]` / `dict[...]`）。
- 新的网络层必须能在无网络/无 key 时安全降级（默认 disabled），并可被
  `monkeypatch` 在单测中替身。

## 4. 测试约定

- 测试放在 `tests/`，文件名 `test_*.py`，函数 `test_*`。
- 使用 `tmp_path` 隔离输出与缓存，**不要**写入真实的 `output/`、`cache/`。
- 网络/大体积基准用 `@pytest.mark.slow` 标记，默认不跑。
- 异步测试用 `pytest-asyncio`（`asyncio_mode = "auto"`）。
- 任何对去重、聚合、冲突、排序、确定性的修改，都必须：
  1. 保持 `test_determinism.py` / `test_integration.py` 的两次运行字节一致；
  2. 若改变默认输出，需同步更新规则文件头版本与相关测试。

## 5. 配置模型约定

- 所有配置项在 `merger/config.py` 中以 pydantic 模型声明，带范围约束。
- 枚举类取值用 `Literal[...]`，拼写错误在加载阶段即失败（fail fast）。
- 新增配置项时：模型 → `AsyncRuleEngine.from_config` 传参 → 引擎构造参数 →
  `config/sources.yaml` 注释示例 → 测试，五处保持一致。
- API key 不得硬编码进 YAML；通过 `VIRUSTOTAL_API_KEY` / `OPENAI_API_KEY`
  环境变量注入（`resolve_api_keys`）。

## 6. 版本与发布约定

- 产品版本只改 `merger/version.py`：
  - `__version__`（语义化 `MAJOR.MINOR.PATCH`）
  - `__version_short__`（User-Agent 与标题使用，如 `7.0`）
- 同步更新：`pyproject.toml`、`README.md` 徽章、`CHANGELOG.md`、CI 缓存键
  （`tests/test_version_consistency.py` 会校验一致性）。
- 磁盘格式版本（`SIDECAR_VERSION` / `CACHE_VERSION`）**不随产品版本**变化，
  只有当缓存/sidecar 序列化布局改变时才提升。
- 发版：更新 `CHANGELOG` 与版本号 → 提交 → 打标签 `git tag vX.Y.Z` →
  `git push origin vX.Y.Z`，`release.yml` 会自动构建并发布 Release。

## 7. 目录里不该提交的东西

`.gitignore` 已排除：`output/`、`cache/`、`.venv/`、`__pycache__`、构建产物
`dist/`/`build/`、`.ruff_cache` 等。GitHub Actions 会在运行时**强制**把
`output/` 加入提交；本地的缓存与产物不应进入版本库。

## 8. 调试建议

- `-v` 打开 DEBUG 日志；`-q` 仅显示错误。
- 怀疑某个源失败：看 `stats.json` 的 `failed_sources` 与报告 HTML 的「失败源」段。
- 怀疑重复/覆盖：查看 `conflicts.json`、`contributions.json`、报告的「源间重复矩阵」。
- 白名单审计异常：用 `--no-audit` 先验证纯合并管线，再逐层排查（默认有 24h 缓存，
  改逻辑时删除 `cache/whitelist_audit_cache.json` 强制重审）。
