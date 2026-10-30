# AdGuard Rules Merger V7 双版本对比分析报告（修正版 · 用户校验 588 passed）

> **对象**：豆包线（发布包，用户当前 HEAD，本地 pytest **588 passed / 0 failed**）vs DeepSeek 线（开发线 git `0140ec7`，576 passed / 3 deselected）。
> **修订**：按用户校验——「2 个失败」为**双方设计分歧**（豆包线有意增强），非缺陷；豆包线全绿。

---

## 1. 执行摘要

1. **豆包线（发布包）本地 pytest 全绿**：**588 passed / 0 failed**。此前报告的「2 failed」来自 DeepSeek 线测试口径，**不成立**。
2. **两条设计分歧（豆包线有意设计，非 bug）**：
   - **CIDR / `sdns://` / RPZ 行**：豆包线**独立成行保留**（KB 增强）；DeepSeek 线视为 unrecognized 丢弃。
   - **ECharts**：豆包线**彻底去掉 ECharts**（报告纯 CSS 自包含，无需守卫）；DeepSeek 线保留 CDN + `typeof echarts` 守卫。
3. **豆包线仍缺 DeepSeek 线 O 系列**：O-1（coverage 正确性）、O-2（同形字缓存分桶）、O-3（源锁）、O-4（混淆 TLD 检全）、O-5~O-9。
4. **DeepSeek 线仍缺豆包线 2 项设计**：CIDR/sdns 独立成行保留、无 ECharts 自包含报告。

---

## 2. 符号 / 行为对照

| 项 | 豆包线（发布包） | DeepSeek 线（开发线） |
|---|---|---|
| D-5/D-6/D-7 / 0.20 / M-4 保留 / P-1/P-2 / blocks-preserved / verdict_cache / canonicalize | ✅ | ✅ |
| **CIDR / sdns / RPZ** | **独立成行保留** | 丢弃（unrecognized） |
| **ECharts** | **无（纯 CSS 自包含）** | CDN + `typeof echarts` 守卫 |
| O-1 coverage 累积 | ❌（`unique=2` 错） | ✅（`shared=1`） |
| O-2 `_detect_candidate` 缓存 / 分桶 | ❌ | ✅ |
| O-3 `_SOURCE_LOCK` | ❌ | ✅ |
| O-4 混淆 TLD 检全（`paypal.cоm`） | ❌（漏报） | ✅ |
| O-5~O-9 | ❌ | ✅ |

---

## 3. 测试状态（双方实测）

| | 豆包线 | DeepSeek 线 |
|---|---|---|
| 全量 pytest | **588 passed / 0 failed** | 576 passed / 3 deselected |
| 设计分歧测试 | CIDR 保留 / 无 ECharts（有意） | 丢弃 / 守卫（DeepSeek 口径） |

> 双方**各自全绿**（豆包线 588；DeepSeek 线 576+3 剔除）。分歧仅在**设计选择**，非正确性缺陷。

---

## 4. 结论

1. **豆包线全绿且 2 项设计更优**（CIDR/sdns 独立保留更贴 KB 语义；无 ECharts 纯 CSS 自包含更轻量、无外部依赖）。
2. **DeepSeek 线全绿且 O 系列更优**（O-1 coverage 正确性、O-2/O-3 性能并发、O-4 混淆 TLD 检全、O-5~O-9）。
3. **双方各有所长，需互相吸收**：
   - 豆包线 ← DeepSeek 线：**O-1（coverage 正确性，明确 bug）+ O-4（混淆 TLD 检全）** 最有价值；O-2/O-3（性能/并发）次之；O-5~O-9 按需。
   - DeepSeek 线 ← 豆包线：CIDR/sdns 独立成行保留、无 ECharts 自包含报告（2 项设计增强）。

---

## 5. 建议

- [ ] **豆包线 · P1**：移植 **O-1**（coverage 累积，同名 block+allow unique/shared 正确性）+ **O-4**（混淆 TLD 检全）。
- [ ] **豆包线 · P2**：移植 **O-2**（同形字缓存分桶，默认审计性能）+ **O-3**（源锁，并发安全）；O-5~O-9 按需。
- [ ] **DeepSeek 线 · P2**：吸收豆包线 **CIDR/sdns 独立成行保留** + **无 ECharts 自包含报告**（对齐 2 项设计增强）。
- [ ] **统一**：互相吸收后双线等价，合并为单一权威源码树。

---

*修正版 2026-10-28 · 豆包线 588 passed / 0 failed（用户实测）；DeepSeek 线 `0140ec7`（576 passed / 3 deselected）*
