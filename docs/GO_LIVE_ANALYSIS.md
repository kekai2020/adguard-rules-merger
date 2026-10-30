# AdGuard Rules Merger V7 上线适配性分析（修订 · 豆包线推荐）

> **对象**：豆包线（发布包 HEAD `6338910`，zip `264070…1802`，127 文件）vs DeepSeek 线 git `44c68f9`。
> **结论**：**豆包线更适合上线**（IDN punycode 归一化 + 591 passed/0 failed + 工程确定性 + 纯净源码树）。
> **修订**：澄清 2 项过时说法——DeepSeek 线 `44c68f9` **已**对齐 CIDR/sdns 保留 + 无 ECharts 纯 CSS；且 O 系列 **DeepSeek 线更全**（O-5~O-9，豆包线缺）。

---

## 1. 实测总览

| 维度 | 豆包线 (`6338910`) | DeepSeek 线 (`44c68f9`) | 优势 |
|---|---|---|---|
| 全量测试 | **591 passed / 0 failed** | 576 passed / 3 deselected | **豆包线** |
| **IDN punycode 归一化** | ✅（`中文域名.com`→`xn--fiq06l2rdsvs.com`） | ❌（原样保留非 ASCII） | **豆包线（独有）** |
| 报告离线性 | 纯 CSS 自包含 | **纯 CSS 自包含**（已对齐） | 平 |
| CIDR/sdns/RPZ | 独立成行保留 | **独立成行保留**（已对齐） | 平 |
| O-1~O-4 | ✅ | ✅ | 平 |
| **O-5~O-9** | ❌ | ✅（`_render_rule`/`itertools.chain`/`_iter_parents`/单源惰性） | **DeepSeek 线** |
| 完整管线性能 | 2.073s | **1.917s（快 8%）** | **DeepSeek 线** |
| 工程确定性 | 10 轮契约 + ruff/build/validate 全绿 | 强 | 豆包线 |
| 源码树洁净度 | 无夹带 | 带 4 份评审 md（文档） | 豆包线 |

---

## 2. 关键澄清（豆包方 2 项过时说法）

1. **「DeepSeek 线依赖 ECharts CDN / 丢弃 CIDR」**——不成立：DeepSeek 线 `44c68f9` 已借鉴豆包线，**无 ECharts 纯 CSS 自包含** + **CIDR/sdns 独立成行保留**（两线已一致）。
2. **「O 系列：豆包线已吸收，DeepSeek 线原版」**——不成立：DeepSeek 线 **O-1~O-9 全**（O-5~O-9 豆包线缺）；豆包线已吸收 O-1~O-4。

## 3. 真正的上线分水岭

| | 豆包线 | DeepSeek 线 |
|---|---|---|
| **独有优势** | **IDN punycode 归一化**（非 ASCII 域名→A-label，保证去重/聚合/匹配一致性）+ 591/0 + 工程确定性 | **O-5~O-9**（性能/可维护性）+ 完整管线快 8% |

**权衡**：IDN 归一化是**功能完整性**（域名处理正确性，上线首要）；O-5~O-9 是**性能微优化**（非功能）。功能完整性 > 性能微优化 → **豆包线更适合上线**。

---

## 4. 结论与建议

1. **豆包线 `6338910` 为发布候选**（591/0 + IDN 归一化 + 工程确定性 + 纯净树）——接受。
2. **最终冒烟**：建议跑一次完整实跑（生成真实 `merged_rules.txt` + `report.html`），验证：591/0、IDN 归一化（含 `中文域名.com`→punycode）、离线报告自包含（断网可开）。
3. **DeepSeek 线后续**：吸收 **IDN punycode 归一化**（补齐则 DeepSeek 线 = O 系列全 + 性能 8% + IDN；可作为合并候选）；豆包线可后补 O-5~O-9。

---

*2026-10-28 修订 · 豆包线 `6338910`（591 passed/0 failed + IDN）；DeepSeek 线 `44c68f9`（576/3 + O 系列全 + 性能 8%）*
