# AdGuard Rules Merger — 规则分析报告

> 合并时间 2026-11-22 08:27:50 | 源：18/18 | 缓存命中：0

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,552,093 |
| Allow 白名单 | 304 |
| 纯去重率（去重阶段） | 23.6% |
| 最终压缩（原始→输出） | 3,399,087 → 2,552,397（-25%） |
| 聚合精简（净） | 46,110 |
| 冲突消解 | 0 |
| 带 $ 修饰符规则数 | 5 |
| 合并时间 | 2026-11-22 08:27:50 |
| 总耗时 | 35.6s |

### ⏱️ 各阶段执行耗时

| 流水线阶段 | 耗时 | 占比 |
|---|---:|---:|
| 抓取/解析 | 20943.2 ms | 59.0% |
| badfilter 取消 | 79.1 ms | 0.2% |
| 聚合 | 4589.7 ms | 12.9% |
| 冲突解析 | 1303.1 ms | 3.7% |
| 排序 | 1494.6 ms | 4.2% |
| 分类重判 | 7 µs | 0.0% |
| 统计/贡献 | 6184.9 ms | 17.4% |
| 白名单审计 | 2 µs | 0.0% |
| 差异对比 | 1 µs | 0.0% |
| 内容哈希 | 873.6 ms | 2.5% |
| **合计** | **35468.3 ms** | **100.0%** |

### 执行摘要

- 最终输出 **2,552,093** 条 Block + **304** 条 Allow（原始 3,399,087，压缩 **-25%**）
- 🔁 相对 diff：新增 0 / 移除 0 域名

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,399,087 | - |
| 去重后（精确 796,189 / 规范化 4,064 / 正则 321） | 2,598,513 | -800,574 |
| badfilter 取消后（被 $badfilter 取消） | 2,598,507 | -6 |
| 聚合后（净：折叠 46,110） | 2,552,397 | -46,110 |
| 冲突消解后（最终输出） | 2,552,397 | -0 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| 普通域名 | 2,551,719 |
| 正则 | 604 |
| IP 地址 | 74 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| 恶意 | 1,648,101 |
| 其他 | 542,296 |
| 广告 | 309,298 |
| 钓鱼 | 51,868 |
| 追踪 | 384 |
| 挖矿 | 146 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 1,650,046 | 1,647,058 | 99.8% | 1,301,561 | 345,497 | 79.0% |
| HaGeZi's Gambling Blocklist | 703,816 | 703,430 | 99.9% | 526,120 | 177,310 | 74.8% |
| HaGeZi's Ultimate Blocklist | 289,814 | 286,568 | 98.9% | 112,352 | 174,216 | 39.2% |
| Phishing Army | 146,193 | 122,524 | 83.8% | 44,636 | 77,888 | 36.4% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,628 | 16,320 | 98.1% | 14,841 | 1,479 | 90.9% |
| CHN: AdRules DNS List | 212,524 | 208,140 | 97.9% | 9,265 | 198,875 | 4.5% |
| CHN: anti-AD | 102,176 | 101,437 | 99.3% | 7,487 | 93,950 | 7.4% |
| AdGuard DNS filter | 192,148 | 189,360 | 98.5% | 5,080 | 184,280 | 2.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 16,606 | 15,462 | 93.1% | 1,731 | 13,731 | 11.2% |
| ShadowWhisperer's Dating List | 1,438 | 1,438 | 100.0% | 1,332 | 106 | 92.6% |
| Malicious URL Blocklist (URLHaus) | 2,117 | 1,991 | 94.0% | 670 | 1,321 | 33.7% |
| Stalkerware Indicators List | 929 | 495 | 53.3% | 191 | 304 | 38.6% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 100.0% | 57 | 0 | 100.0% |
| Scam Blocklist by DurableNapkin | 903 | 899 | 99.6% | 12 | 887 | 1.3% |
| OISD Blocklist Small | 62,067 | 60,230 | 97.0% | 4 | 60,226 | 0.0% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 395 | 387 | 98.0% | 1 | 386 | 0.3% |
| AWAvenue Ads Rule | 918 | 748 | 81.5% | 0 | 748 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **1,647,058** | 🟩 176,272 (8.1%) | 🟩 106,451 (5.8%) | 🟩 33,419 (1.8%) | 🟩 31,048 (1.7%) | 🟩 72,554 (4.3%) | 🟩 23,137 (1.3%) | 🟩 24,280 (1.4%) | 🟩 1,023 (0.1%) | 🟩 8,712 (0.5%) | 🟩 1,159 (0.1%) | 🟩 34 (0.0%) | 🟩 830 (0.1%) | 🟩 20 (0.0%) | 🟩 296 (0.0%) | 🟩 3 (0.0%) | 🟩 123 (0.0%) | · |
| **2** | 🟩 176,272 (8.1%) | **703,430** | 🟩 2,297 (0.2%) | 🟩 488 (0.1%) | 🟩 440 (0.0%) | 🟩 156 (0.0%) | 🟩 234 (0.0%) | 🟩 161 (0.0%) | 🟩 7 (0.0%) | 🟩 34 (0.0%) | 🟩 6 (0.0%) | · | 🟩 4 (0.0%) | · | 🟩 2 (0.0%) | · | 🟩 1 (0.0%) | · |
| **3** | 🟩 106,451 (5.8%) | 🟩 2,297 (0.2%) | **286,568** | 🟨 86,478 (21.2%) | 🟨 80,445 (20.3%) | 🟩 14,004 (3.5%) | 🟨 65,561 (20.3%) | 🟩 56,351 (19.4%) | 🟩 1,347 (0.4%) | 🟩 1,933 (0.6%) | 🟩 1,052 (0.4%) | 🟩 86 (0.0%) | 🟩 352 (0.1%) | 🟩 728 (0.3%) | 🟩 80 (0.0%) | 🟩 383 (0.1%) | 🟩 140 (0.0%) | · |
| **4** | 🟩 33,419 (1.8%) | 🟩 488 (0.1%) | 🟨 86,478 (21.2%) | **208,140** | 🟧 176,379 (79.8%) | 🟩 42 (0.0%) | 🟨 87,447 (39.4%) | 🟨 56,596 (26.7%) | 🟩 86 (0.0%) | 🟩 30 (0.0%) | 🟩 8 (0.0%) | 🟩 37 (0.0%) | 🟩 887 (0.4%) | 🟩 556 (0.3%) | 🟩 3 (0.0%) | 🟩 117 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 31,048 (1.7%) | 🟩 440 (0.0%) | 🟨 80,445 (20.3%) | 🟧 176,379 (79.8%) | **189,360** | 🟩 22 (0.0%) | 🟨 78,032 (36.7%) | 🟨 56,058 (29.0%) | 🟩 35 (0.0%) | 🟩 24 (0.0%) | 🟩 3 (0.0%) | 🟩 32 (0.0%) | 🟩 23 (0.0%) | 🟩 246 (0.1%) | 🟩 2 (0.0%) | 🟩 26 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 72,554 (4.3%) | 🟩 156 (0.0%) | 🟩 14,004 (3.5%) | 🟩 42 (0.0%) | 🟩 22 (0.0%) | **122,524** | 🟩 9 (0.0%) | 🟩 9 (0.0%) | 🟩 8 (0.0%) | 🟩 12,784 (10.2%) | 🟩 10 (0.0%) | · | 🟩 5 (0.0%) | · | · | · | · | · |
| **7** | 🟩 23,137 (1.3%) | 🟩 234 (0.0%) | 🟨 65,561 (20.3%) | 🟨 87,447 (39.4%) | 🟨 78,032 (36.7%) | 🟩 9 (0.0%) | **101,437** | 🟨 41,831 (34.9%) | 🟩 30 (0.0%) | 🟩 23 (0.0%) | 🟩 504 (0.5%) | 🟩 25 (0.0%) | 🟩 9 (0.0%) | 🟩 714 (0.7%) | 🟩 5 (0.0%) | 🟩 69 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 24,280 (1.4%) | 🟩 161 (0.0%) | 🟩 56,351 (19.4%) | 🟨 56,596 (26.7%) | 🟨 56,058 (29.0%) | 🟩 9 (0.0%) | 🟨 41,831 (34.9%) | **60,230** | 🟩 24 (0.0%) | 🟩 12 (0.0%) | 🟩 5 (0.0%) | 🟩 23 (0.0%) | 🟩 13 (0.0%) | 🟩 696 (1.2%) | 🟩 1 (0.0%) | 🟩 26 (0.0%) | 🟩 49 (0.1%) | · |
| **9** | 🟩 1,023 (0.1%) | 🟩 7 (0.0%) | 🟩 1,347 (0.4%) | 🟩 86 (0.0%) | 🟩 35 (0.0%) | 🟩 8 (0.0%) | 🟩 30 (0.0%) | 🟩 24 (0.0%) | **16,320** | 🟩 6 (0.0%) | 🟩 4 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **10** | 🟩 8,712 (0.5%) | 🟩 34 (0.0%) | 🟩 1,933 (0.6%) | 🟩 30 (0.0%) | 🟩 24 (0.0%) | 🟩 12,784 (10.2%) | 🟩 23 (0.0%) | 🟩 12 (0.0%) | 🟩 6 (0.0%) | **15,462** | 🟩 10 (0.1%) | · | 🟩 4 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **11** | 🟩 1,159 (0.1%) | 🟩 6 (0.0%) | 🟩 1,052 (0.4%) | 🟩 8 (0.0%) | 🟩 3 (0.0%) | 🟩 10 (0.0%) | 🟩 504 (0.5%) | 🟩 5 (0.0%) | 🟩 4 (0.0%) | 🟩 10 (0.1%) | **1,991** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | · |
| **12** | 🟩 34 (0.0%) | · | 🟩 86 (0.0%) | 🟩 37 (0.0%) | 🟩 32 (0.0%) | · | 🟩 25 (0.0%) | 🟩 23 (0.0%) | · | · | · | **1,438** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 830 (0.1%) | 🟩 4 (0.0%) | 🟩 352 (0.1%) | 🟩 887 (0.4%) | 🟩 23 (0.0%) | 🟩 5 (0.0%) | 🟩 9 (0.0%) | 🟩 13 (0.0%) | · | 🟩 4 (0.0%) | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **899** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 20 (0.0%) | · | 🟩 728 (0.3%) | 🟩 556 (0.3%) | 🟩 246 (0.1%) | · | 🟩 714 (0.7%) | 🟩 696 (1.2%) | 🟩 2 (0.0%) | 🟩 1 (0.0%) | · | · | · | **748** | 🟩 1 (0.1%) | 🟩 6 (0.5%) | · | · |
| **15** | 🟩 296 (0.0%) | 🟩 2 (0.0%) | 🟩 80 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 5 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **495** | · | · | · |
| **16** | 🟩 3 (0.0%) | · | 🟩 383 (0.1%) | 🟩 117 (0.1%) | 🟩 26 (0.0%) | · | 🟩 69 (0.1%) | 🟩 26 (0.0%) | · | · | · | · | · | 🟩 6 (0.5%) | · | **387** | · | · |
| **17** | 🟩 123 (0.0%) | 🟩 1 (0.0%) | 🟩 140 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | · | 🟩 258 (0.3%) | 🟩 49 (0.1%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **57** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 1,647,058 |
| 2 | HaGeZi's Gambling Blocklist | 703,430 |
| 3 | HaGeZi's Ultimate Blocklist | 286,568 |
| 4 | CHN: AdRules DNS List | 208,140 |
| 5 | AdGuard DNS filter | 189,360 |
| 6 | Phishing Army | 122,524 |
| 7 | CHN: anti-AD | 101,437 |
| 8 | OISD Blocklist Small | 60,230 |
| 9 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,320 |
| 10 | Phishing URL Blocklist (PhishTank and OpenPhish) | 15,462 |
| 11 | Malicious URL Blocklist (URLHaus) | 1,991 |
| 12 | ShadowWhisperer's Dating List | 1,438 |
| 13 | Scam Blocklist by DurableNapkin | 899 |
| 14 | AWAvenue Ads Rule | 748 |
| 15 | Stalkerware Indicators List | 495 |
| 16 | HaGeZi's Windows/Office Tracker Blocklist | 387 |
| 17 | NoCoin Filter List | 269 |
| 18 | HaGeZi's DNS Rebind Protection | 57 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 176,379 | 🟧 79.8% | 93.1% | 84.7% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 176,272 | 🟩 8.1% | 10.7% | 25.1% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 106,451 | 🟩 5.8% | 6.5% | 37.1% |
| CHN: anti-AD | CHN: AdRules DNS List | 87,447 | 🟨 39.4% | 86.2% | 42.0% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 86,478 | 🟨 21.2% | 41.5% | 30.2% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 80,445 | 🟨 20.3% | 42.5% | 28.1% |
| AdGuard DNS filter | CHN: anti-AD | 78,032 | 🟨 36.7% | 41.2% | 76.9% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 72,554 | 🟩 4.3% | 59.2% | 4.4% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 65,561 | 🟨 20.3% | 64.6% | 22.9% |
| CHN: AdRules DNS List | OISD Blocklist Small | 56,596 | 🟨 26.7% | 27.2% | 94.0% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 56,351 | 🟩 19.4% | 19.7% | 93.6% |
| AdGuard DNS filter | OISD Blocklist Small | 56,058 | 🟨 29.0% | 29.6% | 93.1% |
| CHN: anti-AD | OISD Blocklist Small | 41,831 | 🟨 34.9% | 41.2% | 69.5% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 33,419 | 🟩 1.8% | 16.1% | 2.0% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 31,048 | 🟩 1.7% | 16.4% | 1.9% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 24,280 | 🟩 1.4% | 1.5% | 40.3% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 23,137 | 🟩 1.3% | 22.8% | 1.4% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 14,004 | 🟩 3.5% | 11.4% | 4.9% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 12,784 | 🟩 10.2% | 10.4% | 82.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 8,712 | 🟩 0.5% | 56.3% | 0.5% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 1,650,046 | 1,647,058 | 0.2% |
| HaGeZi's Gambling Blocklist | 703,816 | 703,430 | 0.1% |
| HaGeZi's Ultimate Blocklist | 289,814 | 286,568 | 1.1% |
| CHN: AdRules DNS List | 212,524 | 208,140 | 2.1% |
| AdGuard DNS filter | 192,148 | 189,360 | 1.5% |
| Phishing Army | 146,193 | 122,524 | 16.2% |
| CHN: anti-AD | 102,176 | 101,437 | 0.7% |
| OISD Blocklist Small | 62,067 | 60,230 | 3.0% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,628 | 16,320 | 1.9% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 16,606 | 15,462 | 6.9% |
| Malicious URL Blocklist (URLHaus) | 2,117 | 1,991 | 6.0% |
| ShadowWhisperer's Dating List | 1,438 | 1,438 | 0.0% |
| Scam Blocklist by DurableNapkin | 903 | 899 | 0.4% |
| AWAvenue Ads Rule | 918 | 748 | 18.5% |
| Stalkerware Indicators List | 929 | 495 | 46.7% |
| HaGeZi's Windows/Office Tracker Blocklist | 395 | 387 | 2.0% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 与白名单重叠的拦截规则（blocks-preserved 政策：拦截规则保留输出、白名单单独成文件，此处仅记录重叠明细；仅显示前 50 条 / 共 0 条）。展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域，通配符=白名单通配父域（`*.parent`）覆盖子域。完整清单见 output/conflicts.json。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `js.monitor.azure.com` | `\|\|js.monitor.azure.com^` | HaGeZi's Windows/Office Tracker Blocklist | `@@\|\|js.monitor.azure.com^` | AdGuard DNS filter | 精确 |
| `googleadservices.com` | `\|\|googleadservices.com^` | AWAvenue Ads Rule, OISD Blocklist Small, CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|googleadservices.com^` | AdGuard DNS filter | 精确 |
| `proto2ad.durasite.net` | `\|\|proto2ad.durasite.net^` | OISD Blocklist Small, CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|proto2ad.durasite.net^` | AdGuard DNS filter | 精确 |
| `adsterra.com` | `\|\|adsterra.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|adsterra.com^` | AdGuard DNS filter | 精确 |
| `afi-b.com` | `\|\|afi-b.com^` | CHN: anti-AD, AdGuard DNS filter, HaGeZi's Ultimate Blocklist | `@@\|\|afi-b.com^` | AdGuard DNS filter | 精确 |
| `awin1.com` | `\|\|awin1.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|awin1.com^` | AdGuard DNS filter | 精确 |
| `analytics.cibc.com` | `\|\|analytics.cibc.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|analytics.cibc.com^` | AdGuard DNS filter | 精确 |
| `om-ssl.consorsbank.de` | `\|\|om-ssl.consorsbank.de^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|om-ssl.consorsbank.de^` | AdGuard DNS filter | 精确 |
| `data.digital.costco.ca` | `\|\|data.digital.costco.ca^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.digital.costco.ca^` | AdGuard DNS filter | 精确 |
| `data.digital.costco.com` | `\|\|data.digital.costco.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.digital.costco.com^` | AdGuard DNS filter | 精确 |
| `data.orders.costco.com` | `\|\|data.orders.costco.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.orders.costco.com^` | AdGuard DNS filter | 精确 |
| `daraz.com` | `\|\|daraz.com^` | OISD Blocklist Small, CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|daraz.com^` | AdGuard DNS filter | 精确 |
| `datadoghq-browser-agent.com` | `\|\|datadoghq-browser-agent.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|datadoghq-browser-agent.com^` | AdGuard DNS filter | 精确 |
| `marketing.net.idealo-partner.com` | `\|\|marketing.net.idealo-partner.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|marketing.net.idealo-partner.com^` | AdGuard DNS filter | 精确 |
| `jdoqocy.com` | `\|\|jdoqocy.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|jdoqocy.com^` | AdGuard DNS filter | 精确 |
| `omsc.kpn.com` | `\|\|omsc.kpn.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|omsc.kpn.com^` | AdGuard DNS filter | 精确 |
| `torimochi.line-apps.com` | `\|\|torimochi.line-apps.com^` | CHN: anti-AD | `@@\|\|torimochi.line-apps.com^` | AdGuard DNS filter | 精确 |
| `logentries.com` | `\|\|logentries.com^` | CHN: anti-AD, AdGuard DNS filter, HaGeZi's Ultimate Blocklist | `@@\|\|logentries.com^` | AdGuard DNS filter | 精确 |
| `sedge.nfl.com` | `\|\|sedge.nfl.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|sedge.nfl.com^` | AdGuard DNS filter | 精确 |
| `cmp.osano.com` | `\|\|cmp.osano.com^` | CHN: anti-AD, CHN: AdRules DNS List | `@@\|\|cmp.osano.com^` | AdGuard DNS filter | 精确 |
| `data.promo.timhortons.ca` | `\|\|data.promo.timhortons.ca^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.promo.timhortons.ca^` | AdGuard DNS filter | 精确 |
| `hb.afl.rakuten.co.jp` | `\|\|hb.afl.rakuten.co.jp^` | AdGuard DNS filter | `@@\|\|hb.afl.rakuten.co.jp^` | AdGuard DNS filter | 精确 |
| `app.appsflyer.com` | `\|\|app.appsflyer.com^` | AdGuard DNS filter, HaGeZi's Ultimate Blocklist | `@@\|\|app.appsflyer.com^` | AdGuard DNS filter | 精确 |
| `ezodn.com` | `\|\|ezodn.com^` | OISD Blocklist Small, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, HaGeZi's Threat Intelligence Feeds | `@@\|\|ezodn.com^` | AdGuard DNS filter | 精确 |
| `data.email.premierleague.com` | `\|\|data.email.premierleague.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.email.premierleague.com^` | AdGuard DNS filter | 精确 |
| `data.notify.macys.com` | `\|\|data.notify.macys.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.notify.macys.com^` | AdGuard DNS filter | 精确 |
| `data.orders.costco.ca` | `\|\|data.orders.costco.ca^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.orders.costco.ca^` | AdGuard DNS filter | 精确 |
| `unsubscribe.email.premierleague.com` | `\|\|unsubscribe.email.premierleague.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|unsubscribe.email.premierleague.com^` | AdGuard DNS filter | 精确 |
| `omniture.walmart.com` | `\|\|omniture.walmart.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|omniture.walmart.com^` | AdGuard DNS filter | 精确 |
| `swasc.homedepot.com` | `\|\|swasc.homedepot.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|swasc.homedepot.com^` | AdGuard DNS filter | 精确 |
| `tms.capitalone.com` | `\|\|tms.capitalone.com^` | AdGuard DNS filter | `@@\|\|tms.capitalone.com^` | AdGuard DNS filter | 精确 |
| `net.daraz.pk` | `\|\|net.daraz.pk^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|daraz.pk^` | AdGuard DNS filter | 级联 |
| `belgium.wolterskluwer.com` | `\|\|belgium.wolterskluwer.com^` | AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|belgium.wolterskluwer.com^` | AdGuard DNS filter | 精确 |
| `app.adjust.com` | `\|\|app.adjust.com^` | AdGuard DNS filter | `@@\|\|app.adjust.com^` | CHN: anti-AD, AdGuard DNS filter | 精确 |
| `statcounter.com` | `\|\|statcounter.com^` | OISD Blocklist Small, CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, HaGeZi's Threat Intelligence Feeds | `@@\|\|statcounter.com^` | AdGuard DNS filter | 精确 |
| `ad.10010.com` | `\|\|ad.10010.com^` | AWAvenue Ads Rule, OISD Blocklist Small, CHN: anti-AD, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `\|\|ad.ourgame.com^` | CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `sax.sina.com.cn` | `\|\|sax.sina.com.cn^` | OISD Blocklist Small, CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|sax.sina.com.cn^` | AdGuard DNS filter | 精确 |
| `autocomplete.clearbit.com` | `\|\|autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `aax-fe.amazon.co.jp` | `\|\|aax-fe.amazon.co.jp^` | HaGeZi's Ultimate Blocklist | `@@\|\|aax-fe.amazon.co.jp^` | AdGuard DNS filter | 精确 |
| `ad.dogpile.com` | `\|\|ad.dogpile.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|dogpile.com^` | AdGuard DNS filter | 级联 |
| `str.hit.gemius.pl` | `\|\|str.hit.gemius.pl^` | HaGeZi's Ultimate Blocklist | `@@\|\|str.hit.gemius.pl^` | AdGuard DNS filter | 精确 |
| `api.karte.io` | `\|\|api.karte.io^` | HaGeZi's Ultimate Blocklist | `@@\|\|api.karte.io^` | AdGuard DNS filter | 精确 |
| `settings-win.data.microsoft.com` | `\|\|settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `ads.privacy.qq.com` | `\|\|ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|ads.privacy.qq.com^` | CHN: anti-AD | 精确 |

## 八、$ 修饰符分布

> 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 100.0% |

## 九、白名单威胁情报审计

> 多层防御体系：本地 DNS/DoH、离线启发式、同形字检测 + 免费威胁情报（URLhaus/ThreatFox/RDAP/诈骗检测/DNSBL）+ 可选在线情报（VirusTotal/AI/GSB/PhishTank/urlscan/CT）。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

*审计未启用或无域名规则*

## 十、规则语法支持度

| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |
|---------|---------|------|---------|------|
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,551,719 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 0 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 304 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 604 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 74 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 5 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| duckdns.org | 25,429 |
| fbcdn.net | 9,212 |
| whatsapp.net | 5,606 |
| gitbook.io | 3,941 |
| cloudfront.net | 3,196 |
| hl.cn | 2,433 |
| vercel.app | 2,414 |
| web.app | 2,153 |
| ddns.net | 2,104 |
| pages.dev | 2,077 |
| wixstudio.com | 2,068 |
| weebly.com | 2,044 |
| firebaseapp.com | 1,981 |
| amazonaws.com | 1,537 |
| run.app | 1,326 |
| netlify.app | 1,198 |
| godaddysites.com | 1,188 |
| r2.dev | 1,125 |
| co.com | 1,052 |
| my.id | 884 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 35.6s |
| 源成功率 | 18/18 |
| 缓存命中 | 0 |
| 精确去重 | 796,189 |
| 规范化去重 | 4,064 |
| 正则去重 | 321 |
| 质量过滤丢弃 | 39 |
| 模式丢弃 | 0 |
| CSS 丢弃 | 0 |
| 未识别行丢弃 | 112 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.6 字符 |
| 最短/最长域名 | 2 / 236 字符 |

---
*AdGuard Rules Merger · 自动生成 · 2026-11-22*
