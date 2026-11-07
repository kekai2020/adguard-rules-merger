# AdGuard Rules Merger — 规则分析报告

> 合并时间 2026-11-07 05:03:58 | 源：18/18 | 缓存命中：7

## 一、概览

| 指标 | 数值 |
|------|------|
| Block 规则 | 2,450,933 |
| Allow 白名单 | 301 |
| 纯去重率（去重阶段） | 19.6% |
| 最终压缩（原始→输出） | 3,092,477 → 2,451,234（-21%） |
| 聚合精简（净） | 35,015 |
| 冲突消解 | 0 |
| 带 $ 修饰符规则数 | 5 |
| 合并时间 | 2026-11-07 05:03:58 |
| 总耗时 | 59.3s |

### ⏱️ 各阶段执行耗时

| 流水线阶段 | 耗时 | 占比 |
|---|---:|---:|
| 抓取/解析 | 18629.7 ms | 31.5% |
| badfilter 取消 | 71.1 ms | 0.1% |
| 聚合 | 4245.3 ms | 7.2% |
| 冲突解析 | 1189.5 ms | 2.0% |
| 排序 | 1351.0 ms | 2.3% |
| 分类重判 | 7 µs | 0.0% |
| 统计/贡献 | 5927.6 ms | 10.0% |
| 白名单审计 | 27028.1 ms | 45.6% |
| 差异对比 | 2 µs | 0.0% |
| 内容哈希 | 785.3 ms | 1.3% |
| **合计** | **59227.6 ms** | **100.0%** |

### 执行摘要

- 最终输出 **2,450,933** 条 Block + **301** 条 Allow（原始 3,092,477，压缩 **-21%**）
- 🔁 相对 diff：新增 0 / 移除 0 域名

## 二、优化流水线

| 阶段 | 规则数 | 本阶段减少 |
|------|--------|-----------|
| 原始规则（Raw） | 3,092,477 | - |
| 去重后（精确 602,255 / 规范化 3,646 / 正则 321） | 2,486,255 | -606,222 |
| badfilter 取消后（被 $badfilter 取消） | 2,486,249 | -6 |
| 聚合后（净：折叠 35,015） | 2,451,234 | -35,015 |
| 冲突消解后（最终输出） | 2,451,234 | -0 |

## 三、规则类型与类别分布

### 规则类型

| 类型 | 数量 |
|------|------|
| 普通域名 | 2,450,556 |
| 正则 | 604 |
| IP 地址 | 74 |

### 类别分布（Block）

| 类别 | 数量 |
|------|------|
| 恶意 | 1,447,349 |
| 其他 | 640,450 |
| 广告 | 305,470 |
| 钓鱼 | 57,127 |
| 追踪 | 376 |
| 挖矿 | 161 |

## 四、按源贡献分析（独占 vs 共享）

> 统计覆盖最终输出规则（含正则规则）。输出覆盖 = 该源参与的最终规则数（独占+共享）；覆盖率 = 输出覆盖/原始规则；独占率 = 独占/输出覆盖。

| 源 | 原始规则 | 输出覆盖 | 覆盖率 | 独占规则 | 与他源共享 | 独占率 |
|------|---------|---------|--------|---------|-----------|--------|
| HaGeZi's Threat Intelligence Feeds | 1,446,919 | 1,446,266 | 100.0% | 1,295,676 | 150,590 | 89.6% |
| HaGeZi's Gambling Blocklist | 630,828 | 630,771 | 100.0% | 624,482 | 6,289 | 99.0% |
| HaGeZi's Ultimate Blocklist | 261,545 | 259,590 | 99.3% | 102,844 | 156,746 | 39.6% |
| Phishing Army | 145,874 | 124,240 | 85.2% | 41,151 | 83,089 | 33.1% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,360 | 16,093 | 98.4% | 14,675 | 1,418 | 91.2% |
| CHN: AdRules DNS List | 210,185 | 206,089 | 98.1% | 9,282 | 196,807 | 4.5% |
| CHN: anti-AD | 101,876 | 101,170 | 99.3% | 7,578 | 93,592 | 7.5% |
| AdGuard DNS filter | 190,126 | 187,577 | 98.7% | 5,127 | 182,450 | 2.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 21,020 | 19,579 | 93.1% | 2,201 | 17,378 | 11.2% |
| ShadowWhisperer's Dating List | 1,385 | 1,385 | 100.0% | 1,291 | 94 | 93.2% |
| Malicious URL Blocklist (URLHaus) | 1,921 | 1,839 | 95.7% | 530 | 1,309 | 28.8% |
| Stalkerware Indicators List | 929 | 508 | 54.7% | 256 | 252 | 50.4% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 100.0% | 57 | 0 | 100.0% |
| OISD Blocklist Small | 60,923 | 59,282 | 97.3% | 29 | 59,253 | 0.0% |
| Scam Blocklist by DurableNapkin | 924 | 921 | 99.7% | 7 | 914 | 0.8% |
| NoCoin Filter List | 312 | 269 | 86.2% | 3 | 266 | 1.1% |
| HaGeZi's Windows/Office Tracker Blocklist | 384 | 376 | 97.9% | 1 | 375 | 0.3% |
| AWAvenue Ads Rule | 909 | 756 | 83.2% | 0 | 756 | 0.0% |

## 五、源间重复矩阵（两两重复规则数 + 重复率）

> 每格 `共同规则数 (重复率%)`，重复率 = Jaccard = 共同/并集（对称）；对角线为该源输出覆盖数。颜色：🟥≥80% 🟧50–80% 🟨20–50% 🟩<20%（含 0）

| # | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1** | **1,446,266** | 🟩 5,058 (0.2%) | 🟩 85,113 (5.3%) | 🟩 27,036 (1.7%) | 🟩 26,097 (1.6%) | 🟩 69,562 (4.6%) | 🟩 20,658 (1.4%) | 🟩 22,826 (1.5%) | 🟩 4,389 (0.3%) | 🟩 128 (0.0%) | 🟩 1,069 (0.1%) | 🟩 18 (0.0%) | 🟩 838 (0.1%) | 🟩 14 (0.0%) | 🟩 206 (0.0%) | · | 🟩 107 (0.0%) | · |
| **2** | 🟩 5,058 (0.2%) | **630,771** | 🟩 1,518 (0.2%) | 🟩 452 (0.1%) | 🟩 411 (0.1%) | 🟩 163 (0.0%) | 🟩 214 (0.0%) | 🟩 136 (0.0%) | 🟩 28 (0.0%) | 🟩 4 (0.0%) | 🟩 3 (0.0%) | · | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **3** | 🟩 85,113 (5.3%) | 🟩 1,518 (0.2%) | **259,590** | 🟨 81,275 (21.1%) | 🟨 76,037 (20.5%) | 🟩 15,243 (4.1%) | 🟨 63,891 (21.5%) | 🟨 54,448 (20.6%) | 🟩 2,377 (0.9%) | 🟩 1,361 (0.5%) | 🟩 1,136 (0.4%) | 🟩 76 (0.0%) | 🟩 361 (0.1%) | 🟩 690 (0.3%) | 🟩 72 (0.0%) | 🟩 374 (0.1%) | 🟩 117 (0.0%) | · |
| **4** | 🟩 27,036 (1.7%) | 🟩 452 (0.1%) | 🟨 81,275 (21.1%) | **206,089** | 🟧 174,608 (79.7%) | 🟩 23 (0.0%) | 🟨 87,548 (39.8%) | 🟨 55,565 (26.5%) | 🟩 30 (0.0%) | 🟩 85 (0.0%) | 🟩 10 (0.0%) | 🟩 36 (0.0%) | 🟩 914 (0.4%) | 🟩 566 (0.3%) | 🟩 3 (0.0%) | 🟩 111 (0.1%) | 🟩 80 (0.0%) | · |
| **5** | 🟩 26,097 (1.6%) | 🟩 411 (0.1%) | 🟨 76,037 (20.5%) | 🟧 174,608 (79.7%) | **187,577** | 🟩 16 (0.0%) | 🟨 77,867 (36.9%) | 🟨 55,022 (28.7%) | 🟩 25 (0.0%) | 🟩 35 (0.0%) | 🟩 3 (0.0%) | 🟩 31 (0.0%) | 🟩 23 (0.0%) | 🟩 241 (0.1%) | 🟩 2 (0.0%) | 🟩 25 (0.0%) | 🟩 43 (0.0%) | · |
| **6** | 🟩 69,562 (4.6%) | 🟩 163 (0.0%) | 🟩 15,243 (4.1%) | 🟩 23 (0.0%) | 🟩 16 (0.0%) | **124,240** | 🟩 10 (0.0%) | 🟩 8 (0.0%) | 🟩 16,562 (13.0%) | 🟩 9 (0.0%) | 🟩 7 (0.0%) | · | 🟩 4 (0.0%) | · | · | · | · | · |
| **7** | 🟩 20,658 (1.4%) | 🟩 214 (0.0%) | 🟨 63,891 (21.5%) | 🟨 87,548 (39.8%) | 🟨 77,867 (36.9%) | 🟩 10 (0.0%) | **101,170** | 🟨 42,144 (35.6%) | 🟩 22 (0.0%) | 🟩 30 (0.0%) | 🟩 468 (0.5%) | 🟩 25 (0.0%) | 🟩 9 (0.0%) | 🟩 722 (0.7%) | 🟩 4 (0.0%) | 🟩 63 (0.1%) | 🟩 258 (0.3%) | · |
| **8** | 🟩 22,826 (1.5%) | 🟩 136 (0.0%) | 🟨 54,448 (20.6%) | 🟨 55,565 (26.5%) | 🟨 55,022 (28.7%) | 🟩 8 (0.0%) | 🟨 42,144 (35.6%) | **59,282** | 🟩 10 (0.0%) | 🟩 23 (0.0%) | 🟩 6 (0.0%) | 🟩 22 (0.0%) | 🟩 13 (0.0%) | 🟩 703 (1.2%) | 🟩 1 (0.0%) | 🟩 27 (0.0%) | 🟩 53 (0.1%) | · |
| **9** | 🟩 4,389 (0.3%) | 🟩 28 (0.0%) | 🟩 2,377 (0.9%) | 🟩 30 (0.0%) | 🟩 25 (0.0%) | 🟩 16,562 (13.0%) | 🟩 22 (0.0%) | 🟩 10 (0.0%) | **19,579** | 🟩 9 (0.0%) | 🟩 10 (0.0%) | · | 🟩 3 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 2 (0.0%) | · |
| **10** | 🟩 128 (0.0%) | 🟩 4 (0.0%) | 🟩 1,361 (0.5%) | 🟩 85 (0.0%) | 🟩 35 (0.0%) | 🟩 9 (0.0%) | 🟩 30 (0.0%) | 🟩 23 (0.0%) | 🟩 9 (0.0%) | **16,093** | 🟩 4 (0.0%) | · | · | 🟩 2 (0.0%) | · | · | 🟩 1 (0.0%) | · |
| **11** | 🟩 1,069 (0.1%) | 🟩 3 (0.0%) | 🟩 1,136 (0.4%) | 🟩 10 (0.0%) | 🟩 3 (0.0%) | 🟩 7 (0.0%) | 🟩 468 (0.5%) | 🟩 6 (0.0%) | 🟩 10 (0.0%) | 🟩 4 (0.0%) | **1,839** | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · |
| **12** | 🟩 18 (0.0%) | · | 🟩 76 (0.0%) | 🟩 36 (0.0%) | 🟩 31 (0.0%) | · | 🟩 25 (0.0%) | 🟩 22 (0.0%) | · | · | · | **1,385** | 🟩 2 (0.1%) | · | · | · | · | · |
| **13** | 🟩 838 (0.1%) | 🟩 3 (0.0%) | 🟩 361 (0.1%) | 🟩 914 (0.4%) | 🟩 23 (0.0%) | 🟩 4 (0.0%) | 🟩 9 (0.0%) | 🟩 13 (0.0%) | 🟩 3 (0.0%) | · | 🟩 1 (0.0%) | 🟩 2 (0.1%) | **921** | · | · | · | 🟩 1 (0.1%) | · |
| **14** | 🟩 14 (0.0%) | · | 🟩 690 (0.3%) | 🟩 566 (0.3%) | 🟩 241 (0.1%) | · | 🟩 722 (0.7%) | 🟩 703 (1.2%) | 🟩 1 (0.0%) | 🟩 2 (0.0%) | · | · | · | **756** | 🟩 1 (0.1%) | 🟩 7 (0.6%) | · | · |
| **15** | 🟩 206 (0.0%) | 🟩 1 (0.0%) | 🟩 72 (0.0%) | 🟩 3 (0.0%) | 🟩 2 (0.0%) | · | 🟩 4 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.0%) | · | · | 🟩 1 (0.1%) | **508** | · | · | · |
| **16** | · | · | 🟩 374 (0.1%) | 🟩 111 (0.1%) | 🟩 25 (0.0%) | · | 🟩 63 (0.1%) | 🟩 27 (0.0%) | · | · | · | · | · | 🟩 7 (0.6%) | · | **376** | · | · |
| **17** | 🟩 107 (0.0%) | 🟩 1 (0.0%) | 🟩 117 (0.0%) | 🟩 80 (0.0%) | 🟩 43 (0.0%) | · | 🟩 258 (0.3%) | 🟩 53 (0.1%) | 🟩 2 (0.0%) | 🟩 1 (0.0%) | 🟩 1 (0.0%) | · | 🟩 1 (0.1%) | · | · | · | **269** | · |
| **18** | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | · | **57** |

**源编号对照**（按输出覆盖降序）

| # | 源 | 输出覆盖 |
|---|---|----------|
| 1 | HaGeZi's Threat Intelligence Feeds | 1,446,266 |
| 2 | HaGeZi's Gambling Blocklist | 630,771 |
| 3 | HaGeZi's Ultimate Blocklist | 259,590 |
| 4 | CHN: AdRules DNS List | 206,089 |
| 5 | AdGuard DNS filter | 187,577 |
| 6 | Phishing Army | 124,240 |
| 7 | CHN: anti-AD | 101,170 |
| 8 | OISD Blocklist Small | 59,282 |
| 9 | Phishing URL Blocklist (PhishTank and OpenPhish) | 19,579 |
| 10 | HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,093 |
| 11 | Malicious URL Blocklist (URLHaus) | 1,839 |
| 12 | ShadowWhisperer's Dating List | 1,385 |
| 13 | Scam Blocklist by DurableNapkin | 921 |
| 14 | AWAvenue Ads Rule | 756 |
| 15 | Stalkerware Indicators List | 508 |
| 16 | HaGeZi's Windows/Office Tracker Blocklist | 376 |
| 17 | NoCoin Filter List | 269 |
| 18 | HaGeZi's DNS Rebind Protection | 57 |

### 源间重复 Top 20（双向覆盖率明细）

> 每对源共同拥有的规则数；覆盖率 = 共同规则数 / 该源输出覆盖数。

| 源 A | 源 B | 共同规则数 | 重复率 | A 覆盖率 | B 覆盖率 |
|------|------|-----------|--------|---------|---------|
| AdGuard DNS filter | CHN: AdRules DNS List | 174,608 | 🟧 79.7% | 93.1% | 84.7% |
| CHN: anti-AD | CHN: AdRules DNS List | 87,548 | 🟨 39.8% | 86.5% | 42.5% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Ultimate Blocklist | 85,113 | 🟩 5.3% | 5.9% | 32.8% |
| CHN: AdRules DNS List | HaGeZi's Ultimate Blocklist | 81,275 | 🟨 21.1% | 39.4% | 31.3% |
| AdGuard DNS filter | CHN: anti-AD | 77,867 | 🟨 36.9% | 41.5% | 77.0% |
| AdGuard DNS filter | HaGeZi's Ultimate Blocklist | 76,037 | 🟨 20.5% | 40.5% | 29.3% |
| Phishing Army | HaGeZi's Threat Intelligence Feeds | 69,562 | 🟩 4.6% | 56.0% | 4.8% |
| CHN: anti-AD | HaGeZi's Ultimate Blocklist | 63,891 | 🟨 21.5% | 63.2% | 24.6% |
| CHN: AdRules DNS List | OISD Blocklist Small | 55,565 | 🟨 26.5% | 27.0% | 93.7% |
| AdGuard DNS filter | OISD Blocklist Small | 55,022 | 🟨 28.7% | 29.3% | 92.8% |
| HaGeZi's Ultimate Blocklist | OISD Blocklist Small | 54,448 | 🟨 20.6% | 21.0% | 91.8% |
| CHN: anti-AD | OISD Blocklist Small | 42,144 | 🟨 35.6% | 41.7% | 71.1% |
| CHN: AdRules DNS List | HaGeZi's Threat Intelligence Feeds | 27,036 | 🟩 1.7% | 13.1% | 1.9% |
| AdGuard DNS filter | HaGeZi's Threat Intelligence Feeds | 26,097 | 🟩 1.6% | 13.9% | 1.8% |
| HaGeZi's Threat Intelligence Feeds | OISD Blocklist Small | 22,826 | 🟩 1.5% | 1.6% | 38.5% |
| CHN: anti-AD | HaGeZi's Threat Intelligence Feeds | 20,658 | 🟩 1.4% | 20.4% | 1.4% |
| Phishing Army | Phishing URL Blocklist (PhishTank and OpenPhish) | 16,562 | 🟩 13.0% | 13.3% | 84.6% |
| Phishing Army | HaGeZi's Ultimate Blocklist | 15,243 | 🟩 4.1% | 12.3% | 5.9% |
| HaGeZi's Threat Intelligence Feeds | HaGeZi's Gambling Blocklist | 5,058 | 🟩 0.2% | 0.3% | 0.8% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | HaGeZi's Threat Intelligence Feeds | 4,389 | 🟩 0.3% | 22.4% | 0.3% |

## 六、各源自去重率

> 输出覆盖 = 去重/聚合后该源仍覆盖的规则数（含正则规则）；自去重率 = 1 - 输出覆盖/原始。

| 源 | 原始规则 | 去重后有效 | 自去重率 |
|------|---------|-----------|---------|
| HaGeZi's Threat Intelligence Feeds | 1,446,919 | 1,446,266 | 0.0% |
| HaGeZi's Gambling Blocklist | 630,828 | 630,771 | 0.0% |
| HaGeZi's Ultimate Blocklist | 261,545 | 259,590 | 0.7% |
| CHN: AdRules DNS List | 210,185 | 206,089 | 1.9% |
| AdGuard DNS filter | 190,126 | 187,577 | 1.3% |
| Phishing Army | 145,874 | 124,240 | 14.8% |
| CHN: anti-AD | 101,876 | 101,170 | 0.7% |
| OISD Blocklist Small | 60,923 | 59,282 | 2.7% |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 21,020 | 19,579 | 6.9% |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 16,360 | 16,093 | 1.6% |
| Malicious URL Blocklist (URLHaus) | 1,921 | 1,839 | 4.3% |
| ShadowWhisperer's Dating List | 1,385 | 1,385 | 0.0% |
| Scam Blocklist by DurableNapkin | 924 | 921 | 0.3% |
| AWAvenue Ads Rule | 909 | 756 | 16.8% |
| Stalkerware Indicators List | 929 | 508 | 45.3% |
| HaGeZi's Windows/Office Tracker Blocklist | 384 | 376 | 2.1% |
| NoCoin Filter List | 312 | 269 | 13.8% |
| HaGeZi's DNS Rebind Protection | 57 | 57 | 0.0% |

## 七、冲突分析（白名单覆盖拦截）

> 与白名单重叠的拦截规则（blocks-preserved 政策：拦截规则保留输出、白名单单独成文件，此处仅记录重叠明细；仅显示前 50 条 / 共 0 条）。展示双方来源。精确=域名完全匹配，级联=白名单父域覆盖子域，通配符=白名单通配父域（`*.parent`）覆盖子域。完整清单见 output/conflicts.json。

| 域名 | 被拦规则 | 被拦来源 | 白名单规则 | 白名单来源 | 类型 |
|------|---------|---------|-----------|-----------|------|
| `js.monitor.azure.com` | `\|\|js.monitor.azure.com^` | HaGeZi's Windows/Office Tracker Blocklist | `@@\|\|js.monitor.azure.com^` | AdGuard DNS filter | 精确 |
| `googleadservices.com` | `\|\|googleadservices.com^` | AWAvenue Ads Rule, CHN: anti-AD, OISD Blocklist Small, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|googleadservices.com^` | AdGuard DNS filter | 精确 |
| `adsterra.com` | `\|\|adsterra.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|adsterra.com^` | AdGuard DNS filter | 精确 |
| `afi-b.com` | `\|\|afi-b.com^` | CHN: anti-AD, AdGuard DNS filter, HaGeZi's Ultimate Blocklist | `@@\|\|afi-b.com^` | AdGuard DNS filter | 精确 |
| `awin1.com` | `\|\|awin1.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|awin1.com^` | AdGuard DNS filter | 精确 |
| `om-ssl.consorsbank.de` | `\|\|om-ssl.consorsbank.de^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|om-ssl.consorsbank.de^` | AdGuard DNS filter | 精确 |
| `data.digital.costco.ca` | `\|\|data.digital.costco.ca^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.digital.costco.ca^` | AdGuard DNS filter | 精确 |
| `data.digital.costco.com` | `\|\|data.digital.costco.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.digital.costco.com^` | AdGuard DNS filter | 精确 |
| `data.orders.costco.com` | `\|\|data.orders.costco.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.orders.costco.com^` | AdGuard DNS filter | 精确 |
| `daraz.com` | `\|\|daraz.com^` | CHN: anti-AD, OISD Blocklist Small, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|daraz.com^` | AdGuard DNS filter | 精确 |
| `datadoghq-browser-agent.com` | `\|\|datadoghq-browser-agent.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|datadoghq-browser-agent.com^` | AdGuard DNS filter | 精确 |
| `proto2ad.durasite.net` | `\|\|proto2ad.durasite.net^` | CHN: anti-AD, OISD Blocklist Small, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|proto2ad.durasite.net^` | AdGuard DNS filter | 精确 |
| `marketing.net.idealo-partner.com` | `\|\|marketing.net.idealo-partner.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|marketing.net.idealo-partner.com^` | AdGuard DNS filter | 精确 |
| `jdoqocy.com` | `\|\|jdoqocy.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|jdoqocy.com^` | AdGuard DNS filter | 精确 |
| `omsc.kpn.com` | `\|\|omsc.kpn.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|omsc.kpn.com^` | AdGuard DNS filter | 精确 |
| `torimochi.line-apps.com` | `\|\|torimochi.line-apps.com^` | CHN: anti-AD | `@@\|\|torimochi.line-apps.com^` | AdGuard DNS filter | 精确 |
| `logentries.com` | `\|\|logentries.com^` | CHN: anti-AD, AdGuard DNS filter, HaGeZi's Ultimate Blocklist | `@@\|\|logentries.com^` | AdGuard DNS filter | 精确 |
| `sedge.nfl.com` | `\|\|sedge.nfl.com^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|sedge.nfl.com^` | AdGuard DNS filter | 精确 |
| `cmp.osano.com` | `\|\|cmp.osano.com^` | CHN: anti-AD, CHN: AdRules DNS List | `@@\|\|cmp.osano.com^` | AdGuard DNS filter | 精确 |
| `data.promo.timhortons.ca` | `\|\|data.promo.timhortons.ca^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.promo.timhortons.ca^` | AdGuard DNS filter | 精确 |
| `hb.afl.rakuten.co.jp` | `\|\|hb.afl.rakuten.co.jp^` | AdGuard DNS filter | `@@\|\|hb.afl.rakuten.co.jp^` | AdGuard DNS filter | 精确 |
| `app.appsflyer.com` | `\|\|app.appsflyer.com^` | AdGuard DNS filter, HaGeZi's Ultimate Blocklist | `@@\|\|app.appsflyer.com^` | AdGuard DNS filter | 精确 |
| `ezodn.com` | `\|\|ezodn.com^` | OISD Blocklist Small, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist, HaGeZi's Threat Intelligence Feeds | `@@\|\|ezodn.com^` | AdGuard DNS filter | 精确 |
| `data.email.premierleague.com` | `\|\|data.email.premierleague.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.email.premierleague.com^` | AdGuard DNS filter | 精确 |
| `data.notify.macys.com` | `\|\|data.notify.macys.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.notify.macys.com^` | AdGuard DNS filter | 精确 |
| `data.orders.costco.ca` | `\|\|data.orders.costco.ca^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|data.orders.costco.ca^` | AdGuard DNS filter | 精确 |
| `omniture.walmart.com` | `\|\|omniture.walmart.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|omniture.walmart.com^` | AdGuard DNS filter | 精确 |
| `swasc.homedepot.com` | `\|\|swasc.homedepot.com^` | AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|swasc.homedepot.com^` | AdGuard DNS filter | 精确 |
| `tms.capitalone.com` | `\|\|tms.capitalone.com^` | AdGuard DNS filter | `@@\|\|tms.capitalone.com^` | AdGuard DNS filter | 精确 |
| `net.daraz.pk` | `\|\|net.daraz.pk^` | CHN: anti-AD, AdGuard DNS filter, CHN: AdRules DNS List | `@@\|\|daraz.pk^` | AdGuard DNS filter | 级联 |
| `belgium.wolterskluwer.com` | `\|\|belgium.wolterskluwer.com^` | AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|belgium.wolterskluwer.com^` | AdGuard DNS filter | 精确 |
| `app.adjust.com` | `\|\|app.adjust.com^` | AdGuard DNS filter | `@@\|\|app.adjust.com^` | CHN: anti-AD, AdGuard DNS filter | 精确 |
| `statcounter.com` | `\|\|statcounter.com^` | CHN: anti-AD, OISD Blocklist Small, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|statcounter.com^` | AdGuard DNS filter | 精确 |
| `ad.10010.com` | `\|\|ad.10010.com^` | AWAvenue Ads Rule, CHN: anti-AD, OISD Blocklist Small, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|ad.10010.com^` | AdGuard DNS filter | 精确 |
| `ad.ourgame.com` | `\|\|ad.ourgame.com^` | CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|ad.ourgame.com^` | AdGuard DNS filter | 精确 |
| `sax.sina.com.cn` | `\|\|sax.sina.com.cn^` | CHN: anti-AD, OISD Blocklist Small, AdGuard DNS filter, CHN: AdRules DNS List, HaGeZi's Ultimate Blocklist | `@@\|\|sax.sina.com.cn^` | AdGuard DNS filter | 精确 |
| `autocomplete.clearbit.com` | `\|\|autocomplete.clearbit.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|autocomplete.clearbit.com^` | CHN: anti-AD | 精确 |
| `ad.dogpile.com` | `\|\|ad.dogpile.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|dogpile.com^` | AdGuard DNS filter | 级联 |
| `str.hit.gemius.pl` | `\|\|str.hit.gemius.pl^` | HaGeZi's Ultimate Blocklist | `@@\|\|str.hit.gemius.pl^` | AdGuard DNS filter | 精确 |
| `api.karte.io` | `\|\|api.karte.io^` | HaGeZi's Ultimate Blocklist | `@@\|\|api.karte.io^` | AdGuard DNS filter | 精确 |
| `settings-win.data.microsoft.com` | `\|\|settings-win.data.microsoft.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|settings-win.data.microsoft.com^` | CHN: anti-AD | 精确 |
| `global.api.huangye.miui.com` | `\|\|global.api.huangye.miui.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|api.huangye.miui.com^` | CHN: anti-AD | 级联 |
| `ads.privacy.qq.com` | `\|\|ads.privacy.qq.com^` | HaGeZi's Ultimate Blocklist | `@@\|\|ads.privacy.qq.com^` | CHN: anti-AD | 精确 |

## 八、$ 修饰符分布

> 保留 `$` 修饰符（important / badfilter 等），这些列表是 AdGuard Home 语法适配的，修饰符有 DNS 层语义。

| 修饰符 | 规则数 | 占比 |
|--------|--------|------|
| `$important` | 5 | 100.0% |

## 九、白名单威胁情报审计

> 多层防御体系：本地 DNS/DoH、离线启发式、同形字检测 + 免费威胁情报（URLhaus/ThreatFox/RDAP/诈骗检测/DNSBL）+ 可选在线情报（VirusTotal/AI/GSB/PhishTank/urlscan/CT）。🔴 恶意建议移除此白名单；🟡 可疑需人工确认；🟢 安全可放心放行。需在配置中启用 `whitelist_audit.enabled`。

- 🔴 恶意：0
- 🟡 可疑：27
- 🟢 安全：261
- ⚪ 未知：1

### 风险分分布

| 风险分区间 | 数量 |
|-----------|------|
| 高风险 (≥50) | 0 |
| 中风险 (20–49) | 7 |
| 低风险 (1–19) | 20 |
| 无风险 (0) | 262 |

### 风险最高 Top 10

| 域名 | 评级 | 风险分 | 原因 |
|------|------|--------|------|
| `cloud.notification-naviextras.com` | 🟡 | 27 | DNS NXDOMAIN（域名已过期，白名单可能无效）; 拼写劫持仿冒品牌 icloud（编辑距离 1） |
| `email.procook.co.uk` | 🟡 | 27 | DNS NXDOMAIN（域名已过期，白名单可能无效）; 拼写劫持仿冒品牌 gmail（编辑距离 1） |
| `ad.cityu.edu.hk` | 🟡 | 20 | 解析到私有/回环 IP: ['172.26.255.1', '172.26.255.2', '172.26.255.12', '172.26.255.11'] |
| `dishy.starlink.com` | 🟡 | 20 | 解析到私有/回环 IP: ['192.168.100.1'] |
| `edge-enterprise.activity.windows.com` | 🟡 | 20 | 解析到私有/回环 IP: ['127.0.0.1'] |
| `edge.activity.windows.com` | 🟡 | 20 | 解析到私有/回环 IP: ['127.0.0.1'] |
| `plex.direct` | 🟡 | 20 | 解析到私有/回环 IP: ['0.0.0.0'] |
| `a.adwolf.ru` | 🟡 | 15 | DNS NXDOMAIN（域名已过期，白名单可能无效） |
| `ads.tdbank.com` | 🟡 | 15 | DNS NXDOMAIN（域名已过期，白名单可能无效） |
| `avqs.mcafee.com` | 🟡 | 15 | DNS NXDOMAIN（域名已过期，白名单可能无效） |

### 防御层概览

| 层级 | 检测内容 | 状态 | 成本 | 命中数 |
|------|---------|------|------|--------|
| DNS 解析 | NXDOMAIN/私有IP检测 | ✅ 启用 | 免费 | 21 |
| DoH 加密解析 | NextDNS 加密传输，失败回退系统DNS | ✅ 启用 | 免费 | — |
| URLhaus | 恶意软件分发域名 | ✅ 启用 | 免费 | 0 |
| ThreatFox | C2 命令控制域名 | ✅ 启用 | 免费 | 0 |
| RDAP 域名年龄 | 新注册<30天标记 | ✅ 启用 | 免费 | 0 |
| MarketNow 诈骗检测 | 拼写劫持/可疑TLD/未注册 | ✅ 启用 | 免费 | 0 |
| DNSBL 黑名单 | Spamhaus DBL + SURBL | ✅ 启用 | 免费 | 0 |
| VirusTotal | 多引擎厂商信誉 | ⬜ 未启用 | 需API Key | - |
| AI/LLM 分类 | 低置信语义分类 | ⬜ 未启用 | 需API Key | - |
| 内置离线启发式 | 滥用TLD/连字符等（常驻，无开关键） | ✅ 启用 | 免费 | 0 |
| 同形字/拼写劫持 | Cyrillic/Greek 折叠+编辑距离 | ✅ 启用 | 免费·默认开 | 7 |
| MX/SPF 缺失线索 | 需 DNS，默认关 | ⬜ 未启用 | 可选 | - |
| Google Safe Browsing | 在线情报 | ⬜ 未启用 | 需API Key | - |
| PhishTank | 钓鱼库 | ⬜ 未启用 | 需API Key | - |
| urlscan 沙箱 | 可疑页面扫描 | ⬜ 未启用 | 需API Key(可选) | - |
| 证书透明度 CT | 接口预留，默认关 | ⬜ 未启用 | 可选 | — |

### 白名单域名类别分布

| 类别 | 数量 | 占比 |
|------|------|------|
| 广告/营销 | 25 | 8.7% |
| 分析/追踪 | 12 | 4.2% |
| CDN/基础设施 | 7 | 2.4% |
| 微软/Windows 遥测 | 12 | 4.2% |
| 联盟营销/跳转 | 15 | 5.2% |
| 社交/分享 | 4 | 1.4% |
| 电商/支付 | 11 | 3.8% |
| 隐私/安全 | 7 | 2.4% |
| 其他 | 196 | 67.8% |

### 分类置信度分布

> 高置信度=注册域名精确匹配(PSL)，可直接信任；中置信度=子域名前缀匹配，建议人工确认；低置信度=无法分类，需外部API或人工判断。

| 置信度等级 | 数量 | 占比 |
|-----------|------|------|
| 高置信度 (注册域名匹配) | 68 | 23.5% |
| 中置信度 (子域名前缀) | 25 | 8.7% |
| 低置信度 (无法分类) | 196 | 67.8% |

| 域名 | 评级 | 类别 | 风险分 | 建议动作 | 置信度 | 原因 | 来源 |
|------|------|------|--------|---------|--------|------|------|
| `a.adwolf.ru` | 🟡 可疑 | 广告/营销 | 15 | 建议复核 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `ad.cityu.edu.hk` | 🟡 可疑 | 其他 | 20 | 建议复核 | 0.00 | 解析到私有/回环 IP: ['172.26.255.1', '172.26.255.2', '172.26.255.12', '172.26.255.11'] | CHN: anti-AD |
| `ads.tdbank.com` | 🟡 可疑 | 广告/营销 | 15 | 建议复核 | 0.60 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `avqs.mcafee.com` | 🟡 可疑 | 隐私/安全 | 15 | 建议复核 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `avts.mcafee.com` | 🟡 可疑 | 隐私/安全 | 15 | 建议复核 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `cloud.notification-naviextras.com` | 🟡 可疑 | 其他 | 27 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效）; 拼写劫持仿冒品牌 icloud（编辑距离 1） | AdGuard DNS filter |
| `counter-strike.net` | 🟡 可疑 | 其他 | 12 | 建议复核 | 0.00 | 拼写劫持仿冒品牌 stripe（编辑距离 1） | CHN: anti-AD |
| `data.email.premierleague.com` | 🟡 可疑 | 其他 | 12 | 建议复核 | 0.00 | 拼写劫持仿冒品牌 gmail（编辑距离 1） | AdGuard DNS filter |
| `dishy.starlink.com` | 🟡 可疑 | 其他 | 20 | 建议复核 | 0.00 | 解析到私有/回环 IP: ['192.168.100.1'] | HaGeZi's DNS Rebind Protection |
| `edge-enterprise.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 20 | 建议复核 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `edge.activity.windows.com` | 🟡 可疑 | 微软/Windows 遥测 | 20 | 建议复核 | 0.90 | 解析到私有/回环 IP: ['127.0.0.1'] | CHN: anti-AD |
| `email.awscloud.com` | 🟡 可疑 | 其他 | 12 | 建议复核 | 0.00 | 拼写劫持仿冒品牌 gmail（编辑距离 1） | AdGuard DNS filter |
| `email.elitedangerous.com` | 🟡 可疑 | 其他 | 12 | 建议复核 | 0.00 | 拼写劫持仿冒品牌 gmail（编辑距离 1） | AdGuard DNS filter |
| `email.procook.co.uk` | 🟡 可疑 | 其他 | 27 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效）; 拼写劫持仿冒品牌 gmail（编辑距离 1） | AdGuard DNS filter |
| `fritz.box` | 🟡 可疑 | 其他 | 12 | 建议复核 | 0.00 | 拼写劫持仿冒品牌 xbox（编辑距离 1） | HaGeZi's DNS Rebind Protection |
| `fritz.nas` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.powerline` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.repeater` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `fritz.smartgateway` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `guce.advertising.com` | 🟡 可疑 | 广告/营销 | 15 | 建议复核 | 0.90 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `mail.abusix.zone` | 🟡 可疑 | 其他 | 12 | 建议复核 | 0.00 | 拼写劫持仿冒品牌 gmail（编辑距离 1） | HaGeZi's DNS Rebind Protection |
| `meizu.coapi.moji.com` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | CHN: anti-AD |
| `plex.direct` | 🟡 可疑 | 其他 | 20 | 建议复核 | 0.00 | 解析到私有/回环 IP: ['0.0.0.0'] | HaGeZi's DNS Rebind Protection |
| `router.asus.com` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `speedport.ip` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | HaGeZi's DNS Rebind Protection |
| `sponsor.nitropay.com` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `thumbnail.thench.net` | 🟡 可疑 | 其他 | 15 | 建议复核 | 0.00 | DNS NXDOMAIN（域名已过期，白名单可能无效） | AdGuard DNS filter |
| `tplinklogin.net` | ⚪ 未知 | 其他 | 0 | 建议复核 | 0.00 | DNS 查询失败 (timeout)，但威胁情报无命中 | HaGeZi's DNS Rebind Protection |
| `3gppnetwork.org` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `5471782.fls.doubleclick.net` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `79423.analytics.edgekey.net` | 🟢 安全 | CDN/基础设施 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `a.sellpoint.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `aax-fe.amazon.co.jp` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ac.ebis.ne.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `acs-m.daraz.com.bd` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `acs-m.daraz.pk` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `action.metaffiliation.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad-block.dns.adguard.com` | 🟢 安全 | 隐私/安全 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad-gone.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad-putting.gw.zt-express.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad.10010.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.abchina.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.azure.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ad.kazakinfo.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.ourgame.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ad.siemens.com.cn` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `adcdn.pingan.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `admin.dable.io` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ads.adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ads.finance` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ads.privacy.qq.com` | 🟢 安全 | 社交/分享 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `ads.taboola.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `advert.kf5.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `advertisement.taobao.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `affiliate.notion.so` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `affiliates.adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `afi-b.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `analysis.chess.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `analysis.windows.net` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `analytics.amplitude.com` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `anwb.webpower.eu` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ap01.records.in.treasuredata.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `api.ads.tvb.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `api.docodoco.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `api.huangye.miui.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `api.karte.io` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app-advertise.zhihuishu.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app.adjust.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD, AdGuard DNS filter |
| `app.appsflyer.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app.crazyegg.com` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `app.powerbi.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `artifactory.appodeal.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `asusrouter.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `autocomplete.clearbit.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `awin1.com` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `b.barracudacentral.org` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `backscatterer.org` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `baozhang.baidu.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `belgium.wolterskluwer.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `beta.affiliates.adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `beta.partners.adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `beta.publishers.adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `bl.blocklist.de` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `bl.spamcop.net` | 🟢 安全 | 隐私/安全 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `buyad.bi-xenon.cn` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `c.office.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `captcha.su.baidu.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `catchup.thisisdax.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cdn.atmedia.hu` | 🟢 安全 | CDN/基础设施 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cdn.duurzaam.greenchoice.nl` | 🟢 安全 | CDN/基础设施 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cdn.rozetka.com.ua` | 🟢 安全 | CDN/基础设施 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cdn.taboola.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `center-h5api.m.taobao.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `chart-embed.service.newrelic.com` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `cindyholbrook.lpages.co` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `citiintl.122.2o7.net` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cj.dotomi.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cl.link-ag.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `classliving.lpages.co` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.appcast.io` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.avs.io` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.cptrack.de` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.simba.taobao.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.trafficguard.ai` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `click.virt.exacttarget.com` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `clickattr.wayup.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cm-beacon.nakanohito.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cm-widget.nakanohito.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cmp.inmobi.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cmp.osano.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `content.viralize.tv` | 🟢 安全 | CDN/基础设施 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `core.crazyegg.com` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `crm-cdn.peek-cloppenburg.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cs.silverpop.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `cutcaptcha.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `daikoku.ebis.ne.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `daraz.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `daraz.pk` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.digital.costco.ca` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.digital.costco.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.notify.macys.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.orders.costco.ca` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.orders.costco.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `data.promo.timhortons.ca` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `datadoghq-browser-agent.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `direct.quickconnect.to` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dns.msftncsi.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dnsbl.dronebl.org` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dnswl.org` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dogpile.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `dq.spamhaus.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `dxcloud.episerver.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `e.customeriomail.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `emails.educause.edu` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `envato.market` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ezodn.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `f-gear.ec-optimizer.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `feed.adrelayer.com` | 🟢 安全 | 社交/分享 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `forum.notebookreview.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ftp.bmp.ovh` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD, AdGuard DNS filter |
| `future.biz.weibo.com` | 🟢 安全 | 社交/分享 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `gate.first-id.fr` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `get.neofinancial.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `go.adjust.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `go.redirectingat.com` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `go.scorptec.com.au` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `googleadservices.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `goto.target.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `goto.walmart.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `grp07.ias.rakuten.co.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `gs.statcounter.com` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `hash.cymru.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `hb.afl.rakuten.co.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `health.halodoc.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `help-advertisers.adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `hidive.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `home.focusatwill.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `hostkarma.junkemailfilter.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `href.li` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ia.hit.interia.pl` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `id.i2i.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `img.ads.tvb.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `infra-api.newrelic.com` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `insideruser.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `intersport.peerius.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ipv4only.arpa` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `itoya.ec-optimizer.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `jdoqocy.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `js.monitor.azure.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `learn.khanacademy.org` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `leechers-paradise.org` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `link.meet5.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `link.morningbrew.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `link.nzz.ch` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `link.sylikes.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `linka.page` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `links.e.theatlantic.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `links.getblueshift.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `log.mmstat.com` | 🟢 安全 | CDN/基础设施 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD, AdGuard DNS filter |
| `logentries.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `login.sendpulse.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ma135-r.analytics.edgekey.net` | 🟢 安全 | CDN/基础设施 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `mailspike.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `marketing.net.idealo-partner.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `media-consumer365.desigual.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `msftconnecttest.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `my.tealiumiq.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `myunraid.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `netatmo.commander1.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `news-app.abumedia.yql.yahoo.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `news.warhammer.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `nineto5mac-d.openx.net` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `nordspam.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `oa.tr.line.me` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `obituaries.startribune.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `obituaries.therecord.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `obituaries.thestar.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `obituaries.toacorn.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `official.paymaya.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `om-ssl.consorsbank.de` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `omniture.walmart.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `omsc.kpn.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `oneline.nextday.media` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `pagead.l.doubleclick.net` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `partner.everydays.de` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `partner.o2online.de` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `partners.adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `passport.bobo.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `prod.impartner.live` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `promo.gramedia.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `proto2ad.durasite.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `psbl.surriel.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `pt.afl.rakuten.co.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `public-cis.exponea.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `publishers.adsterra.com` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `puzzles-games-api.gp-prod.conde.digital` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `px.a8.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `radiofrance.targetspot.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `rd.bizrate.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `recommender.scarabresearch.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `redir.ownpage.fr` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `redir.tradedoubler.com` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `redirect.appmetrica.yandex.com` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ref.rbauction.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `refer.discover.com` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `remembering.ca` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `res.ads.nicovideo.jp` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `routerlogin.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `routerlogin.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `s.bluecore.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `s.mvconf.f.360.cn` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `sax.sina.com.cn` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `sbs.demdex.net` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `sdkapi.sms.mob.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `secureimage.securedataimages.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `sedge.nfl.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `settings-win.data.microsoft.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skyapi.onedrive.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `skydrivesync.policies.live.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `smtp.focusgroupresearch.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `sophosxl.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spameatingmonkey.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spamhaus.org` | 🟢 安全 | 隐私/安全 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spamrats.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `spartaindependent.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `ssai.aniview.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `stash.roistat.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `stat.jseea.cn` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `statcounter.com` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `stats.gov.cn` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `stats.uptimerobot.com` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `storage.live.com` | 🟢 安全 | 微软/Windows 遥测 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `str.hit.gemius.pl` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `support-beacon.nakanohito.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `support-widget.nakanohito.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `surbl.org` | 🟢 安全 | 隐私/安全 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `surveymyopinion.researchnow.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `swasc.homedepot.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tags.crwdcntrl.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `taiga.maven.io` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tj.gov.cn` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tlaol.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tlh.gedidigital.it` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tms.capitalone.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tongji.cn` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tongji.edu.cn` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `tor.dan.me.uk` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `torexit.dan.me.uk` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `torimochi.line-apps.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tplinkap.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkrepeater.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tplinkwifi.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `tr.rdrtr.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `track.rutarget.ru` | 🟢 安全 | 分析/追踪 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `track.webgains.com` | 🟢 安全 | 联盟营销/跳转 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tracker.eu.org` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.60 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `trk.ecomm.lenovo.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `tube.e.kuaishou.com` | 🟢 安全 | 社交/分享 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `uceprotect.net` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `uland.taobao.com` | 🟢 安全 | 电商/支付 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `unsubscribe.lhinsights.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `uribl.com` | 🟢 安全 | 隐私/安全 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | HaGeZi's DNS Rebind Protection |
| `used.ca` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `validate.perfdrive.com` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `vcentry2.valuecommerce.ne.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `vcentry3.valuecommerce.ne.jp` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |
| `widget.intercom.io` | 🟢 安全 | 其他 | 0 | 建议保留 | 0.00 | DNS 正常解析，无威胁情报标记 | CHN: anti-AD |
| `www3.doubleclick.net` | 🟢 安全 | 广告/营销 | 0 | 建议保留 | 0.90 | DNS 正常解析，无威胁情报标记 | AdGuard DNS filter |

## 十、规则语法支持度

| 规则类型 | 语法示例 | 状态 | 处理方式 | 数量 |
|---------|---------|------|---------|------|
| Block 域名 | `||example.com^` | ✅ 支持 | 核心输出 | 2,450,556 |
| 通配符 | `||*.example.com^` | ✅ 支持 | 聚合覆盖子域 | 0 |
| Allow 白名单 | `@@||example.com^` | ✅ 支持 | 分离到 whitelist.txt | 301 |
| 正则 | `/ads.*/` | ✅ 保留 | 原样保留 | 604 |
| IP 规则 | `||8.8.8.8^` | ✅ 支持 | 按域名字符串处理 | 74 |
| Hosts | `0.0.0.0 example.com` | ✅ 支持 | 转换为 `||domain^` | - |
| $ 修饰符 | `||x.com^$important` | ✅ 保留 | 保留修饰符，纳入去重键，跳过聚合，$important 抗白名单 | 5 |
| CSS/JS | `##.ad` | ❌ 丢弃 | DNS 层不支持 | 0 |

## 十一、域名后缀 Top 20

| 后缀 | 规则数 |
|------|--------|
| fbcdn.net | 9,230 |
| cloudfront.net | 3,103 |
| pages.dev | 2,421 |
| amazonaws.com | 2,085 |
| web.app | 2,008 |
| eu.cc | 1,971 |
| firebaseapp.com | 1,915 |
| weebly.com | 1,736 |
| hl.cn | 1,669 |
| r2.dev | 1,326 |
| vercel.app | 1,200 |
| run.app | 1,133 |
| wixstudio.com | 593 |
| lovable.app | 569 |
| googleapis.com | 550 |
| blogspot.com | 548 |
| workers.dev | 524 |
| ru.com | 485 |
| co.com | 459 |
| netlify.app | 451 |

## 十二、性能与诊断

| 指标 | 数值 |
|------|------|
| 总耗时 | 59.3s |
| 源成功率 | 18/18 |
| 缓存命中 | 7 |
| 精确去重 | 602,255 |
| 规范化去重 | 3,646 |
| 正则去重 | 321 |
| 质量过滤丢弃 | 39 |
| 模式丢弃 | 0 |
| CSS 丢弃 | 0 |
| 未识别行丢弃 | 113 |
| 本次新增域名 | 0 |
| 本次移除域名 | 0 |
| 平均域名长度 | 17.4 字符 |
| 最短/最长域名 | 2 / 202 字符 |

---
## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：152,863 域名 —— 可达 144,253 · **已死亡 944** · 未判定 488

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 19,085 | 17,651 | 944 | 486 |
| important-block | 1 | 0 | 0 | 1 |
| whitelist | 2 | 0 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| HaGeZi's Threat Intelligence Feeds | 366 |
| Phishing Army | 351 |
| CHN: AdRules DNS List | 126 |
| CHN: anti-AD | 92 |
| AdGuard DNS filter | 76 |
| HaGeZi's Ultimate Blocklist | 72 |
| HaGeZi's Gambling Blocklist | 30 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 27 |
| OISD Blocklist Small | 7 |
| Malicious URL Blocklist (URLHaus) | 4 |
| NoCoin Filter List | 1 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `08538c.com`（block-sample）
- `1254er2.wiki`（block-sample）
- `1800sheets.com`（block-sample）
- `1j2nhb3.skin`（block-sample）
- `2.speedknow.co`（block-sample）
- `26sfjkgjdofijgdfgjfdgjoifd.site`（block-sample）
- `2l3ll3e.pics`（block-sample）
- `3mek4.lat`（block-sample）
- `49fgfdkdfgkdfgkf.site`（block-sample）
- `4ie74e.skin`（block-sample）
- `5gr2r2.hair`（block-sample）
- `658459.help`（block-sample）
- `6686.be`（block-sample）
- `66lotte.com`（block-sample）
- `6e8y4k.hair`（block-sample）
- `74674.top`（block-sample）
- `7cjsh.cn`（block-sample）
- `7k-casino251k.lol`（block-sample）
- `7pt3vkz.hair`（block-sample）
- `84562356.top`（block-sample）
- `9765765.lat`（block-sample）
- `99noivas.com`（block-sample）
- `a1.tbuz.com.cn`（block-sample）
- `a4t8x1r.pics`（block-sample）
- `abdelatif.liv-536801.pro`（block-sample）
- `accesspoint.vpce-05543a2aad8ee2eed-whuvptq8-us-east-2a.s3.us-east-2.vpce.amazonaws.com`（block-sample）
- `acciariesp.cyou`（block-sample）
- `acclienquangiare.shop`（block-sample）
- `acrylicholder.shop`（block-sample）
- `activetrap.com`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-07 05:33）。

---
*AdGuard Rules Merger · 自动生成 · 2026-11-07*
