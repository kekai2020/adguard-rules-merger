## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：115,715 域名 —— 可达 108,858 · **已死亡 855** · 未判定 646

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 19,342 | 17,839 | 855 | 644 |
| important-block | 1 | 0 | 0 | 1 |
| whitelist | 2 | 0 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| HaGeZi's Threat Intelligence Feeds | 399 |
| Phishing Army | 284 |
| CHN: AdRules DNS List | 101 |
| CHN: anti-AD | 74 |
| AdGuard DNS filter | 64 |
| HaGeZi's Ultimate Blocklist | 54 |
| HaGeZi's Gambling Blocklist | 25 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 22 |
| OISD Blocklist Small | 2 |
| Malicious URL Blocklist (URLHaus) | 2 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `092-informacja.cfd`（block-sample）
- `0quhuw.lat`（block-sample）
- `1iuh5l.com`（block-sample）
- `24enterpriseprime.digital`（block-sample）
- `2gc26yhw.skin`（block-sample）
- `3i8je3.skin`（block-sample）
- `41grk.icu`（block-sample）
- `47382952.lat`（block-sample）
- `53d434kdfgkdfgkf.site`（block-sample）
- `5wtg35w.skin`（block-sample）
- `632454rd.top`（block-sample）
- `6q8m4xp.lol`（block-sample）
- `7301066.com`（block-sample）
- `737d62f0c1.com`（block-sample）
- `7k-473.casino`（block-sample）
- `83510.lat`（block-sample）
- `9239h9459.shop`（block-sample）
- `a3investments.net`（block-sample）
- `a8cv.picksitter.com`（block-sample）
- `abe-and-sons.com`（block-sample）
- `achietransport.cyou`（block-sample）
- `acv.aun-air-wifi.com`（block-sample）
- `adhecbyydvfly.website`（block-sample）
- `admins.mzzrj.com`（block-sample）
- `ado.delfi.ee`（block-sample）
- `adwidgets.ru`（block-sample）
- `affliacata.store`（block-sample）
- `afresh.media`（block-sample）
- `agootictaticol.com`（block-sample）
- `ai.kaishabaikyaku.com`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-05 06:03）。
