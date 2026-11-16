## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：226,159 域名 —— 可达 214,898 · **已死亡 570** · 未判定 520

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 18,699 | 17,606 | 570 | 519 |
| whitelist | 3 | 1 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| Phishing Army | 313 |
| CHN: AdRules DNS List | 123 |
| CHN: anti-AD | 80 |
| AdGuard DNS filter | 76 |
| HaGeZi's Threat Intelligence Feeds | 61 |
| HaGeZi's Ultimate Blocklist | 35 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 26 |
| OISD Blocklist Small | 14 |
| Malicious URL Blocklist (URLHaus) | 7 |
| HaGeZi's Gambling Blocklist | 6 |
| Stalkerware Indicators List | 2 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 1 |
| Scam Blocklist by DurableNapkin | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `11e3bf8940da.info`（block-sample）
- `16358.vip`（block-sample）
- `198macros.org`（block-sample）
- `1gcv2f.hair`（block-sample）
- `1xbet-guz55.buzz`（block-sample）
- `1y2tft3.hair`（block-sample）
- `2025smarttech.sbs`（block-sample）
- `24kad.com`（block-sample）
- `2907pygnb.z13.web.core.windows.net`（block-sample）
- `2myclearsafespace0000000.li`（block-sample）
- `34589.top`（block-sample）
- `3737282733828.lol`（block-sample）
- `460functions.net`（block-sample）
- `46998.uk`（block-sample）
- `4kt8wrn.hair`（block-sample）
- `59244.my`（block-sample）
- `6853xwp.ink`（block-sample）
- `7uht32eg.hair`（block-sample）
- `8chj9.com`（block-sample）
- `8iru7yur.lol`（block-sample）
- `9099d123.lat`（block-sample）
- `98765.pw`（block-sample）
- `a.e7009.com`（block-sample）
- `a758cca6.wenjunshicai.net`（block-sample）
- `abbalagisc.cyou`（block-sample）
- `ac-ebis-uhome.usen.com`（block-sample）
- `acoossu.top`（block-sample）
- `acrassuper.store`（block-sample）
- `ad.premiumonlinemedia.com`（block-sample）
- `ad.terra.com`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-16 05:55）。
