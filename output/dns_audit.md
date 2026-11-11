## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：207,985 域名 —— 可达 197,291 · **已死亡 653** · 未判定 523

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 18,772 | 17,593 | 653 | 522 |
| whitelist | 3 | 1 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| Phishing Army | 296 |
| HaGeZi's Threat Intelligence Feeds | 150 |
| CHN: AdRules DNS List | 125 |
| CHN: anti-AD | 89 |
| AdGuard DNS filter | 66 |
| HaGeZi's Ultimate Blocklist | 36 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 29 |
| HaGeZi's Gambling Blocklist | 8 |
| Malicious URL Blocklist (URLHaus) | 5 |
| OISD Blocklist Small | 3 |
| Stalkerware Indicators List | 2 |
| Scam Blocklist by DurableNapkin | 1 |
| NoCoin Filter List | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `09mk.cn`（block-sample）
- `0freta9716.cfd`（block-sample）
- `101vertextech.pics`（block-sample）
- `120921988df.xyz`（block-sample）
- `1hkfq6598i.com`（block-sample）
- `1kv7wxa.top`（block-sample）
- `1vectoranalytics.sbs`（block-sample）
- `2026parkside.shop`（block-sample）
- `245635566nett.xyz`（block-sample）
- `2dp72s.punktgate.top`（block-sample）
- `2jse6.icu`（block-sample）
- `2vertexconsulting.digital`（block-sample）
- `31dfgjfgjdffdgjdfgjfd.site`（block-sample）
- `33437.top`（block-sample）
- `37pk49.com`（block-sample）
- `3858239-coinspot.com`（block-sample）
- `480executors.net`（block-sample）
- `4ibrveuncdsklm.com`（block-sample）
- `4qtwr32.hair`（block-sample）
- `53784563453762.sbs`（block-sample）
- `5982.org`（block-sample）
- `5ehgh3.pics`（block-sample）
- `666innovations.net`（block-sample）
- `6a4cc.luytr.com`（block-sample）
- `6ywtwr.casa`（block-sample）
- `7520kra.ink`（block-sample）
- `84xedw3znqz270w.top`（block-sample）
- `852188.lat`（block-sample）
- `8758951985.lat`（block-sample）
- `8vr2knz.hair`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-11 05:45）。
