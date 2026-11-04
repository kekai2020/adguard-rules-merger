## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：96,895 域名 —— 可达 91,019 · **已死亡 1,038** · 未判定 521

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 19,465 | 17,905 | 1,038 | 519 |
| important-block | 1 | 0 | 0 | 1 |
| whitelist | 2 | 0 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| HaGeZi's Threat Intelligence Feeds | 520 |
| Phishing Army | 297 |
| CHN: AdRules DNS List | 128 |
| CHN: anti-AD | 85 |
| AdGuard DNS filter | 83 |
| HaGeZi's Ultimate Blocklist | 65 |
| HaGeZi's Gambling Blocklist | 35 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 23 |
| OISD Blocklist Small | 7 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 3 |
| Malicious URL Blocklist (URLHaus) | 2 |
| NoCoin Filter List | 2 |
| Stalkerware Indicators List | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `0pensea-io.new-revealed.com`（block-sample）
- `1-bmo-client-login.com`（block-sample）
- `121618.com`（block-sample）
- `123192h45.mom`（block-sample）
- `1fbgtqnjhum9qzk4rflp94l.rest`（block-sample）
- `1insighttoken.sbs`（block-sample）
- `1sputnik.ru`（block-sample）
- `1win-kqytx.buzz`（block-sample）
- `21736.xyz`（block-sample）
- `2465tpo.top`（block-sample）
- `253472547265346722.cfd`（block-sample）
- `264f0e77a9fa.com`（block-sample）
- `294115-kraken.com`（block-sample）
- `2maxnextgeneco.sbs`（block-sample）
- `3025vra.skin`（block-sample）
- `3489893g45o.lat`（block-sample）
- `360xstrategyinsight.sbs`（block-sample）
- `4sywe6.hair`（block-sample）
- `5298745832734.xyz`（block-sample）
- `597d2be657ca.gleeze.com`（block-sample）
- `5ot95oj.skin`（block-sample）
- `62194573.xyz`（block-sample）
- `65512.cfd`（block-sample）
- `6b3f9be238.com`（block-sample）
- `837262541.cfd`（block-sample）
- `8wieu3.skin`（block-sample）
- `92114la.com`（block-sample）
- `9754364.top`（block-sample）
- `a8cv.gimuiko.com`（block-sample）
- `abhmssqcicgr.net`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-04 05:33）。
