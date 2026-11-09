## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：189,724 域名 —— 可达 179,697 · **已死亡 676** · 未判定 509

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 18,882 | 17,695 | 675 | 508 |
| important-block | 1 | 0 | 1 | 0 |
| whitelist | 2 | 0 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| Phishing Army | 270 |
| HaGeZi's Threat Intelligence Feeds | 167 |
| CHN: AdRules DNS List | 147 |
| CHN: anti-AD | 90 |
| AdGuard DNS filter | 53 |
| HaGeZi's Ultimate Blocklist | 40 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 23 |
| HaGeZi's Gambling Blocklist | 22 |
| OISD Blocklist Small | 8 |
| Malicious URL Blocklist (URLHaus) | 5 |
| NoCoin Filter List | 3 |
| Stalkerware Indicators List | 2 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `0026n.com`（block-sample）
- `00609c257b.com`（block-sample）
- `027pbj.net`（block-sample）
- `06789.xyz`（block-sample）
- `099312gemini.com`（block-sample）
- `0l-7oxplgomi97.f3qxoj.sbs`（block-sample）
- `101plusinsight.click`（block-sample）
- `1239feffd9.com`（block-sample）
- `12939h74.xyz`（block-sample）
- `15s.pro`（block-sample）
- `1779t.com`（block-sample）
- `2025orbitmetrics.forum`（block-sample）
- `2050cp2050.com`（block-sample）
- `2097lka.top`（block-sample）
- `2381mqn.ink`（block-sample）
- `247apexblock.sbs`（block-sample）
- `25ix8gm8ien.sandbox.panprices.com`（block-sample）
- `2hbets.net`（block-sample）
- `33lotte.com`（block-sample）
- `365omnixconsulting.pics`（block-sample）
- `38kmute.xyz`（block-sample）
- `3mx9qvz.skin`（block-sample）
- `4-fizjopl.shop`（block-sample）
- `40fenzhong.com`（block-sample）
- `467.red`（block-sample）
- `5390490582394823.cfd`（block-sample）
- `685451.top`（block-sample）
- `747212.lol`（block-sample）
- `777betsp.com`（block-sample）
- `8595646basvrsnkmpnyaa.click`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-09 05:44）。
