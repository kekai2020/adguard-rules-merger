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
