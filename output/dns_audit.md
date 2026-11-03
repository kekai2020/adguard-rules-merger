## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：77,918 域名 —— 可达 73,114 · **已死亡 1,043** · 未判定 487

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 19,597 | 18,066 | 1,043 | 485 |
| important-block | 1 | 0 | 0 | 1 |
| whitelist | 2 | 0 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| HaGeZi's Threat Intelligence Feeds | 499 |
| Phishing Army | 294 |
| CHN: AdRules DNS List | 108 |
| CHN: anti-AD | 90 |
| AdGuard DNS filter | 71 |
| HaGeZi's Ultimate Blocklist | 65 |
| HaGeZi's Gambling Blocklist | 56 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 24 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 3 |
| Malicious URL Blocklist (URLHaus) | 2 |
| HaGeZi's Windows/Office Tracker Blocklist | 1 |
| OISD Blocklist Small | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `004-psd2.my-granitnyrt.com`（block-sample）
- `1335n.com`（block-sample）
- `1hshg.pics`（block-sample）
- `1is7m7.cyou`（block-sample）
- `2k6x8mn.pics`（block-sample）
- `2novadigital.click`（block-sample）
- `2qrwde.hair`（block-sample）
- `4i9h38.hair`（block-sample）
- `594ch3fbkgl4qhq7nfrw4xpme9xt.cfd`（block-sample）
- `5giay.cc`（block-sample）
- `65wyg3t.skin`（block-sample）
- `6686h6.com`（block-sample）
- `6788vn.com`（block-sample）
- `77085.xyz`（block-sample）
- `789banca.com`（block-sample）
- `8234920g2-32.lat`（block-sample）
- `861.z7eoil.cfd`（block-sample）
- `89743h304g3d1.lat`（block-sample）
- `991abc.com`（block-sample）
- `abbacimpip.online`（block-sample）
- `abbuopresc.cyou`（block-sample）
- `accamdisal.cyou`（block-sample）
- `account.teslaplatinumfinance.com`（block-sample）
- `ad.onadozo.hu`（block-sample）
- `adconfer.com`（block-sample）
- `ads.oyungemisi.com`（block-sample）
- `affagrinch.store`（block-sample）
- `afsovq.arosa.ru.com`（block-sample）
- `aldi-uk.dahliastock.shop`（block-sample）
- `aldi.zostorex.shop`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-03 05:55）。
