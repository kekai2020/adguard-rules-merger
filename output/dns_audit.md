## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：134,279 域名 —— 可达 126,602 · **已死亡 967** · 未判定 499

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 19,211 | 17,743 | 967 | 497 |
| important-block | 1 | 0 | 0 | 1 |
| whitelist | 3 | 1 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| HaGeZi's Threat Intelligence Feeds | 419 |
| Phishing Army | 317 |
| CHN: AdRules DNS List | 132 |
| CHN: anti-AD | 94 |
| AdGuard DNS filter | 79 |
| HaGeZi's Ultimate Blocklist | 51 |
| HaGeZi's Gambling Blocklist | 32 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 19 |
| OISD Blocklist Small | 5 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 2 |
| AWAvenue Ads Rule | 1 |
| NoCoin Filter List | 1 |
| Malicious URL Blocklist (URLHaus) | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `1jc5t.xyz`（block-sample）
- `1tf2tg.hair`（block-sample）
- `1xbet-casino-online.com`（block-sample）
- `2cloudgroup.digital`（block-sample）
- `2n3uju.skin`（block-sample）
- `365hyperfund.sbs`（block-sample）
- `4e4fe673239a16aa82fedd10de4646b2.xyz`（block-sample）
- `4fizjopl.store`（block-sample）
- `4z7n3kx.pics`（block-sample）
- `5569w.com`（block-sample）
- `56ggt.top`（block-sample）
- `6a3a727872.com`（block-sample）
- `6se76we.skin`（block-sample）
- `7rjru44.hair`（block-sample）
- `88nu.info`（block-sample）
- `890.xbestfiles.pro`（block-sample）
- `8tb11bh7ig8wpufwrt6zb8torymq1b1xp.cfd`（block-sample）
- `97216.cn`（block-sample）
- `9835412.cfd`（block-sample）
- `9anime.world`（block-sample）
- `a8cv.mi-vision.co.jp`（block-sample）
- `aaaneniisyq.cn`（block-sample）
- `aafns.xyz`（block-sample）
- `aakrwlikc.com`（block-sample）
- `abc.phantomchatmatrix1986.com`（block-sample）
- `accesspoint.vpce-022d9a693ed2f5855-2stz3d0z-eu-south-1a.s3.eu-south-1.vpce.amazonaws.com`（block-sample）
- `adebis.harutaka.jp`（block-sample）
- `adinfo.tango.me`（block-sample）
- `admin.academyforconsciousleadership.net`（block-sample）
- `adriftperfunctoryfrost.com`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-06 05:58）。
