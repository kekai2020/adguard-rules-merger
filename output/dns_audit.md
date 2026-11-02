## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：58,855 域名 —— 可达 55,048 · **已死亡 1,056** · 未判定 533

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 19,692 | 18,102 | 1,056 | 531 |
| important-block | 1 | 0 | 0 | 1 |
| whitelist | 2 | 0 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| HaGeZi's Threat Intelligence Feeds | 519 |
| Phishing Army | 295 |
| CHN: AdRules DNS List | 123 |
| CHN: anti-AD | 89 |
| AdGuard DNS filter | 77 |
| HaGeZi's Ultimate Blocklist | 70 |
| HaGeZi's Gambling Blocklist | 42 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 33 |
| Malicious URL Blocklist (URLHaus) | 4 |
| NoCoin Filter List | 2 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 2 |
| ShadowWhisperer's Dating List | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `1cd21cb1e4.com`（block-sample）
- `2387a8930606.info`（block-sample）
- `2h3k4k.skin`（block-sample）
- `31.shaderzone.org`（block-sample）
- `3rd.t.sohu.com`（block-sample）
- `40399oefiiu.shop`（block-sample）
- `4fee6d013f.com`（block-sample）
- `4he5he.icu`（block-sample）
- `57492023.lat`（block-sample）
- `597d2be657ca.co.uk`（block-sample）
- `6qz4xvp.top`（block-sample）
- `7080555.com`（block-sample）
- `7865546.lat`（block-sample）
- `789bet-casino.xyz`（block-sample）
- `78qjn.com`（block-sample）
- `839917.com`（block-sample）
- `89127981798adminphph.jdevcloud.com`（block-sample）
- `8jz2x.icu`（block-sample）
- `9270.com.cn`（block-sample）
- `953771coinbase.com`（block-sample）
- `97aa.casino`（block-sample）
- `a.linkz.ai`（block-sample）
- `a1o1sarkuterifirsatlarinizburadaa.site`（block-sample）
- `aaravelectronicshq.shop`（block-sample）
- `aasddzz.top`（block-sample）
- `abqjst.com`（block-sample）
- `acavavtodfalcspdc.site`（block-sample）
- `accordpianoservice.com`（block-sample）
- `acilkarot.com`（block-sample）
- `aclinicdativalsensate.cyou`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-02 05:04）。
