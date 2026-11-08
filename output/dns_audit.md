## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/11 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：171,338 域名 —— 可达 162,002 · **已死亡 720** · 未判定 494

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 18,964 | 17,748 | 720 | 492 |
| important-block | 1 | 0 | 0 | 1 |
| whitelist | 3 | 1 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| Phishing Army | 300 |
| HaGeZi's Threat Intelligence Feeds | 194 |
| CHN: AdRules DNS List | 130 |
| CHN: anti-AD | 85 |
| AdGuard DNS filter | 68 |
| HaGeZi's Ultimate Blocklist | 43 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 33 |
| HaGeZi's Gambling Blocklist | 15 |
| OISD Blocklist Small | 6 |
| Malicious URL Blocklist (URLHaus) | 3 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 3 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `011play.com`（block-sample）
- `020wujin.cn`（block-sample）
- `123b.vesaire.me`（block-sample）
- `1551235f72.com`（block-sample）
- `1scotiaonlinebanking.digital`（block-sample）
- `21union.com`（block-sample）
- `23896.xyz`（block-sample）
- `333betol.com`（block-sample）
- `3412674812891236.sbs`（block-sample）
- `39e8cb44930f4d2848f9e603f1e327914c073f6b311d4e63420e5bd7.com`（block-sample）
- `3uhgywy3u.pics`（block-sample）
- `4f00.com`（block-sample）
- `4n4e3j.hair`（block-sample）
- `540291.lat`（block-sample）
- `595betpc.com`（block-sample）
- `5gg17gm.com`（block-sample）
- `622958.com`（block-sample）
- `6623vnpay.com`（block-sample）
- `6677648.reddoorz.com`（block-sample）
- `8216rxe.top`（block-sample）
- `857321-crypto.com`（block-sample）
- `8653464.lat`（block-sample）
- `8851885152.click`（block-sample）
- `8wn3mxz.skin`（block-sample）
- `92gt9hh.cyou`（block-sample）
- `a.shangz99991.com`（block-sample）
- `a.wlfnb.com`（block-sample）
- `a8.runway-harmonia.co.jp`（block-sample）
- `abc.zuiairead.com`（block-sample）
- `abcounter.de`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-08 05:33）。
