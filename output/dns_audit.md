## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/10 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：39,661 域名 —— 可达 36,946 · **已死亡 1,085** · 未判定 497

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| block-sample | 19,850 | 18,267 | 1,085 | 495 |
| important-block | 1 | 0 | 0 | 1 |
| whitelist | 2 | 0 | 0 | 1 |

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| HaGeZi's Threat Intelligence Feeds | 564 |
| Phishing Army | 294 |
| CHN: AdRules DNS List | 127 |
| CHN: anti-AD | 77 |
| HaGeZi's Ultimate Blocklist | 69 |
| AdGuard DNS filter | 68 |
| HaGeZi's Gambling Blocklist | 55 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 32 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 3 |
| Malicious URL Blocklist (URLHaus) | 2 |
| ShadowWhisperer's Dating List | 2 |
| Stalkerware Indicators List | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `0-1-x.26215785.xyz`（block-sample）
- `012c2.com`（block-sample）
- `0162advanced-technologythbbhxwfacth.gpirnfras.vu`（block-sample）
- `1.jiangzheba.com`（block-sample）
- `1797wan.com`（block-sample）
- `1f2rfc2g.pics`（block-sample）
- `222764f169.com`（block-sample）
- `2648tkn.ink`（block-sample）
- `3482vpn.ink`（block-sample）
- `3nt9xmr.skin`（block-sample）
- `3qx9mzt.skin`（block-sample）
- `3wff3e.ink`（block-sample）
- `4178185.lat`（block-sample）
- `4336wang.cn`（block-sample）
- `4634-aanmelden.verificatie.qzz.io`（block-sample）
- `4653745.top`（block-sample）
- `4722271.com`（block-sample）
- `4fstores.shop`（block-sample）
- `52aan.cn`（block-sample）
- `53teg.wiki`（block-sample）
- `558-558-559.com`（block-sample）
- `5eyg376y.pics`（block-sample）
- `5kmp7.top`（block-sample）
- `6w1.sharedlinkconnect.com`（block-sample）
- `90offbags.com`（block-sample）
- `92sales.com`（block-sample）
- `93vitui.com`（block-sample）
- `965687.com`（block-sample）
- `97973399.com`（block-sample）
- `a1.twtym.com`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-01 13:35）。
