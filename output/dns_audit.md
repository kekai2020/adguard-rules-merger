## 📡 DNS 可达性审计（多解析器并发）

- 通道：DOH（自诊断通过，6/10 解析器存活；控制域 www.qq.com, www.baidu.com, www.cloudflare.com）
- 解析器（全部为无过滤/非家庭变体）：1.1.1.1 (Cloudflare), 101.226.4.6 (360), 119.29.29.29 (DNSPod), 120.53.53.53 (DNSPod-2), 8.8.8.8 (Google), dns.sb (DNS.SB)
- 判定口径：任一存活解析器解析成功=可达；≥2 个存活解析器均返回 NXDOMAIN=已死亡（交叉验证）；其余=未判定（超时/混合，不视为不可达）
- 审计：20,308 域名 —— 可达 18,679 · **已死亡 1,129** · 未判定 500

| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |
|---|---:|---:|---:|---:|
| badfilter-target | 4 | 4 | 0 | 0 |
| block-sample | 20,000 | 18,398 | 1,105 | 497 |
| important-block | 5 | 3 | 1 | 1 |
| whitelist | 299 | 274 | 23 | 2 |

### 🧹 白名单清理建议

以下 23 条白名单域名已从 DNS 消失（放行对象不存在，规则无效）：

- `a.adwolf.ru` —— 建议：确认后从白名单源移除
- `ads.tdbank.com` —— 建议：确认后从白名单源移除
- `avqs.mcafee.com` —— 建议：确认后从白名单源移除
- `avts.mcafee.com` —— 建议：确认后从白名单源移除
- `brm-core-*.brsrvr.com` —— 建议：确认后从白名单源移除
- `cdn.us*.exponea.com` —— 建议：确认后从白名单源移除
- `click.virt.s*.exacttarget.com` —— 建议：确认后从白名单源移除
- `cloud.notification-naviextras.com` —— 建议：确认后从白名单源移除
- `data-*.herz-fuer-tiere.de` —— 建议：确认后从白名单源移除
- `email.*.skyeng.ru` —— 建议：确认后从白名单源移除
- `email.procook.co.uk` —— 建议：确认后从白名单源移除
- `fritz.nas` —— 建议：确认后从白名单源移除
- `fritz.powerline` —— 建议：确认后从白名单源移除
- `fritz.repeater` —— 建议：确认后从白名单源移除
- `fritz.smartgateway` —— 建议：确认后从白名单源移除
- `guce.advertising.com` —— 建议：确认后从白名单源移除
- `mc.*.exacttarget.com` —— 建议：确认后从白名单源移除
- `meizu.coapi.moji.com` —— 建议：确认后从白名单源移除
- `router.asus.com` —— 建议：确认后从白名单源移除
- `speedport.ip` —— 建议：确认后从白名单源移除
- `sponsor.nitropay.com` —— 建议：确认后从白名单源移除
- `thumbnail.thench.net` —— 建议：确认后从白名单源移除
- `tlaol.com` —— 建议：确认后从白名单源移除

### 已死亡域名 · 按来源分布

| 来源列表 | 死亡域名数 |
|---|---:|
| HaGeZi's Threat Intelligence Feeds | 569 |
| Phishing Army | 292 |
| CHN: AdRules DNS List | 122 |
| AdGuard DNS filter | 87 |
| CHN: anti-AD | 83 |
| HaGeZi's Ultimate Blocklist | 73 |
| HaGeZi's Gambling Blocklist | 55 |
| Phishing URL Blocklist (PhishTank and OpenPhish) | 26 |
| HaGeZi's DNS Rebind Protection | 8 |
| Malicious URL Blocklist (URLHaus) | 2 |
| AWAvenue Ads Rule | 1 |
| OISD Blocklist Small | 1 |
| HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass | 1 |
| Stalkerware Indicators List | 1 |

### 已死亡域名样例（前 30，完整见 dns_audit.json）

- `*-ad-sign.byteimg.com`（block-sample）
- `02u23hq.skin`（block-sample）
- `10magneticslots31.com`（block-sample）
- `1514.info`（block-sample）
- `17d43b078f9b1076af37d7b4b8a0ab03bce14877edb5ffbad6286254.com`（block-sample）
- `1945jkk.shop`（block-sample）
- `1c680fa3bc1c1937c0c8675e1b2d5a83d1b23867a18269a887361a35.com`（block-sample）
- `1edefd90f2ee46827e525d3a42756ff227b1d171514cb4982d170aa6.com`（block-sample）
- `1nr8eb9bkxt24ub4mwtcullg2wu.cfd`（block-sample）
- `1win-casino84.buzz`（block-sample）
- `1xbet-tmxp.top`（block-sample）
- `2.wantsext.me`（block-sample）
- `203710.com`（block-sample）
- `230129h8h57.xyz`（block-sample）
- `247appbank.com`（block-sample）
- `2765tka.top`（block-sample）
- `2974tka.top`（block-sample）
- `2e55a2d58f.com`（block-sample）
- `2zt7vkp.hair`（block-sample）
- `3158wra.hair`（block-sample）
- `328238smart843.xyz`（block-sample）
- `40-dashboard-concrete.pages.dev`（block-sample）
- `446834wi.top`（block-sample）
- `4722218.com`（block-sample）
- `4efefc837412591a.com`（block-sample）
- `4inroecmawdapsaxals.site`（block-sample）
- `586520.com`（block-sample）
- `5okj84.cfd`（block-sample）
- `604929.lol`（block-sample）
- `654363.lat`（block-sample）

> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；
> 本附录由 scripts/dns_coverage_audit.py v3 生成（2026-11-01 10:11）。
