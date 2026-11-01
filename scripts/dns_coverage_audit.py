"""Multi-DNS concurrent reachability audit (R8, v2 — DoH-first).

Audits (allow-side by semantics, plus an optional block sample):
  whitelist.txt domains ∪ $important block domains ∪ $badfilter target domains
  ∪ --blocks-sample N plain block domains.

v2 hardening (after the port-53 blocked-network lesson):
- DoH (443) JSON APIs are the DEFAULT transport — AliDNS/DNSPod/Cloudflare/
  Google; raw UDP/53 kept as --mode udp for networks where it works.
- CHANNEL SELF-DIAGNOSIS: control domains (qq/baidu/cloudflare) are probed
  first; only resolvers that resolve a control are "live". A DEAD verdict
  (domain gone) requires NXDOMAIN from >=2 live resolvers — timeouts on a
  live resolver never kill a domain, they mark it unresolved instead.
- Wildcard entries (*.x.com) are audited via their PARENT domain and tagged.
- Per-source attribution: which upstream list(s) each dead domain came from.
- Writes dns_audit.json + dns_audit.md, and (--append-report, default on when
  report.md exists) inserts a summary section into the final report.md.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

import aiohttp

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DOH_RESOLVERS = [
    {"label": "223.5.5.5 (AliDNS)", "url": "https://223.5.5.5/resolve"},
    {"label": "223.6.6.6 (AliDNS)", "url": "https://223.6.6.6/resolve"},
    {"label": "119.29.29.29 (DNSPod)", "url": "https://doh.pub/resolve"},
    {"label": "120.53.53.53 (DNSPod-2)", "url": "https://120.53.53.53/resolve"},
    {"label": "101.226.4.6 (360)", "url": "https://doh.360.cn/resolve"},
    {"label": "1.1.1.1 (Cloudflare)", "url": "https://cloudflare-dns.com/dns-query", "json": True},
    {"label": "8.8.8.8 (Google)", "url": "https://dns.google/resolve"},
]
UDP_RESOLVERS = ["223.6.6.6", "119.29.29.29", "114.114.114.114", "1.1.1.1", "8.8.8.8"]
CONTROL_DOMAINS = ["www.qq.com", "www.baidu.com", "www.cloudflare.com"]


# ── transports ────────────────────────────────────────────────────────


async def _doh_query(session, sem, resolver, name, timeout_s=6):
    url = f"{resolver['url']}?name={name}&type=A"
    headers = {"Accept": "application/dns-json"} if resolver.get("json") else {}
    async with sem:
        try:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout_s)
            ) as resp:
                if resp.status != 200:
                    return ("http_error", str(resp.status))
                data = await resp.json(content_type=None)
                status = data.get("Status")
                if status == 0:
                    return ("ok", None)
                if status == 3:
                    return ("nxdomain", None)
                if status == 2:
                    return ("servfail", None)
                return ("rcode", str(status))
        except Exception as e:  # noqa: BLE001 — transport failures are data here
            return ("timeout", type(e).__name__)


def _udp_query(ip, name):
    import dns.resolver

    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [ip]
    res.lifetime = res.timeout = 4
    try:
        res.resolve(name, "A")
        return ("ok", None)
    except dns.resolver.NXDOMAIN:
        return ("nxdomain", None)
    except dns.resolver.NoNameservers:
        return ("servfail", None)
    except Exception as e:  # noqa: BLE001
        return ("timeout", type(e).__name__)


async def query_all(names, resolvers, mode, concurrency, timeout_s=6):
    """Return {name: [(resolver_label, result, detail), ...]}.

    NOTE: sequential over domains by design — the semaphore bounds total
    in-flight queries, and per-domain asyncio.gather keeps a domain's five
    resolver probes together so verdicts complete in submission order.
    """
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, list] = {}
    args_timeout_s = timeout_s
    loop = asyncio.get_running_loop()
    async with aiohttp.ClientSession() as session:
        for name in names:

            async def one(resolver, name=name):
                if mode == "doh":
                    r, d = await _doh_query(session, sem, resolver, name, args_timeout_s)
                    if r == "timeout" and args_timeout_s >= 6:
                        # single retry on the long timeout; short sweep timeout
                        # skips retries to keep large samples tractable
                        r, d = await _doh_query(session, sem, resolver, name, args_timeout_s)
                else:
                    r, d = await loop.run_in_executor(None, _udp_query, resolver["ip"], name)
                return resolver["label"], r, d

            out[name] = await asyncio.gather(*(one(r) for r in resolvers))
    return out


# ── domain collection ─────────────────────────────────────────────────


def collect_domains(out_dir: Path, cache_dir: Path, blocks_sample: int) -> dict[str, str]:
    doms: dict[str, str] = {}
    for line in (out_dir / "whitelist.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("@@||"):
            d = line[4:].split("^")[0].split("$")[0].lower().rstrip(".")
            if d:
                doms[d] = "whitelist"
    for line in (out_dir / "merged_rules.txt").read_text(encoding="utf-8").splitlines():
        if "$important" in line and line.startswith("||"):
            d = line[2:].split("^")[0].split("$")[0].lower().rstrip(".")
            if d:
                doms.setdefault(d, "important-block")
    idx = cache_dir / "index.json"
    if idx.exists():
        entries = json.loads(idx.read_text(encoding="utf-8"))["entries"]
        for e in entries.values():
            body = (cache_dir / e["content_path"]).read_text(encoding="utf-8-sig", errors="replace")
            for s in body.splitlines():
                if "$badfilter" in s and s.startswith("||"):
                    d = s[2:].split("^")[0].split("$")[0].lower().rstrip(".").removeprefix("*.")
                    if d:
                        doms.setdefault(d, "badfilter-target")
    if blocks_sample:
        # SYSTEMATIC stride sample (every k-th rule): unbiased coverage across
        # the whole file — the previous first-N head bias concentrated on
        # alphabetically-early sources.
        cands = []
        for line in (out_dir / "merged_rules.txt").read_text(encoding="utf-8").splitlines():
            if line.startswith("||") and "$" not in line:
                d = line[2:].split("^")[0].lower().rstrip(".")
                if d and not d.replace(".", "").isdigit():
                    cands.append(d)
        total = len(cands)
        if total:
            stride = max(1, total // blocks_sample)
            for d in cands[::stride][:blocks_sample]:
                if d not in doms:
                    doms[d] = "block-sample"
    return doms


def source_attribution(cache_dir: Path, targets: set[str]) -> dict[str, set[str]]:
    """Map each audited domain to the upstream source list(s) declaring it."""
    from merger.config import load_config
    from merger.parser import RuleParser

    cfg = load_config(str(ROOT / "config" / "sources.yaml"))
    names = {s.url: s.name for s in cfg.sources}
    idx = cache_dir / "index.json"
    entries = json.loads(idx.read_text(encoding="utf-8"))["entries"] if idx.exists() else {}
    dom2src: dict[str, set[str]] = {t: set() for t in targets}
    for url, e in entries.items():
        parser = RuleParser(strip_www=True)
        rules = parser.parse_text(
            (cache_dir / e["content_path"]).read_text(encoding="utf-8-sig", errors="replace"),
            source=url,
            category="ads",
        )
        for r in rules:
            if r.normalized_domain in dom2src:
                dom2src[r.normalized_domain].add(names.get(url, url.split("/")[-1]))
    return dom2src


# ── main ──────────────────────────────────────────────────────────────


def verdict(results: list[tuple[str, str, str]], min_live: int) -> str:
    kinds = {r for _, r, _ in results}
    if "ok" in kinds:
        return "reachable"
    if "nxdomain" in kinds and kinds <= {"nxdomain", "servfail"} and len(kinds) >= min_live:
        # NXDOMAIN is an authoritative registry answer; with a single live
        # resolver it is trusted but reported without cross-validation.
        return "dead"
    return "unresolved"  # timeouts / mixed — channel or resolver trouble


async def run(args) -> int:
    out_dir, cache_dir = Path(args.out_dir), Path(args.cache_dir)
    doms = collect_domains(out_dir, cache_dir, args.blocks_sample)
    if not doms:
        print("nothing to audit")
        return 1

    mode = args.mode
    resolvers = (
        DOH_RESOLVERS if mode == "doh" else [{"label": ip, "ip": ip} for ip in UDP_RESOLVERS]
    )
    if mode == "auto":  # prefer UDP when 53 works, else DoH
        udp_probe = await query_all(
            CONTROL_DOMAINS[:1],
            [{"label": ip, "ip": ip} for ip in UDP_RESOLVERS],
            "udp",
            5,
        )
        if any(r == "ok" for rs in udp_probe.values() for _, r, _ in rs):
            mode, resolvers = "udp", [{"label": ip, "ip": ip} for ip in UDP_RESOLVERS]
        else:
            mode, resolvers = "doh", DOH_RESOLVERS

    # 1) channel self-diagnosis on control domains
    control = await query_all(
        CONTROL_DOMAINS, resolvers, mode, min(args.concurrency, 10), max(args.timeout, 6)
    )
    live: set[str] = set()
    channel_rows = []
    for r in resolvers:
        lbl = r["label"]
        oks = sum(
            1
            for dom in CONTROL_DOMAINS
            for lab, res, _ in control[dom]
            if lab == lbl and res == "ok"
        )
        if oks:
            live.add(lbl)
        channel_rows.append((lbl, oks, len(CONTROL_DOMAINS)))
    print(f"channel[{mode}]: live resolvers = {len(live)}/{len(resolvers)}")
    for lbl, oks, total in channel_rows:
        print(f"  {lbl:<22} controls {oks}/{total}")
    if len(live) < args.min_live:
        print(f"ABORT: {len(live)} live resolver(s) < --min-live {args.min_live}.")
        return 2
    live_resolvers = [r for r in resolvers if r["label"] in live]

    # 2) sweep (wildcards audited via parent domain)
    audit_names = sorted({d.removeprefix("*.") if d.startswith("*.") else d for d in doms})
    print(f"sweeping {len(audit_names):,} domains x {len(live_resolvers)} live resolvers ...")
    raw = await query_all(audit_names, live_resolvers, mode, args.concurrency, args.timeout)

    results = []
    for d in sorted(doms):
        qname = d.removeprefix("*.") if d.startswith("*.") else d
        results.append(
            {
                "domain": d,
                "kind": doms[d],
                "via_parent": d.startswith("*."),
                "verdict": verdict(raw[qname], args.min_live),
                "answers": [
                    {"resolver": lab, "result": r, "detail": det} for lab, r, det in raw[qname]
                ],
            }
        )

    dead = [r for r in results if r["verdict"] == "dead"]
    unresolved = [r for r in results if r["verdict"] == "unresolved"]
    by_kind: dict[str, Counter] = {}
    for r in results:
        by_kind.setdefault(r["kind"], Counter())[r["verdict"]] += 1

    # 3) per-source attribution for dead domains
    dom2src = source_attribution(cache_dir, {r["domain"] for r in dead}) if dead else {}
    by_source: Counter = Counter()
    for r in dead:
        for s in dom2src.get(r["domain"], {"?"}):
            by_source[s] += 1

    # 4) outputs
    payload = {
        "mode": mode,
        "channel": {
            lbl: {"controls_ok": oks, "controls_total": total} for lbl, oks, total in channel_rows
        },
        "totals": {
            "audited": len(results),
            "reachable": sum(1 for r in results if r["verdict"] == "reachable"),
            "dead": len(dead),
            "unresolved": len(unresolved),
        },
        "by_kind": {k: dict(v) for k, v in by_kind.items()},
        "dead_by_source": dict(by_source),
        "results": results,
    }
    (out_dir / "dns_audit.json").write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )

    md = [
        "## 📡 DNS 可达性审计（多解析器并发）",
        "",
        f"- 通道：{mode.upper()}（自诊断通过，{len(live)}/{len(resolvers)} 解析器存活；"
        f"控制域 {', '.join(CONTROL_DOMAINS)}）",
        f"- 解析器：{', '.join(sorted(live))}",
        "- 判定口径：任一存活解析器解析成功=可达；≥2 存活解析器均返回 NXDOMAIN=已死亡；"
        "其余=未判定（超时/混合，不视为不可达）",
        f"- 审计：{len(results):,} 域名 —— 可达 {payload['totals']['reachable']:,} · "
        f"**已死亡 {len(dead):,}** · 未判定 {len(unresolved):,}",
        "",
        "| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |",
        "|---|---:|---:|---:|---:|",
    ]
    for k in sorted(by_kind):
        c = by_kind[k]
        md.append(
            f"| {k} | {sum(c.values()):,} | {c.get('reachable', 0):,} | "
            f"{c.get('dead', 0):,} | {c.get('unresolved', 0):,} |"
        )
    wl_dead = [r["domain"] for r in dead if r["kind"] == "whitelist" and not r["via_parent"]]
    if wl_dead:
        md += [
            "",
            "### 🧹 白名单清理建议",
            "",
            f"以下 {len(wl_dead)} 条白名单域名已从 DNS 消失（放行对象不存在，规则无效）：",
            "",
        ]
        md += [f"- `{d}` —— 建议：确认后从白名单源移除" for d in wl_dead]
    if dead:
        md += ["", "### 已死亡域名 · 按来源分布", "", "| 来源列表 | 死亡域名数 |", "|---|---:|"]
        for s, n in by_source.most_common():
            md.append(f"| {s} | {n:,} |")
        md += ["", "### 已死亡域名样例（前 30，完整见 dns_audit.json）", ""]
        for r in dead[:30]:
            md.append(f"- `{r['domain']}`（{r['kind']}）")
    md += [
        "",
        "> 通配条目（`*.x`）经父域 `x` 代查并已标注 `via_parent`；",
        "> 本附录由 scripts/dns_coverage_audit.py 生成。",
    ]
    section = "\n".join(md)
    (out_dir / "dns_audit.md").write_text(section + "\n", encoding="utf-8")

    report = out_dir / "report.md"
    if args.append_report and report.exists():
        text = report.read_text(encoding="utf-8")
        footer = "*AdGuard Rules Merger V8 ·"
        if footer in text:
            text = text.replace(footer, section + "\n\n---\n" + footer, 1)
        else:
            text += "\n" + section + "\n"
        report.write_text(text, encoding="utf-8")
        print("appended summary section to report.md")

    print(
        f"RESULT: audited={len(results):,} reachable={payload['totals']['reachable']:,} "
        f"dead={len(dead):,} unresolved={len(unresolved):,}"
    )
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default="output-final")
    ap.add_argument("--cache-dir", default="cache")
    ap.add_argument("--mode", choices=["doh", "udp", "auto"], default="doh")
    ap.add_argument("--concurrency", type=int, default=80)
    ap.add_argument("--blocks-sample", type=int, default=0)
    ap.add_argument("--min-live", type=int, default=2)
    ap.add_argument(
        "--timeout", type=float, default=6, help="per-query DoH timeout (s); lower for large sweeps"
    )
    ap.add_argument("--no-append-report", action="store_true")
    args = ap.parse_args()
    args.append_report = not args.no_append_report
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
