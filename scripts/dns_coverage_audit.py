"""Multi-DNS concurrent reachability audit (R8).

Audits: whitelist domains ∪ $important block domains ∪ $badfilter target
domains (these are allow-side by semantics) — plus an optional block-rule
sample — resolved against domestic + public resolvers concurrently. A domain
is UNREACHABLE only when EVERY resolver fails. Writes json + md appendix.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
from pathlib import Path

import dns.resolver

RESOLVERS = ["223.6.6.6", "119.29.29.29", "114.114.114.114", "1.1.1.1", "8.8.8.8"]


def resolve_one(domain: str) -> dict:
    out = {"domain": domain, "ok": [], "fail": []}
    for r in RESOLVERS:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [r]
        res.lifetime = res.timeout = 4
        try:
            res.resolve(domain, "A")
            out["ok"].append(r)
        except Exception as e:  # noqa: BLE001
            out["fail"].append(f"{r}:{type(e).__name__}")
    out["reachable"] = bool(out["ok"])
    return out


def collect(out_dir: Path) -> tuple[set[str], dict[str, str]]:
    doms: dict[str, str] = {}
    for line in (out_dir / "whitelist.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("@@||"):
            d = line[4:].split("^")[0].split("$")[0].lower()
            if d:
                doms[d] = "whitelist"
    for line in (out_dir / "merged_rules.txt").read_text(encoding="utf-8").splitlines():
        if "$important" in line and line.startswith("||"):
            d = line[2:].split("^")[0].split("$")[0].removeprefix("*.").lower()
            if d and d not in doms:
                doms[d] = "important-block"
    return set(doms), doms


def badfilter_targets(cache_dir: Path) -> set[str]:
    idx = cache_dir / "index.json"
    if not idx.exists():
        return set()
    entries = json.loads(idx.read_text(encoding="utf-8"))["entries"]
    out: set[str] = set()
    for e in entries.values():
        t = (cache_dir / e["content_path"]).read_text(encoding="utf-8-sig", errors="replace")
        for line in t.splitlines():
            s = line.strip()
            if "$badfilter" in s and s.startswith("||"):
                d = s[2:].split("^")[0].split("$")[0].removeprefix("*.").lower()
                if d:
                    out.add(d)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="output-final")
    ap.add_argument("--cache-dir", default="cache")
    ap.add_argument("--workers", type=int, default=100)
    ap.add_argument("--blocks-sample", type=int, default=0, help="audit N sampled block domains too")
    a = ap.parse_args()
    out_dir, cache_dir = Path(a.out_dir), Path(a.cache_dir)

    doms_set, kind = collect(out_dir)
    doms = dict.fromkeys(doms_set)
    for d in badfilter_targets(cache_dir):
        doms.setdefault(d, "badfilter-target")
    if a.blocks_sample:
        n = 0
        for line in (out_dir / "merged_rules.txt").read_text(encoding="utf-8").splitlines():
            if line.startswith("||") and "$" not in line and n < a.blocks_sample:
                d = line[2:].split("^")[0].lower()
                if d and d not in doms:
                    doms[d] = "block-sample"
                    n += 1

    results = []
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for res in ex.map(resolve_one, sorted(doms)):
            results.append(res)

    unreachable = [r for r in results if not r["reachable"]]
    by_kind: dict[str, list] = {}
    for d, k in kind.items():
        by_kind.setdefault(k, []).append(d)
    lines = ["# DNS 可达性审计附录（R8）", "",
             f"- 解析器（并发）：{', '.join(RESOLVERS)}", f"- 审计域名：{len(results)}"
             f"（白名单 {len(by_kind.get('whitelist', []))} / important-block {len(by_kind.get('important-block', []))}"
             f" / badfilter-target {len(by_kind.get('badfilter-target', []))}"
             f" / block-sample {len(by_kind.get('block-sample', []))}）",
             f"- **全解析器不可达：{len(unreachable)}**", ""]
    if unreachable:
        lines += ["| 域名 | 类别 | 失败明细 |", "|---|---|---|"]
        for r in unreachable:
            lines.append(f"| {r['domain']} | {kind.get(r['domain'], '?')} | {'; '.join(r['fail'][:2])} |")
    (out_dir / "dns_audit.json").write_text(
        json.dumps({"resolvers": RESOLVERS, "results": results}, ensure_ascii=False), encoding="utf-8")
    (out_dir / "dns_audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"audited={len(results)} unreachable={len(unreachable)}")
    for r in unreachable[:20]:
        print("UNREACHABLE:", r["domain"], kind.get(r["domain"], "?"))


if __name__ == "__main__":
    main()
