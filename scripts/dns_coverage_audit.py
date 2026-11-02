"""Multi-DNS concurrent reachability audit (R8, v3 — pipelined sweep).

Audits (allow-side by semantics, plus an optional block sample):
  whitelist.txt domains ∪ $important block domains ∪ $badfilter target domains
  ∪ --blocks-sample N stride-sampled block domains.

v3 performance/robustness (after profiling the v2 run at ~4 domains/s):
- FULLY PIPELINED sweep: every (domain × live resolver) pair is an independent
  task — no per-domain barrier, the semaphore is the only throttle (v2 waited
  for a domain's slowest probe before starting the next domain);
- live progress: running rate + ETA every --progress-every completed queries;
- bounded memory: per-query answers are aggregated to verdicts on the fly;
  dns_audit.json stores per-domain verdicts (use --full-json for raw answers);
- checkpoint: partial verdicts flushed to dns_audit.partial.json at
  --checkpoint-every (0 = off) so multi-hour full sweeps survive interruption;
- DoH (443) JSON APIs are the default transport (7 endpoints); channel
  SELF-DIAGNOSIS on control domains gates the run (ABORT when live <
  --min-live) so a dead channel can never fabricate verdicts;
- verdicts: reachable = any live resolver OK; dead = NXDOMAIN-only answers
  from >= min-live live resolvers; everything else = unresolved (timeouts are
  NEVER counted as dead); wildcards (*.x) audited via parent + via_parent tag;
- per-source attribution of dead domains + dead-WHITELIST cleanup suggestions;
- appends the summary into report.md when present.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path

import aiohttp

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Only NON-FILTERING variants (no ad/malware/family blocking) — a filtering
# resolver would answer blocked domains with NXDOMAIN/0.0.0.0 and fabricate
# false "dead" verdicts. Quad9 = dns11 (unfiltered), AdGuard = unfiltered
# variant, per https://adguard-dns.io/kb/zh-CN/general/dns-providers/
# 无过滤池（2025 国内DNS调研 + AdGuard kb）：114 用无过滤通道
# 114.114.115.115（114.114.114.114 是广告过滤版，会伪造死亡判定）；
# OneDNS 自带拦截、CNNIC 无 DoH，不入池；Quad9/AdGuard 取无过滤变体。
DOH_RESOLVERS = [
    {"label": "223.5.5.5 (AliDNS)", "url": "https://dns.alidns.com/dns-query"},
    {"label": "223.6.6.6 (AliDNS)", "url": "https://dns.alidns.com/dns-query"},
    {"label": "119.29.29.29 (DNSPod)", "url": "https://doh.pub/dns-query"},
    {"label": "120.53.53.53 (DNSPod-2)", "url": "https://120.53.53.53/resolve"},
    {"label": "101.226.4.6 (360)", "url": "https://doh.360.cn/resolve"},
    {"label": "180.76.76.76 (Baidu)", "url": "https://doh.baidu.com/dns-query"},
    {"label": "1.1.1.1 (Cloudflare)", "url": "https://cloudflare-dns.com/dns-query", "json": True},
    {"label": "8.8.8.8 (Google)", "url": "https://dns.google/resolve"},
    {
        "label": "9.9.9.10 (Quad9-unfiltered)",
        "url": "https://dns11.quad9.net/dns-query",
        "json": True,
    },
    {
        "label": "94.140.14.140 (AdGuard-nonfilter)",
        "url": "https://dns.unfiltered.adguard-dns.org/dns-query",
        "json": True,
    },
    {"label": "dns.sb (DNS.SB)", "url": "https://doh.dns.sb/dns-query", "json": True},
]
UDP_RESOLVERS = [
    "223.6.6.6",  # AliDNS 无过滤
    "119.29.29.29",  # DNSPod 无过滤
    "114.114.115.115",  # 114 无过滤通道（114.114.114.114 是过滤版！）
    "180.76.76.76",  # 百度
    "1.1.1.1",
    "8.8.8.8",
]
CONTROL_DOMAINS = ["www.qq.com", "www.baidu.com", "www.cloudflare.com"]


# ── transports ────────────────────────────────────────────────────────


async def _doh_query(session, resolver, name, timeout_s):
    url = f"{resolver['url']}?name={name}&type=A"
    headers = {"Accept": "application/dns-json"} if resolver.get("json") else {}
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
    except Exception as e:  # noqa: BLE001 — transport failures are audit data
        return ("timeout", type(e).__name__)


def _udp_query(ip, name, timeout_s):
    import dns.resolver

    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [ip]
    res.lifetime = res.timeout = timeout_s
    try:
        res.resolve(name, "A")
        return ("ok", None)
    except dns.resolver.NXDOMAIN:
        return ("nxdomain", None)
    except dns.resolver.NoNameservers:
        return ("servfail", None)
    except Exception as e:  # noqa: BLE001
        return ("timeout", type(e).__name__)


async def query_shard(names, resolvers, mode, args, timeout_s, into):
    """Round-1 shard sweep: each domain is queried by exactly ONE resolver
    (round-robin assignment). Returns the names whose probe FAILED — those
    enter the round-2 all-resolver cross-check."""
    loop = asyncio.get_running_loop()
    failed: list[str] = []

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=max(args.concurrency * 2, 100))
    ) as session:

        async def one(name, resolver):
            # weighted phase assigns dedicated semaphores; pre-weighting
            # probes (controls) get an equal-share semaphore on first use
            rsem = resolver.get("sem")
            if rsem is None:
                rsem = resolver["sem"] = asyncio.Semaphore(
                    max(args.concurrency // max(len(resolvers), 1), 8)
                )
            async with rsem:
                if mode == "doh":
                    r, d = await _doh_query(session, resolver, name, timeout_s)
                else:
                    r, d = await loop.run_in_executor(
                        None, _udp_query, resolver["ip"], name, timeout_s
                    )
                into.setdefault(name, []).append((resolver["label"], r, d))
                if r != "ok":
                    failed.append(name)

        tasks = [one(n, resolvers[i % len(resolvers)]) for i, n in enumerate(names)]
        await asyncio.gather(*tasks)
    return failed


async def query_all(names, resolvers, mode, args, timeout_s, into=None):
    """Fully pipelined sweep over every (name × resolver) pair.

    Returns {name: [(label, result, detail), ...]}. The semaphore is the only
    throttle; a progress task prints rate/ETA and checkpoints partial verdicts
    independently of the workers.
    """
    out: dict[str, list] = into if into is not None else {n: [] for n in names}
    for n in names:
        out.setdefault(n, [])
    loop = asyncio.get_running_loop()
    state = {"done": 0, "total": len(names) * len(resolvers)}
    started = time.monotonic()

    async def progress():
        while state["done"] < state["total"]:
            await asyncio.sleep(max(args.progress_every, 1))
            rate = state["done"] / max(time.monotonic() - started, 1e-6)
            eta = (state["total"] - state["done"]) / max(rate, 1e-6)
            print(
                f"  progress {state['done']:,}/{state['total']:,} queries "
                f"({rate:,.0f} q/s, ETA {eta / 60:.0f} min)",
                flush=True,
            )
            if args.checkpoint_every:
                _checkpoint(out, Path(args.out_dir), mode)
            # sleep in whole progress ticks; the loop re-checks state each tick

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=max(args.concurrency * 2, 100))
    ) as session:

        async def one(name, resolver):
            # weighted phase assigns dedicated semaphores; pre-weighting
            # probes (controls) get an equal-share semaphore on first use
            rsem = resolver.get("sem")
            if rsem is None:
                rsem = resolver["sem"] = asyncio.Semaphore(
                    max(args.concurrency // max(len(resolvers), 1), 8)
                )
            async with rsem:
                if mode == "doh":
                    r, d = await _doh_query(session, resolver, name, timeout_s)
                    if r == "timeout" and timeout_s >= 6:
                        # single retry on the long timeout; short sweep timeouts
                        # skip retries to keep large samples tractable
                        r, d = await _doh_query(session, resolver, name, timeout_s)
                else:
                    r, d = await loop.run_in_executor(
                        None, _udp_query, resolver["ip"], name, timeout_s
                    )
                out[name].append((resolver["label"], r, d))
                state["done"] += 1

        prog = asyncio.create_task(progress())
        # pipelined: submit every (domain × resolver) pair in bounded batches;
        # the semaphore is the only throttle (v2's per-domain barrier was the
        # dominant slowdown)
        tasks = [one(n, r) for n in names for r in resolvers]
        batch = 20_000
        for i in range(0, len(tasks), batch):
            await asyncio.gather(*tasks[i : i + batch])
            print(f"  batch {i // batch + 1}: completed", flush=True)
            if args.checkpoint_every:
                _checkpoint(out, Path(args.out_dir), mode)
        prog.cancel()
    return out


def _checkpoint(out: dict, out_dir: Path, mode: str) -> None:
    """Flush partial per-domain verdicts so long sweeps are crash-safe."""
    partial = {d: verdict(v, 1) for d, v in out.items() if v}
    (out_dir / "dns_audit.partial.json").write_text(
        json.dumps({"mode": mode, "partial_verdicts": partial}, ensure_ascii=False),
        encoding="utf-8",
    )


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
        # the whole file — a first-N head sample concentrates on
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


def _payload_from(
    results: list[dict],
    mode: str,
    channel_rows: list,
    min_live: int,
    cache_dir: Path | None = None,
) -> dict:
    dead = [r for r in results if r["verdict"] == "dead"]
    unresolved = [r for r in results if r["verdict"] == "unresolved"]
    by_kind: dict[str, Counter] = {}
    for r in results:
        by_kind.setdefault(r["kind"], Counter())[r["verdict"]] += 1
    by_source: Counter = Counter()
    if dead and cache_dir is not None:
        dom2src = source_attribution(cache_dir, {r["domain"] for r in dead})
        for r in dead:
            for s in dom2src.get(r["domain"], {"?"}):
                by_source[s] += 1
    return {
        "mode": mode,
        "channel": {
            lbl: {
                "controls_ok": oks,
                "controls_total": total,
                "latency_ms": ms,
            }
            for lbl, oks, total, ms in channel_rows
        },
        "min_live": min_live,
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


def verdict(results: list[tuple[str, str, str]], min_live: int) -> str:
    kinds = {r for _, r, _ in results}
    if "ok" in kinds:
        return "reachable"
    nx = sum(1 for _, r, _ in results if r == "nxdomain")
    if nx >= min_live and kinds <= {"nxdomain", "servfail"}:
        # NXDOMAIN is an authoritative registry answer; with a single live
        # resolver it is trusted but reported without cross-validation.
        return "dead"
    return "unresolved"  # timeouts / mixed — channel or resolver trouble


async def sweep_pipelined(names, live_resolvers, mode, args, raw, out_dir):
    """R8.5 pipelined sweep — NO phase barrier (user spec):

    round 1 probes are spawned for every domain against its weighted-shard
    resolver; the moment a probe FAILS, round-2 tasks for that domain are
    spawned against ALL live resolvers immediately — a resolver group that
    finishes its own shard instantly starts working on other groups'
    failures (no idle waiting). reachable on the FIRST ok (one vote);
    dead only when every live resolver answered NXDOMAIN/servfail;
    otherwise unresolved. Concurrency bounded by per-resolver weighted
    semaphores + a bounded spawn window.
    """
    from collections import deque

    loop = asyncio.get_running_loop()
    session_cm = aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=max(args.concurrency * 2, 100))
    )

    async def probe(domain, r, timeout_s):
        async with r["sem"]:
            if mode == "doh":
                return await _doh_query(session_cm, r, domain, timeout_s)
            return await loop.run_in_executor(None, _udp_query, r["ip"], domain, timeout_s)

    total = len(names)
    finals: set[str] = set()
    r2_left: dict[str, list] = {}
    spawn_log = {"done": 0}
    t0 = time.monotonic()
    done_evt = asyncio.Event()

    def final(domain):
        finals.add(domain)
        r2_left.pop(domain, None)
        if len(finals) >= total:
            done_evt.set()

    all_tasks: set[asyncio.Task] = set()

    def spawn(coro):
        t = asyncio.create_task(coro)
        all_tasks.add(t)
        t.add_done_callback(all_tasks.discard)
        return t

    async def r1_task(domain, r):
        spawn_log["done"] += 1
        res, det = await probe(domain, r, args.r1_timeout)
        raw[domain].append((r["label"], res, det))
        if res == "ok":
            final(domain)
            return
        # failure -> round 2: fan out to ALL live resolvers immediately
        r2_left[domain] = list(live_resolvers)
        for rr in live_resolvers:
            spawn(r2_task(domain, rr))

    async def r2_task(domain, rr):
        res, det = await probe(domain, rr, args.timeout)
        raw[domain].append((rr["label"], res, det))
        left = r2_left.get(domain)
        if left is None:
            return
        if rr in left:
            left.remove(rr)
        if res == "ok":
            final(domain)
        elif not left:
            # every live resolver has answered — dead or unresolved
            final(domain)

    async def progress():
        while len(finals) < total:
            await asyncio.sleep(10)
            rate = spawn_log["done"] / max(time.monotonic() - t0, 1e-6)
            print(
                f"  pipelined {len(finals):,}/{total:,} finals, "
                f"{len(all_tasks):,} in-flight ({rate:,.0f} spawns/s)",
                flush=True,
            )

    # bounded window: keep ~concurrency*6 tasks in flight
    assignments = deque((n, live_resolvers[i % len(live_resolvers)]) for i, n in enumerate(names))
    prog = asyncio.create_task(progress())
    window = max(args.concurrency * 6, 60)

    def spawn_next(count: int) -> None:
        for _ in range(count):
            item = next(assignments_iter, None)
            if item is None:
                return
            spawn(r1_task(item[0], item[1]))

    assignments_iter = iter(list(assignments))
    spawn_next(window)
    while all_tasks and len(finals) < total:
        done, _ = await asyncio.wait(all_tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            all_tasks.discard(t)
        spawn_next(len(done))
        if args.checkpoint_every and spawn_log["done"] >= args.checkpoint_every:
            _checkpoint(raw, out_dir, mode)
    prog.cancel()
    if all_tasks:
        await asyncio.gather(*all_tasks, return_exceptions=True)
    # unresolved retry: one fresh all-resolver pass over unresolved domains
    unresolved = [n for n in names if n not in finals]
    if unresolved and args.unresolved_retry:
        print(f"retry pass: {len(unresolved):,} unresolved, all resolvers ...")
        for n in unresolved:
            raw[n] = []
            r2_left[n] = list(live_resolvers)
            t2 = set()
            for rr in live_resolvers:
                t = asyncio.create_task(r2_task(n, rr))
                t2.add(t)
            if t2:
                await asyncio.gather(*t2, return_exceptions=True)
    await session_cm.close()


async def run(args) -> int:
    out_dir, cache_dir = Path(args.out_dir), Path(args.cache_dir)
    doms = collect_domains(out_dir, cache_dir, args.blocks_sample)
    if not doms:
        print("nothing to audit")
        return 1

    # R9 verdict cache: prior reachable/dead verdicts are persisted facts —
    # a rerun only audits UNSEEN domains (+ optional unresolved retry), so the
    # first full sweep is the only expensive one (incremental runs = minutes).
    prior: dict[str, dict] = {}
    cache_file = out_dir / "dns_audit.json"
    if not args.force and cache_file.exists():
        try:
            old = json.loads(cache_file.read_text(encoding="utf-8"))
            for r in old.get("results", []):
                if r.get("verdict") in ("reachable", "dead"):
                    prior[r["domain"]] = r
            print(f"verdict cache: {len(prior):,} prior verdicts loaded")
        except (OSError, json.JSONDecodeError) as e:
            print(f"verdict cache unreadable ({e}); full sweep")
    todo = {d: k for d, k in doms.items() if d not in prior}
    print(f"to audit this run: {len(todo):,} (skipped {len(doms) - len(todo):,} cached)")

    mode = args.mode
    resolvers = (
        DOH_RESOLVERS if mode == "doh" else [{"label": ip, "ip": ip} for ip in UDP_RESOLVERS]
    )
    if mode == "auto":  # prefer UDP when 53 works, else DoH
        udp_probe = await query_all(
            CONTROL_DOMAINS[:1],
            [{"label": ip, "ip": ip} for ip in UDP_RESOLVERS],
            "udp",
            args,
            max(args.timeout, 6),
        )
        if any(r == "ok" for rs in udp_probe.values() for _, r, _ in rs):
            mode, resolvers = "udp", [{"label": ip, "ip": ip} for ip in UDP_RESOLVERS]
        else:
            mode, resolvers = "doh", DOH_RESOLVERS

    # 1) channel self-diagnosis WITH latency measurement (R8.2):
    #    each resolver resolves the control domains twice and keeps the median
    #    wall-time of successes -> weight = 1/median -> shard quota
    #    proportional to speed, so slow resolvers never leave fast groups
    #    waiting and each group runs under its OWN semaphore (R8.3).
    import time as _time

    control = await query_all(CONTROL_DOMAINS, resolvers, mode, args, max(args.timeout, 6))
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
        channel_rows.append((lbl, oks, len(CONTROL_DOMAINS), round(r.get("latency", 0) * 1000)))
    print(f"channel[{mode}]: live resolvers = {len(live)}/{len(resolvers)}")
    for lbl, oks, total, _ms in channel_rows:
        print(f"  {lbl:<34} controls {oks}/{total}")
    if len(live) < args.min_live:
        print(f"ABORT: {len(live)} live resolver(s) < --min-live {args.min_live}.")
        return 2

    # latency probe: 2 timed control resolutions per live resolver
    live_resolvers = [r for r in resolvers if r["label"] in live]
    for r in live_resolvers:
        times = []
        for _ in range(2):
            t0 = _time.monotonic()
            probe = await query_all(CONTROL_DOMAINS[:1], [r], mode, args, max(args.timeout, 6))
            if any(res == "ok" for rs in probe.values() for _, res, _ in rs):
                times.append(_time.monotonic() - t0)
        r["latency"] = sorted(times)[len(times) // 2] if times else args.timeout
    weights = {r["label"]: 1.0 / max(r["latency"], 0.01) for r in live_resolvers}
    wsum = sum(weights.values())
    caps = {}
    quotas = {}
    for r in live_resolvers:
        share = weights[r["label"]] / wsum
        caps[r["label"]] = max(8, round(args.concurrency * share))
        quotas[r["label"]] = max(20, round(len(doms) * share))
    for r in live_resolvers:
        r["sem"] = asyncio.Semaphore(caps[r["label"]])
    print("weighted sharding (latency ms -> domains quota / concurrency cap):")
    for r in live_resolvers:
        print(
            f"  {r['label']:<34} {r['latency'] * 1000:6.0f} ms  ->  "
            f"{quotas[r['label']]:,} / {caps[r['label']]}"
        )

    # 2) TWO-PHASE SHARDED sweep (R8.1):
    #    round 1 — rules split evenly across live resolvers, ONE query each
    #              (a success anywhere is a final "reachable");
    #    round 2 — every round-1 failure is re-tested by ALL live resolvers
    #              concurrently (cross-validated dead/unresolved verdict).
    #    Query volume: N + F*R instead of N*R — ~60% fewer queries at the
    #    observed 92% reachable rate.
    audit_names = sorted({d.removeprefix("*.") if d.startswith("*.") else d for d in todo})
    if args.shard_count > 1:
        # deterministic stride partition: shard i owns names[i::count] —
        # parallel matrix jobs cover the whole set with zero overlap
        audit_names = audit_names[args.shard_index :: args.shard_count]
    total_domains = len(audit_names)
    if not audit_names:
        print("nothing new to audit (all domains have cached verdicts)")
        # still refresh report sections from the cache
        results = [dict(r, kind=doms.get(r["domain"], r["kind"])) for r in prior.values()]
        payload = _payload_from(results, mode="cache", channel_rows=[], min_live=args.min_live)
        (out_dir / "dns_audit.json").write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
        # dns_audit.md is regenerated by the next live sweep; json+html are
        # the always-current surfaces after an incremental run
        patch_html_report(out_dir, payload)
        print("report sections refreshed from cache")
        return 0
    # weighted round-robin assignment pool (per-resolver quotas by latency)
    assign_pool: list = []
    for r in live_resolvers:
        assign_pool += [r] * quotas[r["label"]]
    raw: dict[str, list] = {}
    if args.two_phase:
        print(
            f"sweeping {total_domains:,} domains across "
            f"{len(live_resolvers)} live resolvers (timeout {args.timeout}s, "
            f"concurrency {args.concurrency}) ..."
        )
        t0 = time.monotonic()

        # round 1 — one resolver per domain, round-robin sharded
        r1_fail: list[str] = []
        for i in range(0, total_domains, args.concurrency * 4):
            chunk = audit_names[i : i + args.concurrency * 4]
            part = await query_shard(chunk, live_resolvers, mode, args, args.r1_timeout, raw)
            r1_fail.extend(part)
            if args.checkpoint_every:
                _checkpoint(raw, out_dir, mode)
            print(
                f"  round1 {min(i + len(chunk), total_domains):,}/{total_domains:,} "
                f"({len(r1_fail):,} failed -> round 2)",
                flush=True,
            )
        r1_elapsed = time.monotonic() - t0
        print(
            f"round 1 done in {r1_elapsed / 60:.1f} min: "
            f"{total_domains - len(r1_fail):,} reachable on first probe, "
            f"{len(r1_fail):,} enter round 2"
        )
        if args.checkpoint_every:
            _checkpoint(raw, out_dir, mode)

        # round 2 — all resolvers on every round-1 failure
        t1 = time.monotonic()
        if r1_fail:
            for i in range(0, len(r1_fail), args.concurrency * 4):
                chunk = r1_fail[i : i + args.concurrency * 4]
                await query_all(chunk, live_resolvers, mode, args, args.timeout, into=raw)
                print(
                    f"  round2 {min(i + len(chunk), len(r1_fail)):,}/{len(r1_fail):,}", flush=True
                )
        print(f"round 2 done in {(time.monotonic() - t1) / 60:.1f} min")

        # round 3 — unresolved retry: timeouts are often transient; one fresh
        # all-resolver pass over the unresolved set, then re-verdict
        t2 = time.monotonic()
        still: list[str] = [
            d for d in audit_names if raw.get(d) and verdict(raw[d], args.min_live) == "unresolved"
        ]
        if still and args.unresolved_retry:
            print(f"round 3: retrying {len(still):,} unresolved with all resolvers ...")
            for i in range(0, len(still), args.concurrency * 4):
                chunk = still[i : i + args.concurrency * 4]
                for name in chunk:
                    raw[name] = []  # clear stale answers; re-probe fresh
                await query_all(chunk, live_resolvers, mode, args, max(args.timeout, 6), into=raw)
                print(f"  round3 {min(i + len(chunk), len(still)):,}/{len(still):,}", flush=True)
            print(f"round 3 done in {(time.monotonic() - t2) / 60:.1f} min")

    else:
        retry_stats = await sweep_pipelined(audit_names, live_resolvers, mode, args, raw, out_dir)
        pipeline_meta = {
            "mode": "pipelined",
            "live": len(live_resolvers),
            "shard": {"index": args.shard_index, "count": args.shard_count},
            "retry_pass": retry_stats,
        }
        payload["pipeline"] = pipeline_meta

    # 3) aggregate to verdicts (answers kept only with --full-json)
    shard_set = set(audit_names)
    results = []
    for d in sorted(doms):
        if d not in shard_set:
            continue  # other shards own this domain (sharded runs)
        if "*" in d and not d.startswith("*."):
            # mid-domain wildcard whitelist entry (e.g. bcicl.*.evergage.com):
            # not a literal DNS name — counted separately, never probed
            results.append(
                {
                    "domain": d,
                    "kind": doms[d],
                    "via_parent": False,
                    "verdict": "wildcard-literal",
                }
            )
            continue
        qname = d.removeprefix("*.") if d.startswith("*.") else d
        answers = raw[qname]
        row = {
            "domain": d,
            "kind": doms[d],
            "via_parent": d.startswith("*."),
            "verdict": verdict(answers, args.min_live),
        }
        if args.full_json:
            row["answers"] = [
                {"resolver": lab, "result": r, "detail": det} for lab, r, det in answers
            ]
        results.append(row)

    dead = [r for r in results if r["verdict"] == "dead"]
    unresolved = [r for r in results if r["verdict"] == "unresolved"]
    by_kind: dict[str, Counter] = {}
    for r in results:
        by_kind.setdefault(r["kind"], Counter())[r["verdict"]] += 1

    # 4) per-source attribution for dead domains
    dom2src = source_attribution(cache_dir, {r["domain"] for r in dead}) if dead else {}
    by_source: Counter = Counter()
    for r in dead:
        for s in dom2src.get(r["domain"], {"?"}):
            by_source[s] += 1

    # 5) outputs: merge cached verdicts with this run's fresh ones
    for d, r in prior.items():
        if d not in {x["domain"] for x in results}:
            results.append(dict(r, kind=doms.get(d, r["kind"])))
    payload = {
        "mode": mode,
        "channel": {
            lbl: {
                "controls_ok": oks,
                "controls_total": total,
                "latency_ms": ms,
            }
            for lbl, oks, total, ms in channel_rows
        },
        "shard": {"index": args.shard_index, "count": args.shard_count},
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
    out_name = (
        f"dns_audit.shard{args.shard_index}of{args.shard_count}.json"
        if args.shard_count > 1
        else "dns_audit.json"
    )
    (out_dir / out_name).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    md = [
        "## 📡 DNS 可达性审计（多解析器并发）",
        "",
        f"- 通道：{mode.upper()}（自诊断通过，{len(live)}/{len(resolvers)} 解析器存活；"
        f"控制域 {', '.join(CONTROL_DOMAINS)}）",
        f"- 解析器（全部为无过滤/非家庭变体）：{', '.join(sorted(live))}",
        "- 判定口径：任一存活解析器解析成功=可达；"
        f"≥{args.min_live} 个存活解析器均返回 NXDOMAIN=已死亡"
        + ("（单解析器，无交叉验证，置信度降低）" if len(live) == 1 else "（交叉验证）")
        + "；其余=未判定（超时/混合，不视为不可达）",
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
        f"> 本附录由 scripts/dns_coverage_audit.py v3 生成（{time.strftime('%Y-%m-%d %H:%M')}）。",
    ]
    section = "\n".join(md)
    (out_dir / "dns_audit.md").write_text(section + "\n", encoding="utf-8")

    if args.shard_count == 1 and patch_html_report(out_dir, payload):
        print("injected/updated DNS audit section in report.html")

    report = out_dir / "report.md"
    if args.shard_count == 1 and args.append_report and report.exists():
        text = report.read_text(encoding="utf-8")
        footer = "*AdGuard Rules Merger ·"
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


def build_html_section(payload: dict) -> str:
    """Render the audit payload as a report.html section (report-styled)."""
    from html import escape

    t = payload["totals"]
    rows_kind = ""
    for k in sorted(payload.get("by_kind", {})):
        c = payload["by_kind"][k]
        rows_kind += (
            f"<tr><td>{escape(k)}</td><td class='num'>{sum(c.values()):,}</td>"
            f"<td class='num'>{c.get('reachable', 0):,}</td>"
            f"<td class='num'>{c.get('dead', 0):,}</td>"
            f"<td class='num'>{c.get('unresolved', 0):,}</td></tr>"
        )
    rows_src = "".join(
        f"<tr><td>{escape(src)}</td><td class='num'>{n:,}</td></tr>"
        for src, n in sorted(payload.get("dead_by_source", {}).items(), key=lambda kv: -kv[1])
    )
    wl_dead = [
        r["domain"]
        for r in payload.get("results", [])
        if r["kind"] == "whitelist" and r["verdict"] == "dead" and not r["via_parent"]
    ]
    rows_wl = "".join(
        f"<tr><td><code>{escape(d)}</code></td>"
        f"<td><span class='tag tag-yellow'>建议确认后从白名单源移除</span></td></tr>"
        for d in wl_dead
    )
    # 通道自诊断表：实测延时 + 存活状态（R8.6）
    chan_rows = ""
    for lbl, info in sorted((payload.get("channel") or {}).items()):
        ok = info.get("controls_ok", 0)
        tt = info.get("controls_total", 0)
        ms = info.get("latency_ms") or 0
        status = (
            '<span class="tag tag-green">存活</span>'
            if ok
            else '<span class="tag tag-red">剔除</span>'
        )
        lat = f"{ms} ms" if ms else "—"
        chan_rows += (
            f"<tr><td>{escape(lbl)}</td><td class='num'>{ok}/{tt}</td>"
            f"<td>{status}</td><td class='num'>{lat}</td></tr>"
        )
    chan_block = (
        (
            '<h3 style="margin:16px 0 8px">通道自诊断（控制域实测）</h3>'
            '<div class="table-wrap"><table>'
            "<thead><tr><th>解析器</th><th class='num'>控制域通过</th>"
            "<th>状态</th><th class='num'>实测延时</th></tr></thead>"
            f"<tbody>{chan_rows}</tbody></table></div>"
        )
        if chan_rows
        else ""
    )
    rp = (payload.get("pipeline") or {}).get("retry_pass") or {}
    retry_cards = (
        (
            f"<div class='stat-card'><div class='value'>{rp.get('retried', 0):,}</div>"
            "<div class='label'>未判定重试</div></div>"
            f"<div class='stat-card'><div class='value'>{rp.get('recovered', 0):,}</div>"
            "<div class='label'>重试收回</div></div>"
        )
        if rp.get("retried")
        else ""
    )
    wl_lit = sum(1 for r in payload.get("results", []) if r.get("verdict") == "wildcard-literal")
    lit_note = (
        (
            f"<div class='stat-card'><div class='value'>{wl_lit}</div>"
            "<div class='label'>通配字面(未探测)</div></div>"
        )
        if wl_lit
        else ""
    )
    dead_block = ""
    if rows_src:
        dead_block += (
            '<h3 style="margin:16px 0 8px">已死亡域名 · 按来源分布</h3>'
            '<div class="table-wrap"><table>'
            "<thead><tr><th>来源列表</th><th class='num'>死亡域名数</th></tr></thead>"
            f"<tbody>{rows_src}</tbody></table></div>"
        )
    if rows_wl:
        dead_block += (
            '<h3 style="margin:16px 0 8px">🧹 白名单清理建议</h3>'
            '<p class="note">以下白名单域名已从 DNS 消失（放行对象不存在，规则无效）：</p>'
            '<div class="table-wrap"><table>'
            "<thead><tr><th>域名</th><th>建议</th></tr></thead>"
            f"<tbody>{rows_wl}</tbody></table></div>"
        )
    return (
        '<div class="section" id="dns-audit">'
        '<h2><span class="sec-no">16</span>📡 DNS 可达性审计（多解析器并发 · 流水线动态抢占）</h2>'
        '<p class="sec-intro">多解析器并发解析的可达性核验（旁路分析，'
        "由 scripts/dns_coverage_audit.py 写入）。通道："
        f"{escape(payload['mode'].upper())}；"
        "判定口径：任一存活解析器成功=可达；"
        f"≥{payload.get('min_live', 1)} 个存活解析器 NXDOMAIN=已死亡（全解析器应答后才判死）；"
        "其余=未判定（超时永不判死）。通配条目经父域代查（via_parent）；"
        "中缀通配白名单（bcicl.*.x 类）非字面域名，单列为 wildcard-literal。</p>"
        + chan_block
        + '<div class="stats-grid">'
        + f"<div class='stat-card'><div class='value'>{t['audited']:,}</div><div class='label'>审计域名</div></div>"
        + f"<div class='stat-card'><div class='value'>{t['reachable']:,}</div><div class='label'>可达</div></div>"
        + f"<div class='stat-card'><div class='value'>{t['dead']:,}</div><div class='label'>已死亡</div></div>"
        + f"<div class='stat-card'><div class='value'>{t['unresolved']:,}</div><div class='label'>未判定</div></div>"
        + lit_note
        + retry_cards
        + "</div>"
        + dead_block
        + '<p class="note">本节为 DNS 旁路审计结果，与合并管线无耦合；'
        "详细逐域数据见 dns_audit.json / dns_audit.md。</p>"
        "</div>"
    )


def patch_html_report(out_dir: Path, payload: dict) -> bool:
    """Inject/replace the audit section in report.html (idempotent)."""
    html_path = out_dir / "report.html"
    if not html_path.exists():
        return False
    text = html_path.read_text(encoding="utf-8")
    section = build_html_section(payload)
    marker = '<div class="section" id="dns-audit">'
    if marker in text:
        start = text.index(marker)
        end = text.find('<div class="footer">', start)
        end = len(text) if end == -1 else end
        text = text[:start] + section + "\n\n  " + text[end:]
    else:
        anchor = '<div class="footer">'
        if anchor in text:
            text = text.replace(anchor, section + "\n\n  " + anchor, 1)
        else:
            text += section
    html_path.write_text(text, encoding="utf-8")
    return True


def gather(out_dir: Path, args) -> int:
    """Merge dns_audit.shard*of*.json payloads into final json/md/html."""
    shard_files = sorted(out_dir.glob("dns_audit.shard*of*.json"))
    if not shard_files:
        print("no shard payloads found")
        return 1
    results: list[dict] = []
    modes: set[str] = set()
    live: set[str] = set()
    min_live = args.min_live
    for f in shard_files:
        d = json.loads(f.read_text(encoding="utf-8"))
        results.extend(d.get("results", []))
        modes.add(d.get("mode", "?"))
        for lbl, info in (d.get("channel") or {}).items():
            if info.get("controls_ok"):
                live.add(lbl)
        min_live = max(min_live, int(d.get("min_live", 1)))
    # dedupe by domain (later shards win — partitions are disjoint so this is a safety net)
    uniq = {r["domain"]: r for r in results}
    results = sorted(uniq.values(), key=lambda r: r["domain"])
    payload = _payload_from(
        results,
        mode="+".join(sorted(modes)),
        channel_rows=[(lbl, 1, 1, 0) for lbl in sorted(live)],
        min_live=min_live,
        cache_dir=Path(args.cache_dir),
    )
    payload["gathered_from"] = [f.name for f in shard_files]
    (out_dir / "dns_audit.json").write_text(
        json.dumps(payload, ensure_ascii=False), encoding="utf-8"
    )
    md = [
        "## 📡 DNS 可达性审计（多解析器并发 · 分片汇聚）",
        "",
        f"- 通道：{payload['mode']}；存活解析器：{', '.join(sorted(live)) or '?'}",
        "- 判定口径：任一存活解析器成功=可达；"
        f"≥{min_live} 个存活解析器 NXDOMAIN=已死亡；其余=未判定",
        f"- 审计：{len(results):,} 域名 —— 可达 {payload['totals']['reachable']:,} · "
        f"**已死亡 {payload['totals']['dead']:,}** · 未判定 {payload['totals']['unresolved']:,}",
        "",
        "| 类别 | 审计数 | 可达 | 已死亡 | 未判定 |",
        "|---|---:|---:|---:|---:|",
    ]
    for k in sorted(payload["by_kind"]):
        c = payload["by_kind"][k]
        md.append(
            f"| {k} | {sum(c.values()):,} | {c.get('reachable', 0):,} | "
            f"{c.get('dead', 0):,} | {c.get('unresolved', 0):,} |"
        )
    wl_dead = [
        r["domain"]
        for r in results
        if r["kind"] == "whitelist" and r["verdict"] == "dead" and not r.get("via_parent")
    ]
    if wl_dead:
        md += [
            "",
            "### 🧹 白名单清理建议",
            "",
            f"以下 {len(wl_dead)} 条白名单域名已从 DNS 消失：",
            "",
        ]
        md += [f"- `{d}` —— 建议：确认后从白名单源移除" for d in wl_dead]
    if payload["dead_by_source"]:
        md += ["", "### 已死亡域名 · 按来源分布", "", "| 来源列表 | 死亡域名数 |", "|---|---:|"]
        for src, n in sorted(payload["dead_by_source"].items(), key=lambda kv: -kv[1]):
            md.append(f"| {src} | {n:,} |")
    md += ["", f"> 汇聚自 {len(shard_files)} 个分片（{', '.join(f.name for f in shard_files)}）。"]
    (out_dir / "dns_audit.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    patch_html_report(out_dir, payload)
    for f in shard_files:
        f.unlink()
    print(
        f"GATHERED: {len(results):,} domains, dead={payload['totals']['dead']:,}, "
        f"unresolved={payload['totals']['unresolved']:,}; json/md/html updated"
    )
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default="output-final")
    ap.add_argument("--cache-dir", default="cache")
    ap.add_argument("--mode", choices=["doh", "udp", "auto"], default="doh")
    ap.add_argument("--concurrency", type=int, default=150)
    ap.add_argument("--timeout", type=float, default=4, help="per-query timeout (s)")
    ap.add_argument(
        "--r1-timeout",
        type=float,
        default=2.5,
        help="round-1 fast-fail timeout (s); failures re-probe in round 2",
    )
    ap.add_argument("--min-live", type=int, default=2)
    ap.add_argument("--shard-index", type=int, default=0)
    ap.add_argument("--shard-count", type=int, default=1)
    ap.add_argument(
        "--gather", action="store_true", help="merge shard payloads into final artifacts"
    )
    ap.add_argument("--force", action="store_true", help="ignore verdict cache, full re-sweep")
    ap.add_argument(
        "--two-phase",
        action="store_true",
        help="use the barrier two-phase sweep instead of the pipelined default",
    )
    ap.add_argument(
        "--no-pipeline", action="store_true", help="fall back to the two-phase barrier sweep"
    )
    ap.add_argument(
        "--no-unresolved-retry",
        action="store_true",
        help="skip the round-3 fresh retry of unresolved domains",
    )
    ap.add_argument("--blocks-sample", type=int, default=0)
    ap.add_argument("--full-json", action="store_true", help="keep raw answers in json")
    ap.add_argument("--progress-every", type=int, default=5000)
    ap.add_argument(
        "--checkpoint-every",
        type=int,
        default=0,
        help="flush partial verdicts at each batch boundary when set",
    )
    ap.add_argument("--no-append-report", action="store_true")
    ap.add_argument(
        "--html-only",
        action="store_true",
        help="re-apply existing dns_audit.json to report.html and exit",
    )
    args = ap.parse_args()
    args.append_report = not args.no_append_report
    args.unresolved_retry = not args.no_unresolved_retry
    if args.gather:
        raise SystemExit(gather(Path(args.out_dir), args))
    if args.html_only:
        out_dir = Path(args.out_dir)
        payload = json.loads((out_dir / "dns_audit.json").read_text(encoding="utf-8"))
        payload["min_live"] = args.min_live
        ok = patch_html_report(out_dir, payload)
        print("report.html updated" if ok else "report.html not found")
        raise SystemExit(0 if ok else 1)
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
