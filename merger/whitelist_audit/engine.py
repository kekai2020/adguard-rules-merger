"""``audit_whitelist`` orchestrator: parallel per-domain multi-layer audit.

All network layers run concurrently per domain; the offline PSL classifier and
heuristics/homograph layers run synchronously, AI runs after the gather. Bodies
moved verbatim during the P1-3 package split.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

from ..ai_classifier import classify_with_ai
from ..domain_classifier import (
    ClassifierRuleSet,
    category_counts,
    classify_domain_with_confidence,
)
from ..homograph import detect_typosquat
from ..models import Rule
from .config import AuditConfig, _CacheEntry
from .constants import (
    _RECOMMEND,
    _RECOMMEND_LABEL,
    CACHE_TTL,
    RATING_MALICIOUS,
    RATING_SAFE,
    RATING_SUSPICIOUS,
    RATING_UNKNOWN,
)
from .disk_cache import _disk_cache_load, _disk_cache_path, _disk_cache_save, _is_private_ip
from .fusion import _fuse_rating
from .heuristics import local_heuristics, recycled_domain_clue
from .registry import LAYER_REGISTRY, AuditLayerContext, specs_by_name

# Layer specs indexed by name once at import; declaration order drives task
# submission and the gather→zip mapping (R2 declarative registry).
_SPECS_BY_NAME = specs_by_name()

logger = logging.getLogger(__name__)


async def audit_whitelist(
    allows: list[Rule],
    source_names: dict[str, str] | None = None,
    config: AuditConfig | None = None,
    # Backwards-compat kwargs (deprecated, use config instead)
    concurrency: int = 10,
    use_dns: bool = True,
    use_urlhaus: bool = True,
    use_threatfox: bool = True,
    urlhaus_delay: float = 1.0,
    # R4: optional session factory replacing the inline aiohttp.ClientSession();
    # omitted uses the production factory. Layers still receive the raw session.
    session_factory: Callable[[], Any] | None = None,
    # G-2: offline classifier ruleset. The block rejudge path runs with the
    # engine's ``classification_ruleset`` (seeded from category_seeds.json);
    # the audit must use the SAME tables or a custom seed set is classified
    # differently in the two pipelines. Omitted → default singleton (matches
    # the pre-G-2 behavior exactly).
    ruleset: ClassifierRuleSet | None = None,
) -> dict[str, Any]:
    """Audit all domain-based whitelist rules with parallel multi-layer fusion.

    All independent network layers execute concurrently per domain.
    """
    if config is None:
        config = AuditConfig(
            use_dns=use_dns,
            use_urlhaus=use_urlhaus,
            use_threatfox=use_threatfox,
            concurrency=concurrency,
            urlhaus_delay=urlhaus_delay,
        )

    source_names = source_names or {}
    targets = [a for a in allows if a.normalized_domain]
    if not targets:
        return {
            "summary": {"total": 0, "safe": 0, "suspicious": 0, "malicious": 0, "unknown": 0},
            "rules": [],
        }

    # ── V5.2 disk cache: previously audited domains skip the network ──
    disk_cache = _disk_cache_load(config)
    disk_hits = [0]  # list for nonlocal mutation
    fresh_disk: dict[str, dict[str, Any]] = {}
    # V5.3: per-run in-process cache (local, not module-level) to avoid
    # cross-run / cross-test pollution. _audit_one reads/writes this dict.
    result_cache: dict[str, _CacheEntry] = {}

    # ── Shared HTTP session for all network layers ──
    # R4: session creation goes through the injectable factory; layers still
    # receive the raw session object (R2 registry and layer signatures unchanged).
    from ..ports import default_audit_session_factory

    session_cm = session_factory or default_audit_session_factory

    sem = asyncio.Semaphore(config.concurrency)
    ti_sem = asyncio.Semaphore(3)  # per-run, bound to this event loop
    # W-2 (reviewed, non-issue): layer_hits / disk_hits / ai_budget are mutated
    # in _audit_one but ONLY in blocks with no `await` between the read and the
    # write. asyncio cooperatively schedules on a single thread and a coroutine
    # only yields at an `await`, so those increments are atomic — no lock is
    # needed. If a future edit introduces an `await` inside such a block (e.g.
    # an async counter helper), move the count to the caller instead of locking.
    layer_hits = {
        "dns_nxdomain": 0,
        "dns_private_ip": 0,
        "urlhaus": 0,
        "threatfox": 0,
        "rdap_new_domain": 0,
        "scam_check": 0,
        "virustotal": 0,
        "ai_classified": 0,
        "heuristics": 0,
        "dnsbl_malicious": 0,
        "dnsbl_listed": 0,
        # V6 layers
        "homograph": 0,
        "dns_mx_missing": 0,
        "gsb": 0,
        "phishtank": 0,
        "urlscan": 0,
    }
    # AI budget: limit LLM calls to config.ai_max_domains (cost control)
    ai_budget = [config.ai_max_domains]  # list for nonlocal mutation in nested fn

    async with session_cm() as session:
        # V5.3: build threat-feed index once (ti_mode=auto). On failure
        # _audit_one falls back to per-domain API calls.
        feed_index = None
        if config.ti_mode == "auto" and (config.use_urlhaus or config.use_threatfox):
            from ..threat_feeds import ThreatFeedIndex

            feed_index = ThreatFeedIndex(
                cache_dir=config.cache_dir, ttl_seconds=config.feed_ttl_seconds
            )
            await feed_index.build(session)

        async def _audit_one(rule: Rule) -> dict[str, Any]:
            domain = rule.normalized_domain
            cache_key = f"audit:{domain}"
            _entry = result_cache.get(cache_key)
            cached = (
                _entry.result if _entry and (time.time() - _entry.timestamp) < CACHE_TTL else None
            )
            if cached:
                cached = dict(cached)
                cached["sources"] = [source_names.get(s, s) for s in rule.source_ids]
                cached["rule"] = rule.output_raw
                cached["disk_cache"] = False
                return cached
            if domain in disk_cache:
                disk_hits[0] += 1
                hit = dict(disk_cache[domain])
                hit["sources"] = [source_names.get(s, s) for s in rule.source_ids]
                hit["rule"] = rule.output_raw
                hit["disk_cache"] = True
                result_cache[cache_key] = _CacheEntry(
                    result={
                        k: v for k, v in hit.items() if k not in ("sources", "rule", "disk_cache")
                    }
                )
                return hit

            async with sem:
                # Layer 6: Offline PSL classification (sync, microseconds)
                # G-2: use the injected ruleset so the audit agrees with the
                # block rejudge pipeline for custom seed files.
                category: str
                confidence: float
                cat_reason: str
                category, confidence, cat_reason = classify_domain_with_confidence(
                    domain, ruleset=ruleset
                )

                # ── Layers 1-5: parallel network queries (R2 declarative registry) ──
                layer_ctx = AuditLayerContext(
                    domain=domain,
                    session=session,
                    config=config,
                    feed_index=feed_index,
                    ti_sem=ti_sem,
                )
                tasks = []
                task_names = []
                for spec in LAYER_REGISTRY:
                    if spec.gate(layer_ctx):
                        tasks.append(spec.build(layer_ctx))
                        task_names.append(spec.name)

                # Execute all network layers concurrently. return_exceptions=True
                # so one layer raising does NOT discard the evidence the other
                # layers already collected; the failing layer simply falls back
                # to its disabled-default shape (same as a skipped layer).
                gathered = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []
                layer_data = {}
                # strict=True pins the invariant that gather() returns exactly
                # one result per submitted task (a mismatch must be a bug, not
                # a silent mis-mapping).
                for name, res in zip(task_names, gathered, strict=True):
                    if isinstance(res, BaseException):
                        layer_data[name] = _SPECS_BY_NAME[name].default()
                    else:
                        layer_data[name] = res

                dns = layer_data.get("dns", _SPECS_BY_NAME["dns"].default())
                ti = layer_data.get("ti", _SPECS_BY_NAME["ti"].default())
                urlhaus, threatfox = ti if isinstance(ti, tuple) else _SPECS_BY_NAME["ti"].default()
                rdap = layer_data.get("rdap", _SPECS_BY_NAME["rdap"].default())
                scam = layer_data.get("scam", _SPECS_BY_NAME["scam"].default())
                vt = layer_data.get("vt", _SPECS_BY_NAME["vt"].default())
                dnsbl = layer_data.get("dnsbl", _SPECS_BY_NAME["dnsbl"].default())
                mxspf = layer_data.get("mxspf", _SPECS_BY_NAME["mxspf"].default())
                gsb = layer_data.get("gsb", _SPECS_BY_NAME["gsb"].default())
                phishtank = layer_data.get("phishtank", _SPECS_BY_NAME["phishtank"].default())
                urlscan = layer_data.get("urlscan", _SPECS_BY_NAME["urlscan"].default())
                crtsh = layer_data.get("crtsh", _SPECS_BY_NAME["crtsh"].default())

                # Offline heuristics (sync, microseconds)
                heur = (
                    local_heuristics(domain)
                    if config.use_heuristics
                    else {"score": 0, "flags": [], "is_risky": False, "tld": ""}
                )

                # V6: offline homograph / typosquat (sync, zero network, error-safe)
                try:
                    hom = (
                        detect_typosquat(domain)
                        if config.use_homograph
                        else {
                            "is_typosquat": False,
                            "matched_brand": None,
                            "distance": None,
                            "reasons": [],
                            "folded": "",
                            "homograph": False,
                        }
                    )
                except Exception as e:  # noqa: BLE001 — layer must never hard-fail
                    hom = {
                        "is_typosquat": False,
                        "matched_brand": None,
                        "distance": None,
                        "reasons": [],
                        "folded": "",
                        "homograph": False,
                        "error": str(e),
                    }

                # V6: offline recycled-domain clue (from collected RDAP+DNS;
                # informational only, never scores on its own).
                mxspf["recycled_clue"] = recycled_domain_clue(rdap, dns)

                # Layer 7: AI classification (only for low confidence, after gather)
                ai_result: dict[str, Any] = {
                    "category": None,
                    "confidence": 0.0,
                    "reason": "",
                    "error": "disabled",
                }
                if (
                    config.use_ai
                    and config.ai_api_key
                    and confidence < config.ai_min_confidence
                    and ai_budget[0] > 0
                ):
                    ai_budget[0] -= 1
                    try:
                        ai_result = await classify_with_ai(
                            domain,
                            config.ai_api_key,
                            session,
                            base_url=config.ai_base_url,
                            model=config.ai_model,
                        )
                        if ai_result.get("category") and not ai_result.get("error"):
                            category = ai_result["category"]
                            confidence = max(confidence, ai_result["confidence"] * 0.7)
                            cat_reason = f"AI: {ai_result.get('reason', '')}"
                    except Exception as e:
                        ai_result["error"] = str(e)

            # ── Multi-layer fusion (V5.2: all reasons + risk score) ──
            rating, reasons, risk_score = _fuse_rating(
                dns,
                urlhaus,
                threatfox,
                rdap,
                scam,
                vt,
                config,
                dnsbl=dnsbl,
                heuristics=heur,
                homograph=hom,
                mxspf=mxspf,
                gsb=gsb,
                phishtank=phishtank,
                urlscan=urlscan,
            )

            # Track layer hits
            if dns.get("nxdomain"):
                layer_hits["dns_nxdomain"] += 1
            if dns.get("ips") and any(_is_private_ip(ip) for ip in dns["ips"]):
                layer_hits["dns_private_ip"] += 1
            if urlhaus.get("malicious"):
                layer_hits["urlhaus"] += 1
            if threatfox.get("malicious"):
                layer_hits["threatfox"] += 1
            if rdap.get("is_new_domain"):
                layer_hits["rdap_new_domain"] += 1
            if scam.get("is_suspicious"):
                layer_hits["scam_check"] += 1
            if vt.get("malicious"):
                layer_hits["virustotal"] += 1
            if dnsbl.get("malicious"):
                layer_hits["dnsbl_malicious"] += 1
            elif dnsbl.get("listed"):
                layer_hits["dnsbl_listed"] += 1
            if heur.get("is_risky"):
                layer_hits["heuristics"] += 1
            if hom.get("is_typosquat"):
                layer_hits["homograph"] += 1
            if config.use_dns_mx and (mxspf.get("missing_mx") or mxspf.get("missing_spf")):
                layer_hits["dns_mx_missing"] += 1
            if gsb.get("malicious"):
                layer_hits["gsb"] += 1
            if phishtank.get("malicious"):
                layer_hits["phishtank"] += 1
            if urlscan.get("malicious"):
                layer_hits["urlscan"] += 1
            if ai_result.get("category") and not ai_result.get("error"):
                layer_hits["ai_classified"] += 1

            result = {
                "domain": domain,
                "rule": rule.output_raw,
                "sources": [source_names.get(s, s) for s in rule.source_ids],
                "rating": rating,
                "category": category,
                "category_confidence": round(confidence, 2),
                "category_reason": cat_reason,
                "reason": "; ".join(reasons),
                "dns_ips": dns.get("ips", []),
                "dns_nxdomain": dns.get("nxdomain", False),
                "urlhaus_malicious": urlhaus.get("malicious", False),
                "threatfox_malicious": threatfox.get("malicious", False),
                "rdap_new_domain": rdap.get("is_new_domain", False),
                "rdap_domain_age_days": rdap.get("domain_age_days"),
                "rdap_registrar": rdap.get("registrar"),
                "scam_suspicious": scam.get("is_suspicious", False),
                "scam_decision": scam.get("decision"),
                "scam_risk_score": scam.get("risk_score", 0),
                "virustotal_malicious": vt.get("malicious", False),
                "virustotal_reputation": vt.get("reputation_score", 0.0),
                "dnsbl_listed": dnsbl.get("listed", False),
                "dnsbl_malicious": dnsbl.get("malicious", False),
                "dnsbl_hits": dnsbl.get("hits", []),
                "risk_score": risk_score,
                "heuristics_score": heur.get("score", 0),
                "heuristics_flags": heur.get("flags", []),
                # V6: offline homograph / typosquat
                "homograph_is_typosquat": hom.get("is_typosquat", False),
                "homograph_brand": hom.get("matched_brand"),
                "homograph_distance": hom.get("distance"),
                "homograph_reasons": hom.get("reasons", []),
                # V6: MX/SPF DNS clue
                "mxspf_has_mx": mxspf.get("has_mx"),
                "mxspf_has_spf": mxspf.get("has_spf"),
                "mxspf_missing": bool(mxspf.get("missing_mx") or mxspf.get("missing_spf")),
                "mxspf_recycled_clue": bool(mxspf.get("recycled_clue")),
                # V6: optional online intel
                "gsb_malicious": gsb.get("malicious", False),
                "phishtank_malicious": phishtank.get("malicious", False),
                "urlscan_malicious": urlscan.get("malicious", False),
                "crtsh_entries": crtsh.get("entries", []),
                "recommendation": _RECOMMEND.get(rating, "review"),
                "recommendation_label": _RECOMMEND_LABEL.get(
                    _RECOMMEND.get(rating, "review"), "建议复核"
                ),
                "ai_classified": ai_result.get("category") is not None
                and not ai_result.get("error"),
            }
            stored = {k: v for k, v in result.items() if k not in ("sources", "rule", "disk_cache")}
            result_cache[cache_key] = _CacheEntry(result=stored)
            fresh_disk[domain] = stored
            return result

        # W-3: bound concurrent coroutine creation. Building one coroutine per
        # target up-front is O(n) memory and inflates the event loop even though
        # `sem` caps actual parallelism. Process in batches of `concurrency` so
        # only a bounded number of coroutines exist at once; results are still
        # appended in target order (the final summary re-sorts by rating/domain).
        results: list[dict[str, Any]] = []
        batch = max(1, config.concurrency)
        for start in range(0, len(targets), batch):
            chunk = targets[start : start + batch]
            tasks = [_audit_one(r) for r in chunk]
            # Defensive: a single domain must never take the whole audit down.
            # Exceptions (from any layer) are demoted to an "unknown" record.
            gathered = await asyncio.gather(*tasks, return_exceptions=True)
            for r, rule in zip(gathered, chunk, strict=True):
                if isinstance(r, BaseException):
                    logger.warning("audit failed for %s: %s", rule.normalized_domain, r)
                    results.append(
                        {
                            "domain": rule.normalized_domain,
                            "rule": rule.output_raw,
                            "sources": [source_names.get(s, s) for s in rule.source_ids],
                            "rating": RATING_UNKNOWN,
                            "category": "other",
                            "category_confidence": 0.0,
                            "category_reason": "audit exception",
                            "reason": f"审计异常: {r}",
                            "dns_ips": [],
                            "dns_nxdomain": False,
                            "urlhaus_malicious": False,
                            "threatfox_malicious": False,
                            "rdap_new_domain": False,
                            "rdap_domain_age_days": None,
                            "rdap_registrar": None,
                            "scam_suspicious": False,
                            "scam_decision": None,
                            "scam_risk_score": 0,
                            "virustotal_malicious": False,
                            "virustotal_reputation": 0.0,
                            "dnsbl_listed": False,
                            "dnsbl_malicious": False,
                            "dnsbl_hits": [],
                            "risk_score": 0,
                            "heuristics_score": 0,
                            "heuristics_flags": [],
                            "homograph_is_typosquat": False,
                            "homograph_brand": None,
                            "homograph_distance": None,
                            "homograph_reasons": [],
                            "mxspf_has_mx": None,
                            "mxspf_has_spf": None,
                            "mxspf_missing": False,
                            "mxspf_recycled_clue": False,
                            "gsb_malicious": False,
                            "phishtank_malicious": False,
                            "urlscan_malicious": False,
                            "crtsh_entries": [],
                            "recommendation": "review",
                            "recommendation_label": "建议复核",
                            "ai_classified": False,
                        }
                    )
                else:
                    results.append(r)

            # W-4: periodic flush so a mid-audit crash does not lose the whole
            # run's fresh audit results (the final save below writes the rest).
            if (start // batch) % 10 == 9:
                _disk_cache_save(config, fresh_disk)

    # persist fresh results to the disk cache (V5.2)
    _disk_cache_save(config, fresh_disk)

    # ── summary ──
    summary: dict[str, Any] = {
        "total": len(results),
        "safe": 0,
        "suspicious": 0,
        "malicious": 0,
        "unknown": 0,
    }
    all_categories = []
    for r in results:
        summary[r["rating"]] += 1
        all_categories.append(r["category"])
    summary["category_counts"] = category_counts(all_categories)
    summary["by_rating"] = {}
    for rating in (RATING_SAFE, RATING_SUSPICIOUS, RATING_MALICIOUS, RATING_UNKNOWN):
        cats = [r["category"] for r in results if r["rating"] == rating]
        summary["by_rating"][rating] = category_counts(cats)
    conf_buckets = {"high(>=0.9)": 0, "medium(0.6-0.89)": 0, "low(<0.6)": 0}
    for r in results:
        c = r.get("category_confidence", 0)
        if c >= 0.9:
            conf_buckets["high(>=0.9)"] += 1
        elif c >= 0.6:
            conf_buckets["medium(0.6-0.89)"] += 1
        else:
            conf_buckets["low(<0.6)"] += 1
    summary["category_confidence"] = conf_buckets
    # V5.2 risk score distribution + top risky domains
    risk_buckets = {"high(>=50)": 0, "medium(20-49)": 0, "low(1-19)": 0, "none(0)": 0}
    for r in results:
        s = r.get("risk_score", 0)
        if s >= 50:
            risk_buckets["high(>=50)"] += 1
        elif s >= 20:
            risk_buckets["medium(20-49)"] += 1
        elif s >= 1:
            risk_buckets["low(1-19)"] += 1
        else:
            risk_buckets["none(0)"] += 1
    summary["risk_score_buckets"] = risk_buckets
    summary["top_risky"] = [
        {
            "domain": r["domain"],
            "rating": r["rating"],
            "risk_score": r.get("risk_score", 0),
            "reason": r["reason"],
        }
        for r in sorted(results, key=lambda r: (-r.get("risk_score", 0), r.get("domain", "")))[:10]
        if r.get("risk_score", 0) > 0
    ]
    summary["disk_cache"] = {
        "enabled": config.cache_results,
        "hits": disk_hits[0],
        "stored": len(fresh_disk),
        "path": str(_disk_cache_path(config)) if config.cache_results else None,
    }
    summary["layer_hits"] = layer_hits
    summary["layers_enabled"] = {
        "dns": config.use_dns,
        "doh": bool(config.doh_endpoint),
        "urlhaus": config.use_urlhaus,
        "threatfox": config.use_threatfox,
        "rdap": config.use_rdap,
        "scam_check": config.use_scam_check,
        "dnsbl": config.use_dnsbl,
        "virustotal": config.use_virustotal,
        "ai": config.use_ai,
        # V6 layers
        "homograph": config.use_homograph,
        "dns_mx": config.use_dns_mx,
        "gsb": config.use_gsb,
        "phishtank": config.use_phishtank,
        "urlscan": config.use_urlscan,
        "crtsh": config.use_crtsh,
    }
    summary["execution_mode"] = "parallel"
    if feed_index is not None:
        summary["threat_feeds"] = feed_index.stats
    else:
        summary["threat_feeds"] = {"mode": "api"}

    order = {RATING_MALICIOUS: 0, RATING_SUSPICIOUS: 1, RATING_UNKNOWN: 2, RATING_SAFE: 3}
    results.sort(key=lambda r: (order.get(r["rating"], 9), r["domain"]))

    return {"summary": summary, "rules": results}
