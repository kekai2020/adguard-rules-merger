"""AsyncRuleEngine: orchestrates fetch -> dedup -> aggregate -> conflicts -> stats.

The engine composes the fetch/aggregation/conflict/stats mixins; constructor,
``from_config``, ``run`` and ``run_sync`` bodies are moved verbatim from the
legacy ``merger.core`` module during the P1-3 package split.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import contextmanager
from itertools import chain
from pathlib import Path
from typing import Any

import aiohttp

from ..cache import SourceCache
from ..domain_classifier import ClassifierRuleSet, load_seed_file
from ..models import SourceMeta
from ..parser import RuleParser
from ..ports import AioHttpHttpPort, DnspythonDnsPort, SourceCachePort
from ..version import user_agent as default_user_agent
from .aggregation import AggregationMixin
from .conflicts import ConflictMixin
from .fetch import FetchMixin
from .outcome import MergeOutcome
from .stages import (
    compute_content_version,
    compute_contributions,
    compute_modifier_stats,
    sort_merged,
)
from .stats import StatsMixin

logger = logging.getLogger(__name__)


def config_to_kwargs(cfg: Any) -> dict[str, Any]:
    """D-6: single source for ``MergeConfig`` → engine-constructor kwargs.

    Centralises the config→attribute mapping that used to live inline in
    ``from_config``, so adding a new config knob touches exactly one mapping
    here (plus the constructor signature) instead of being repeated across the
    engine body. ``from_config`` and the ``config=`` object entry both use it.
    """
    cache_dir = cfg.cache.directory if cfg.cache.enabled else None
    ai = cfg.whitelist_audit.ai
    wa = cfg.whitelist_audit
    clf = getattr(cfg, "classification", None)
    return {
        "timeout": cfg.timeout,
        "max_concurrency": cfg.max_concurrency,
        "cache_dir": cache_dir,
        "cache_ttl": cfg.cache.ttl_seconds,
        "cache_max_size_mb": cfg.cache.max_size_mb,
        "strip_www": cfg.dedup.strip_www,
        "quality_filter_enabled": cfg.quality_filter.enabled,
        "min_domain_length": cfg.quality_filter.min_domain_length,
        "max_domain_length": cfg.quality_filter.max_domain_length,
        "filter_localhost": cfg.quality_filter.filter_localhost,
        "filter_ip_rules": cfg.quality_filter.filter_ip_rules,
        "aggregation_enabled": cfg.aggregation.enabled,
        "min_aggregator_labels": cfg.aggregation.min_aggregator_labels,
        "wildcard_child_aggregation": cfg.aggregation.wildcard_child_aggregation,
        "wildcard_promotion_threshold": cfg.aggregation.wildcard_promotion_threshold,
        "psl_guard": cfg.aggregation.psl_guard,
        "promotion_mode": cfg.aggregation.promotion_mode,
        "promotion_pattern_min_ratio": cfg.aggregation.promotion_pattern_min_ratio,
        "conflict_resolution_enabled": cfg.conflict_resolution.enabled,
        "cascade_subdomains": cfg.conflict_resolution.cascade_subdomains,
        "classification_enabled": clf is not None and clf.enabled,
        "classification_registered_only": clf is None or clf.rejudge_registered_only,
        "classification_seed_file": clf.seed_file if clf is not None else "",
        "classification_use_cname_hints": clf is not None and clf.use_cname_hints,
        "whitelist_audit_enabled": wa.enabled,
        "whitelist_audit_concurrency": wa.concurrency,
        "whitelist_audit_use_dns": wa.use_dns,
        "whitelist_audit_use_urlhaus": wa.use_urlhaus,
        "whitelist_audit_use_threatfox": wa.use_threatfox,
        "whitelist_audit_use_rdap": wa.use_rdap,
        "whitelist_audit_use_scam_check": wa.use_scam_check,
        "whitelist_audit_use_dnsbl": wa.use_dnsbl,
        "whitelist_audit_cache_results": wa.cache_results,
        "whitelist_audit_cache_dir": cfg.cache.directory or "cache",
        "whitelist_audit_use_virustotal": wa.use_virustotal,
        "whitelist_audit_vt_api_key": wa.virustotal_api_key,
        "whitelist_audit_use_ai": ai.enabled,
        "whitelist_audit_ai_api_key": ai.api_key,
        "whitelist_audit_ai_base_url": ai.base_url,
        "whitelist_audit_ai_model": ai.model,
        "whitelist_audit_ai_min_confidence": ai.min_confidence,
        "whitelist_audit_ai_max_domains": ai.max_domains,
        "whitelist_audit_new_domain_days": wa.new_domain_threshold_days,
        "whitelist_audit_urlhaus_delay": wa.urlhaus_delay,
        "whitelist_audit_ti_mode": wa.ti_mode,
        "whitelist_audit_feed_ttl": wa.feed_ttl_seconds,
        "whitelist_audit_use_heuristics": wa.use_heuristics,
        "whitelist_audit_fusion_weights": wa.fusion_weights,
        "whitelist_audit_doh_endpoint": wa.doh_endpoint,
        "whitelist_audit_use_homograph": wa.use_homograph,
        "whitelist_audit_use_dns_mx": wa.use_dns_mx,
        "whitelist_audit_use_gsb": wa.use_gsb,
        "whitelist_audit_gsb_api_key": wa.gsb_api_key,
        "whitelist_audit_use_phishtank": wa.use_phishtank,
        "whitelist_audit_phishtank_api_key": wa.phishtank_api_key,
        "whitelist_audit_use_urlscan": wa.use_urlscan,
        "whitelist_audit_urlscan_api_key": wa.urlscan_api_key,
        "whitelist_audit_use_crtsh": wa.use_crtsh,
        "fail_threshold": cfg.fail_threshold,
        "diff_against": cfg.diff_against,
        "user_agent": cfg.download.user_agent,
        "retry_count": cfg.download.retry_count,
        "retry_delay": cfg.download.retry_delay,
        "source_deadline": getattr(cfg.download, "source_deadline", 120.0),
        "backoff": getattr(cfg.download, "backoff", "linear"),
        "negative_ttl_seconds": getattr(cfg.cache, "negative_ttl_seconds", 300),
    }


class AsyncRuleEngine(FetchMixin, AggregationMixin, ConflictMixin, StatsMixin):
    """Fetch + merge AdGuard DNS rules (async)."""

    def __init__(
        self,
        timeout: int = 60,
        max_concurrency: int = 50,
        cache_dir: str | None = None,
        cache_ttl: int = 0,
        cache_max_size_mb: int = 0,
        strip_www: bool = False,
        quality_filter_enabled: bool = True,
        min_domain_length: int = 4,
        max_domain_length: int = 253,
        filter_localhost: bool = True,
        filter_ip_rules: bool = False,
        aggregation_enabled: bool = True,
        min_aggregator_labels: int = 2,
        wildcard_child_aggregation: bool = True,
        wildcard_promotion_threshold: int = 0,
        psl_guard: bool = True,
        promotion_mode: str = "count",
        promotion_pattern_min_ratio: float = 0.8,
        conflict_resolution_enabled: bool = True,
        cascade_subdomains: bool = True,
        # Offline high-confidence block-category re-judgement (default off).
        classification_enabled: bool = False,
        classification_registered_only: bool = True,
        classification_seed_file: str = "",
        classification_use_cname_hints: bool = False,
        whitelist_audit_enabled: bool = False,
        whitelist_audit_concurrency: int = 10,
        whitelist_audit_use_dns: bool = True,
        whitelist_audit_use_urlhaus: bool = True,
        whitelist_audit_use_threatfox: bool = True,
        whitelist_audit_use_rdap: bool = True,
        whitelist_audit_use_scam_check: bool = True,
        whitelist_audit_use_dnsbl: bool = False,
        whitelist_audit_cache_results: bool = False,
        whitelist_audit_cache_dir: str = "cache",
        whitelist_audit_use_virustotal: bool = False,
        whitelist_audit_vt_api_key: str = "",
        whitelist_audit_use_ai: bool = False,
        whitelist_audit_ai_api_key: str = "",
        whitelist_audit_ai_base_url: str = "https://api.openai.com/v1",
        whitelist_audit_ai_model: str = "gpt-4o-mini",
        whitelist_audit_ai_min_confidence: float = 0.6,
        whitelist_audit_ai_max_domains: int = 100,
        whitelist_audit_new_domain_days: int = 30,
        whitelist_audit_urlhaus_delay: float = 1.0,
        whitelist_audit_ti_mode: str = "api",
        whitelist_audit_feed_ttl: int = 3600,
        fail_threshold: float = 0.5,
        diff_against: str | None = None,
        user_agent: str = default_user_agent(),
        retry_count: int = 2,
        retry_delay: float = 1.5,
        source_deadline: float = 120.0,
        backoff: str = "linear",
        negative_ttl_seconds: int = 300,
        # V8: offline heuristic layer toggle and fusion weights are now
        # constructor-configurable (previously the weights were hard-coded to
        # an empty dict, making the AuditConfig/YAML knobs unreachable here).
        whitelist_audit_use_heuristics: bool = True,
        whitelist_audit_fusion_weights: dict[str, int] | None = None,
        whitelist_audit_doh_endpoint: str = "",
        # Offline homograph/typosquat layer (zero network, on by default).
        whitelist_audit_use_homograph: bool = True,
        # MX/SPF absence clue (needs DNS; off by default).
        whitelist_audit_use_dns_mx: bool = False,
        # Optional online intel layers (off by default, skip without key).
        whitelist_audit_use_gsb: bool = False,
        whitelist_audit_gsb_api_key: str = "",
        whitelist_audit_use_phishtank: bool = False,
        whitelist_audit_phishtank_api_key: str = "",
        whitelist_audit_use_urlscan: bool = False,
        whitelist_audit_urlscan_api_key: str = "",
        whitelist_audit_use_crtsh: bool = False,
        # R4: optional thin IO ports for offline/fake injection; omitted means
        # the production adapter. Optional kwargs only; public API unchanged.
        http_port: Any = None,
        dns_port: Any = None,
        cache_port: Any = None,
    ) -> None:
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.strip_www = strip_www
        self.aggregation_enabled = aggregation_enabled
        self.conflict_resolution_enabled = conflict_resolution_enabled
        self.cascade_subdomains = cascade_subdomains
        self.classification_enabled = classification_enabled
        self.classification_registered_only = classification_registered_only
        self.classification_seed_file = classification_seed_file or ""
        self.classification_use_cname_hints = classification_use_cname_hints
        # R3: each engine owns an independent rule set; external seeds merge
        # into this instance instead of the module default singleton, so
        # repeated runs/tests never accumulate into shared mutable globals.
        self.classification_ruleset = ClassifierRuleSet()
        self.whitelist_audit_enabled = whitelist_audit_enabled
        self.whitelist_audit_concurrency = whitelist_audit_concurrency
        self.whitelist_audit_use_dns = whitelist_audit_use_dns
        self.whitelist_audit_use_urlhaus = whitelist_audit_use_urlhaus
        self.whitelist_audit_use_threatfox = whitelist_audit_use_threatfox
        self.whitelist_audit_use_rdap = whitelist_audit_use_rdap
        self.whitelist_audit_use_scam_check = whitelist_audit_use_scam_check
        self.whitelist_audit_use_dnsbl = whitelist_audit_use_dnsbl
        self.whitelist_audit_cache_results = whitelist_audit_cache_results
        self.whitelist_audit_cache_dir = whitelist_audit_cache_dir
        self.whitelist_audit_use_virustotal = whitelist_audit_use_virustotal
        self.whitelist_audit_vt_api_key = whitelist_audit_vt_api_key
        self.whitelist_audit_use_ai = whitelist_audit_use_ai
        self.whitelist_audit_ai_api_key = whitelist_audit_ai_api_key
        self.whitelist_audit_ai_base_url = whitelist_audit_ai_base_url
        self.whitelist_audit_ai_model = whitelist_audit_ai_model
        self.whitelist_audit_ai_min_confidence = whitelist_audit_ai_min_confidence
        self.whitelist_audit_ai_max_domains = whitelist_audit_ai_max_domains
        self.whitelist_audit_new_domain_days = whitelist_audit_new_domain_days
        self.whitelist_audit_urlhaus_delay = whitelist_audit_urlhaus_delay
        self.whitelist_audit_ti_mode = whitelist_audit_ti_mode
        self.whitelist_audit_feed_ttl = whitelist_audit_feed_ttl
        self.whitelist_audit_use_heuristics = whitelist_audit_use_heuristics
        self.whitelist_audit_fusion_weights = dict(whitelist_audit_fusion_weights or {})
        self.whitelist_audit_doh_endpoint = whitelist_audit_doh_endpoint
        self.whitelist_audit_use_homograph = whitelist_audit_use_homograph
        self.whitelist_audit_use_dns_mx = whitelist_audit_use_dns_mx
        self.whitelist_audit_use_gsb = whitelist_audit_use_gsb
        self.whitelist_audit_gsb_api_key = whitelist_audit_gsb_api_key
        self.whitelist_audit_use_phishtank = whitelist_audit_use_phishtank
        self.whitelist_audit_phishtank_api_key = whitelist_audit_phishtank_api_key
        self.whitelist_audit_use_urlscan = whitelist_audit_use_urlscan
        self.whitelist_audit_urlscan_api_key = whitelist_audit_urlscan_api_key
        self.whitelist_audit_use_crtsh = whitelist_audit_use_crtsh
        # D-6: canonical config object when built via ``from_config``; None for
        # the direct 70-kwarg constructor path. Exposed read-only via ``config``.
        self._merge_config: Any = None
        self.min_aggregator_labels = min_aggregator_labels
        self.wildcard_child_aggregation = wildcard_child_aggregation
        self.wildcard_promotion_threshold = wildcard_promotion_threshold
        self.psl_guard = psl_guard
        self.promotion_mode = promotion_mode
        self.promotion_pattern_min_ratio = promotion_pattern_min_ratio
        self.fail_threshold = fail_threshold
        self.diff_against = diff_against
        # download.user_agent="" means "use the versioned UA" (per the config
        # docstring) — never send an empty User-Agent on the wire.
        self.user_agent = user_agent or default_user_agent()
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        # V5.2: hard per-source time budget. A dead source used to burn
        # (retry_count+1) x timeout ≈ 380s of wall time; the deadline caps
        # the whole retry chain and falls back to the stale cache instead.
        self.source_deadline = source_deadline
        self.backoff = backoff
        self.negative_ttl_seconds = negative_ttl_seconds
        self._negative_cache: dict[str, float] = {}
        self._badfilter_cancelled: set[tuple[str, bool]] = set()
        self._parser_kwargs = dict(
            strip_www=strip_www,
            quality_filter=quality_filter_enabled,
            min_domain_length=min_domain_length,
            max_domain_length=max_domain_length,
            filter_localhost=filter_localhost,
            filter_ip_rules=filter_ip_rules,
        )
        self.parser = RuleParser(**self._parser_kwargs)
        self.cache: SourceCache | None = None
        if cache_dir is not None:
            self.cache = SourceCache(
                cache_dir=cache_dir, ttl_seconds=cache_ttl, max_size_mb=cache_max_size_mb
            )
            self.cache.load()
        self._session: aiohttp.ClientSession | None = None
        self._cache_lock: asyncio.Lock | None = None
        # R4 thin ports: default adapters wrap the live session / dnspython /
        # SourceCache verbatim; an injected fake replaces only the IO call
        # point (retries, 304, negative cache and CNAME walk stay unchanged).
        self.http_port = http_port or AioHttpHttpPort(lambda: self._session)
        self.dns_port = dns_port or DnspythonDnsPort(timeout=self._CNAME_TIMEOUT)
        self.cache_port = cache_port or SourceCachePort(self.cache)
        self.pattern_dropped = 0
        self.quality_dropped = 0
        self.css_dropped = 0
        self.comment_dropped = 0
        self.modifier_stripped = 0
        self.unrecognized_dropped = 0
        self.unsupported_modifier = 0

    @property
    def config(self) -> Any:
        """D-6: canonical ``MergeConfig`` this engine was built from.

        ``None`` when constructed via the 70-kwarg constructor directly. Kept
        read-only so callers can introspect the config object without re-deriving
        it from the individual attributes.
        """
        return self._merge_config

    def _build_audit_config(self) -> Any:
        """D-6: single source of truth for the whitelist-audit config.

        Centralizes the attribute → ``AuditConfig`` wiring in one construction
        point. Building fresh each call keeps it exact — no stale cache if a
        caller mutates an attribute between runs. The field mapping itself is
        declarative and lives in ``AuditConfig.from_engine`` (conventional
        ``whitelist_audit_*`` attributes map automatically; only renames are
        listed there); completeness is guarded by
        ``tests/test_config_wiring.py``.
        """
        from ..whitelist_audit import AuditConfig

        return AuditConfig.from_engine(self)

    @classmethod
    def from_config(cls, cfg: Any) -> AsyncRuleEngine:
        """Build an engine from a ``MergeConfig`` (avoids 40-kwarg plumbing).

        D-6: delegates to the single ``config_to_kwargs`` mapping and keeps the
        canonical config object on ``engine.config`` for introspection.
        """
        engine = cls(**config_to_kwargs(cfg))
        engine._merge_config = cfg
        return engine

    # ── high-level run ──────────────────────────────────────────

    async def run(self, sources: list[SourceMeta]) -> MergeOutcome:
        sources = [s for s in sources if s.enabled]
        if not sources:
            raise ValueError("No enabled sources")

        t0 = time.time()
        stages: dict[str, float] = {}

        @contextmanager
        def _stage(name: str):
            """Time one pipeline stage into ``stages`` (single writer, no manual
            perf_counter pairs to keep in sync when stages are added/moved)."""
            pt0 = time.perf_counter()
            try:
                yield
            finally:
                stages[name] = time.perf_counter() - pt0

        with _stage("fetch"):
            (
                block_map,
                allow_map,
                regex_blocks,
                regex_allows,
                raw_count,
                ok,
                cached,
                exact_merged,
                normalized_merged,
                regex_merged,
                failures,
                source_raw_counts,
                source_names,
            ) = await self.fetch_all(sources)

        total = len(sources)
        if ok == 0:
            raise RuntimeError("All sources failed to download")
        fail_rate = len(failures) / total
        if fail_rate > self.fail_threshold:
            raise RuntimeError(
                f"Source failure rate {fail_rate:.0%} exceeds threshold "
                f"{self.fail_threshold:.0%}: {[f.name for f in failures]}"
            )

        logger.info(
            "raw rules: %d from %d/%d sources (%d cached); block_keys=%d allow_keys=%d regex=%d",
            raw_count,
            ok,
            total,
            cached,
            len(block_map),
            len(allow_map),
            len(regex_blocks) + len(regex_allows),
        )

        for r in chain(block_map.values(), allow_map.values()):
            r.raw = ""

        with _stage("badfilter"):
            badfilter_removed = self._apply_badfilter(block_map, allow_map)
        if badfilter_removed:
            logger.info("badfilter cancellation: removed %d rules", badfilter_removed)

        aggregated_n = wild_agg_n = promoted_n = 0
        promo_counters: dict[str, int] = {}
        with _stage("aggregation"):
            if self.aggregation_enabled:
                allow_domains = {
                    r.normalized_domain for r in allow_map.values() if r.normalized_domain
                }
                aggregated_blocks, aggregated_n, wild_agg_n, promoted_n = self._aggregate(
                    block_map, allow_domains=allow_domains, counters=promo_counters
                )
                if promo_counters.get("promotion_multi_level_skipped"):
                    logger.info(
                        "promotion multi-level skipped: %d",
                        promo_counters["promotion_multi_level_skipped"],
                    )
                logger.info(
                    "aggregation: exact=%d wildcard=%d promoted=%d",
                    aggregated_n,
                    wild_agg_n,
                    promoted_n,
                )
            else:
                aggregated_blocks = list(block_map.values())

        with _stage("conflict"):
            if self.conflict_resolution_enabled:
                final_blocks, removed_n, conflicts = self._resolve_conflicts(
                    aggregated_blocks, list(allow_map.values()), source_names
                )
            else:
                final_blocks, removed_n, conflicts = aggregated_blocks, 0, []

        with _stage("sort"):
            final_blocks, final_allows = sort_merged(
                final_blocks, regex_blocks, allow_map.values(), regex_allows
            )

        with _stage("rejudge"):
            # Offline high-confidence re-judgement (no-op unless enabled); runs
            # before stats/contributions so bucket counts reflect the new bucket.
            if self.classification_enabled and self.classification_seed_file:
                self.classification_ruleset = self.classification_ruleset.with_seeds(
                    load_seed_file(self.classification_seed_file)
                )
            reclassified = await self._rejudge_block_categories(final_blocks)

        with _stage("stats"):
            contributions, source_overlap = compute_contributions(
                final_blocks, final_allows, source_names, source_raw_counts
            )
            modifier_stats = compute_modifier_stats(final_blocks, final_allows)

        whitelist_audit: dict[str, Any] = {}
        with _stage("audit"):
            if self.whitelist_audit_enabled:
                from ..whitelist_audit import audit_whitelist

                logger.info("running whitelist multi-layer audit...")
                # D-6: single construction via _build_audit_config (no per-run
                # re-derivation from ~35 attributes).
                audit_cfg = self._build_audit_config()
                whitelist_audit = await audit_whitelist(
                    final_allows,
                    source_names,
                    config=audit_cfg,
                    # G-2: share the pipeline's classifier tables so the audit and
                    # the block rejudge agree for custom category_seeds.json.
                    ruleset=self.classification_ruleset,
                )
                logger.info("whitelist audit: %s", whitelist_audit.get("summary", {}))

        added, removed = [], []
        added_allows, removed_allows = [], []
        with _stage("diff"):
            if self.diff_against:
                # File IO must not run on the event loop (ASYNC240): the previous
                # output can be tens of MB, and reading it inline would stall all
                # concurrent work until the IO completes. Stats (is_dir/exists)
                # go through the executor too.
                loop = asyncio.get_running_loop()
                diff_path = Path(self.diff_against)
                if await loop.run_in_executor(None, diff_path.is_dir):
                    blocks_file = str(diff_path / "merged_rules.txt")
                    allows_file = diff_path / "whitelist.txt"
                else:
                    blocks_file = self.diff_against
                    allows_file = None
                new_domains = {b.normalized_domain for b in final_blocks if b.normalized_domain}
                old_domains = await loop.run_in_executor(
                    None, self._load_previous_domains, blocks_file
                )
                added = sorted(new_domains - old_domains)
                removed = sorted(old_domains - new_domains)
                if allows_file is not None and await loop.run_in_executor(
                    None, Path.exists, allows_file
                ):
                    new_allows = {a.normalized_domain for a in final_allows if a.normalized_domain}
                    old_allows = await loop.run_in_executor(
                        None, self._load_previous_domains, str(allows_file)
                    )
                    added_allows = sorted(new_allows - old_allows)
                    removed_allows = sorted(old_allows - new_allows)
                logger.info(
                    "diff: blocks +%d -%d, allows +%d -%d",
                    len(added),
                    len(removed),
                    len(added_allows),
                    len(removed_allows),
                )

        with _stage("content_version"):
            content_version = compute_content_version(final_blocks, final_allows)

        outcome = MergeOutcome(
            blocks=final_blocks,
            allows=final_allows,
            regex_blocks=regex_blocks,
            regex_allows=regex_allows,
            raw_count=raw_count,
            sources_ok=ok,
            sources_total=total,
            sources_cached=cached,
            exact_merged=exact_merged,
            normalized_merged=normalized_merged,
            regex_merged=regex_merged,
            aggregated=aggregated_n,
            wildcard_aggregated=wild_agg_n,
            wildcard_promoted=promoted_n,
            wildcard_promoted_groups=promo_counters.get("wildcard_promoted_groups", 0),
            conflict_resolved=removed_n,
            whitelist_blocked=removed_n,
            pattern_dropped=self.pattern_dropped,
            quality_dropped=self.quality_dropped,
            css_dropped=self.css_dropped,
            comment_dropped=self.comment_dropped,
            modifier_stripped=self.modifier_stripped,
            unrecognized_dropped=self.unrecognized_dropped,
            unsupported_modifier=self.unsupported_modifier,
            badfilter_removed=badfilter_removed,
            reclassified=reclassified,
            conflicts=conflicts,
            failed_sources=[
                {"name": f.name, "url": f.url, "error": f.error, "error_type": f.error_type}
                for f in failures
            ],
            contributions=contributions,
            source_overlap=source_overlap,
            modifier_stats=modifier_stats,
            whitelist_audit=whitelist_audit,
            added=added,
            removed=removed,
            added_allows=added_allows,
            removed_allows=removed_allows,
            elapsed=time.time() - t0,
            stage_timings=stages,
            content_version=content_version,
        )
        return outcome

    def run_sync(self, sources: list[SourceMeta]) -> MergeOutcome:
        # `asyncio.run()` cannot be entered from a running event loop; give a
        # clear error instead of the cryptic RuntimeError it would raise.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "AsyncRuleEngine.run_sync() called from a running event loop; "
                "use `await engine.run(sources)` instead."
            )

        async def _go():
            async with self:
                return await self.run(sources)

        return asyncio.run(_go())
