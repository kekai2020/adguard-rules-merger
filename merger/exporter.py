"""V8 streaming multi-format exporter.

Outputs:
  merged_rules.txt   AdGuard block rules (||domain^ + /regex/)
  whitelist.txt      AdGuard allow rules (@@||domain^)
  hosts.txt          0.0.0.0 domain
  domains.txt        one plain domain per line
  clash.yaml         DOMAIN-SUFFIX,domain
  surge.list         DOMAIN-SUFFIX,domain
  smartdns.conf      address /domain/#
  merged_ads.txt / merged_malware.txt / merged_tracking.txt /
  merged_phishing.txt / merged_mining.txt   tiered subsets by category
  stats.json         machine-readable optimisation report
  conflicts.json     block rules removed by whitelist overrides
  contributions.json per-source unique/shared rule counts
  added.txt / removed.txt  diff vs previous run (optional)
  report.html        interactive analysis dashboard
  report.md          Markdown analysis report (GitHub-friendly)

By default all committed artifacts are byte-stable for a given rule set
(``report_timestamp=False``); no wall-clock time or runtime is embedded.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable, Iterable
from itertools import chain
from pathlib import Path
from typing import Any

from .config import HOMEPAGE
from .core.stages import compute_content_version
from .models import (
    CATEGORY_ADS,
    CATEGORY_MALWARE,
    CATEGORY_MINING,
    CATEGORY_OTHER,
    CATEGORY_PHISHING,
    CATEGORY_TRACKING,
    TIERED_CATEGORIES,
    Rule,
)
from .report.analysis import _generation_label
from .version import __version__


def _content_hash(blocks: list[Rule], allows: list[Rule]) -> str:
    """SHA-256 hash of all rule bodies (excluding headers).

    Backwards-compatible delegate to the single R1 stage kernel
    :func:`merger.core.stages.compute_content_version`; the duplicated sha-256
    loop lived here until R5 and now lives in exactly one place. Returns the
    first 12 hex chars, unchanged.
    """
    return compute_content_version(blocks, allows)


def _content_hash_lines(lines: list[str]) -> str:
    """SHA-256 hash of concrete output lines (e.g. graded whitelist rules).

    Unlike ``_content_hash`` which takes Rule objects, this operates on
    already-rendered string lines — used for graded whitelist files where
    each line is a ``@@||domain^`` allow rule.
    """
    h = hashlib.sha256()
    for line in lines:
        h.update(line.encode("utf-8", errors="replace"))
        h.update(b"\n")
    return h.hexdigest()[:12]


class Exporter:
    """Stream all output formats to disk."""

    def __init__(
        self,
        out_dir: str | Path,
        formats: list[str] | None = None,
        tiered: bool = True,
        report: bool = True,
        write_diff: bool = False,
        whitelist_output: Any = None,
        report_timestamp: bool = False,
        renderer: Callable[..., tuple[str, str]] | None = None,
        reports: tuple[str, str] | None = None,
    ) -> None:
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.formats = formats or [
            "adguard",
            "whitelist",
            "hosts",
            "domains",
            "clash",
            "surge",
            "smartdns",
        ]
        self.tiered = tiered
        self.report = report
        self.write_diff_enabled = write_diff
        self.whitelist_output = whitelist_output
        # V8: when False (default), reports/stats omit wall-clock time and
        # runtime so identical inputs produce byte-identical artifacts.
        self.report_timestamp = report_timestamp
        # R5 decoupling: rendering (analyze_rules + HTML/Markdown generation)
        # lives in the ``merger.report`` render stage, not here. ``renderer`` is
        # an optional ``(blocks, allows, outcome, include_time) -> (html, md)``
        # callback; ``reports`` carries already-rendered ``(html, md)`` bytes
        # produced by orchestration. When both are absent the default report
        # stage is used lazily, preserving the historical default path.
        self.renderer = renderer
        self._reports = reports
        self.modifier_skipped = 0
        self._domain_cache: list[str] | None = None

    # ── header helpers ────────────────────────────────────────────

    def _main_header(
        self, blocks: list[Rule], allows: list[Rule], outcome: Any, cat_counts: Counter
    ) -> list[str]:
        src_ok = outcome.sources_ok
        src_tot = outcome.sources_total
        cached = outcome.sources_cached
        # Cache-hit count is a property of the local run environment (cold vs
        # warm cache), not of the rule set. It is omitted from the committed
        # header in deterministic mode so identical inputs produce byte-identical
        # rule files; it is still shown when report_timestamp is requested.
        sources_line = f"! Sources: {src_ok}/{src_tot}"
        if self.report_timestamp:
            sources_line += f" ({cached} cached)"
        before = outcome.raw_count
        after = len(blocks) + len(allows)
        dedup_rate = (1 - after / before) * 100 if before else 0.0
        content_ver = getattr(outcome, "content_version", None) or _content_hash(blocks, allows)
        cats = " ".join(
            f"{k}={cat_counts.get(k, 0)}"
            for k in ("ads", "malware", "tracking", "phishing", "mining", "other")
        )
        lines = [
            "! Title: Merged AdGuard Home Filter Rules",
            f"! Description: Auto-merged from {src_tot} sources (dedup + aggregation + conflict resolution)",
            f"! Version: {content_ver}",
            # 合并时间戳：仅 report_timestamp 模式输出（默认确定性产物无墙钟）；
            # 尊重 SOURCE_DATE_EPOCH，CI 与本地手动构建可复现。
            *([f"! Generated: {_generation_label(True)}"] if self.report_timestamp else []),
            f"! Homepage: {HOMEPAGE}",
            f"! Total block rules: {len(blocks)}",
            f"! Total whitelist rules: {len(allows)}",
            sources_line,
            f"! Dedup rate: {dedup_rate:.1f}%",
            f"! Exact dedup: {outcome.exact_merged} | Normalized dedup: {outcome.normalized_merged} | Regex dedup: {outcome.regex_merged}",
            f"! Aggregated: exact={outcome.aggregated} wildcard={outcome.wildcard_aggregated} promoted={outcome.wildcard_promoted}",
            f"! Conflicts recorded (block rules kept): {len(outcome.conflicts)}",
            f"! Dropped: pattern={outcome.pattern_dropped} quality={outcome.quality_dropped} css={outcome.css_dropped} badfilter={getattr(outcome, 'badfilter_removed', 0)} comments={getattr(outcome, 'comment_dropped', 0)}",
            f"! Categories: {cats}",
        ]
        if outcome.failed_sources:
            lines.append(f"! WARNING: {len(outcome.failed_sources)} source(s) failed:")
            for fs in outcome.failed_sources:
                lines.append(f"!   FAILED: {fs['name']} — {fs['error']}")
        lines.append("!")
        return lines

    def _whitelist_header(self, allows: list[Rule]) -> list[str]:
        content_ver = _content_hash([], allows)
        return [
            "! Title: Whitelist for Merged Rules",
            "! Description: Allow rules separated from main filter",
            f"! Version: {content_ver}",
            *([f"! Generated: {_generation_label(True)}"] if self.report_timestamp else []),
            f"! Total allow rules: {len(allows)}",
            "!",
        ]

    # ── writers (all streaming) ─────────────────────────────────

    def _write_lines(self, path: Path, header: list[str], body: Iterable[str]) -> None:
        with open(path, "w", encoding="utf-8", buffering=1024 * 64) as f:
            for line in header:
                f.write(line + "\n")
            for line in body:
                f.write(line + "\n")

    def _domain_rules(self, blocks: list[Rule]):
        """Yield unique plain domains (skip regex AND skip modifier rules) for
        hosts/domains/clash/surge/smartdns formats.

        Results are cached after the first call so the 5 plain-domain formats
        don't rebuild the seen set over 3.7M rules each time. Only the domain
        string is kept — every consumer just renders the name, and holding the
        Rule refs would pin ~200 MB of dead tuples at production scale.
        """
        if self._domain_cache is None:
            seen = set()
            cached: list[str] = []
            for b in blocks:
                if b.modifiers:
                    continue
                d = b.normalized_domain
                if d and d not in seen:
                    seen.add(d)
                    cached.append(d)
            self._domain_cache = cached
        return iter(self._domain_cache)

    def write_adguard(self, blocks, allows, outcome, cat_counts):
        header = self._main_header(blocks, allows, outcome, cat_counts)
        self._write_lines(self.out / "merged_rules.txt", header, (b.output_raw for b in blocks))

    def write_whitelist(self, allows):
        header = self._whitelist_header(allows)
        self._write_lines(self.out / "whitelist.txt", header, (a.output_raw for a in allows))

    def write_hosts(self, blocks):
        def body():
            for d in self._domain_rules(blocks):
                yield f"0.0.0.0 {d}"

        self._write_lines(
            self.out / "hosts.txt", ["# Hosts format — AdGuard Rules Merger", "#"], body()
        )

    def write_domains(self, blocks):
        def body():
            yield from self._domain_rules(blocks)

        self._write_lines(self.out / "domains.txt", [], body())

    def write_clash(self, blocks):
        def body():
            for d in self._domain_rules(blocks):
                yield f"  - DOMAIN-SUFFIX,{d}"

        self._write_lines(
            self.out / "clash.yaml",
            ["# Clash rule-set — AdGuard Rules Merger", "payload:"],
            body(),
        )

    def write_surge(self, blocks):
        def body():
            for d in self._domain_rules(blocks):
                yield f"DOMAIN-SUFFIX,{d}"

        self._write_lines(
            self.out / "surge.list",
            ["# Surge rule-set — AdGuard Rules Merger", "# DOMAIN-SUFFIX,<domain>"],
            body(),
        )

    def write_smartdns(self, blocks):
        def body():
            for d in self._domain_rules(blocks):
                yield f"address /{d}/#"

        self._write_lines(
            self.out / "smartdns.conf",
            [
                "# SmartDNS blocking config — AdGuard Rules Merger",
                "# address /domain/#  (blocks domain + subdomains)",
            ],
            body(),
        )

    def write_tiered(self, blocks, parent_ver=None):
        buckets: dict[str, list[Rule]] = {c: [] for c in TIERED_CATEGORIES}
        for b in blocks:
            if b.category in buckets:
                buckets[b.category].append(b)
        filenames = {
            CATEGORY_ADS: "merged_ads.txt",
            CATEGORY_MALWARE: "merged_malware.txt",
            CATEGORY_TRACKING: "merged_tracking.txt",
            CATEGORY_PHISHING: "merged_phishing.txt",
            CATEGORY_MINING: "merged_mining.txt",
            CATEGORY_OTHER: "merged_other.txt",
        }
        for cat, rules in buckets.items():
            content_ver = f"{parent_ver}-{cat}" if parent_ver else _content_hash(rules, [])
            header = [
                f"! Title: Merged {cat} filter",
                f"! Category: {cat}",
                f"! Version: {content_ver}",
                f"! Rules: {len(rules)}",
                "!",
            ]
            self._write_lines(self.out / filenames[cat], header, (r.output_raw for r in rules))

    def write_stats(self, blocks, allows, outcome):
        cat_counts = Counter(b.category for b in blocks)
        before = outcome.raw_count
        after = len(blocks) + len(allows)
        total_agg = outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted
        content_ver = getattr(outcome, "content_version", None) or _content_hash(blocks, allows)
        stats = {
            "version": __version__,
            "content_version": content_ver,
            **({"generated_at": _generation_label(True)} if self.report_timestamp else {}),
            "sources": {
                "total": outcome.sources_total,
                "ok": outcome.sources_ok,
                # Cache-hit count is environment-dependent; null in deterministic
                # mode keeps stats.json byte-stable for identical rule sets.
                # D-8: the field is `int | null` — consumers MUST handle null
                # (not assume an int). See ARCHITECTURE.md §4.5.
                "cached": outcome.sources_cached if self.report_timestamp else None,
                "failed": outcome.failed_sources,
            },
            "rules": {
                "before": before,
                "after": after,
                "block": len(blocks),
                "allow": len(allows),
                "dedup_rate": round((1 - after / before) * 100, 1) if before else 0.0,
            },
            "dedup": {
                "exact_merged": outcome.exact_merged,
                "normalized_merged": outcome.normalized_merged,
                "regex_merged": outcome.regex_merged,
            },
            "optimization": {
                "exact_aggregated": outcome.aggregated,
                "wildcard_aggregated": outcome.wildcard_aggregated,
                "wildcard_promoted": outcome.wildcard_promoted,
                "total_aggregated": total_agg,
                "conflict_resolved": outcome.conflict_resolved,
                "whitelist_blocked": outcome.whitelist_blocked,
            },
            "dropped": {
                "pattern_dropped": outcome.pattern_dropped,
                "quality_dropped": outcome.quality_dropped,
                "css_dropped": outcome.css_dropped,
                "comment_dropped": getattr(outcome, "comment_dropped", 0),
                "modifier_stripped": getattr(outcome, "modifier_stripped", 0),
                "badfilter_removed": getattr(outcome, "badfilter_removed", 0),
                "modifier_rules_skipped": self.modifier_skipped,
                **(
                    {"unrecognized_dropped": outcome.unrecognized_dropped}
                    if getattr(outcome, "unrecognized_dropped", 0)
                    else {}
                ),
            },
            "categories": {
                "ads": cat_counts.get(CATEGORY_ADS, 0),
                "malware": cat_counts.get(CATEGORY_MALWARE, 0),
                "tracking": cat_counts.get(CATEGORY_TRACKING, 0),
                "phishing": cat_counts.get(CATEGORY_PHISHING, 0),
                "mining": cat_counts.get(CATEGORY_MINING, 0),
                "other": cat_counts.get("other", 0),
            },
            "modifier_stats": getattr(outcome, "modifier_stats", {}) or {},
            "source_overlap": getattr(outcome, "source_overlap", {}) or {},
            "diff": {
                "added": len(outcome.added),
                "removed": len(outcome.removed),
            },
        }
        # V8: wall-clock runtime is only embedded when explicitly requested,
        # keeping stats.json byte-stable for identical rule sets.
        if self.report_timestamp:
            stats["elapsed_seconds"] = round(outcome.elapsed, 3)
            # Per-stage timings (only when timestamps enabled, for byte stability)
            stage_timings = getattr(outcome, "stage_timings", {}) or {}
            if stage_timings:
                stats["stage_timings"] = {k: round(v, 6) for k, v in stage_timings.items()}
        # Offline reclassification hits are reported only when they actually
        # moved a rule, so the default (disabled) stats.json is byte-identical.
        reclassified = getattr(outcome, "reclassified", 0) or 0
        if reclassified:
            stats["classification"] = {"reclassified": reclassified}
        self._write_json(self.out / "stats.json", stats)

    def write_history(self, blocks, allows, outcome):
        """Append a snapshot of this run to history.json for trend analysis.

        Keeps the last 30 runs. Each entry has timestamp, rule counts,
        compression ratio, and stage timings if available.
        """
        import json
        from datetime import datetime, timezone

        history_path = self.out / "history.json"
        history = []
        if history_path.exists():
            try:
                history = json.loads(history_path.read_text(encoding="utf-8"))
                if not isinstance(history, list):
                    history = []
            except (json.JSONDecodeError, OSError):
                history = []

        # Build snapshot
        before = outcome.raw_count
        after = len(blocks) + len(allows)
        snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_count": before,
            "block_count": len(blocks),
            "allow_count": len(allows),
            "total_count": after,
            "compression_pct": round((1 - after / before) * 100, 1) if before else 0.0,
            "elapsed_seconds": round(outcome.elapsed, 3) if self.report_timestamp else None,
            "sources_ok": outcome.sources_ok,
            "sources_total": outcome.sources_total,
            "added": len(getattr(outcome, "added", []) or []),
            "removed": len(getattr(outcome, "removed", []) or []),
        }
        stage_timings = getattr(outcome, "stage_timings", {}) or {}
        if stage_timings and self.report_timestamp:
            snapshot["stage_timings"] = {k: round(v, 6) for k, v in stage_timings.items()}

        history.append(snapshot)
        # Keep only last 30 runs
        history = history[-30:]

        # Atomic write (tmp + replace) like every other artifact: a crash
        # mid-write must not leave a truncated history.json behind.
        tmp = history_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(history, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        tmp.replace(history_path)

    def write_conflicts(self, conflicts):
        self._write_json(self.out / "conflicts.json", conflicts)

    def write_contributions(self, contributions):
        self._write_json(self.out / "contributions.json", contributions)

    def write_whitelist_audit(self, outcome):
        """V5: write whitelist threat-intel audit results (if enabled)."""
        audit = getattr(outcome, "whitelist_audit", {}) or {}
        if not audit:
            return
        self._write_json(self.out / "whitelist_audit.json", audit)

    def write_whitelist_graded(self, outcome):
        """V5: split whitelist into graded sub-files by rating + category.

        Requires whitelist_audit to have run (outcome.whitelist_audit non-empty).
        Controlled by self.whitelist_output config.
        """
        from .domain_classifier import CATEGORY_LABELS, CATEGORY_ORDER

        audit = getattr(outcome, "whitelist_audit", {}) or {}
        rules = audit.get("rules", [])
        cfg = self.whitelist_output
        if not rules or cfg is None or not getattr(cfg, "enabled", True):
            return

        ratings = ("safe", "suspicious", "malicious", "unknown")
        cat_filter = set(getattr(cfg, "categories", []) or [])
        include_all = getattr(cfg, "include_all_ratings", False)

        # ── by rating ──
        if getattr(cfg, "by_rating", True):
            by_rating: dict[str, list[str]] = {r: [] for r in ratings}
            for r in rules:
                by_rating[r["rating"]].append(r["rule"])
            for rating in ratings:
                if not by_rating[rating]:
                    continue
                header = [
                    f"! Title: AdGuard Rules Merger — Whitelist ({rating})",
                    f"! Count: {len(by_rating[rating])}",
                    f"! Version: {_content_hash_lines(by_rating[rating])}",
                ]
                self._write_lines(self.out / f"whitelist_{rating}.txt", header, by_rating[rating])

        # ── by category (within each rating) ──
        if getattr(cfg, "by_category", True):
            cat_dir = self.out / "whitelist_by_category"
            cat_dir.mkdir(parents=True, exist_ok=True)
            active_ratings = ratings if include_all else ("safe",)
            for rating in active_ratings:
                by_cat: dict[str, list[str]] = {c: [] for c in CATEGORY_ORDER}
                for r in rules:
                    if r["rating"] != rating:
                        continue
                    cat = r.get("category", "other")
                    if cat_filter and cat not in cat_filter:
                        cat = "other"
                    by_cat[cat].append(r["rule"])
                for cat in CATEGORY_ORDER:
                    if not by_cat[cat]:
                        continue
                    label = CATEGORY_LABELS.get(cat, cat)
                    header = [
                        f"! Title: AdGuard Rules Merger — Whitelist ({rating} / {label})",
                        f"! Count: {len(by_cat[cat])}",
                        f"! Version: {_content_hash_lines(by_cat[cat])}",
                    ]
                    fname = f"{rating}_{cat}.txt"
                    self._write_lines(cat_dir / fname, header, by_cat[cat])

    def write_diff_files(self, outcome):
        if not self.write_diff_enabled:
            return
        self._write_lines(
            self.out / "added.txt",
            [f"# New domains this run ({len(outcome.added)})"],
            outcome.added,
        )
        self._write_lines(
            self.out / "removed.txt",
            [f"# Domains removed this run ({len(outcome.removed)})"],
            outcome.removed,
        )

    def write_report(self, blocks, allows, outcome):
        """Persist report.html / report.md bytes atomically (R5: write-only).

        Rendering itself is owned by the ``merger.report`` stage: either
        orchestration supplies already-rendered ``reports=(html, md)`` bytes, or
        the injected ``renderer`` callback produces them, or — as the final
        fallback — the default report stage is bound lazily. This method never
        calls ``analyze_rules`` or the HTML/Markdown generators directly; the
        tmp-file + ``replace`` atomic write sequence is preserved verbatim.
        """
        if self._reports is not None:
            html, md = self._reports
        else:
            renderer = self.renderer
            if renderer is None:
                # Lazy binding keeps the module-level import free of any report
                # coupling; the default stage still yields identical bytes.
                from .report import render_reports

                renderer = render_reports
            html, md = renderer(blocks, allows, outcome, include_time=self.report_timestamp)
        tmp = self.out / "report.html.tmp"
        tmp.write_text(html, encoding="utf-8")
        tmp.replace(self.out / "report.html")
        # Markdown report (no external deps, GitHub-friendly)
        tmp_md = self.out / "report.md.tmp"
        tmp_md.write_text(md, encoding="utf-8")
        tmp_md.replace(self.out / "report.md")

    @staticmethod
    def _write_json(path: Path, data):
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)

    # ── orchestration ────────────────────────────────────────────

    def export_all(self, blocks: list[Rule], allows: list[Rule], outcome: Any) -> Counter:
        cat_counts = Counter(b.category for b in blocks)
        self.modifier_skipped = sum(1 for b in blocks if b.modifiers)

        if "adguard" in self.formats:
            self.write_adguard(blocks, allows, outcome, cat_counts)
        if "whitelist" in self.formats:
            self.write_whitelist(allows)
        if "hosts" in self.formats:
            self.write_hosts(blocks)
        if "domains" in self.formats:
            self.write_domains(blocks)
        if "clash" in self.formats:
            self.write_clash(blocks)
        if "surge" in self.formats:
            self.write_surge(blocks)
        if "smartdns" in self.formats:
            self.write_smartdns(blocks)

        if self.tiered:
            parent_ver = getattr(outcome, "content_version", None)
            self.write_tiered(blocks, parent_ver=parent_ver)

        self.write_stats(blocks, allows, outcome)
        # history.json embeds wall-clock timestamps by design (trend log), so
        # it is written ONLY in timestamped mode. Writing it unconditionally
        # broke the byte-determinism contract for output/ (a committed artifact
        # containing wall-clock time) and made the CI "commit only when rules
        # changed" guard fire on every run.
        if self.report_timestamp:
            self.write_history(blocks, allows, outcome)
        self.write_conflicts(outcome.conflicts)
        self.write_contributions(outcome.contributions)
        self.write_whitelist_audit(outcome)
        self.write_whitelist_graded(outcome)
        self.write_diff_files(outcome)

        if self.report:
            self.write_report(blocks, allows, outcome)

        # V5 memory optimization: stats/conflicts/contributions already written,
        # provenance tuples are no longer needed — release them.
        for r in chain(blocks, allows):
            r.source_ids = ()

        return cat_counts
