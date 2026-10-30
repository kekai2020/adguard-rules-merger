"""V7 configuration loading and validation (pydantic).

This module replaces the top-level ``config_loader.py`` (which now remains
as a thin backward-compatible shim re-exporting the symbols below). It is
the single place that turns ``config/sources.yaml`` into typed
configuration objects consumed by the engine and CLI.

V7 enhancements over V6:
- ``download.backoff`` is a validated ``Literal`` (a typo fails fast).
- ``whitelist_audit.fusion_weights`` / ``use_heuristics`` are exposed and
  actually reach the auditor (V6 only read them from defaults).
- ``output.report_timestamp`` (default false) makes ``report.html`` /
  ``report.md`` / ``stats.json`` byte-stable across runs that produce the
  same rules, so the CI job only commits when rules genuinely change.
- Source URLs are validated for scheme (http/https/file) and shape.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

HOMEPAGE = "https://github.com/kekai2020/adguard-rules-merger-v8"


class _StrictConfig(BaseModel):
    """Config base that rejects unknown keys.

    The README promises that a config typo fails fast at load time; the
    default pydantic ``extra='ignore'`` silently dropped misspelled keys
    (e.g. ``whitelist_audit.us_dns``), leaving a switch disabled with no
    error. ``extra='forbid'`` turns that into a load/validation failure.
    """

    model_config = ConfigDict(extra="forbid")


VALID_CATEGORIES = ["ads", "tracking", "malware", "phishing", "mining", "other"]

# Default fusion weights. This table MUST stay in lock-step with
# ``whitelist_audit.AuditConfig.fusion_weights``: values mirror the hard-coded
# scoring fallbacks in ``whitelist_audit/fusion.py``, so a user who leaves
# every weight untouched gets byte-identical audit scoring to the V5.2/V6
# baseline.  Users override only the keys they name; the engine shallow-merges
# their table on top of the AuditConfig defaults (no whole-table replacement).
# Keys here are exactly the ones ``fusion.py`` actually reads — no dead knobs.
DEFAULT_FUSION_WEIGHTS = {
    "threat_intel": 40,
    "dnsbl_malicious": 30,
    "scam_confirmed": 30,
    "dns_private_ip": 20,
    "scam_suspicious": 20,
    "dnsbl_listed": 15,
    "dns_nxdomain": 15,
    "rdap_new_domain": 15,
    "heuristics": 10,
    "homograph": 12,
    "dns_mx_missing": 8,
    "gsb_malicious": 35,
    "phishtank_malicious": 30,
    "urlscan_suspicious": 20,
}


class DownloadConfig(_StrictConfig):
    retry_count: int = Field(default=2, ge=0, le=10)
    retry_delay: float = Field(default=1.5, ge=0.0, le=60.0)
    # Hard per-source time budget (all retries combined, seconds).
    source_deadline: float = Field(default=120.0, ge=0.0)
    # V7: backoff strategy is now validated (a typo used to fall through to
    # "linear" silently).
    backoff: Literal["linear", "exponential"] = "linear"
    # Optional override; empty means the engine uses its versioned UA.
    user_agent: str = ""


class DedupConfig(_StrictConfig):
    strip_www: bool = True


class QualityFilterConfig(_StrictConfig):
    enabled: bool = True
    min_domain_length: int = Field(default=4, ge=1, le=253)
    max_domain_length: int = Field(default=253, ge=1, le=253)
    filter_localhost: bool = True
    filter_ip_rules: bool = False


class AggregationConfig(_StrictConfig):
    enabled: bool = True
    min_aggregator_labels: int = Field(default=2, ge=2, le=10)
    wildcard_child_aggregation: bool = True
    wildcard_promotion_threshold: int = Field(default=0, ge=0, le=100000)
    # "count" = promote once N exact siblings are seen; "pattern" additionally
    # requires those sibling labels to share a common variation pattern.
    promotion_mode: Literal["count", "pattern"] = "count"
    psl_guard: bool = True
    promotion_pattern_min_ratio: float = Field(default=0.8, ge=0.0, le=1.0)


class ConflictResolutionConfig(_StrictConfig):
    enabled: bool = True
    cascade_subdomains: bool = True


class AIAuditConfig(_StrictConfig):
    enabled: bool = False
    api_key: str = ""
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"
    min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    max_domains: int = Field(default=100, ge=0, le=10000)


class WhitelistAuditConfig(_StrictConfig):
    enabled: bool = False
    concurrency: int = Field(default=20, ge=1, le=50)
    # Layer 1: DNS
    use_dns: bool = True
    # Layer 2: threat intel (keyless API / cached dataset)
    use_urlhaus: bool = True
    use_threatfox: bool = True
    urlhaus_delay: float = Field(default=0.2, ge=0.0, le=60.0)
    ti_mode: Literal["api", "auto"] = "api"
    # Layer 3: RDAP
    use_rdap: bool = True
    new_domain_threshold_days: int = Field(default=30, ge=1, le=3650)
    # Layer 4: MarketNow
    use_scam_check: bool = True
    # Layer 5: DNSBL (opt-in; default False to match AuditConfig and keep the
    # offline/hermetic default path zero-network — enable explicitly in YAML).
    use_dnsbl: bool = False
    # 24h disk cache for audit results (opt-in; default False like AuditConfig).
    cache_results: bool = False
    # Layer 6: VirusTotal
    use_virustotal: bool = False
    virustotal_api_key: str = ""
    # Layer 7 (offline) + Layer 8: AI
    ai: AIAuditConfig = Field(default_factory=AIAuditConfig)
    # V7: offline heuristic layer toggle + fusion weights (now actually wired
    # through to whitelist_audit.AuditConfig).
    use_heuristics: bool = True
    fusion_weights: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_FUSION_WEIGHTS))
    # Lifetime of the bundled threat-intel dataset on disk (seconds).
    feed_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    # Optional DNS-over-HTTPS JSON endpoint (e.g. NextDNS ``https://dns.nextdns.io/<id>``).
    # Empty = system resolver. Must be http/https; DoH failure falls back to system DNS.
    doh_endpoint: str = ""
    # Offline homograph/typosquat layer (zero network, on by default).
    use_homograph: bool = True
    # MX/SPF absence clue (needs DNS; off by default).
    use_dns_mx: bool = False
    # Optional online intel layers (off by default; skipped when key missing).
    use_gsb: bool = False
    gsb_api_key: str = ""
    use_phishtank: bool = False
    phishtank_api_key: str = ""
    use_urlscan: bool = False
    urlscan_api_key: str = ""
    # Certificate transparency (crt.sh) lookup; interface-only, off by default.
    use_crtsh: bool = False

    @field_validator("doh_endpoint")
    @classmethod
    def _validate_doh_scheme(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not (v.startswith("https://") or v.startswith("http://")):
            raise ValueError("whitelist_audit.doh_endpoint must be an http(s) URL")
        return v


class WhitelistOutputConfig(_StrictConfig):
    enabled: bool = True
    by_rating: bool = True
    by_category: bool = True
    include_all_ratings: bool = False
    categories: list[str] = Field(default_factory=list)


class ClassificationConfig(_StrictConfig):
    """Offline high-confidence re-judgement of block-rule source categories.

    Default ``enabled=False``: rule categories come solely from source
    declarations, so existing artifacts are byte-identical.  When enabled,
    only high-confidence registered-domain exact matches may move a rule
    into the ads/tracking buckets; security declarations (malware/phishing/
    mining) are never downgraded and CDN/payment/privacy verdicts keep the
    source bucket.
    """

    enabled: bool = False
    # When True (default), only CONFIDENCE_REGISTERED exact matches override;
    # subdomain-prefix (medium) and CNAME/no-hit (low) verdicts keep source.
    rejudge_registered_only: bool = True
    # Optional offline external seed file (Shallalist `domain;cat` / UT1
    # `domain,ID`); empty = none. Missing/bad files are safely skipped.
    seed_file: str = ""
    # Optional DNS CNAME hint resolution (dnspython, short timeout). Default
    # off: DNS results are environment-specific and stay out of the
    # deterministic default path. A verdict is accepted only when a CNAME
    # target itself hits a registered domain at 0.9.
    use_cname_hints: bool = False


class CacheConfig(_StrictConfig):
    enabled: bool = True
    directory: str = "cache"
    ttl_seconds: int = Field(default=0, ge=0)
    max_size_mb: int = Field(default=500, ge=1, le=10000)
    # How long a source that failed to download is marked "lame" so a repeat
    # run falls back to its stale cache instead of retrying immediately.
    negative_ttl_seconds: int = Field(default=300, ge=0)


class OutputConfig(_StrictConfig):
    directory: str = "output"
    formats: list[str] = Field(default_factory=lambda: ["adguard", "whitelist"])
    tiered: bool = True
    report: bool = True
    write_diff: bool = False
    # V7: when false (default), omit wall-clock timestamps and runtime from
    # committed artifacts so identical inputs yield byte-identical outputs.
    report_timestamp: bool = False
    publish_domains: bool = True

    @field_validator("formats")
    @classmethod
    def validate_formats(cls, v: list[str]) -> list[str]:
        valid = {"adguard", "whitelist", "hosts", "domains", "clash", "surge", "smartdns"}
        for fmt in v:
            if fmt not in valid:
                raise ValueError(f"Unknown output format: {fmt}")
        return v


class SourceConfig(_StrictConfig):
    enabled: bool = True
    url: str
    name: str
    category: str
    id: int = 0

    @field_validator("category")
    @classmethod
    def valid_category(cls, v: str) -> str:
        if v not in VALID_CATEGORIES:
            raise ValueError(f"Category must be one of {VALID_CATEGORIES}, got: {v}")
        return v

    @field_validator("url")
    @classmethod
    def valid_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("source url must not be empty")
        # Anything with an explicit scheme must be http/https/file; a string
        # without a scheme is treated as a local file path (POSIX, Windows
        # drive, UNC, or relative), which keeps offline/local-file merging
        # working without forcing users to spell file:// everywhere.
        if "://" in v:
            lowered = v.split("://", 1)[0].lower()
            if lowered not in ("http", "https", "file"):
                raise ValueError(f"unsupported source url scheme {lowered!r} (use http/https/file)")
        return v


class MergeConfig(_StrictConfig):
    timeout: int = Field(default=120, ge=1, le=600)
    max_concurrency: int = Field(default=50, ge=1, le=200)
    fail_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    diff_against: str | None = None
    download: DownloadConfig = Field(default_factory=DownloadConfig)
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    quality_filter: QualityFilterConfig = Field(default_factory=QualityFilterConfig)
    aggregation: AggregationConfig = Field(default_factory=AggregationConfig)
    conflict_resolution: ConflictResolutionConfig = Field(default_factory=ConflictResolutionConfig)
    whitelist_audit: WhitelistAuditConfig = Field(default_factory=WhitelistAuditConfig)
    whitelist_output: WhitelistOutputConfig = Field(default_factory=WhitelistOutputConfig)
    classification: ClassificationConfig = Field(default_factory=ClassificationConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    sources: list[SourceConfig] = Field(default_factory=list)

    @field_validator("fail_threshold")
    @classmethod
    def valid_threshold(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("fail_threshold must be between 0.0 and 1.0")
        return v


def load_config(path: str = "config/sources.yaml") -> MergeConfig:
    """Load and parse YAML config into a typed MergeConfig."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return MergeConfig(**raw)


def validate_config(path: str) -> list[str]:
    """Check a config file for problems; return a list of human-readable
    problems. Empty list means valid."""
    problems: list[str] = []
    p = Path(path)
    if not p.exists():
        return [f"Config file not found: {path}"]

    try:
        with open(p, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    if not raw or not isinstance(raw, dict):
        return ["Config is empty or not a mapping"]

    sources_raw = raw.get("sources")
    if not sources_raw or not isinstance(sources_raw, list):
        return ["No 'sources' list found"]

    # Validate whole-model first (catches type/Literal errors).
    try:
        cfg = MergeConfig(**raw)
    except Exception as e:  # pydantic ValidationError or ValueError
        problems.append(str(e))
        # Still run per-source checks below for richer diagnostics.
        cfg = None

    seen_ids: set[int] = set()
    enabled = 0
    for idx, s in enumerate(sources_raw):
        prefix = (
            f"sources[{idx}] ({s.get('name', s.get('url', '?')) if isinstance(s, dict) else '?'}):"
        )
        if not isinstance(s, dict):
            problems.append(f"{prefix} entry is not a mapping")
            continue
        if not s.get("url"):
            problems.append(f"{prefix} missing 'url'")
        else:
            try:
                SourceConfig(
                    url=s["url"], name=s.get("name", "?"), category=s.get("category", "other")
                )
            except Exception as e:
                problems.append(f"{prefix} {e}")
        if s.get("category") not in VALID_CATEGORIES:
            problems.append(f"{prefix} invalid category {s.get('category')!r}")
        sid = s.get("id")
        if sid is not None:
            if sid in seen_ids:
                problems.append(f"{prefix} duplicate id {sid}")
            seen_ids.add(sid)
        if s.get("enabled", True):
            enabled += 1

    if enabled == 0:
        problems.append("No enabled sources")

    if cfg is not None:
        # Directory writability checks (best effort).
        out_dir = Path(cfg.output.directory)
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            probe = out_dir / ".write_test"
            probe.write_text("test", encoding="utf-8")
            probe.unlink()
        except OSError:
            problems.append(f"Output directory not writable: {cfg.output.directory}")

        if cfg.cache.enabled:
            cdir = Path(cfg.cache.directory)
            try:
                cdir.mkdir(parents=True, exist_ok=True)
                probe = cdir / ".write_test"
                probe.write_text("test", encoding="utf-8")
                probe.unlink()
            except OSError:
                problems.append(f"Cache directory not writable: {cfg.cache.directory}")

    return problems


def resolve_api_keys(cfg: MergeConfig) -> MergeConfig:
    """Fill blank API keys from environment variables (never log them)."""
    wa = cfg.whitelist_audit
    if not wa.virustotal_api_key and os.environ.get("VIRUSTOTAL_API_KEY"):
        wa.virustotal_api_key = os.environ["VIRUSTOTAL_API_KEY"]
    if not wa.ai.api_key and os.environ.get("OPENAI_API_KEY"):
        wa.ai.api_key = os.environ["OPENAI_API_KEY"]
    # NOTE: VT / AI used to be force-enabled here when the env key was present,
    # which contradicted the README contract ("online layers must be enabled
    # explicitly in YAML") and could silently reach the network. Only the key
    # is filled now; the switch is never flipped here.
    # Online intel keys are filled from the environment but the layer stays
    # switched off until explicitly enabled in YAML (offline by default).
    if not wa.gsb_api_key and os.environ.get("GSB_API_KEY"):
        wa.gsb_api_key = os.environ["GSB_API_KEY"]
    if not wa.phishtank_api_key and os.environ.get("PHISHTANK_API_KEY"):
        wa.phishtank_api_key = os.environ["PHISHTANK_API_KEY"]
    if not wa.urlscan_api_key and os.environ.get("URLSCAN_API_KEY"):
        wa.urlscan_api_key = os.environ["URLSCAN_API_KEY"]
    return cfg
