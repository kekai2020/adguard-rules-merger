"""Declarative, ordered registry for the parallel network audit layers (R2).

The orchestrator (``engine._audit_one``) used to hand-write an if-gate chain
that appended coroutines to ``tasks`` / ``task_names`` one layer at a time.
R2 moves that chain into a fixed ordered list of :class:`LayerSpec`; the
orchestrator walks the list, keeps the enabled layers, and builds their
concurrent tasks. Declaration order is the previous if-chain order, so task
submission and result mapping stay deterministic (C1 byte-identical output).

Seam layers (``_dns_check`` / ``_query_threat_intel`` / ``_query_dnsbl``) are
still resolved through :func:`seam.resolve` at call time, so existing
``monkeypatch.setattr(package, name, fake)`` seams keep hitting; every other
layer keeps its direct call. Synchronous heuristics/homograph, the post-gather
AI call, feed-index building, disk cache, summary bucketing and the outer
``gather(..., return_exceptions=True)`` fallback are NOT registered here and
stay inline in the engine.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..scam_check import query_scam_check
from ..virustotal_audit import query_virustotal
from .config import AuditConfig
from .dns_doh import _query_mx_spf
from .online import _query_crtsh, _query_gsb, _query_phishtank, _query_urlscan
from .rdap import _query_rdap_wrapper
from .seam import resolve
from .threat_intel import _query_threat_intel_dataset


@dataclass(frozen=True)
class AuditLayerContext:
    """Per-domain context handed to a spec's ``gate`` / ``build`` callables.

    Carries everything a layer needs to schedule; ``feed_index`` / ``ti_sem``
    are optional and only the threat-intel layer consumes them.
    """

    domain: str
    session: Any
    config: AuditConfig
    feed_index: Any = None
    ti_sem: Any = None


@dataclass(frozen=True)
class LayerSpec:
    """One parallel network layer: gate, task builder, disabled fallback.

    Attributes:
        name: task name used for ``task_names`` / ``layer_data`` mapping.
        gate: predicate over :class:`AuditLayerContext`; True schedules the layer.
        build: returns the layer coroutine for this domain when gated on.
        default: zero-arg factory returning the fresh disabled fallback shape.
    """

    name: str
    gate: Callable[[AuditLayerContext], bool]
    build: Callable[[AuditLayerContext], Any]
    default: Callable[[], Any]


# ── Threat-intel (URLhaus + ThreatFox): feed-index ready → dataset lookup,
# otherwise per-domain API calls via the seam; count the API fallback. ──


def _build_ti(ctx: AuditLayerContext) -> Any:
    if ctx.feed_index is not None and ctx.feed_index.ready:
        return _query_threat_intel_dataset(ctx.domain, ctx.feed_index)
    if ctx.feed_index is not None:
        ctx.feed_index.stats["api_fallbacks"] += 1
    return resolve("_query_threat_intel")(ctx.domain, ctx.session, ctx.config, ti_sem=ctx.ti_sem)


# ── Declarative ordered registry ────────────────────────────────────────
# Order = the previous if-chain order; do not reorder without re-checking the
# gather→zip mapping and every existing audit test.

LAYER_REGISTRY: tuple[LayerSpec, ...] = (
    LayerSpec(
        name="dns",
        gate=lambda ctx: ctx.config.use_dns,
        build=lambda ctx: resolve("_dns_check")(
            ctx.domain,
            timeout=ctx.config.doh_timeout,
            doh_endpoint=ctx.config.doh_endpoint,
            session=ctx.session,
        ),
        default=lambda: {"nxdomain": False, "ips": [], "error": "disabled"},
    ),
    LayerSpec(
        name="ti",
        gate=lambda ctx: ctx.config.use_urlhaus or ctx.config.use_threatfox,
        build=_build_ti,
        default=lambda: (
            {"malicious": False, "error": "disabled"},
            {"malicious": False, "error": "disabled"},
        ),
    ),
    LayerSpec(
        name="rdap",
        gate=lambda ctx: ctx.config.use_rdap,
        build=lambda ctx: _query_rdap_wrapper(ctx.domain, ctx.session, ctx.config),
        default=lambda: {
            "is_new_domain": False,
            "domain_age_days": None,
            "registrar": None,
            "error": "disabled",
        },
    ),
    LayerSpec(
        name="scam",
        gate=lambda ctx: ctx.config.use_scam_check,
        build=lambda ctx: query_scam_check(ctx.domain, ctx.session),
        default=lambda: {
            "is_suspicious": False,
            "is_confirmed_scam": False,
            "decision": None,
            "risk_score": 0,
            "reasons": [],
            "error": "disabled",
        },
    ),
    LayerSpec(
        name="dnsbl",
        gate=lambda ctx: ctx.config.use_dnsbl,
        build=lambda ctx: resolve("_query_dnsbl")(ctx.domain),
        default=lambda: {
            "listed": False,
            "malicious": False,
            "hits": [],
            "error": "disabled",
        },
    ),
    LayerSpec(
        name="vt",
        gate=lambda ctx: ctx.config.use_virustotal and bool(ctx.config.virustotal_api_key),
        build=lambda ctx: query_virustotal(ctx.domain, ctx.config.virustotal_api_key, ctx.session),
        default=lambda: {
            "malicious": False,
            "error": "disabled",
            "reputation_score": 0.0,
            "malicious_votes": 0,
        },
    ),
    LayerSpec(
        name="mxspf",
        gate=lambda ctx: ctx.config.use_dns_mx,
        build=lambda ctx: _query_mx_spf(ctx.domain),
        default=lambda: {
            "has_mx": None,
            "has_spf": None,
            "missing_mx": False,
            "missing_spf": False,
            "recycled_clue": False,
            "reasons": [],
            "error": "disabled",
        },
    ),
    LayerSpec(
        name="gsb",
        gate=lambda ctx: ctx.config.use_gsb and bool(ctx.config.gsb_api_key),
        build=lambda ctx: _query_gsb(ctx.domain, ctx.config.gsb_api_key, ctx.session),
        default=lambda: {"malicious": False, "threats": [], "error": "disabled"},
    ),
    LayerSpec(
        name="phishtank",
        gate=lambda ctx: ctx.config.use_phishtank and bool(ctx.config.phishtank_api_key),
        build=lambda ctx: _query_phishtank(ctx.domain, ctx.config.phishtank_api_key, ctx.session),
        default=lambda: {
            "malicious": False,
            "phish_id": None,
            "error": "disabled",
        },
    ),
    LayerSpec(
        name="urlscan",
        gate=lambda ctx: ctx.config.use_urlscan,
        build=lambda ctx: _query_urlscan(ctx.domain, ctx.config.urlscan_api_key, ctx.session),
        default=lambda: {
            "malicious": False,
            "verdict": None,
            "error": "disabled",
        },
    ),
    LayerSpec(
        name="crtsh",
        gate=lambda ctx: ctx.config.use_crtsh,
        build=lambda ctx: _query_crtsh(ctx.domain, ctx.session),
        default=lambda: {"entries": [], "error": "disabled"},
    ),
)


def specs_by_name() -> dict[str, LayerSpec]:
    """Index the registry by layer name (declaration order preserved)."""
    return {spec.name: spec for spec in LAYER_REGISTRY}
