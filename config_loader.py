"""Backward-compatibility shim.

The configuration loader moved into the package in V7: ``merger/config.py``.
This module re-exports the same public API so that existing imports such as
``from config_loader import load_config, validate_config`` and documented
commands keep working. New code should import from :mod:`merger.config`.
"""

from __future__ import annotations

from merger.config import (
    DEFAULT_FUSION_WEIGHTS,
    HOMEPAGE,
    VALID_CATEGORIES,
    AggregationConfig,
    AIAuditConfig,
    CacheConfig,
    ConflictResolutionConfig,
    DedupConfig,
    DownloadConfig,
    MergeConfig,
    OutputConfig,
    QualityFilterConfig,
    SourceConfig,
    WhitelistAuditConfig,
    WhitelistOutputConfig,
    load_config,
    resolve_api_keys,
    validate_config,
)

__all__ = [
    "HOMEPAGE",
    "VALID_CATEGORIES",
    "DEFAULT_FUSION_WEIGHTS",
    "DownloadConfig",
    "DedupConfig",
    "QualityFilterConfig",
    "AggregationConfig",
    "ConflictResolutionConfig",
    "AIAuditConfig",
    "WhitelistAuditConfig",
    "WhitelistOutputConfig",
    "CacheConfig",
    "OutputConfig",
    "SourceConfig",
    "MergeConfig",
    "load_config",
    "validate_config",
    "resolve_api_keys",
]

if __name__ == "__main__":  # pragma: no cover - manual convenience
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "config/sources.yaml"
    problems = validate_config(path)
    if problems:
        print(f"Found {len(problems)} problem(s):")
        for p in problems:
            print(f"  ✗ {p}")
        sys.exit(1)
    print(f"✓ Valid config: {path}")
