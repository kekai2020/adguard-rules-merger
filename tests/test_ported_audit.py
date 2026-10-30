"""Ported audit improvements (batch移植)."""

from merger.core.engine import config_to_kwargs
from merger.models import intern_source, reset_source_registry


def test_virustotal_threshold():
    from merger.virustotal_audit import MALICIOUS_THRESHOLD

    assert MALICIOUS_THRESHOLD == 0.20


def test_config_to_kwargs_keys(monkeypatch):
    from merger.config import load_config

    cfg = load_config("config/sources.yaml")
    kw = config_to_kwargs(cfg)
    # spot-check a few mapped keys
    assert "timeout" in kw
    assert kw["whitelist_audit_doh_endpoint"] == cfg.whitelist_audit.doh_endpoint
    assert kw["fail_threshold"] == cfg.fail_threshold


def test_reset_source_registry():
    reset_source_registry()
    b1 = intern_source("uniq-src-x")
    b2 = intern_source("uniq-src-y")
    assert b1 != b2
    reset_source_registry()
    assert intern_source("uniq-src-x") == b1
    reset_source_registry()
