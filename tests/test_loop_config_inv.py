"""Config invariants locked by the task contract."""

from merger.whitelist_audit.config import AuditConfig


def test_doh_endpoint_retained():
    cfg = AuditConfig()
    # doh_endpoint must remain a configurable field (empty default, not removed).
    assert hasattr(cfg, "doh_endpoint")
    assert isinstance(cfg.doh_endpoint, str)


def test_online_layers_default_off():
    cfg = AuditConfig()
    # online TI layers default off (offline hermetic).
    assert cfg.use_virustotal is False
    assert cfg.use_ai is False
    assert cfg.use_gsb is False
    assert cfg.use_phishtank is False
