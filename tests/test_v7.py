"""V7 feature and regression tests.

Covers the V7 hardening that has no direct V6 counterpart:
- validated ``download.backoff`` Literal and source URL scheme checks
- fusion weights / offline heuristic flags wired from config to the engine
- byte-stable reports and stats (deterministic mode, no wall clock)
- the package-native CLI (version / validate / sources / cache) and the
  top-level compatibility shims
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")

from merger.cli import app
from merger.config import DEFAULT_FUSION_WEIGHTS, MergeConfig, load_config
from merger.core import AsyncRuleEngine
from merger.exporter import Exporter
from merger.models import SourceMeta

SRC_TEXT = (
    "||ads.example.com^\n"
    "||track.example.com^\n"
    "||ads.example.com^\n"
    "||child.ads.example.com^\n"
    "@@||cdn.example.com^\n"
    "0.0.0.0 host.example.com\n"
)


def _src(tmp_path: Path) -> str:
    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / "source.txt"
    p.write_text(SRC_TEXT, encoding="utf-8")
    return str(p)


def _run_once(tmp_path: Path, report_timestamp: bool):
    cfg = MergeConfig()
    cfg.cache.enabled = False
    cfg.output.directory = str(tmp_path / "out")
    cfg.output.report = True
    cfg.output.report_timestamp = report_timestamp
    cfg.whitelist_output.enabled = False
    engine = AsyncRuleEngine(cache_dir=None)
    outcome = engine.run_sync([SourceMeta(name="s1", url=_src(tmp_path), category="ads")])
    Exporter(
        cfg.output.directory,
        tiered=False,
        report=True,
        write_diff=False,
        whitelist_output=cfg.whitelist_output,
        report_timestamp=report_timestamp,
    ).export_all(outcome.blocks, outcome.allows, outcome)
    out = Path(cfg.output.directory)
    return {
        "html": (out / "report.html").read_text(encoding="utf-8"),
        "md": (out / "report.md").read_text(encoding="utf-8"),
        "stats": (out / "stats.json").read_text(encoding="utf-8"),
    }


# ── config hardening ──────────────────────────────────────────────


def test_backoff_literal_rejects_typo(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("download:\n  backoff: expinential\nsources: []\n", encoding="utf-8")
    with pytest.raises(Exception):
        load_config(str(p))


def test_backoff_accepts_known_values():
    assert MergeConfig().download.backoff == "linear"
    cfg = MergeConfig(download={"backoff": "exponential"})
    assert cfg.download.backoff == "exponential"


def test_url_scheme_rejects_ftp():
    from merger.config import SourceConfig

    with pytest.raises(Exception):
        SourceConfig(url="ftp://host/list.txt", name="x", category="ads")


def test_url_accepts_http_https_and_local_path(tmp_path):
    from merger.config import SourceConfig

    assert SourceConfig(url="https://a.com/list.txt", name="x", category="ads").url
    assert SourceConfig(url="file:///tmp/list.txt", name="x", category="ads").url
    assert SourceConfig(url=str(tmp_path / "list.txt"), name="x", category="ads").url


def test_fusion_weights_defaults_present():
    cfg = MergeConfig()
    assert cfg.whitelist_audit.fusion_weights == DEFAULT_FUSION_WEIGHTS
    assert cfg.whitelist_audit.use_heuristics is True
    assert cfg.whitelist_audit.feed_ttl_seconds >= 60
    assert cfg.cache.negative_ttl_seconds >= 0
    assert cfg.output.report_timestamp is False


# ── fusion/heuristic wiring ────────────────────────────────────────


def test_from_config_wires_fusion_weights_and_heuristics():
    cfg = MergeConfig()
    cfg.whitelist_audit.fusion_weights = {**DEFAULT_FUSION_WEIGHTS, "threat_intel": 77}
    cfg.whitelist_audit.use_heuristics = False
    engine = AsyncRuleEngine.from_config(cfg)
    assert engine.whitelist_audit_fusion_weights["threat_intel"] == 77
    assert engine.whitelist_audit_use_heuristics is False


# ── deterministic reports ──────────────────────────────────────────


def test_reports_are_byte_stable_without_timestamp(tmp_path):
    a = _run_once(tmp_path / "a", False)
    b = _run_once(tmp_path / "b", False)
    for key in ("html", "md", "stats"):
        assert a[key] == b[key], f"{key} not deterministic"
    # No wall-clock artifacts; content version is shown instead.
    assert "内容版本" in a["html"]
    assert "内容版本" in a["md"]
    assert not DATE_RE.search(a["html"]), "deterministic HTML must not embed a date"
    stats = json.loads(a["stats"])
    assert "elapsed_seconds" not in stats


def test_reports_include_runtime_when_requested(tmp_path):
    a = _run_once(tmp_path / "a", True)
    assert "内容版本" not in a["html"]
    assert DATE_RE.search(a["html"]), "timestamped HTML must embed a generation date"
    assert DATE_RE.search(a["md"])
    stats = json.loads(a["stats"])
    assert "elapsed_seconds" in stats


# ── cold vs warm cache determinism ─────────────────────────────────

_DET_FILES = ("merged_rules.txt", "whitelist.txt", "stats.json", "report.html", "report.md")


def _run_to_dir(base: Path, cache_dir: Path, src_path: Path, report_timestamp: bool):
    out_dir = base / "out"
    cache_dir.mkdir(parents=True, exist_ok=True)
    engine = AsyncRuleEngine(cache_dir=str(cache_dir))
    outcome = engine.run_sync([SourceMeta(name="s1", url=str(src_path), category="ads")])
    Exporter(
        str(out_dir),
        tiered=False,
        report=True,
        write_diff=False,
        whitelist_output=MergeConfig().whitelist_output,
        report_timestamp=report_timestamp,
    ).export_all(outcome.blocks, outcome.allows, outcome)
    return {name: (out_dir / name).read_bytes() for name in _DET_FILES}


def test_cold_and_warm_cache_runs_are_byte_identical(tmp_path):
    src_path = tmp_path / "source.txt"
    src_path.write_text(SRC_TEXT + "||extra.example.net^\n", encoding="utf-8")
    cache_dir = tmp_path / "cache"
    cold = _run_to_dir(tmp_path / "cold", cache_dir, src_path, False)
    warm = _run_to_dir(tmp_path / "warm", cache_dir, src_path, False)
    for name in _DET_FILES:
        assert cold[name] == warm[name], f"{name} differs between cold and warm cache runs"
    header = cold["merged_rules.txt"].decode("utf-8")
    assert "cached)" not in header, "cache-hit count must not enter the committed header"
    assert json.loads(cold["stats.json"].decode("utf-8"))["sources"]["cached"] is None


def test_cache_hits_are_reported_in_timestamp_mode(tmp_path):
    src_path = tmp_path / "source.txt"
    src_path.write_text(SRC_TEXT + "||extra.example.net^\n", encoding="utf-8")
    cache_dir = tmp_path / "cache"
    _run_to_dir(tmp_path / "cold", cache_dir, src_path, True)
    warm = _run_to_dir(tmp_path / "warm", cache_dir, src_path, True)
    assert "(1 cached)" in warm["merged_rules.txt"].decode("utf-8")
    assert json.loads(warm["stats.json"].decode("utf-8"))["sources"]["cached"] == 1


# ── CLI ────────────────────────────────────────────────────────────

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "8.0.1" in result.stdout
    assert "AdGuard-Rules-Merger/8" in result.stdout


def test_cli_validate_on_real_config():
    root = Path(__file__).resolve().parent.parent
    result = runner.invoke(app, ["validate", str(root / "config" / "sources.yaml")])
    assert result.exit_code == 0, result.stdout
    assert "18" in result.stdout


def test_cli_validate_json(tmp_path):
    src = _src(tmp_path)
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        f"output:\n  directory: {tmp_path / 'out'}\n"
        f"cache:\n  directory: {tmp_path / 'cache'}\n"
        f"sources:\n  - id: 1\n    url: {src}\n    name: X\n    category: ads\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["validate", str(cfg), "--json"])
    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["valid"] is True


def test_cli_sources_lists_rows():
    root = Path(__file__).resolve().parent.parent
    result = runner.invoke(app, ["sources", "--config", str(root / "config" / "sources.yaml")])
    assert result.exit_code == 0, result.stdout
    assert "AdGuard DNS filter" in result.stdout


def test_cli_cache_stats_on_empty(tmp_path):
    cfg = tmp_path / "c.yaml"
    cdir = tmp_path / "cache"
    cfg.write_text(f"cache:\n  directory: {cdir}\n", encoding="utf-8")
    result = runner.invoke(app, ["cache", "stats", "--config", str(cfg)])
    assert result.exit_code == 0, result.stdout
    assert "0" in result.stdout


def test_cli_validate_bad_config_exits_nonzero(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "sources:\n  - id: 1\n    url: ftp://x\n    name: x\n    category: ads\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["validate", str(bad)])
    assert result.exit_code == 1


# ── packaging / shims ──────────────────────────────────────────────


def test_shim_modules_reexport_public_api():
    import config_loader as shim

    assert shim.load_config is load_config
    assert shim.MergeConfig is MergeConfig

    import merge_rules as launcher

    assert launcher.app is app


def test_module_main_exists():
    import merger.__main__ as m

    assert hasattr(m, "app")


def test_console_script_ep_declared():
    pyproject = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "[project.scripts]" in pyproject
    assert 'adguard-rules-merger = "merger.cli:app"' in pyproject
