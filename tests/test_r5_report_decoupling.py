"""R5 report decoupling regression tests (fully offline, local file sources).

Guards the R5 boundary:
  - Exporter is write-only: it never calls ``analyze_rules`` or the HTML/Markdown
    generators itself; rendering lives in the independent ``render_reports``
    stage owned by orchestration (CLI).
  - The default Exporter path still produces byte-identical report.html /
    report.md (lazy default stage), so existing callers are unaffected.
  - ``_content_hash`` delegates to the single R1 ``compute_content_version``
    kernel instead of running its own duplicate sha-256 loop.

No network, no real cache/output directory; every case uses a local file
source through ``AsyncRuleEngine.run_sync``.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from merger import AsyncRuleEngine, Exporter
from merger.core.stages import compute_content_version
from merger.exporter import _content_hash, _content_hash_lines
from merger.models import SourceMeta
from merger.report import (
    analyze_rules,
    generate_html_report,
    generate_markdown_report,
    render_reports,
)

SRC_TEXT = (
    "||ads.example.com^\n"
    "||track.example.com^\n"
    "||ads.example.com^\n"
    "||child.ads.example.com^\n"
    "@@||cdn.example.com^\n"
    "0.0.0.0 host.example.com\n"
)


def _engine_outcome(tmp_path: Path):
    src = tmp_path / "source.txt"
    src.write_text(SRC_TEXT, encoding="utf-8")
    engine = AsyncRuleEngine(cache_dir=None)
    return engine.run_sync([SourceMeta(name="s1", url=str(src), category="ads")])


# ── default path still renders byte-identical reports ────────────────


def test_default_exporter_still_renders_reports_bytes(tmp_path):
    """No renderer injected: the lazy default stage must reproduce exactly what
    ``render_reports`` produces, byte for byte."""
    outcome = _engine_outcome(tmp_path)
    out_dir = tmp_path / "out"
    Exporter(str(out_dir), tiered=False, report=True, write_diff=False).export_all(
        outcome.blocks, outcome.allows, outcome
    )
    expected_html, expected_md = render_reports(
        outcome.blocks, outcome.allows, outcome, include_time=False
    )
    # Compare decoded text: write_text applies the platform newline translation,
    # which R5 does not alter; content equivalence is what must hold.
    assert (out_dir / "report.html").read_text(encoding="utf-8") == expected_html
    assert (out_dir / "report.md").read_text(encoding="utf-8") == expected_md
    # stats.json remains a valid machine-readable artifact on the default path.
    assert (out_dir / "stats.json").exists()


# ── injected renderer callback is used; builtin generation bypassed ───


def test_injected_renderer_callback_is_invoked(tmp_path):
    calls: list[tuple] = []

    def spy(blocks, allows, outcome, include_time=False):
        calls.append((blocks, allows, outcome, include_time))
        return "<spy-html/>", "<spy-md/>"

    outcome = _engine_outcome(tmp_path)
    out_dir = tmp_path / "out"
    Exporter(str(out_dir), tiered=False, report=True, write_diff=False, renderer=spy).export_all(
        outcome.blocks, outcome.allows, outcome
    )

    assert len(calls) == 1
    blocks, allows, received_outcome, include_time = calls[0]
    assert blocks is outcome.blocks
    assert allows is outcome.allows
    assert received_outcome is outcome
    assert include_time is False
    # The callback's bytes are what get written — builtin generators are not
    # invoked for this artifact.
    assert "<spy-html/>" == (out_dir / "report.html").read_text(encoding="utf-8")
    assert "<spy-md/>" == (out_dir / "report.md").read_text(encoding="utf-8")


# ── pre-rendered bytes are persisted verbatim; renderer not invoked ───


def test_prerendered_reports_written_verbatim(tmp_path):
    outcome = _engine_outcome(tmp_path)
    html, md = render_reports(outcome.blocks, outcome.allows, outcome, include_time=False)

    def must_not_be_called(*args, **kwargs):
        raise AssertionError("renderer must not run when reports are supplied")

    out_dir = tmp_path / "out"
    Exporter(
        str(out_dir),
        tiered=False,
        report=True,
        write_diff=False,
        renderer=must_not_be_called,
        reports=(html, md),
    ).export_all(outcome.blocks, outcome.allows, outcome)

    assert (out_dir / "report.html").read_text(encoding="utf-8") == html
    assert (out_dir / "report.md").read_text(encoding="utf-8") == md


# ── module-level import coupling removed ─────────────────────────────


def test_exporter_module_has_no_render_import_coupling():
    """``merger.exporter`` must not import analyze_rules / the generators at
    module scope; rendering is decoupled into the ``merger.report`` stage."""
    import merger.exporter as exporter_mod

    for symbol in ("analyze_rules", "generate_html_report", "generate_markdown_report"):
        assert symbol not in exporter_mod.__dict__, f"{symbol} leaked into exporter"

    source = inspect.getsource(exporter_mod)
    for line in source.splitlines():
        stripped = line.strip()
        # The lazy default binding inside write_report may import render_reports,
        # but there must be no top-level import of the analysis/generators.
        assert not stripped.startswith("from .report import analyze_rules")
        assert not stripped.startswith("from .report import generate_html_report")
        assert not stripped.startswith("from .report import generate_markdown_report")

    # The independent stage lives in the report package and is re-exported.
    assert callable(render_reports)
    assert render_reports.__module__ == "merger.report.render"


# ── _content_hash delegates to the single R1 kernel ──────────────────


def test_content_hash_delegates_to_compute_content_version(tmp_path):
    outcome = _engine_outcome(tmp_path)
    blocks, allows = outcome.blocks, outcome.allows

    assert _content_hash(blocks, allows) == compute_content_version(blocks, allows)
    # Whitelist-only / tiered fallback shapes used by the exporter.
    assert _content_hash([], allows) == compute_content_version([], allows)
    assert _content_hash(blocks, []) == compute_content_version(blocks, [])
    assert _content_hash([], []) == compute_content_version([], [])


def test_content_hash_lines_helper_unchanged():
    """The line-based graded-whitelist hash is a separate, untouched helper."""
    lines = ["@@||a.example.com^", "@@||b.example.com^"]
    digest = _content_hash_lines(lines)
    assert isinstance(digest, str) and len(digest) == 12
    # Deterministic over identical input.
    assert _content_hash_lines(lines) == digest


# ── render_reports stage wrapper is faithful to direct generators ────


def test_render_reports_matches_direct_generators(tmp_path):
    outcome = _engine_outcome(tmp_path)
    blocks, allows = outcome.blocks, outcome.allows

    stage_html, stage_md = render_reports(blocks, allows, outcome, include_time=False)
    analysis = analyze_rules(blocks, allows)
    direct_html = generate_html_report(blocks, allows, outcome, analysis, include_time=False)
    direct_md = generate_markdown_report(blocks, allows, outcome, analysis, include_time=False)

    assert stage_html == direct_html
    assert stage_md == direct_md

    # Timestamp forwarding honored.
    ts_html, ts_md = render_reports(blocks, allows, outcome, include_time=True)
    assert ts_html != stage_html
    assert ts_md != stage_md
