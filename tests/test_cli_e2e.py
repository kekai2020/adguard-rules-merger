"""P1-5: offline CLI end-to-end tests driven by ``typer.testing.CliRunner``.

Every case runs against ``merger.cli.app`` with temporary local files only;
no real network access, no real cache/ or output/ directory.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from merger.cli import app

runner = CliRunner()


# ── version ────────────────────────────────────────────────────────────


def test_version_command_reports_800_and_ua():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0, result.output
    assert "8.0.1" in result.output
    # User-Agent advertised on fetches (version.short derived from version.py).
    assert "AdGuard-Rules-Merger" in result.output


# ── validate ───────────────────────────────────────────────────────────


def _write_yaml(tmp_path: Path, body: str) -> str:
    p = tmp_path / "config.yaml"
    p.write_text(body, encoding="utf-8")
    return str(p)


def test_validate_accepts_valid_local_config(tmp_path: Path):
    src = tmp_path / "list.txt"
    src.write_text("||ads.example.com^\n", encoding="utf-8")
    cfg = _write_yaml(
        tmp_path,
        f"""
output:
  directory: {str(tmp_path / "out").replace(chr(92), "/")}
cache:
  directory: {str(tmp_path / "cache").replace(chr(92), "/")}
sources:
  - id: 1
    url: {str(src).replace(chr(92), "/")}
    name: Local
    category: ads
    enabled: true
""",
    )
    result = runner.invoke(app, ["validate", cfg])
    assert result.exit_code == 0, result.output


def test_validate_rejects_bad_category(tmp_path: Path):
    cfg = _write_yaml(
        tmp_path,
        """
sources:
  - id: 1
    url: https://example.com/list.txt
    name: X
    category: not-a-category
""",
    )
    result = runner.invoke(app, ["validate", cfg])
    assert result.exit_code != 0, result.output


def test_validate_rejects_missing_file(tmp_path: Path):
    result = runner.invoke(app, ["validate", str(tmp_path / "nope.yaml")])
    assert result.exit_code != 0, result.output


# ── merge (fully offline, local file sources, --no-audit) ───────────────


def test_merge_runs_offline_pipeline_and_writes_outputs(tmp_path: Path):
    src = tmp_path / "list.txt"
    src.write_text(
        "||ads.example.com^\n||track.example.com^\n||ads.example.com^\n@@||allow.example.com^\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    cache_dir = tmp_path / "cache"
    cfg = _write_yaml(
        tmp_path,
        f"""
output:
  directory: {str(out_dir).replace(chr(92), "/")}
cache:
  directory: {str(cache_dir).replace(chr(92), "/")}
sources:
  - id: 1
    url: {str(src).replace(chr(92), "/")}
    name: Local
    category: ads
    enabled: true
""",
    )

    result = runner.invoke(
        app,
        [
            "merge",
            "--config",
            cfg,
            "--no-audit",
            "--output",
            str(out_dir),
            "--cache-dir",
            str(cache_dir),
        ],
    )
    assert result.exit_code == 0, result.output

    # Key artifacts exist; the local block rule survived the offline pipeline.
    assert (out_dir / "merged_rules.txt").exists(), "merged_rules.txt missing"
    merged = (out_dir / "merged_rules.txt").read_text(encoding="utf-8")
    assert "ads.example.com" in merged
    # The allow rule was exported to the whitelist tier, not dropped.
    whitelist = (out_dir / "whitelist.txt").read_text(encoding="utf-8")
    assert "allow.example.com" in whitelist
    # Report artifacts are produced by the default report-enabled run.
    assert (out_dir / "report.html").exists(), "report.html missing"
    assert (out_dir / "report.md").exists(), "report.md missing"
