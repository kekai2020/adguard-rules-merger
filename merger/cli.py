"""V8 command line interface.

This is the package-native entry point, exposed as the ``adguard-rules-merger``
console script and runnable via ``python -m merger``. The top-level
``merge_rules.py`` is a thin backward-compatible launcher that calls
:func:`app`.

Commands:
  merge      Fetch, merge, and write subscription files (default command)
  validate   Validate a YAML config without touching the network
  version    Print the version
  sources    List configured sources (id, category, status, URL)
  cache      Manage the local source cache (stats / clear)
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import typer

from . import __version__, __version_short__, user_agent
from .cache import SourceCache
from .config import (
    load_config,
    resolve_api_keys,
    validate_config,
)
from .core import AsyncRuleEngine
from .exporter import Exporter
from .models import SourceMeta
from .report import render_reports

logger = logging.getLogger("adguard_merger")


def _force_utf8_stdio() -> None:
    """Reconfigure stdout/stderr to UTF-8 so ``✓/✗`` survive a cp936 console.

    On Windows the default console codepage (e.g. cp936/GBK) cannot encode
    the ``✓``/``✗`` glyphs used by :func:`typer.secho`, which previously
    raised ``UnicodeEncodeError`` on every ``merge``/``validate`` run.
    Reconfiguring the streams (safe no-op for StringIO / non-reconfigurable
    streams) keeps the glyphs intact without changing program logic.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            from typing import TextIO, cast

            cast(TextIO, stream).reconfigure(encoding="utf-8", errors="backslashreplace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass


# Release-package alias for the same UTF-8 stdio guard (cross-version test
# compatibility); the entry point below calls _force_utf8_stdio().
_reconfigure_stdio_utf8 = _force_utf8_stdio


_force_utf8_stdio()

app = typer.Typer(
    add_completion=False,
    help="AdGuard Rules Merger — download, merge, deduplicate, and publish "
    "AdGuard Home filter rules.",
    no_args_is_help=True,
)
cache_app = typer.Typer(no_args_is_help=True, help="Inspect or prune the local source cache.")
app.add_typer(cache_app, name="cache")


def _setup_logging(verbose: bool, quiet: bool) -> None:
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )


@app.command()
def merge(
    config: Path = typer.Option(
        Path("config/sources.yaml"), "--config", "-c", help="Path to the YAML source config."
    ),
    output_dir: str | None = typer.Option(
        None, "--output", "-o", help="Override output directory."
    ),
    cache_dir: str | None = typer.Option(None, "--cache-dir", help="Override cache directory."),
    timeout: int | None = typer.Option(
        None, "--timeout", help="Override per-source timeout (seconds)."
    ),
    concurrency: int | None = typer.Option(
        None, "--concurrency", help="Override max concurrent downloads."
    ),
    no_audit: bool = typer.Option(
        False, "--no-audit", help="Skip the whitelist multi-layer audit."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug logging."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Errors only."),
) -> None:
    """Fetch, merge, and write all subscription files."""
    _setup_logging(verbose, quiet)
    try:
        cfg = load_config(str(config))
    except Exception as e:
        typer.secho(f"✗ Failed to load config: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    cfg = resolve_api_keys(cfg)
    if no_audit:
        cfg.whitelist_audit.enabled = False

    if output_dir:
        cfg.output.directory = output_dir
    if cache_dir:
        cfg.cache.directory = cache_dir
    if timeout is not None:
        cfg.timeout = timeout
    if concurrency is not None:
        cfg.max_concurrency = concurrency

    Path(cfg.output.directory).mkdir(parents=True, exist_ok=True)
    if cfg.cache.enabled:
        Path(cfg.cache.directory).mkdir(parents=True, exist_ok=True)

    typer.secho(f"AdGuard Rules Merger V{__version_short__}", fg=typer.colors.CYAN, bold=True)
    typer.secho(f"User-Agent: {user_agent()}", fg=typer.colors.BRIGHT_BLACK)
    enabled = [s for s in cfg.sources if s.enabled]
    typer.secho(f"Enabled sources: {len(enabled)} / {len(cfg.sources)}", fg=typer.colors.CYAN)
    if cfg.whitelist_audit.enabled:
        typer.secho("Whitelist audit: enabled (multi-layer)", fg=typer.colors.YELLOW)
    else:
        typer.secho("Whitelist audit: disabled", fg=typer.colors.BRIGHT_BLACK)

    sources = [
        SourceMeta(name=s.name, url=s.url, category=s.category, enabled=s.enabled, id=s.id)
        for s in cfg.sources
    ]

    engine = AsyncRuleEngine.from_config(cfg)
    try:
        outcome = engine.run_sync(sources)
    except (RuntimeError, ValueError, OSError) as e:
        typer.secho(f"✗ Merge aborted: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)

    # CLI informational banner only — never written into the artifact headers.
    if outcome.failed_sources:
        typer.secho(f"\n✗ {len(outcome.failed_sources)} source(s) failed:", fg=typer.colors.RED)
        for fs in outcome.failed_sources:
            typer.secho(f"  ✗ {fs['name']}: {fs['error']}", fg=typer.colors.RED)

    # R5 independent render stage: orchestration renders HTML/Markdown from the
    # engine outcome, and hands finished bytes to the write-only Exporter. The
    # exporter never calls analyze_rules or the HTML/Markdown generators.
    reports = None
    if cfg.output.report:
        reports = render_reports(
            outcome.blocks,
            outcome.allows,
            outcome,
            include_time=cfg.output.report_timestamp,
        )

    exporter = Exporter(
        cfg.output.directory,
        formats=cfg.output.formats,
        tiered=cfg.output.tiered,
        report=cfg.output.report,
        write_diff=cfg.output.write_diff,
        whitelist_output=cfg.whitelist_output,
        report_timestamp=cfg.output.report_timestamp,
        reports=reports,
    )
    exporter.export_all(outcome.blocks, outcome.allows, outcome)

    typer.secho(
        f"\n✓ Done: {len(outcome.blocks):,} block + {len(outcome.allows):,} allow "
        f"rules in {outcome.elapsed:.1f}s",
        fg=typer.colors.GREEN,
        bold=True,
    )
    if outcome.aggregated + outcome.wildcard_aggregated + outcome.wildcard_promoted > 0:
        typer.secho(
            f"  Aggregated: {outcome.aggregated:,} exact + "
            f"{outcome.wildcard_aggregated:,} wildcard + "
            f"{outcome.wildcard_promoted:,} promoted",
            fg=typer.colors.BRIGHT_BLACK,
        )
    if outcome.conflict_resolved:
        typer.secho(
            f"  Conflicts resolved: {outcome.conflict_resolved:,}", fg=typer.colors.BRIGHT_BLACK
        )
    typer.secho(f"✓ Output: {cfg.output.directory}/", fg=typer.colors.GREEN)


@app.command()
def validate(
    config: Path = typer.Argument(
        Path("config/sources.yaml"), help="Path to the YAML source config."
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Validate a config file and report any problems."""
    problems = validate_config(str(config))
    if json_output:
        typer.echo(
            json.dumps({"valid": not problems, "problems": problems}, ensure_ascii=False, indent=2)
        )
        raise typer.Exit(0 if not problems else 1)
    if problems:
        typer.secho(f"✗ Found {len(problems)} problem(s):", fg=typer.colors.RED)
        for p in problems:
            typer.secho(f"  ✗ {p}", fg=typer.colors.RED)
        raise typer.Exit(1)
    try:
        cfg = load_config(str(config))
    except Exception as e:  # defensive; validate_config already covered this
        typer.secho(f"✗ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)
    enabled = sum(1 for s in cfg.sources if s.enabled)
    cats: dict[str, int] = {}
    for s in cfg.sources:
        if s.enabled:
            cats[s.category] = cats.get(s.category, 0) + 1
    typer.secho("✓ Valid config", fg=typer.colors.GREEN, bold=True)
    typer.secho(f"  Sources: {enabled} enabled / {len(cfg.sources)} total")
    typer.secho(f"  Categories: {cats}")
    typer.secho(f"  Output: {cfg.output.directory} | Cache: {cfg.cache.directory}")


@app.command()
def version() -> None:
    """Print the AdGuard Rules Merger version."""
    typer.echo(f"AdGuard Rules Merger v{__version__}")
    typer.echo(f"User-Agent: {user_agent()}")


@app.command()
def sources(
    config: Path = typer.Option(
        Path("config/sources.yaml"), "--config", "-c", help="Path to the YAML config."
    ),
    include_disabled: bool = typer.Option(False, "--all", help="Include disabled sources."),
) -> None:
    """List configured sources with their category and status."""
    try:
        cfg = load_config(str(config))
    except Exception as e:
        typer.secho(f"✗ Failed to load config: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    rows = cfg.sources if include_disabled else [s for s in cfg.sources if s.enabled]
    typer.secho(f"{'ID':>3}  {'状态':<4} {'分类':<9} 名称")
    typer.secho("-" * 72)
    for s in sorted(rows, key=lambda x: x.id):
        status = "启用" if s.enabled else "停用"
        typer.secho(f"{s.id:>3}  {status:<4} {s.category:<9} {s.name}")
    typer.secho("-" * 72)
    typer.secho(f"{len(rows)} source(s) shown.", fg=typer.colors.CYAN)


def _resolve_cache_dir(config: Path) -> Path:
    try:
        cfg = load_config(str(config))
        return Path(cfg.cache.directory)
    except Exception:
        return Path("cache")


@cache_app.command("stats")
def cache_stats(
    config: Path = typer.Option(
        Path("config/sources.yaml"), "--config", "-c", help="Path to the YAML config."
    ),
) -> None:
    """Show cache disk usage and the number of cached source entries."""
    cdir = _resolve_cache_dir(config)
    if not cdir.exists():
        typer.secho(f"Cache directory not found: {cdir}", fg=typer.colors.YELLOW)
        raise typer.Exit(0)
    try:
        stats = SourceCache(str(cdir)).stats()
    except Exception as e:
        typer.secho(f"✗ Unable to read cache: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    typer.secho(f"Cache directory: {cdir}")
    typer.secho(f"Cached source entries: {stats['entry_count']}")
    typer.secho(f"Disk usage: {stats['total_size_mb']:.2f} MB")


@cache_app.command("clear")
def cache_clear(
    config: Path = typer.Option(
        Path("config/sources.yaml"), "--config", "-c", help="Path to the YAML config."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not prompt."),
) -> None:
    """Delete all cached source bodies (the next run refetches everything)."""
    cdir = _resolve_cache_dir(config)
    if not cdir.exists():
        typer.secho(f"Cache directory not found: {cdir}", fg=typer.colors.YELLOW)
        raise typer.Exit(0)
    if not yes:
        confirm = typer.confirm(f"Delete everything under {cdir}?", default=False)
        if not confirm:
            typer.secho("Aborted.", fg=typer.colors.YELLOW)
            raise typer.Exit(0)
    try:
        SourceCache(str(cdir)).clear()
    except Exception as e:
        typer.secho(f"✗ Unable to clear cache: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    typer.secho(f"✓ Cleared cache at {cdir}", fg=typer.colors.GREEN)


if __name__ == "__main__":
    app()
