"""C-1: CLI must not crash on a GBK console when printing Unicode glyphs."""

import io

import merger.cli as cli


def test_reconfigure_stdio_idempotent_no_crash(monkeypatch):
    buf = io.TextIOWrapper(io.BytesIO(), encoding="cp936", errors="strict")
    monkeypatch.setattr(cli.sys, "stdout", buf)
    monkeypatch.setattr(cli.sys, "stderr", buf)
    cli._reconfigure_stdio_utf8()  # must not raise
    # printing a U+2713 glyph now uses errors="replace", never UnicodeEncodeError
    buf.write("✓ done\n")
    buf.flush()
