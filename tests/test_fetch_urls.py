"""Tests for fetch.py file:// URL handling and cache paths."""

from __future__ import annotations

from merger.core.fetch import _file_url_to_path


def test_file_url_posix():
    assert _file_url_to_path("file:///etc/hosts") == "/etc/hosts"


def test_file_url_windows_drive():
    # file:///C:/x -> /C:/x (stripped to C:/x on Path())
    out = _file_url_to_path("file:///C:/x/rules.txt")
    assert "C:" in out or out.endswith("x/rules.txt")


def test_file_url_non_http():
    assert _file_url_to_path("https://example.com/rules.txt") is None


def test_file_url_empty():
    assert _file_url_to_path("") is None
