"""Tests for report/analysis.py helpers."""

from __future__ import annotations

from merger.report import analysis


def test_generation_label_deterministic():
    assert analysis._generation_label(False) == ""


def test_generation_label_with_time(monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    out = analysis._generation_label(True)
    assert out.startswith("2023-11-14")


def test_classify_rule():
    class R:
        normalized_domain = "example.com"
        wildcard = False
    assert analysis._classify_rule(R()) == "domain"
    R.wildcard = True
    assert analysis._classify_rule(R()) == "wildcard"
    R.wildcard = False
    R.normalized_domain = ""
    assert analysis._classify_rule(R()) == "regex"
    R.normalized_domain = "1.2.3.4"
    assert analysis._classify_rule(R()) == "ip"


def test_extract_suffix():
    assert analysis._extract_suffix("example.com") == "example.com"
    assert analysis._extract_suffix("co.uk") == "co.uk"
    assert analysis._extract_suffix("sub.example.com") == "example.com"
    assert analysis._extract_suffix("x") == "x"


def test_overlap_heat_color():
    assert analysis._overlap_heat_color(90) == "#f8d7da"
    assert analysis._overlap_heat_color(60) == "#fff3cd"
    assert analysis._overlap_heat_color(30) == "#d1ecf1"
    assert analysis._overlap_heat_color(5) == "#d4edda"


def test_dup_color():
    assert analysis._dup_color(10) == "#d9ead3"
    assert analysis._dup_color(30) == "#fff2cc"
    assert analysis._dup_color(60) == "#f9cb9c"
    assert analysis._dup_color(90) == "#e06666"


def test_dup_emoji():
    assert analysis._dup_emoji(10) == "🟩"
    assert analysis._dup_emoji(30) == "🟨"
    assert analysis._dup_emoji(60) == "🟧"
    assert analysis._dup_emoji(90) == "🟥"


def test_defense_layer_rows():
    rows = analysis._defense_layer_rows({"dns": True, "doh": False}, {"dns_nxdomain": 3})
    assert isinstance(rows, list)
    assert len(rows) == len(analysis.DEFENSE_LAYERS)
    assert rows[0]["enabled"] is True


def test_build_matrix_from_pairs():
    src = {
        "source_effective": {"a": 90, "b": 70},
        "pairs": [
            {"source_a": "a", "source_b": "b", "overlap": 20, "rate_a": 22.0, "rate_b": 18.0, "jaccard": 12.5},
        ],
    }
    m = analysis._build_matrix(src)
    assert m["order"] == ["a", "b"]
    cell = m["get"]("a", "b")
    assert cell["overlap"] == 20


def test_build_matrix_diagonal():
    src = {"source_effective": {"a": 90}, "pairs": []}
    m = analysis._build_matrix(src)
    assert m["get"]("a", "a") is None


def test_json_for_script_escapes_script_tag():
    out = analysis._json_for_script({"d": "x</script>"})
    assert "</" not in out


def test_modifier_total():
    assert analysis._modifier_total({"important": 3, "badfilter": 2}) == 5
