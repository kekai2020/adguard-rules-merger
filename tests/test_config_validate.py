"""V5.3 C12: validate_config semantic enhancement tests."""

from config_loader import validate_config


def _write_yaml(tmp_path, content):
    p = tmp_path / "test.yaml"
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_valid_config_no_problems(tmp_path):
    out_dir = str(tmp_path / "output").replace("\\", "/")
    cache_dir = str(tmp_path / "cache").replace("\\", "/")
    p = _write_yaml(
        tmp_path,
        f"""
output:
  directory: {out_dir}
cache:
  directory: {cache_dir}
sources:
  - id: 1
    url: https://example.com/list.txt
    name: Example
    category: ads
    enabled: true
""",
    )
    assert validate_config(p) == []


def test_duplicate_id_reported(tmp_path):
    p = _write_yaml(
        tmp_path,
        """
sources:
  - id: 99
    url: https://a.com/list.txt
    name: A
    category: ads
  - id: 99
    url: https://b.com/list.txt
    name: B
    category: ads
""",
    )
    problems = validate_config(p)
    assert any("duplicate" in p.lower() for p in problems)


def test_invalid_category_reported(tmp_path):
    p = _write_yaml(
        tmp_path,
        """
sources:
  - id: 101
    url: https://a.com/list.txt
    name: A
    category: badcat
""",
    )
    problems = validate_config(p)
    assert len(problems) >= 1


def test_no_enabled_sources_reported(tmp_path):
    p = _write_yaml(
        tmp_path,
        """
sources:
  - id: 102
    url: https://a.com/list.txt
    name: A
    category: ads
    enabled: false
""",
    )
    problems = validate_config(p)
    assert len(problems) >= 1


def test_fail_threshold_out_of_range(tmp_path):
    p = _write_yaml(
        tmp_path,
        """
fail_threshold: 1.5
sources:
  - id: 103
    url: https://a.com/list.txt
    name: A
    category: ads
""",
    )
    problems = validate_config(p)
    assert len(problems) >= 1


def test_missing_file_reported(tmp_path):
    problems = validate_config(str(tmp_path / "nonexistent.yaml"))
    assert len(problems) >= 1


def test_validate_does_not_create_directories(tmp_path):
    """Read-only pre-flight (audit P2): validate must not mkdir output/cache.

    Merge creates and validates them for real; a validate run — especially
    with --json in CI — must stay side-effect-free for missing directories.
    """
    out = tmp_path / "out_missing"
    cache = tmp_path / "cache_missing"
    p = _write_yaml(
        tmp_path,
        f"""
output:
  directory: {out.as_posix()}
cache:
  directory: {cache.as_posix()}
sources:
  - id: 1
    url: https://example.com/list.txt
    name: Example
    category: ads
""",
    )
    assert validate_config(p) == []
    assert not out.exists()
    assert not cache.exists()


def test_validate_existing_writable_dir_no_problems(tmp_path):
    """An EXISTING writable directory still passes the probe unchanged."""
    d = tmp_path / "out_existing"
    d.mkdir()
    p = _write_yaml(
        tmp_path,
        f"""
output:
  directory: {d.as_posix()}
sources:
  - id: 1
    url: https://example.com/list.txt
    name: Example
    category: ads
""",
    )
    assert validate_config(str(p)) == []
