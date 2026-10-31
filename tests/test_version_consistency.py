"""Version single-source-of-truth guard (M0).

Pins the semver version and scans the static version points that cannot be
derived at runtime (pyproject metadata, README badge, CI cache key) for stale
fragments. Docstrings / CHANGELOG prose that mention older versions as a
*feature* reference (not a version point) are deliberately not scanned.
"""

from pathlib import Path

from merger import __version__, __version_short__, user_agent

ROOT = Path(__file__).resolve().parent.parent


def test_version_is_8_0_1():
    assert __version__ == "8.0.1"


def test_version_short_is_8_0():
    assert __version_short__ == "8"


def test_user_agent_tracks_version():
    assert user_agent() == "AdGuard-Rules-Merger/8"
    assert user_agent() == f"AdGuard-Rules-Merger/{__version_short__}"


def test_pyproject_version_aligned():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "8.0.1"' in text
    assert "6.1.0" not in text
    assert "5.2.0" not in text


def test_pyproject_exposes_console_script():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "adguard-rules-merger" in text
    assert "merger.cli:app" in text


def test_readme_badge_aligned():
    text = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Version-8.0.1-blue" in text
    assert "Version-6.1.0-blue" not in text
    assert "Version-5.3.0-blue" not in text


def test_ci_cache_key_and_name_aligned():
    text = (ROOT / ".github" / "workflows" / "merge.yml").read_text(encoding="utf-8")
    assert "Merge Rules (V8)" in text
    assert "rule-cache-v8-" in text
    assert "Merge Rules (V6)" not in text
    assert "rule-cache-v6-" not in text
    assert "rule-cache-v51" not in text
    assert "Merge Rules (V5.1)" not in text
    # The merge job greps the produced rule file for the version label in its
    # title; the exporter's label and this CI assertion must stay in lockstep.
    assert "grep -q '(V8)' output/merged_rules.txt" in text
    assert "(V7)" not in text
    # The uploaded-artifact name must carry the V8 label too; a stale `v7`
    # artifact name is exactly the class of V7 residue the guard exists to catch.
    assert "merged-rules-v8" in text
    assert "merged-rules-v7" not in text


def test_exported_titles_are_v8():
    # The exporter and both report renderers embed the version label directly in
    # their output. CI greps for the merged_rules.txt title, so keep these in
    # sync with the exporter label and the workflow assertion above.
    exporter = (ROOT / "merger" / "exporter.py").read_text(encoding="utf-8")
    assert "Merged AdGuard Home Filter Rules (V8)" in exporter
    assert "Whitelist for Merged Rules (V8)" in exporter
    assert "AdGuard Rules Merger V8" in exporter
    html = (ROOT / "merger" / "report" / "html.py").read_text(encoding="utf-8")
    assert "AdGuard Rules Merger V8" in html
    md = (ROOT / "merger" / "report" / "markdown.py").read_text(encoding="utf-8")
    assert "AdGuard Rules Merger V8" in md
    # No residual V7 labels in generated-output code paths.
    assert "(V7)" not in exporter
    assert "(V7)" not in html
    assert "(V7)" not in md


def test_sources_yaml_no_hardcoded_user_agent():
    text = (ROOT / "config" / "sources.yaml").read_text(encoding="utf-8")
    assert "AdGuard-Rules-Merger/5.2" not in text
    assert "AdGuard-Rules-Merger/6.1" not in text
    assert "user_agent:" not in text


def test_homepage_points_at_v8():
    from merger.config import HOMEPAGE
    from merger.exporter import HOMEPAGE as EXPORTER_HOMEPAGE

    assert HOMEPAGE.endswith("adguard-rules-merger-v8")
    assert EXPORTER_HOMEPAGE == HOMEPAGE


def test_dockerfile_version_aligned():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "8.0.1" in text
    # Development-iteration numbers (8.1/8.2/8.3) must not leak into metadata;
    # 8.0.1 is the current public release number (see CHANGELOG 8.0.1).
    assert "8.1.0" not in text
    assert "8.2.0" not in text
    assert "8.3.0" not in text


def test_readme_repo_urls_point_at_v8():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "# AdGuard Rules Merger V8" in text
    # Clone / badge / subscription raw URLs must reference the v8 repository.
    assert "adguard-rules-merger-v7" not in text
    assert "adguard-rules-merger-v8" in text


def test_pyproject_packages_cover_all_subpackages():
    # v8.2 split domain_classifier into a sub-package but forgot to ship it in
    # [tool.setuptools] packages, so installed wheels crashed on ``merge``
    # while CI (which only ran ``version``) stayed green. Guard every actual
    # sub-package on disk against the packaging list.
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    subpackages = [
        p.name for p in (ROOT / "merger").iterdir() if p.is_dir() and (p / "__init__.py").exists()
    ]
    assert subpackages, "expected at least one merger sub-package on disk"
    for name in subpackages:
        assert f'"merger.{name}"' in text, (
            f"subpackage merger.{name} missing from [tool.setuptools] packages"
        )
