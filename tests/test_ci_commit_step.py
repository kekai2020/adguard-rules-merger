"""CI commit-step regression guard.

Two things are pinned here:

1. The git sequence that publishes output/ lives in scripts/commit_output.py and
   is exercised against a FAKE git runner (no real repo touched) across the
   success / no-change / retry-then-success / all-attempts-exhausted paths.
2. A workflow-lint assertion: the "Commit subscription files" step in
   .github/workflows/merge.yml must NEVER use ``git pull --rebase``. output/ is
   fully regenerated every run, so rebasing is both meaningless and
   conflict-prone (two merge runs 18 min apart raced and the rebase collided
   with the different output/ the first run had already pushed). The step must
   soft-reset onto origin/main instead.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "merge.yml"
COMMIT_SCRIPT = ROOT / "scripts" / "commit_output.py"


def _load_commit_module():
    """Load scripts/commit_output.py by path (scripts/ is not an installed package)."""
    spec = importlib.util.spec_from_file_location("commit_output", COMMIT_SCRIPT)
    assert spec and spec.loader, f"cannot load {COMMIT_SCRIPT}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


commit_output_mod = _load_commit_module()
commit_output = commit_output_mod.commit_output
NoChanges = commit_output_mod.NoChanges


class FakeGit:
    """Programmable fake git runner.

    ``push_fails_until`` makes the first N pushes fail (exit 1) and subsequent
    ones succeed — this models origin/main moving between our fetch and push.
    ``no_changes`` makes ``git diff --cached --quiet`` exit 0 (nothing staged).
    """

    def __init__(self, *, push_fails_until: int = 0, no_changes: bool = False):
        self.push_fails_until = push_fails_until
        self.no_changes = no_changes
        self.calls: list[list[str]] = []
        self.push_count = 0
        self.sleeps: list[float] = []

    def run(self, args: list[str]) -> int:
        self.calls.append(list(args))
        cmd = args[1] if len(args) > 1 else ""
        if cmd == "push":
            self.push_count += 1
            return 1 if self.push_count <= self.push_fails_until else 0
        if cmd == "diff":
            # `git diff --quiet` exits 0 when there are NO changes, 1 when there ARE.
            return 0 if self.no_changes else 1
        return 0

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)

    def ran(self, *fragments: str) -> bool:
        return any(all(f in c for f in fragments) for c in self.calls)

    def command_order(self) -> list[str]:
        return [c[1] if len(c) > 1 else "" for c in self.calls]


def test_success_first_try():
    g = FakeGit()
    ok = commit_output(
        output_dir="output",
        message="msg",
        sleep=g.sleep,
        run=g.run,
        output=lambda *_: None,
    )
    assert ok is True
    # Soft-reset path, never a rebase.
    assert g.ran("reset", "--soft", "origin/main")
    assert not g.ran("pull", "--rebase")
    assert g.ran("push", "origin", "main")
    assert g.push_count == 1
    assert g.sleeps == []  # no retry -> no sleep


def test_no_changes_raises_and_skips_commit():
    g = FakeGit(no_changes=True)
    with pytest.raises(NoChanges):
        commit_output(
            output_dir="output",
            message="msg",
            sleep=g.sleep,
            run=g.run,
            output=lambda *_: None,
        )
    # We fetched + reset + staged, but never committed or pushed.
    assert g.ran("diff", "--cached", "--quiet")
    assert not g.ran("commit")
    assert not g.ran("push")


def test_retry_then_success_after_origin_moves():
    # First push fails (origin moved), second succeeds.
    g = FakeGit(push_fails_until=1)
    ok = commit_output(
        output_dir="output",
        message="msg",
        sleep=g.sleep,
        run=g.run,
        output=lambda *_: None,
    )
    assert ok is True
    assert g.push_count == 2
    # Two soft resets (one per attempt) — rebuilt on the NEW origin/main.
    assert g.command_order().count("reset") == 2
    assert not g.ran("pull", "--rebase")
    assert g.sleeps == [5.0]  # one backoff between attempts


def test_all_attempts_exhausted_returns_false():
    g = FakeGit(push_fails_until=99)  # never succeeds
    ok = commit_output(
        output_dir="output",
        message="msg",
        attempts=3,
        sleep=g.sleep,
        run=g.run,
        output=lambda *_: None,
    )
    assert ok is False
    assert g.push_count == 3
    assert g.sleeps == [5.0, 5.0, 5.0]


def test_rebase_is_never_invoked_even_on_retries():
    # The whole point of the rewrite: no code path may call pull --rebase.
    g = FakeGit(push_fails_until=2)
    commit_output(
        output_dir="output",
        message="msg",
        attempts=3,
        sleep=g.sleep,
        run=g.run,
        output=lambda *_: None,
    )
    assert not g.ran("pull", "--rebase")


def test_default_message_summarises_stats(tmp_path: Path):
    import json

    stats = tmp_path / "stats.json"
    stats.write_text(
        json.dumps({"rules": {"block": 2552093, "allow": 304}}), encoding="utf-8"
    )
    msg = commit_output_mod._default_message(tmp_path)
    assert "block=2,552,093" in msg
    assert "allow=304" in msg
    assert msg.startswith("Auto-merge: update rules")


def test_workflow_commit_step_never_rebases():
    """Workflow-lint: the commit step must delegate to the script, never rebase."""
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("Commit subscription files")
    # The step runs until the next top-level "- name:" step.
    nxt = text.find("\n      - name:", start + 1)
    step = text[start : nxt if nxt != -1 else len(text)]
    # Comments may mention the old approach; executable lines must not rebase.
    code = "\n".join(
        ln for ln in step.splitlines() if not ln.strip().startswith("#")
    )
    assert "pull --rebase" not in code, (
        "commit step regressed to git pull --rebase — this raced two merge runs "
        "and failed the job; keep the soft-reset-onto-origin/main approach"
    )
    assert "scripts/commit_output.py" in code


def test_commit_script_uses_soft_reset_not_rebase():
    """The script that owns the git sequence must soft-reset, never pull --rebase."""
    src = COMMIT_SCRIPT.read_text(encoding="utf-8")
    # The module docstring documents the historical pull --rebase failure, so we
    # assert on the actual dangerous invocation (a git pull --rebase call), not
    # on the bare words appearing anywhere in prose.
    assert '["git", "pull"' not in src, (
        "commit_output.py regressed to git pull — pull --rebase raced two merge "
        "runs and failed the job; the soft-reset approach is conflict-free"
    )
    assert '["git", "reset", "--soft"' in src
    assert '["git", "fetch"' in src


def test_workflow_commit_step_invokes_script():
    """The workflow should delegate to scripts/commit_output.py (tested above)."""
    text = WORKFLOW.read_text(encoding="utf-8")
    start = text.index("Commit subscription files")
    nxt = text.find("\n      - name:", start + 1)
    step = text[start : nxt if nxt != -1 else len(text)]
    assert "scripts/commit_output.py" in step
