"""KB syntax probe: parse each annotated golden case and report classification.

Usage: python scripts/probe_kb_syntax.py
Prints a table: line | expected | actual | match?
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from merger.parser import RuleParser

CASES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "kb_syntax_cases.txt"


def classify(text: str):
    p = RuleParser()
    rules = p.parse_text(text, source="s", category="ads")
    if p.comment_dropped:
        return ("comment", "", "")
    if p.css_dropped:
        return ("css", "", "")
    if p.unrecognized_dropped:
        return ("unrecognized", "", "")
    if not rules:
        return ("none", "", "")
    r = rules[0]
    return (r.rule_type, r.normalized_domain, r.modifiers)


def main():
    for raw in CASES.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "# exp:" in raw:
            line, exp = raw.split("# exp:", 1)
            exp = exp.strip()
        else:
            line, exp = raw, "?"
        kind, dom, mod = classify(line.strip())
        print(f"{line.strip():38s} exp={exp:28s} got={kind}/{dom}/{mod}")


if __name__ == "__main__":
    main()
