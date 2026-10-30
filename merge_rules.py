#!/usr/bin/env python3
"""Backward-compatible launcher (pre-V7 entry point).

The CLI moved into the package in V7: :mod:`merger.cli`. This module keeps the
documented invocation ``python merge_rules.py merge --config ...`` working and
delegates everything to the package command. The preferred entry points are:

    uv run adguard-rules-merger ...      # console script
    uv run python -m merger ...          # module form
"""

from __future__ import annotations

from merger.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
