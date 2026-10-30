"""Runtime seam: resolve a layer callable from the package namespace at call time.

After the flat ``whitelist_audit`` module was split into submodules, a callable
referenced as a submodule global no longer sees a ``monkeypatch.setattr(package,
name, fake)`` applied to the package attribute. Resolving through the package
namespace at call time keeps those test seams working; when unpatched the
attribute holds the very same function, so production behaviour is identical.
"""

from __future__ import annotations

import sys
from typing import Any


def resolve(name: str) -> Any:
    """Look up ``name`` on the ``merger.whitelist_audit`` package at call time."""
    pkg = sys.modules[__package__]
    return getattr(pkg, name)
