"""K-1: config rejects unknown YAML keys (typos fail fast)."""

import pytest
from pydantic import ValidationError

from merger.config import MergeConfig


def test_unknown_top_level_key_rejected():
    with pytest.raises(ValidationError):
        MergeConfig(us_dns=False, sources=[])


def test_unknown_source_key_rejected():
    bad = {
        "sources": [{"name": "x", "url": "https://e.com/a.txt", "category": "ads", "typo_key": 1}]
    }
    with pytest.raises(ValidationError):
        MergeConfig(**bad)
