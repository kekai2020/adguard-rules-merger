"""AdGuard Rules Merger - A tool for merging and deduplicating AdGuard filter rules."""

from .core import RuleEngine
from .models import Rule
from .parser import RuleParser

__version__ = "0.1.0"
__all__ = ["RuleEngine", "Rule", "RuleParser"]