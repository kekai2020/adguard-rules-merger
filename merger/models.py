"""Data models for AdGuard rules."""

from dataclasses import dataclass, field
from typing import Optional
import re


@dataclass(slots=True)
class Rule:
    """Represents a single AdGuard filter rule."""
    
    raw: str  # Original line from source
    domain: str  # Normalized domain (without wildcards)
    type: str  # Type: 'block', 'allow', 'comment'
    wildcard: bool  # Whether rule contains wildcards
    source: str  # Source identifier
    _normalized_domain: str = field(init=False, repr=False, compare=False)
    
    def __post_init__(self):
        """Validate and normalize the rule after creation."""
        # Normalize domain by removing wildcard prefix and converting to lowercase
        normalized = self.domain.lower()
        if normalized.startswith('*.'):
            object.__setattr__(self, '_normalized_domain', normalized[2:])
        else:
            object.__setattr__(self, '_normalized_domain', normalized)
    
    @property
    def normalized_domain(self) -> str:
        """Get normalized domain for comparison (without wildcard prefix)."""
        return self._normalized_domain
    
    def is_equivalent_to(self, other: 'Rule') -> bool:
        """
        Check if two rules are equivalent for deduplication purposes.
        
        Rules are equivalent if they have the same normalized domain and type.
        For example: *.example.com and example.com are equivalent.
        """
        if not isinstance(other, Rule):
            return False
        
        return (self.normalized_domain == other.normalized_domain and 
                self.type == other.type)
    
    def is_subdomain_of(self, other: 'Rule') -> bool:
        """
        Check if this rule's domain is a subdomain of another rule's domain.
        
        This is used for wildcard optimization - if we have *.example.com,
        we don't need ads.example.com.
        """
        if not isinstance(other, Rule):
            return False
        
        # Only check subdomain relationship for block/allow rules
        if self.type not in ['block', 'allow'] or other.type not in ['block', 'allow']:
            return False
        
        # If other rule has wildcard, check if our domain is a subdomain
        if other.wildcard:
            other_domain = other.normalized_domain
            our_domain = self.normalized_domain
            
            # Check if our domain ends with the other domain
            # e.g., ads.example.com ends with example.com
            return our_domain.endswith('.' + other_domain) or our_domain == other_domain
        
        return False
    
    def __str__(self) -> str:
        """Return the original raw rule."""
        return self.raw
    
    def __hash__(self) -> int:
        """Make Rule hashable for use in sets."""
        return hash((self.normalized_domain, self.type))
    
    def __eq__(self, other: object) -> bool:
        """Check equality based on normalized domain and type."""
        if not isinstance(other, Rule):
            return False
        return self.is_equivalent_to(other)
