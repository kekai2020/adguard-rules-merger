"""RDAP registration-age query wrapper (registered domain only).

Moved verbatim during the P1-3 package split.
"""

from __future__ import annotations

from typing import Any

from ..whois_audit import query_rdap
from .config import AuditConfig


async def _query_rdap_wrapper(domain: str, session, config: AuditConfig) -> dict[str, Any]:
    """RDAP query using registered domain (eTLD+1)."""
    try:
        from ..domain_classifier import registered_domain

        reg_domain = registered_domain(domain)
        return await query_rdap(
            reg_domain, session, threshold_days=config.new_domain_threshold_days
        )
    except Exception as e:
        return {"is_new_domain": False, "domain_age_days": None, "registrar": None, "error": str(e)}
