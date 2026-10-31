"""Portable DNS resolution via dnspython (V5.3).

Replaces the getaddrinfo + glibc-string-matching approach in
whitelist_audit._dns_check with dnspython's explicit rcode handling,
which works identically on glibc / musl / Windows. When dnspython is
not installed, falls back to getaddrinfo with best-effort NXDOMAIN
detection (platform-dependent strings).
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

logger = logging.getLogger(__name__)

_DNS_AVAILABLE = False
try:
    import dns.exception
    import dns.resolver

    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    logger.warning(
        "dnspython not installed; DnsChecker falls back to getaddrinfo "
        "(NXDOMAIN detection will be best-effort)"
    )


class _Nxdomain(Exception):
    pass


class _Servfail(Exception):
    pass


class _Timeout(Exception):
    pass


class DnsChecker:
    """Portable async DNS resolver with explicit NXDOMAIN detection.

    Uses dnspython when available (explicit rcode, no string matching).
    Falls back to getaddrinfo when dnspython is missing.
    """

    def __init__(
        self,
        resolvers: list[str] | None = None,
        timeout: float = 5.0,
        force_tcp: bool = False,
    ) -> None:
        self.timeout = timeout
        self.force_tcp = force_tcp
        self._resolver = None
        if _DNS_AVAILABLE:
            self._resolver = dns.resolver.Resolver()
            if resolvers:
                self._resolver.nameservers = list(resolvers)
            self._resolver.lifetime = timeout
            self._resolver.timeout = timeout

    async def check(self, domain: str) -> dict[str, Any]:
        """Resolve *domain*.

        Returns ``{"rcode", "nxdomain", "ips", "error_type"}`` where
        error_type is None on success or one of
        ``nxdomain``/``servfail``/``timeout``/``resolver_error``.
        """
        if self._resolver is not None:
            return await self._check_dnspython(domain)
        return await self._check_getaddrinfo(domain)

    async def _check_dnspython(self, domain: str) -> dict[str, Any]:
        loop = asyncio.get_running_loop()
        retries = 2
        for attempt in range(retries + 1):
            # A and AAAA are independent lookups — run them concurrently instead of
            # serially. return_exceptions=True lets us translate control-flow
            # outcomes (NXDOMAIN / servfail / timeout) below without gather raising.
            results = await asyncio.gather(
                loop.run_in_executor(None, self._resolve, domain, "A"),
                loop.run_in_executor(None, self._resolve, domain, "AAAA"),
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, _Nxdomain):
                    return {"rcode": 3, "nxdomain": True, "ips": [], "error_type": "nxdomain"}
                if isinstance(r, _Servfail):
                    return {"rcode": 2, "nxdomain": False, "ips": [], "error_type": "servfail"}
                if isinstance(r, _Timeout):
                    return {"rcode": None, "nxdomain": False, "ips": [], "error_type": "timeout"}
            unexpected = next((r for r in results if isinstance(r, Exception)), None)
            if unexpected is not None:
                logger.exception(
                    "DnsChecker resolver error for %s (attempt %d)", domain, attempt + 1
                )
                if attempt < retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                return {"rcode": None, "nxdomain": False, "ips": [], "error_type": "resolver_error"}
            ips: list[str] = []
            for r in results:
                if isinstance(r, list):
                    ips.extend(r)
            return {"rcode": 0, "nxdomain": False, "ips": ips, "error_type": None}
        # All retries exhausted without a classified outcome.
        return {"rcode": None, "nxdomain": False, "ips": [], "error_type": "resolver_error"}

    def _resolve(self, domain: str, rdtype: str) -> list[str]:
        assert self._resolver is not None
        try:
            answer = self._resolver.resolve(domain, rdtype, tcp=self.force_tcp)
            return [r.to_text() for r in answer]
        except dns.resolver.NXDOMAIN:
            # Sentinel exceptions: the original DNS error is translated, not
            # chained (callers classify on the sentinel type alone).
            raise _Nxdomain from None
        except dns.resolver.NoNameservers:
            raise _Servfail from None
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
            raise _Timeout from None
        except dns.resolver.NoAnswer:
            return []

    async def _check_getaddrinfo(self, domain: str) -> dict[str, Any]:
        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, None, family=socket.AF_UNSPEC),
                timeout=self.timeout,
            )
            ips = list({info[4][0] for info in infos})
            return {"rcode": 0, "nxdomain": False, "ips": ips, "error_type": None}
        except asyncio.TimeoutError:
            return {"rcode": None, "nxdomain": False, "ips": [], "error_type": "timeout"}
        except Exception as e:
            msg = str(e).lower()
            if (
                "name or service not known" in msg
                or "nodename nor servname" in msg
                or "getaddrinfo failed" in msg
                or "name resolution" in msg
            ):
                return {"rcode": 3, "nxdomain": True, "ips": [], "error_type": "nxdomain"}
            return {"rcode": None, "nxdomain": False, "ips": [], "error_type": "resolver_error"}
