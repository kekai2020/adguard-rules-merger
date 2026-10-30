"""DNSBL layer: Spamhaus DBL return codes + SURBL bitmask parsing and lookup.

Moved verbatim during the P1-3 package split; code/bit meaning and blocked-
resolver guard are unchanged.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from .constants import _DBL_CODES, _DNSBL_BLOCKED, _SURBL_BITS, DNSBL_LISTS
from .seam import resolve


def parse_dnsbl_response(list_name: str, ip: str) -> tuple[bool, list[str]]:
    """Interpret a 127.0.0.x DNSBL reply.

    Returns (malicious_signal, labels). Spamhaus DBL uses one code per last
    octet; SURBL multi uses a bitmask. Codes marking phishing / malware /
    scam / botnet produce a malicious signal; spam/junk/abused only warn.
    """
    if not ip.startswith("127."):
        return False, []
    try:
        last = int(ip.rsplit(".", 1)[-1])
    except ValueError:
        return False, []
    bad = False
    labels: list[str] = []
    if list_name == "SpamhausDBL":
        name, mal = _DBL_CODES.get(last, (f"code-{last}", False))
        labels.append(f"{list_name}:{name}")
        bad = mal
    else:  # SURBL-style bitmask
        for bit, name, mal in _SURBL_BITS:
            if last & bit:
                labels.append(f"{list_name}:{name}")
                bad = bad or mal
    return bad, labels


async def _dnsbl_lookup(qname: str, timeout: int) -> list[str]:
    """Resolve a DNSBL query name, returning the A-record answers.

    NXDOMAIN / not-listed raises ``socket.gaierror`` (handled by the caller).
    Factored out so tests can stub resolution without touching asyncio.
    """
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(qname, None, family=socket.AF_INET), timeout=timeout
    )
    return [info[4][0] for info in infos]  # type: ignore[misc]


async def _query_dnsbl(domain: str, timeout: int = 6) -> dict[str, Any]:
    """Free keyless DNSBL lookups (Spamhaus DBL + SURBL multi).

    NXDOMAIN means "not listed" — the normal, healthy answer — so these
    queries are cheap and safe to fan out. Volume is one lookup per whitelist
    domain per run (plus disk-cache hits skipped entirely).
    """
    hits: list[str] = []
    errors: list[str] = []
    malicious = False
    for zone, list_name in DNSBL_LISTS:
        qname = f"{domain}.{zone}"
        try:
            for ip in await resolve("_dnsbl_lookup")(qname, timeout):
                if any(ip.startswith(p) for p in _DNSBL_BLOCKED):
                    errors.append(f"{list_name}: query blocked (open resolver)")
                    continue
                bad, labels = parse_dnsbl_response(list_name, ip)
                hits.extend(labels)
                malicious = malicious or bad
        except socket.gaierror:
            continue  # NXDOMAIN / not listed
        except asyncio.TimeoutError:
            errors.append(f"{list_name}: timeout")
        except Exception as e:  # noqa: BLE001
            errors.append(f"{list_name}: {e}")
    return {
        "listed": bool(hits),
        "malicious": malicious,
        "hits": hits,
        "error": "; ".join(errors) or None,
    }
