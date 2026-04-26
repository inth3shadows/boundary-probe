from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class DnsSlice:
    ok: bool
    resolved_ips: list[str]
    resolver_used: str | None
    elapsed_ms: int
    note: str


def collect_dns(target_host: str) -> DnsSlice:
    """Resolve target_host via the OS resolver (AF_INET only). No subprocess."""
    try:
        ipaddress.ip_address(target_host)
        return DnsSlice(ok=True, resolved_ips=[target_host], resolver_used=None,
                        elapsed_ms=0, note="target is already an IP address")
    except ValueError:
        pass

    t0 = time.monotonic()
    try:
        results = socket.getaddrinfo(target_host, None, socket.AF_INET)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        ips = list({r[4][0] for r in results})
        return DnsSlice(ok=True, resolved_ips=ips, resolver_used=None,
                        elapsed_ms=elapsed_ms, note="")
    except socket.gaierror as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return DnsSlice(ok=False, resolved_ips=[], resolver_used=None,
                        elapsed_ms=elapsed_ms, note=str(exc))
    except OSError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return DnsSlice(ok=False, resolved_ips=[], resolver_used=None,
                        elapsed_ms=elapsed_ms, note=str(exc))
