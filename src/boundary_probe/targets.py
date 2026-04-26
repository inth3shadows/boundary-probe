from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit


@dataclass(slots=True)
class ParsedTarget:
    raw: str
    kind: Literal["host", "ip", "url"]
    host: str
    port: int | None
    scheme: str | None


def parse_target(raw: str) -> ParsedTarget:
    """Parse a user-supplied target string into a typed ParsedTarget.

    Accepts:
      - URL:      "https://example.com/path" or "http://example.com:8080"
      - IP:       "1.1.1.1" or "192.168.1.1:443" (IPv4 only; IPv6 rejected)
      - Hostname: "example.com" or "example.com:443"

    Raises ValueError for empty input or IPv6 literals.
    """
    if not raw or not raw.strip():
        raise ValueError("target must not be empty")

    raw = raw.strip()

    if "://" in raw:
        parsed = urlsplit(raw)
        return ParsedTarget(
            raw=raw,
            kind="url",
            host=parsed.hostname or "",
            port=parsed.port,
            scheme=parsed.scheme or None,
        )

    host_part, _, port_str = raw.partition(":")
    port = int(port_str) if port_str.isdigit() else None

    try:
        addr = ipaddress.ip_address(host_part)
    except ValueError:
        return ParsedTarget(raw=raw, kind="host", host=host_part, port=port, scheme=None)

    if isinstance(addr, ipaddress.IPv6Address):
        raise ValueError(f"IPv6 targets are not supported in v1: {raw!r}")
    return ParsedTarget(raw=raw, kind="ip", host=host_part, port=port, scheme=None)
