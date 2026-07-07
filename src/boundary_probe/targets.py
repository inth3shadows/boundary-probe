from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

# RFC-1123 hostname: dot-separated labels of [A-Za-z0-9-], each 1-63 chars, no
# leading/trailing hyphen, total <= 253. Rejecting anything else at this trust
# boundary stops both argv injection (a leading "-" becomes a ping/tracert flag
# on Windows, which has no "--" separator) and HTML/script injection into the
# web UI, since the target is later echoed into the page.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def _validate_host(host: str, raw: str) -> None:
    if not _HOSTNAME_RE.match(host):
        raise ValueError(f"invalid hostname in target: {raw!r}")


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

    Raises ValueError for empty input, IPv6 literals, or a malformed/out-of-range
    port (0-65535). A silently-dropped or silently-wrapped bad port is worse than
    a loud error: ``socket.getaddrinfo`` truncates an out-of-range port to 16 bits
    instead of raising, so an unvalidated port here would make the TCP-connect
    collector silently probe the wrong port and hand back a diagnosis for a
    target the user never asked about.
    """
    if not raw or not raw.strip():
        raise ValueError("target must not be empty")

    raw = raw.strip()

    if "://" in raw:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        _validate_host(host, raw)
        return ParsedTarget(
            raw=raw,
            kind="url",
            host=host,
            port=parsed.port,
            scheme=parsed.scheme or None,
        )

    host_part, sep, port_str = raw.partition(":")
    port: int | None = None
    if sep:
        if not port_str.isdigit() or not (0 <= int(port_str) <= 65535):
            raise ValueError(f"invalid port in target: {raw!r}")
        port = int(port_str)

    try:
        addr = ipaddress.ip_address(host_part)
    except ValueError:
        _validate_host(host_part, raw)
        return ParsedTarget(raw=raw, kind="host", host=host_part, port=port, scheme=None)

    if isinstance(addr, ipaddress.IPv6Address):
        raise ValueError(f"IPv6 targets are not supported in v1: {raw!r}")
    return ParsedTarget(raw=raw, kind="ip", host=host_part, port=port, scheme=None)
