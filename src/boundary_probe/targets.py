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

    Raises ValueError for empty input or IPv6 literals.
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

    host_part, _, port_str = raw.partition(":")
    port = int(port_str) if port_str.isdigit() else None

    try:
        addr = ipaddress.ip_address(host_part)
    except ValueError:
        _validate_host(host_part, raw)
        return ParsedTarget(raw=raw, kind="host", host=host_part, port=port, scheme=None)

    if isinstance(addr, ipaddress.IPv6Address):
        raise ValueError(f"IPv6 targets are not supported in v1: {raw!r}")
    return ParsedTarget(raw=raw, kind="ip", host=host_part, port=port, scheme=None)
