from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class PingStats:
    sent: int
    received: int
    loss_pct: float
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None


_PACKETS_RE = re.compile(r"Packets: Sent = (\d+), Received = (\d+), Lost = \d+")
_RTT_RE = re.compile(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms")

_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"(<?\d+\s+ms|\*)\s+"
    r"(<?\d+\s+ms|\*)\s+"
    r"(<?\d+\s+ms|\*)\s+"
    r"(.+?)\s*$",
    re.MULTILINE,
)


def parse_ping_output(stdout: str) -> PingStats:
    """Parse Windows ping stdout into PingStats. Returns 100% loss on missing statistics block."""
    pkts = _PACKETS_RE.search(stdout)
    if not pkts:
        return PingStats(sent=0, received=0, loss_pct=100.0, min_ms=None, avg_ms=None, max_ms=None)

    sent, received = int(pkts.group(1)), int(pkts.group(2))
    lost = sent - received
    loss_pct = (lost / sent * 100.0) if sent > 0 else 100.0

    rtt = _RTT_RE.search(stdout)
    if rtt:
        min_ms = float(rtt.group(1))
        max_ms = float(rtt.group(2))
        avg_ms = float(rtt.group(3))
    else:
        min_ms = avg_ms = max_ms = None

    return PingStats(sent=sent, received=received, loss_pct=loss_pct, min_ms=min_ms, avg_ms=avg_ms, max_ms=max_ms)


def _parse_rtt_value(s: str) -> float | None:
    s = s.strip()
    if s == "*":
        return None
    s = s.lstrip("<").strip()
    parts = s.split()
    try:
        return float(parts[0])
    except (ValueError, IndexError):
        return None


def parse_tracert_output(stdout: str) -> list[dict]:
    """Parse Windows tracert stdout into a list of hop dicts.

    Each dict has keys: index (int), loss_pct (float 0–100), rtt_ms (float|None), host (str).
    All-asterisk hops get loss_pct=100.0, rtt_ms=None, host='*'.
    """
    hops = []
    for m in _HOP_RE.finditer(stdout):
        index = int(m.group(1))
        raw_rtts = [m.group(2), m.group(3), m.group(4)]
        rtts = [_parse_rtt_value(r) for r in raw_rtts]
        star_count = sum(1 for r in rtts if r is None)
        loss_pct = (star_count / 3) * 100.0
        present = [r for r in rtts if r is not None]
        rtt_ms = sum(present) / len(present) if present else None
        host = "*" if star_count == 3 else m.group(5).strip()
        hops.append({"index": index, "loss_pct": loss_pct, "rtt_ms": rtt_ms, "host": host})
    return hops


def parse_route_print_default_gateway(stdout: str) -> str | None:
    """Return the default IPv4 gateway from `route print -4` output, or None."""
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            candidate = parts[2]
            try:
                addr = ipaddress.ip_address(candidate)
                if isinstance(addr, ipaddress.IPv4Address):
                    return candidate
            except ValueError:
                continue
    return None
