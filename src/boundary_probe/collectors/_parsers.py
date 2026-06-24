from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass

# Stored via an intermediate str so type narrowers don't eliminate non-Windows branches.
_PLATFORM: str = sys.platform
_WIN: bool = _PLATFORM == "win32"
_MAC: bool = _PLATFORM == "darwin"


@dataclass(slots=True, frozen=True)
class PingStats:
    sent: int
    received: int
    loss_pct: float
    min_ms: float | None
    avg_ms: float | None
    max_ms: float | None


# ---------------------------------------------------------------------------
# Windows parsers
# ---------------------------------------------------------------------------

_WIN_PACKETS_RE = re.compile(r"Packets: Sent = (\d+), Received = (\d+), Lost = \d+")
_WIN_RTT_RE = re.compile(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms")
_WIN_HOP_RE = re.compile(
    r"^\s*(\d+)\s+"
    r"(<?\d+\s+ms|\*)\s+"
    r"(<?\d+\s+ms|\*)\s+"
    r"(<?\d+\s+ms|\*)\s+"
    r"(.+?)\s*$",
    re.MULTILINE,
)


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


def _parse_ping_win(stdout: str) -> PingStats:
    """Parse Windows ping stdout into PingStats. Returns 100% loss on missing statistics block."""
    pkts = _WIN_PACKETS_RE.search(stdout)
    if not pkts:
        return PingStats(sent=0, received=0, loss_pct=100.0, min_ms=None, avg_ms=None, max_ms=None)

    sent, received = int(pkts.group(1)), int(pkts.group(2))
    lost = sent - received
    loss_pct = (lost / sent * 100.0) if sent > 0 else 100.0

    rtt = _WIN_RTT_RE.search(stdout)
    if rtt:
        min_ms = float(rtt.group(1))
        max_ms = float(rtt.group(2))
        avg_ms = float(rtt.group(3))
    else:
        min_ms = avg_ms = max_ms = None

    return PingStats(sent=sent, received=received, loss_pct=loss_pct, min_ms=min_ms, avg_ms=avg_ms, max_ms=max_ms)


def _parse_tracert_win(stdout: str) -> list[dict]:
    """Parse Windows tracert stdout. Each hop dict: index, loss_pct, rtt_ms, host."""
    hops = []
    for m in _WIN_HOP_RE.finditer(stdout):
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


def _parse_route_win(stdout: str) -> str | None:
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


# ---------------------------------------------------------------------------
# Linux parsers
# ---------------------------------------------------------------------------

_LINUX_PING_STATS_RE = re.compile(
    r"(\d+) packets transmitted, (\d+) received,\s+(\d+)% packet loss"
)
_LINUX_PING_RTT_RE = re.compile(
    r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms"
)
_LINUX_HOP_LINE_RE = re.compile(r"^\s*(\d+)\s+(.+)$", re.MULTILINE)
_LINUX_RTT_VALUE_RE = re.compile(r"([\d.]+)\s+ms")
_LINUX_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
_LINUX_ROUTE_GW_RE = re.compile(r"default via (\d{1,3}(?:\.\d{1,3}){3})")


def _parse_ping_linux(stdout: str) -> PingStats:
    """Parse Linux ping stdout into PingStats."""
    m = _LINUX_PING_STATS_RE.search(stdout)
    if not m:
        return PingStats(sent=0, received=0, loss_pct=100.0, min_ms=None, avg_ms=None, max_ms=None)
    sent, received = int(m.group(1)), int(m.group(2))
    loss_pct = float(m.group(3))
    rtt = _LINUX_PING_RTT_RE.search(stdout)
    avg_ms = float(rtt.group(1)) if rtt else None
    return PingStats(sent=sent, received=received, loss_pct=loss_pct, min_ms=None, avg_ms=avg_ms, max_ms=None)


def _parse_traceroute_linux(stdout: str) -> list[dict]:
    """Parse Linux traceroute stdout. Each hop dict: index, loss_pct, rtt_ms, host."""
    hops = []
    for m in _LINUX_HOP_LINE_RE.finditer(stdout):
        index = int(m.group(1))
        rest = m.group(2).strip()
        tokens = rest.split()
        star_count = sum(1 for t in tokens if t == "*")
        loss_pct = min((star_count / 3) * 100.0, 100.0)
        rtts = [float(v) for v in _LINUX_RTT_VALUE_RE.findall(rest)]
        rtt_ms = sum(rtts) / len(rtts) if rtts else None
        if star_count >= 3:
            host = "*"
        else:
            ip_match = _LINUX_IP_RE.search(rest)
            host = ip_match.group(1) if ip_match else (tokens[0] if tokens else "*")
        hops.append({"index": index, "loss_pct": loss_pct, "rtt_ms": rtt_ms, "host": host})
    return hops


def _parse_route_linux(stdout: str) -> str | None:
    """Return the default IPv4 gateway from `ip route show default` output, or None."""
    m = _LINUX_ROUTE_GW_RE.search(stdout)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# macOS parsers
# ---------------------------------------------------------------------------
# BSD ping differs from Linux in three ways the Linux regexes miss: it says
# "N packets received" (not "N received"), reports loss as a float ("0.0%"),
# and labels RTT "round-trip ... stddev" (not "rtt ... mdev"). Traceroute output
# is BSD-format-identical to Linux, so that parser is reused. `route -n get
# default` prints a "gateway: <ip>" line instead of "default via <ip>".

_MAC_PING_STATS_RE = re.compile(
    # BSD ping inserts ", +N errors" before the loss% when it gets ICMP errors
    # (host/net unreachable) rather than plain timeouts; tolerate it optionally.
    r"(\d+) packets transmitted, (\d+) packets received,(?: \+\d+ errors,)? ([\d.]+)% packet loss"
)
_MAC_PING_RTT_RE = re.compile(
    r"round-trip min/avg/max/stddev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms"
)
_MAC_ROUTE_GW_RE = re.compile(r"gateway:\s*(\d{1,3}(?:\.\d{1,3}){3})")


def _parse_ping_mac(stdout: str) -> PingStats:
    """Parse macOS (BSD) ping stdout into PingStats."""
    m = _MAC_PING_STATS_RE.search(stdout)
    if not m:
        return PingStats(sent=0, received=0, loss_pct=100.0, min_ms=None, avg_ms=None, max_ms=None)
    sent, received = int(m.group(1)), int(m.group(2))
    loss_pct = float(m.group(3))
    rtt = _MAC_PING_RTT_RE.search(stdout)
    avg_ms = float(rtt.group(1)) if rtt else None
    return PingStats(sent=sent, received=received, loss_pct=loss_pct, min_ms=None, avg_ms=avg_ms, max_ms=None)


# BSD traceroute output matches the Linux format this parser already handles.
_parse_traceroute_mac = _parse_traceroute_linux


def _parse_route_mac(stdout: str) -> str | None:
    """Return the default IPv4 gateway from `route -n get default` output, or None."""
    m = _MAC_ROUTE_GW_RE.search(stdout)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Public API — dispatcher wrappers select the right implementation at runtime
# ---------------------------------------------------------------------------

def parse_ping_output(stdout: str) -> PingStats:
    if _WIN:
        return _parse_ping_win(stdout)
    if _MAC:
        return _parse_ping_mac(stdout)
    return _parse_ping_linux(stdout)


def parse_tracert_output(stdout: str) -> list[dict]:
    if _WIN:
        return _parse_tracert_win(stdout)
    if _MAC:
        return _parse_traceroute_mac(stdout)
    return _parse_traceroute_linux(stdout)


def parse_route_print_default_gateway(stdout: str) -> str | None:
    if _WIN:
        return _parse_route_win(stdout)
    if _MAC:
        return _parse_route_mac(stdout)
    return _parse_route_linux(stdout)
