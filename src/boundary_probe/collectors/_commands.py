from __future__ import annotations

import sys

# Stored via an intermediate str so type narrowers don't eliminate non-Windows branches.
_PLATFORM: str = sys.platform
_WIN: bool = _PLATFORM == "win32"
_MAC: bool = _PLATFORM == "darwin"


def ping_cmd(host: str, count: int, timeout_ms: int) -> list[str]:
    """Return the platform-appropriate ping command."""
    if _WIN:
        return ["ping", "-4", "-n", str(count), "-w", str(timeout_ms), host]
    if _MAC:
        # BSD ping: -W is the per-packet wait in MILLISECONDS (Linux uses seconds);
        # it has no `-4` flag (IPv4 is the default; ping6 is separate) and no `--`.
        return ["ping", "-c", str(count), "-W", str(timeout_ms), host]
    timeout_s = max(1, timeout_ms // 1000)
    return ["ping", "-c", str(count), "-W", str(timeout_s), "-4", "--", host]


def traceroute_cmd(host: str, max_hops: int, timeout_ms: int) -> list[str]:
    """Return the platform-appropriate traceroute command."""
    if _WIN:
        return ["tracert", "-4", "-h", str(max_hops), "-w", str(timeout_ms), host]
    timeout_s = max(1, timeout_ms // 1000)
    if _MAC:
        # BSD traceroute: no `-4` / `--`; -w wait is in seconds (as on Linux).
        return ["traceroute", "-q", "3", "-m", str(max_hops), "-w", str(timeout_s), host]
    return ["traceroute", "-4", "-q", "3", "-m", str(max_hops), "-w", str(timeout_s), "--", host]


def route_cmd() -> list[str]:
    """Return the platform-appropriate command to discover the default gateway."""
    if _WIN:
        return ["route", "print", "-4"]
    if _MAC:
        # macOS has no iproute2; `route -n get default` prints a `gateway:` line.
        return ["route", "-n", "get", "default"]
    return ["ip", "route", "show", "default"]
