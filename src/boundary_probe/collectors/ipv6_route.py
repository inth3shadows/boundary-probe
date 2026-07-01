"""IPv6 default-route presence check — cheap guard, not full dual-stack support.

When a host has no IPv4 default route, the engine's ``local-device`` rule fires
at 0.97 confidence: "the problem is local to this device." But a host can lack
a v4 default route while having a working v6 one — the internet is fine over
v6, and ``local-device`` would be a confident misdiagnosis, the most egregious
kind (it literally blames the user's machine). This collector answers only
"does an IPv6 default route exist" (presence, no address parsing) so the
engine can withhold that specific lie without building full dual-stack probing
(deferred; see the IPv6 v0.2 backlog item).

Fail-open by design: a missing/erroring command means "no v6 route detected",
never a fabricated one — worst case is today's behavior (local-device still
fires), never a new false negative for a wired v4 fault.
"""
from __future__ import annotations

from dataclasses import dataclass

from boundary_probe.collectors._commands import route6_cmd
from boundary_probe.collectors._parsers import parse_ipv6_default_route_present
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.config import ProbeConfig, load_config


@dataclass(slots=True, frozen=True)
class Ipv6RouteSlice:
    present: bool
    note: str


def collect_ipv6_route(
    runner: SubprocessRunner | None = None,
    *,
    cfg: ProbeConfig | None = None,
    route_timeout_s: float | None = None,
) -> Ipv6RouteSlice:
    """Check for IPv6 default-route presence. Never raises (fail-open)."""
    cfg = cfg if cfg is not None else load_config()
    r = runner or DefaultRunner()
    _route_t = route_timeout_s if route_timeout_s is not None else cfg.gateway_route_s

    result = r.run(route6_cmd(), timeout_s=_route_t)
    if result.timed_out or result.returncode != 0:
        return Ipv6RouteSlice(present=False, note="v6 route check failed or timed out")

    present = parse_ipv6_default_route_present(result.stdout)
    return Ipv6RouteSlice(present=present, note="" if present else "no IPv6 default route found")
