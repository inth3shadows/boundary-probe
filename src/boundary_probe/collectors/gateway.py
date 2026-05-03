from __future__ import annotations

from dataclasses import dataclass

from boundary_probe.collectors._commands import ping_cmd, route_cmd
from boundary_probe.collectors._parsers import (
    parse_ping_output,
    parse_route_print_default_gateway,
)
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.config import load_config


@dataclass(slots=True, frozen=True)
class GatewaySlice:
    reachable: bool
    gateway_ip: str | None
    rtt_ms: float | None
    note: str


def collect_gateway(
    runner: SubprocessRunner | None = None,
    *,
    route_timeout_s: float | None = None,
    ping_timeout_s: float | None = None,
    min_replies: int | None = None,
) -> GatewaySlice:
    """Discover the default IPv4 gateway via `route print -4`, then ping it 4 times."""
    cfg = load_config()
    r = runner or DefaultRunner()
    _route_t = route_timeout_s if route_timeout_s is not None else cfg.gateway_route_s
    _ping_t = ping_timeout_s if ping_timeout_s is not None else cfg.gateway_ping_s
    _min_replies = min_replies if min_replies is not None else cfg.gateway_min_replies

    route_result = r.run(route_cmd(), timeout_s=_route_t)
    if route_result.timed_out or route_result.returncode != 0:
        return GatewaySlice(reachable=False, gateway_ip=None, rtt_ms=None,
                            note="route print failed or timed out")

    gateway_ip = parse_route_print_default_gateway(route_result.stdout)
    if not gateway_ip:
        return GatewaySlice(reachable=False, gateway_ip=None, rtt_ms=None,
                            note="could not determine default gateway from route table")

    ping_result = r.run(ping_cmd(gateway_ip, 4, 1000), timeout_s=_ping_t)
    if ping_result.timed_out:
        return GatewaySlice(reachable=False, gateway_ip=gateway_ip, rtt_ms=None,
                            note=f"ping to {gateway_ip} timed out after {_ping_t:.0f}s")

    stats = parse_ping_output(ping_result.stdout)
    if stats.sent == 0:
        return GatewaySlice(reachable=False, gateway_ip=gateway_ip, rtt_ms=None,
                            note="unrecognized output format from ping")

    reachable = stats.received >= _min_replies
    return GatewaySlice(
        reachable=reachable,
        gateway_ip=gateway_ip,
        rtt_ms=stats.avg_ms,
        note="" if reachable else f"only {stats.received}/{stats.sent} ping replies from gateway",
    )
