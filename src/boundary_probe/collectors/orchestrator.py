from __future__ import annotations

import time
from dataclasses import dataclass

from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.collectors.captive_portal import CaptivePortalSlice, collect_captive_portal
from boundary_probe.collectors.control_hosts import ControlHostsSlice, collect_control_hosts
from boundary_probe.collectors.dns import DnsSlice, collect_dns
from boundary_probe.collectors.gateway import GatewaySlice, collect_gateway
from boundary_probe.collectors.ip_connectivity import IpConnectivitySlice, collect_ip_connectivity
from boundary_probe.collectors.ipv6_route import Ipv6RouteSlice, collect_ipv6_route
from boundary_probe.collectors.path import PathSlice, collect_path
from boundary_probe.collectors.target_service import TargetServiceSlice, collect_target_service
from boundary_probe.config import load_config
from boundary_probe.models import SignalSnapshot
from boundary_probe.normalizer import normalize_from_paths
from boundary_probe.targets import ParsedTarget


@dataclass(slots=True, frozen=True)
class CollectionResult:
    snapshot: SignalSnapshot
    gateway: GatewaySlice
    dns: DnsSlice
    ip: IpConnectivitySlice
    controls: ControlHostsSlice
    target: TargetServiceSlice
    path_primary: PathSlice
    path_secondary: PathSlice | None
    captive: CaptivePortalSlice
    ipv6_route: Ipv6RouteSlice
    elapsed_ms: int


def collect_signals(
    parsed_target: ParsedTarget,
    runner: SubprocessRunner | None = None,
    skip_path: bool = False,
    skip_captive: bool = False,
) -> CollectionResult:
    """Run all collectors sequentially and return a CollectionResult with the derived SignalSnapshot."""
    r = runner or DefaultRunner()
    t0 = time.monotonic()
    cfg = load_config()

    gateway = collect_gateway(r, cfg=cfg)
    ipv6_route = collect_ipv6_route(r, cfg=cfg)
    dns = collect_dns(parsed_target.host)
    ip = collect_ip_connectivity(r, cfg=cfg)
    controls = collect_control_hosts(r, cfg=cfg)
    target = collect_target_service(parsed_target, r, cfg=cfg)

    if skip_captive or not cfg.captive_check_url:
        captive = collect_captive_portal(check_url="")  # disabled -> checked=False
    else:
        captive = collect_captive_portal(cfg.captive_check_url, cfg.captive_check_s)

    secondary_target = cfg.secondary_target

    if skip_path:
        path_primary = PathSlice(raw_hops=[], target=parsed_target.host, completed=False,
                                 note="skipped via --no-path")
        path_secondary = None
    else:
        path_primary = collect_path(parsed_target.host, r, cfg=cfg)
        needs_secondary = not ip.ok or not controls.all_ok
        path_secondary = collect_path(secondary_target, r, cfg=cfg) if needs_secondary else None

    path_signals = normalize_from_paths(path_primary, path_secondary, cfg=cfg)

    snapshot = SignalSnapshot(
        gateway_reachable=gateway.reachable,
        dns_ok=dns.ok,
        ip_connectivity_ok=ip.ok,
        control_hosts_ok=controls.all_ok,
        target_service_ok=target.ok,
        # No gateway IP in the route table => no default route => local-device fault,
        # not a router that simply failed to answer a ping.
        default_route_present=gateway.gateway_ip is not None,
        packet_loss_after_hop1=path_signals.packet_loss_after_hop1,
        packet_loss_multiple_targets=path_signals.packet_loss_multiple_targets,
        captive_portal_detected=captive.portal_detected,
        ipv6_default_route_present=ipv6_route.present,
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    return CollectionResult(
        snapshot=snapshot,
        gateway=gateway,
        dns=dns,
        ip=ip,
        controls=controls,
        target=target,
        path_primary=path_primary,
        path_secondary=path_secondary,
        captive=captive,
        ipv6_route=ipv6_route,
        elapsed_ms=elapsed_ms,
    )
