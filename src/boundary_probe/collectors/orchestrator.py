from __future__ import annotations

import time
from dataclasses import dataclass

from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.collectors.control_hosts import ControlHostsSlice, collect_control_hosts
from boundary_probe.collectors.dns import DnsSlice, collect_dns
from boundary_probe.collectors.gateway import GatewaySlice, collect_gateway
from boundary_probe.collectors.ip_connectivity import IpConnectivitySlice, collect_ip_connectivity
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
    elapsed_ms: int


def collect_signals(
    parsed_target: ParsedTarget,
    runner: SubprocessRunner | None = None,
    skip_path: bool = False,
) -> CollectionResult:
    """Run all collectors sequentially and return a CollectionResult with the derived SignalSnapshot."""
    r = runner or DefaultRunner()
    t0 = time.monotonic()

    gateway = collect_gateway(r)
    dns = collect_dns(parsed_target.host)
    ip = collect_ip_connectivity(r)
    controls = collect_control_hosts(r)
    target = collect_target_service(parsed_target, r)

    secondary_target = load_config().secondary_target

    if skip_path:
        path_primary = PathSlice(raw_hops=[], target=parsed_target.host, completed=False,
                                 note="skipped via --no-path")
        path_secondary = None
    else:
        path_primary = collect_path(parsed_target.host, r)
        needs_secondary = not ip.ok or not controls.all_ok
        path_secondary = collect_path(secondary_target, r) if needs_secondary else None

    path_signals = normalize_from_paths(path_primary, path_secondary)

    snapshot = SignalSnapshot(
        gateway_reachable=gateway.reachable,
        dns_ok=dns.ok,
        ip_connectivity_ok=ip.ok,
        control_hosts_ok=controls.all_ok,
        target_service_ok=target.ok,
        packet_loss_after_hop1=path_signals.packet_loss_after_hop1,
        packet_loss_multiple_targets=path_signals.packet_loss_multiple_targets,
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
        elapsed_ms=elapsed_ms,
    )
