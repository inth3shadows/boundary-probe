"""Exhaustive coverage of the boundary decision table.

Enumerates every combination of the boolean signal fields and asserts the table
is total (every input lands somewhere) and tight (no declared boundary is
unreachable). This is the regression that pins the local-device gap: before the
local-device rule existed, the boundary was documented but no input could reach
it.
"""

from __future__ import annotations

import itertools

from boundary_probe.engine import BOUNDARIES, diagnose
from boundary_probe.models import SignalSnapshot

# Every boolean field on SignalSnapshot that the engine reads.
_BOOL_FIELDS = (
    "gateway_reachable",
    "dns_ok",
    "ip_connectivity_ok",
    "control_hosts_ok",
    "target_service_ok",
    "default_route_present",
    "packet_loss_after_hop1",
    "packet_loss_multiple_targets",
    "captive_portal_detected",
    "ipv6_default_route_present",
)


def _all_snapshots() -> list[SignalSnapshot]:
    return [
        SignalSnapshot(**dict(zip(_BOOL_FIELDS, combo)))
        for combo in itertools.product((False, True), repeat=len(_BOOL_FIELDS))
    ]


def test_every_snapshot_maps_to_a_known_boundary() -> None:
    for snap in _all_snapshots():
        diagnosis = diagnose(snap)
        assert diagnosis.boundary in BOUNDARIES, snap


def test_every_declared_boundary_is_reachable() -> None:
    reached = {diagnose(snap).boundary for snap in _all_snapshots()}
    unreachable = set(BOUNDARIES) - reached
    assert not unreachable, f"declared but unreachable boundaries: {sorted(unreachable)}"


def test_confidence_always_in_unit_range() -> None:
    for snap in _all_snapshots():
        confidence = diagnose(snap).confidence
        assert 0.0 <= confidence <= 1.0, snap


def test_no_default_route_classifies_as_local_device() -> None:
    # gateway unreachable BECAUSE there is no default route -> local-device, not router-gateway.
    snap = SignalSnapshot(
        gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False, default_route_present=False,
    )
    assert diagnose(snap).boundary == "local-device"


def test_gateway_down_with_route_present_stays_router_gateway() -> None:
    # Default route exists, the gateway does not answer, AND nothing external is
    # reachable through it -> router-gateway boundary.
    snap = SignalSnapshot(
        gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False, default_route_present=True,
    )
    assert diagnose(snap).boundary == "router-gateway"


def test_forwarding_gateway_is_never_blamed_locally() -> None:
    # Invariant pinning the ICMP-filtered-gateway false positive: if traffic
    # provably traversed the gateway (the canary or control hosts are reachable),
    # the gateway cannot be the accused boundary — regardless of whether it
    # answered ICMP. Holds across all 2^8 signal combinations.
    for snap in _all_snapshots():
        if snap.ip_connectivity_ok or snap.control_hosts_ok:
            boundary = diagnose(snap).boundary
            assert boundary not in ("router-gateway", "local-device"), snap


def test_no_v4_route_with_v6_route_present_is_ipv6_only_not_local_device() -> None:
    # No IPv4 default route, but a v6 default route exists -> ipv6-only, not
    # the flat "problem is local to this device" lie.
    snap = SignalSnapshot(
        gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False, default_route_present=False,
        ipv6_default_route_present=True,
    )
    assert diagnose(snap).boundary == "ipv6-only"


def test_dual_stack_host_unaffected_by_v6_route_presence() -> None:
    # A normal dual-stack host (v4 works) must classify identically regardless
    # of whether a v6 default route also exists — the new rule requires
    # gateway_functional=False, so it never fires here.
    for ipv6 in (False, True):
        snap = SignalSnapshot(
            gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
            control_hosts_ok=True, target_service_ok=True, default_route_present=True,
            ipv6_default_route_present=ipv6,
        )
        assert diagnose(snap).boundary == "healthy"


def test_no_v4_and_no_v6_route_still_classifies_as_local_device() -> None:
    # True no-route host (neither v4 nor v6) -> local-device, unchanged.
    snap = SignalSnapshot(
        gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False, default_route_present=False,
        ipv6_default_route_present=False,
    )
    assert diagnose(snap).boundary == "local-device"
