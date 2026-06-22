from boundary_probe.engine import diagnose
from boundary_probe.models import SignalSnapshot


def demo_signals(name: str) -> SignalSnapshot:
    scenarios = {
        "router-down": SignalSnapshot(
            gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
            control_hosts_ok=False, target_service_ok=False,
        ),
        "dns-failure": SignalSnapshot(
            gateway_reachable=True, dns_ok=False, ip_connectivity_ok=True,
            control_hosts_ok=True, target_service_ok=False,
        ),
        "isp-path": SignalSnapshot(
            gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
            control_hosts_ok=False, target_service_ok=False,
            packet_loss_after_hop1=True, packet_loss_multiple_targets=True,
        ),
        "remote-service": SignalSnapshot(
            gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
            control_hosts_ok=True, target_service_ok=False,
        ),
    }
    try:
        return scenarios[name]
    except KeyError as exc:
        available = ", ".join(sorted(scenarios))
        raise ValueError(f"unknown scenario '{name}'. Available: {available}") from exc


def test_router_down_classifies_as_router_gateway() -> None:
    diagnosis = diagnose(demo_signals("router-down"))
    assert diagnosis.boundary == "router-gateway"
    assert diagnosis.confidence == 0.99


def test_dns_failure_classifies_as_dns() -> None:
    diagnosis = diagnose(demo_signals("dns-failure"))
    assert diagnosis.boundary == "dns"
    assert diagnosis.confidence == 0.96


def test_isp_upstream_classifies_correctly() -> None:
    diagnosis = diagnose(demo_signals("isp-path"))
    assert diagnosis.boundary == "isp-upstream"
    assert diagnosis.confidence == 0.93


def test_remote_service_classifies_correctly() -> None:
    diagnosis = diagnose(demo_signals("remote-service"))
    assert diagnosis.boundary == "remote-service"
    assert diagnosis.confidence == 0.95


def test_healthy_when_all_green() -> None:
    # Every signal green → positive `healthy` verdict, NOT inconclusive.
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=True, target_service_ok=True,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "healthy"
    assert diagnosis.confidence == 0.9


def test_icmp_filtered_gateway_is_not_a_lan_incident() -> None:
    # Regression (2026-06-22, WSL2): a gateway that does not answer ICMP but is
    # forwarding traffic — control hosts and the canary are reachable *through*
    # it — must NOT be accused as a router-gateway LAN incident. Before the
    # gateway_functional fix this classified as router-gateway @ 0.99 while the
    # whole connection was demonstrably healthy.
    snap = SignalSnapshot(
        gateway_reachable=False,    # gateway filters ICMP echo to itself
        dns_ok=True,
        ip_connectivity_ok=True,
        control_hosts_ok=True,      # traffic provably traversed the gateway
        target_service_ok=True,
        default_route_present=True,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "healthy"
    assert diagnosis.confidence == 0.9
    # Evidence must reflect reality: forwarding, not a falsely-claimed ICMP reply.
    gw = next(e for e in diagnosis.evidence if e.label == "gateway")
    assert "forwarding" in gw.detail.lower()
    assert "reachable" not in gw.detail.lower() or "external hosts are reachable" in gw.detail.lower()


def test_gateway_down_and_external_down_still_router_gateway() -> None:
    # The genuine fault is preserved: gateway silent AND no external reachability
    # (nothing traversed it) → router-gateway, and the "external also failed"
    # evidence is now true by construction.
    snap = SignalSnapshot(
        gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False, default_route_present=True,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "router-gateway"
    assert diagnosis.confidence == 0.99


def test_wan_gateway_classifies_correctly() -> None:
    # gateway up, IP and DNS both down → WAN connection failure, not router-local
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "wan-gateway"
    assert diagnosis.confidence == 0.94


def test_isp_upstream_requires_both_loss_flags() -> None:
    # Only one loss flag — must NOT classify as isp-upstream
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=False, target_service_ok=False,
        packet_loss_after_hop1=True, packet_loss_multiple_targets=False,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary != "isp-upstream"

    snap2 = SignalSnapshot(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=False, target_service_ok=False,
        packet_loss_after_hop1=False, packet_loss_multiple_targets=True,
    )
    diagnosis2 = diagnose(snap2)
    assert diagnosis2.boundary != "isp-upstream"


def test_dns_rule_requires_ip_connectivity_ok() -> None:
    # DNS fails AND IP connectivity fails → wan-gateway, not dns
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "wan-gateway"


def test_remote_service_requires_controls_ok() -> None:
    # Controls failing → cannot be classified as remote-service
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=False, target_service_ok=False,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary != "remote-service"


def test_confidence_values_for_all_boundaries() -> None:
    expected = {
        "router-down": ("router-gateway", 0.99),
        "dns-failure": ("dns", 0.96),
        "isp-path": ("isp-upstream", 0.93),
        "remote-service": ("remote-service", 0.95),
    }
    for scenario, (boundary, conf) in expected.items():
        d = diagnose(demo_signals(scenario))
        assert d.boundary == boundary, f"{scenario}: expected {boundary}, got {d.boundary}"
        assert d.confidence == conf, f"{scenario}: expected {conf}, got {d.confidence}"


def test_inconclusive_evidence_is_signal_aware() -> None:
    # Controls failing, dns ok, ip ok, target down → inconclusive (no path loss flags)
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=False, target_service_ok=False,
        packet_loss_after_hop1=False, packet_loss_multiple_targets=False,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "inconclusive"
    labels = {e.label for e in diagnosis.evidence}
    assert "gateway" in labels
    assert "dns" in labels
    assert "coverage" in labels


def test_healthy_verdict_includes_all_green_evidence() -> None:
    # All green including target → healthy, with evidence covering every probed signal.
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=True, target_service_ok=True,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "healthy"
    labels = {e.label for e in diagnosis.evidence}
    assert {"gateway", "dns", "ip-connectivity", "controls", "target"} <= labels
