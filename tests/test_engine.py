from boundary_probe.engine import demo_signals, diagnose
from boundary_probe.models import SignalSnapshot


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


def test_inconclusive_when_all_healthy() -> None:
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=True, target_service_ok=True,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "inconclusive"
    assert diagnosis.confidence == 0.5


def test_inconclusive_when_partial_ambiguous() -> None:
    # gateway up, everything else down, but no path-loss flags → no clean boundary
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "inconclusive"


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
    # DNS fails AND IP connectivity fails → not the dns boundary
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary != "dns"


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
    # gateway up, ip down → dns rule doesn't fire (needs ip_ok); falls to inconclusive
    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False,
    )
    diagnosis = diagnose(snap)
    assert diagnosis.boundary == "inconclusive"
    labels = {e.label for e in diagnosis.evidence}
    assert "gateway" in labels
    assert "dns" in labels
    assert "coverage" in labels
    # Verify the gateway item reflects the actual signal
    gw_evidence = next(e for e in diagnosis.evidence if e.label == "gateway")
    assert gw_evidence.detail == "reachable"
