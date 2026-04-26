from __future__ import annotations

from boundary_probe.models import Diagnosis, EvidenceItem, SignalSnapshot


def demo_signals(name: str) -> SignalSnapshot:
    scenarios = {
        "router-down": SignalSnapshot(
            gateway_reachable=False,
            dns_ok=False,
            ip_connectivity_ok=False,
            control_hosts_ok=False,
            target_service_ok=False,
        ),
        "dns-failure": SignalSnapshot(
            gateway_reachable=True,
            dns_ok=False,
            ip_connectivity_ok=True,
            control_hosts_ok=True,
            target_service_ok=False,
        ),
        "isp-path": SignalSnapshot(
            gateway_reachable=True,
            dns_ok=True,
            ip_connectivity_ok=True,
            control_hosts_ok=False,
            target_service_ok=False,
            packet_loss_after_hop1=True,
            packet_loss_multiple_targets=True,
        ),
        "remote-service": SignalSnapshot(
            gateway_reachable=True,
            dns_ok=True,
            ip_connectivity_ok=True,
            control_hosts_ok=True,
            target_service_ok=False,
        ),
    }
    try:
        return scenarios[name]
    except KeyError as exc:
        available = ", ".join(sorted(scenarios))
        raise ValueError(f"unknown scenario '{name}'. Available: {available}") from exc


def diagnose(signals: SignalSnapshot) -> Diagnosis:
    if not signals.gateway_reachable:
        return Diagnosis(
            boundary="router-gateway",
            confidence=0.99,
            summary="The local gateway is not reachable, so the problem is most likely on the LAN or router boundary.",
            evidence=[
                EvidenceItem("gateway", "Default gateway did not respond."),
                EvidenceItem("external", "External reachability also failed, which is consistent with a local boundary."),
            ],
            remediation=[
                "Check the local link first: cable, Wi-Fi association, and interface status.",
                "Power-cycle the router or gateway after confirming the modem or upstream link is stable.",
                "If possible, test from a second device on the same LAN before escalating further.",
            ],
        )

    if signals.ip_connectivity_ok and not signals.dns_ok:
        return Diagnosis(
            boundary="dns",
            confidence=0.96,
            summary="Raw connectivity is available, but name resolution is failing.",
            evidence=[
                EvidenceItem("gateway", "Gateway reachability is healthy."),
                EvidenceItem("ip-connectivity", "Direct IP connectivity still works."),
                EvidenceItem("dns", "DNS lookups are failing or inconsistent."),
            ],
            remediation=[
                "Retry the lookup using a known-good resolver such as 1.1.1.1 or 8.8.8.8.",
                "Inspect the router or OS DNS settings for stale or unreachable resolvers.",
                "If only one resolver fails, replace it before changing broader network settings.",
            ],
        )

    if (
        signals.gateway_reachable
        and signals.dns_ok
        and signals.packet_loss_after_hop1
        and signals.packet_loss_multiple_targets
    ):
        return Diagnosis(
            boundary="isp-upstream",
            confidence=0.93,
            summary="The local network appears healthy, but loss is beginning after the local boundary across multiple destinations.",
            evidence=[
                EvidenceItem("gateway", "Gateway reachability is healthy."),
                EvidenceItem("dns", "DNS is working."),
                EvidenceItem("path", "Loss begins after hop 1."),
                EvidenceItem("breadth", "More than one external target shows the same degradation."),
            ],
            remediation=[
                "Repeat the run twice more over a 10-15 minute window to confirm it is not a transient spike.",
                "Bypass the router if practical to separate ISP issues from router firmware or NAT pressure.",
                "Escalate to the ISP with timestamps, packet loss, and the fact that multiple targets degrade similarly.",
            ],
        )

    if signals.gateway_reachable and signals.dns_ok and signals.control_hosts_ok and not signals.target_service_ok:
        return Diagnosis(
            boundary="remote-service",
            confidence=0.95,
            summary="General internet health is good, but the target service is failing specifically.",
            evidence=[
                EvidenceItem("controls", "Known-good internet controls are healthy."),
                EvidenceItem("target", "The target service still fails."),
            ],
            remediation=[
                "Check the target service status page or origin health before changing local network settings.",
                "Try a second network only to confirm the target-specific failure pattern, not as the first step.",
                "If you operate the service, inspect TLS, DNS, reverse proxy, and origin availability.",
            ],
        )

    return Diagnosis(
        boundary="inconclusive",
        confidence=0.5,
        summary="The current signal set does not isolate the boundary cleanly.",
        evidence=[
            EvidenceItem("coverage", "The available checks are not strong enough to place the fault with confidence."),
        ],
        remediation=[
            "Collect gateway, DNS, and at least one control-host result in the same run.",
            "Repeat the diagnostics to rule out a transient failure before drawing a conclusion.",
        ],
    )

