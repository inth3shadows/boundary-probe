from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from boundary_probe.models import Diagnosis, EvidenceItem, SignalSnapshot, VantageSlice


@dataclass(frozen=True)
class Rule:
    """One row of the boundary decision table.

    ``match`` maps ``SignalSnapshot`` field names to the boolean value they must
    hold for this rule to fire; fields omitted from ``match`` are don't-care.
    Rules are evaluated top-to-bottom and the first whose ``match`` is fully
    satisfied wins, so more specific rows must precede broader ones. ``build``
    produces the full Diagnosis once the row is selected (some rows, e.g.
    ``inconclusive``, build signal-aware evidence, so this stays a callable).
    """

    boundary: str
    match: dict[str, bool]
    build: Callable[[SignalSnapshot], Diagnosis]

    def matches(self, signals: SignalSnapshot) -> bool:
        return all(getattr(signals, field) == expected for field, expected in self.match.items())


def _gateway_evidence(signals: SignalSnapshot) -> EvidenceItem:
    """Gateway-health evidence that reflects *how* the gateway was judged healthy.

    Only called from build functions that fire when ``gateway_functional`` is
    True. If the gateway did not answer ICMP, forwarding was proven by reaching
    an external host — say so rather than falsely claiming the gateway "is
    reachable".
    """
    if signals.gateway_reachable:
        return EvidenceItem("gateway", "Local gateway is reachable.")
    return EvidenceItem(
        "gateway",
        "Gateway did not answer ICMP (likely filtered), but traffic is forwarding through it — external hosts are reachable.",
    )


def _ipv6_only(_: SignalSnapshot) -> Diagnosis:
    return Diagnosis(
        boundary="ipv6-only",
        confidence=0.7,
        summary="No IPv4 default route, but an IPv6 default route is present — your connectivity may be working over IPv6, which this tool does not yet probe. A v4-based diagnosis would mislead, so it is withheld.",
        evidence=[
            EvidenceItem("route", "No IPv4 default gateway is present in the local route table."),
            EvidenceItem("route6", "An IPv6 default route is present."),
        ],
        remediation=[
            "Test the target over IPv6 directly if it supports it — this connection may already be working.",
            "If you need IPv4-specific connectivity, check why no IPv4 default route was offered (DHCP, ISP dual-stack config).",
        ],
    )


def _local_device(_: SignalSnapshot) -> Diagnosis:
    return Diagnosis(
        boundary="local-device",
        confidence=0.97,
        summary="No default route is available on this machine, so the problem is local to this device rather than the router or upstream network.",
        evidence=[
            EvidenceItem("route", "No default gateway is present in the local route table."),
            EvidenceItem("local", "Without a default route, traffic cannot leave this machine regardless of router or ISP state."),
        ],
        remediation=[
            "Confirm the network interface is up and associated (Wi-Fi connected or Ethernet linked).",
            "Check that the interface has a valid IP address and was offered a default gateway by DHCP.",
            "Renew the DHCP lease or reconnect the interface, then re-run the diagnosis.",
        ],
    )


def _router_gateway(_: SignalSnapshot) -> Diagnosis:
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


def _captive_portal(_: SignalSnapshot) -> Diagnosis:
    return Diagnosis(
        boundary="captive-portal",
        confidence=0.97,
        summary="A captive portal is intercepting traffic — the network requires sign-in or acceptance before it will pass real internet traffic.",
        evidence=[
            EvidenceItem("gateway", "The local gateway is reachable and forwarding."),
            EvidenceItem("captive-portal", "A known-content connectivity check was intercepted (a redirect or unexpected response where an empty 204 was expected)."),
            EvidenceItem("dns", "Name resolution may appear to work because the portal answers DNS — this does not mean the internet is reachable."),
        ],
        remediation=[
            "Open a web browser and load any http:// page to trigger the portal's sign-in screen, then accept the terms or log in.",
            "If you already signed in, the session may have expired — re-open the portal page to re-authenticate.",
            "On a network you do not control (hotel, airport, café), captive sign-in is expected; on your own network, check for an interception/parental-control proxy.",
        ],
    )


def _wan_gateway(signals: SignalSnapshot) -> Diagnosis:
    return Diagnosis(
        boundary="wan-gateway",
        confidence=0.94,
        summary="The local gateway is reachable, but IP connectivity and DNS are both failing — the WAN connection appears to be down.",
        evidence=[
            _gateway_evidence(signals),
            EvidenceItem("ip-connectivity", "Direct IP connectivity (canary ping) failed."),
            EvidenceItem("dns", "DNS resolution also failed."),
        ],
        remediation=[
            "Check whether the router shows a WAN IP or PPPoE connection status.",
            "Power-cycle the modem/ONT independently of the router.",
            "If both devices power-cycled and no WAN IP appears, contact your ISP.",
        ],
    )


def _dns(signals: SignalSnapshot) -> Diagnosis:
    return Diagnosis(
        boundary="dns",
        confidence=0.96,
        summary="Raw connectivity is available, but name resolution is failing.",
        evidence=[
            _gateway_evidence(signals),
            EvidenceItem("ip-connectivity", "Direct IP connectivity still works."),
            EvidenceItem("dns", "DNS lookups are failing or inconsistent."),
        ],
        remediation=[
            "Retry the lookup using a known-good resolver such as 1.1.1.1 or 8.8.8.8.",
            "Inspect the router or OS DNS settings for stale or unreachable resolvers.",
            "If only one resolver fails, replace it before changing broader network settings.",
        ],
    )


def _isp_upstream(signals: SignalSnapshot) -> Diagnosis:
    return Diagnosis(
        boundary="isp-upstream",
        confidence=0.93,
        summary="The local network appears healthy, but loss is beginning after the local boundary across multiple destinations.",
        evidence=[
            _gateway_evidence(signals),
            EvidenceItem("dns", "DNS is working."),
            EvidenceItem("path", "The gateway answers normally, but packets to destinations beyond it are being lost."),
            EvidenceItem("breadth", "At least two independent external destinations show the same loss, measured by direct echo replies rather than traceroute."),
        ],
        remediation=[
            "Repeat the run twice more over a 10-15 minute window to confirm it is not a transient spike.",
            "Bypass the router if practical to separate ISP issues from router firmware or NAT pressure.",
            "Escalate to the ISP with timestamps, packet loss, and the fact that multiple targets degrade similarly.",
        ],
    )


def _remote_service(_: SignalSnapshot) -> Diagnosis:
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


def _healthy(signals: SignalSnapshot) -> Diagnosis:
    # Why a positive verdict exists at all:
    # The fault rules above only fire on a *detected* failure. Before this row,
    # an all-green connection matched nothing and fell through to `inconclusive`
    # at 0.5 — i.e. a perfectly working connection was reported identically to
    # "I couldn't tell." That erodes trust: a user running the tool when things
    # are fine got an "I don't know" instead of an "all checks passed." A
    # `healthy` verdict asserts the difference — the green path was actively
    # probed (gateway, DNS, IP, controls, target, no path loss), not merely
    # unmatched. Confidence is 0.9, not 0.99: health is a point-in-time snapshot
    # that a later run can revise, so we stop short of the "direct, repeated
    # evidence" tier the confidence model reserves for 0.99.
    return Diagnosis(
        boundary="healthy",
        confidence=0.9,
        summary="All checks passed: the gateway, DNS, direct connectivity, control hosts, and the target service are reachable with no path loss.",
        evidence=[
            _gateway_evidence(signals),
            EvidenceItem("dns", "Name resolution is working."),
            EvidenceItem("ip-connectivity", "Direct IP connectivity is healthy."),
            EvidenceItem("controls", "Known-good internet controls are reachable."),
            EvidenceItem("target", "The target service is reachable."),
        ],
        remediation=[
            "No action needed — connectivity is healthy as of this run.",
            "If you are troubleshooting an intermittent issue, re-run during the failure window to capture it.",
        ],
    )


def _inconclusive(signals: SignalSnapshot) -> Diagnosis:
    evidence = [
        EvidenceItem("gateway", "reachable" if signals.gateway_reachable else "unreachable"),
        EvidenceItem("dns", "ok" if signals.dns_ok else "failed"),
        EvidenceItem("ip-connectivity", "ok" if signals.ip_connectivity_ok else "failed"),
        EvidenceItem("controls", "ok" if signals.control_hosts_ok else "failed"),
        EvidenceItem("target", "reachable" if signals.target_service_ok else "failed"),
        EvidenceItem("coverage", "Signal set did not isolate a single boundary cleanly."),
    ]
    return Diagnosis(
        boundary="inconclusive",
        confidence=0.5,
        summary="The current signal set does not isolate the boundary cleanly.",
        evidence=evidence,
        remediation=[
            "Collect gateway, DNS, and at least one control-host result in the same run.",
            "Repeat the diagnostics to rule out a transient failure before drawing a conclusion.",
        ],
    )


# Ordered narrowest-certain-first; the first matching row wins. local-device
# precedes router-gateway so a missing default route is not absorbed by the
# broader gateway-down row. The final row matches everything (catch-all).
#
# Gateway rows key on `gateway_functional` (gateway answered ICMP OR traffic
# provably traversed it), NOT raw `gateway_reachable`. This is deliberate: a
# gateway that filters ICMP echo to itself but forwards traffic normally is
# common (WSL2 NAT, cloud VMs, hardened/corporate routers). Keying on
# `gateway_reachable` alone falsely accused the LAN boundary at 0.99 confidence
# whenever the gateway was reachable-through but not pingable, while DNS, the
# canary, and control hosts were all green. `gateway_functional` ensures the
# gateway is only blamed when external reachability *also* fails (see model
# property for the full rationale).
RULES: list[Rule] = [
    # Must precede local-device: a host with no v4 default route but a working
    # v6 one is not "the problem is local to this device" — that would be a
    # confident misdiagnosis. On a normal dual-stack host gateway_functional is
    # True, so this rule never fires there; v6 presence is don't-care whenever
    # v4 already works.
    Rule(
        "ipv6-only",
        {"gateway_functional": False, "default_route_present": False, "ipv6_default_route_present": True},
        _ipv6_only,
    ),
    Rule("local-device", {"gateway_functional": False, "default_route_present": False}, _local_device),
    Rule("router-gateway", {"gateway_functional": False}, _router_gateway),
    # Captive portal is decisive and must precede every rule that keys on the
    # (portal-faked) green signals — DNS, ISP, remote-service, and healthy would
    # all misfire otherwise. The `gateway_functional` guard makes the invariant
    # explicit (a portal is only reachable when the gateway forwards) so the
    # build's "gateway is forwarding" evidence stays true regardless of row order.
    Rule("captive-portal", {"gateway_functional": True, "captive_portal_detected": True}, _captive_portal),
    Rule("wan-gateway", {"gateway_functional": True, "ip_connectivity_ok": False, "dns_ok": False}, _wan_gateway),
    Rule("dns", {"ip_connectivity_ok": True, "dns_ok": False}, _dns),
    Rule(
        "isp-upstream",
        {"gateway_functional": True, "dns_ok": True, "packet_loss_after_hop1": True, "packet_loss_multiple_targets": True},
        _isp_upstream,
    ),
    Rule(
        "remote-service",
        {"gateway_functional": True, "dns_ok": True, "control_hosts_ok": True, "target_service_ok": False},
        _remote_service,
    ),
    # Positive verdict: every fault signal green. Must precede the inconclusive
    # catch-all so an all-healthy connection is affirmed, not reported as unknown.
    Rule(
        "healthy",
        {
            "gateway_functional": True,
            "dns_ok": True,
            "ip_connectivity_ok": True,
            "control_hosts_ok": True,
            "target_service_ok": True,
            "packet_loss_after_hop1": False,
            "packet_loss_multiple_targets": False,
        },
        _healthy,
    ),
    Rule("inconclusive", {}, _inconclusive),
]

# Single source of truth for the boundary vocabulary, derived from the table.
BOUNDARIES: tuple[str, ...] = tuple(rule.boundary for rule in RULES)


def diagnose(signals: SignalSnapshot) -> Diagnosis:
    for rule in RULES:
        if rule.matches(signals):
            return rule.build(signals)
    # The final rule has an empty match and always fires, so this is unreachable.
    raise AssertionError("decision table has no catch-all rule")  # pragma: no cover


# Boundaries an external vantage can disambiguate: both depend on whether the
# target is reachable from somewhere *other* than this connection — a question a
# single machine cannot answer. All other verdicts pass through refine unchanged.
_VANTAGE_REFINABLE: frozenset[str] = frozenset({"isp-upstream", "remote-service"})


def refine(diagnosis: Diagnosis, vantage: VantageSlice) -> Diagnosis:
    """Apply an optional external-vantage result to a base diagnosis.

    Pure and advisory by design. Returns the diagnosis byte-for-byte unchanged
    unless (1) the vantage was consulted with a definite answer AND (2) the base
    boundary is one a vantage can disambiguate. It NEVER changes the boundary in
    v1 — only nudges confidence and appends an evidence line — so a misbehaving,
    compromised, or upstream-correlated vantage cannot flip a verdict a user
    escalates on. Network I/O happens in the collector; this stays pure so the
    256-combo coverage guarantee on ``diagnose`` is untouched.
    """
    if not vantage.consulted or vantage.target_reachable_externally is None:
        return diagnosis
    if diagnosis.boundary not in _VANTAGE_REFINABLE:
        return diagnosis

    reachable = vantage.target_reachable_externally
    evidence = list(diagnosis.evidence)
    confidence = diagnosis.confidence

    if diagnosis.boundary == "remote-service":
        if not reachable:
            confidence = min(0.99, confidence + 0.03)
            evidence.append(EvidenceItem(
                "vantage",
                "An independent external vantage also could not reach the target — "
                "it appears down for everyone, not just this network.",
            ))
        else:
            confidence = max(0.50, confidence - 0.15)
            evidence.append(EvidenceItem(
                "vantage",
                "An external vantage CAN reach the target — the failure may be "
                "specific to this connection's path, not the service itself.",
            ))
    else:  # isp-upstream
        if reachable:
            confidence = min(0.99, confidence + 0.04)
            evidence.append(EvidenceItem(
                "vantage",
                "An external vantage reached the target — the loss is on this "
                "connection's path, not a widespread outage.",
            ))
        else:
            evidence.append(EvidenceItem(
                "vantage",
                "An external vantage also failed to reach the target — a wider "
                "upstream outage is possible; re-run to confirm.",
            ))

    return Diagnosis(
        boundary=diagnosis.boundary,
        confidence=confidence,
        summary=diagnosis.summary,
        evidence=evidence,
        remediation=list(diagnosis.remediation),
    )
