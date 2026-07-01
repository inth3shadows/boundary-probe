from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SignalSnapshot:
    gateway_reachable: bool
    dns_ok: bool
    ip_connectivity_ok: bool
    control_hosts_ok: bool
    target_service_ok: bool
    # True when a usable default route exists. False distinguishes a local-device
    # fault (no default gateway in the route table) from a router-gateway fault
    # (gateway present but unresponsive) — both otherwise look like gateway_reachable=False.
    default_route_present: bool = True
    packet_loss_after_hop1: bool = False
    packet_loss_multiple_targets: bool = False
    # True when a known-content connectivity check was intercepted (a redirect or
    # a non-204 body where an empty 204 was expected) — the fingerprint of a
    # captive portal. Decisive: a portal makes every ICMP/DNS signal read green,
    # so without this the engine would call a hijacked network `healthy`.
    captive_portal_detected: bool = False
    # True when an IPv6 default route exists (presence only, no v6 probing).
    # Guards against the local-device rule confidently blaming this device when
    # v4 has no default route but v6 does — the internet may be fine over v6,
    # which this tool does not yet probe. Don't-care on any host with a working
    # v4 default route (gateway_functional=True), so behavior is unchanged for
    # normal dual-stack hosts.
    ipv6_default_route_present: bool = False

    @property
    def gateway_functional(self) -> bool:
        """Whether the gateway is functionally healthy (forwarding traffic).

        True if the gateway answered ICMP directly (``gateway_reachable``) OR
        traffic provably traversed it to reach an external host
        (``ip_connectivity_ok`` or ``control_hosts_ok``). ICMP echo *to* a
        gateway is an unreliable liveness signal — many gateways and NATs
        filter or de-prioritize it while forwarding normally (the same reason
        ``normalizer`` distrusts hop-1 ICMP for path loss). Reaching anything
        beyond the gateway is direct proof it forwards, so an unanswered
        gateway ping must not, on its own, accuse the LAN boundary. The engine
        keys gateway-related rules on this, not on ``gateway_reachable``.
        """
        return self.gateway_reachable or self.ip_connectivity_ok or self.control_hosts_ok


@dataclass(slots=True, frozen=True)
class VantageSlice:
    """Result of an optional external-vantage reachability check.

    Carries a tri-state: ``consulted`` is False when no vantage was configured
    or the call failed (fail-open), in which case ``target_reachable_externally``
    is None and the engine refinement is a no-op. This is deliberately NOT a
    field on ``SignalSnapshot`` — it must never enter the pure decision table;
    it is applied after classification by ``engine.refine``.
    """

    consulted: bool
    target_reachable_externally: bool | None
    note: str
    latency_ms: float | None = None


@dataclass(slots=True)
class EvidenceItem:
    label: str
    detail: str


@dataclass(slots=True)
class Diagnosis:
    boundary: str
    confidence: float
    summary: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)

