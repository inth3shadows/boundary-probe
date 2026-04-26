from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SignalSnapshot:
    gateway_reachable: bool
    dns_ok: bool
    ip_connectivity_ok: bool
    control_hosts_ok: bool
    target_service_ok: bool
    packet_loss_after_hop1: bool = False
    packet_loss_multiple_targets: bool = False


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

