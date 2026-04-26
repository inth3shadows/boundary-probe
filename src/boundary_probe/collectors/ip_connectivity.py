from __future__ import annotations

from dataclasses import dataclass

from boundary_probe.collectors._parsers import parse_ping_output
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner

_CANARY_IP = "1.1.1.1"


@dataclass(slots=True, frozen=True)
class IpConnectivitySlice:
    ok: bool
    target_ip: str
    loss_pct: float
    avg_rtt_ms: float | None
    note: str


def collect_ip_connectivity(runner: SubprocessRunner | None = None) -> IpConnectivitySlice:
    """Ping 1.1.1.1 directly to confirm raw IP path works independent of DNS."""
    r = runner or DefaultRunner()
    result = r.run(["ping", "-4", "-n", "10", "-w", "1000", _CANARY_IP], timeout_s=15.0)

    if result.timed_out:
        return IpConnectivitySlice(ok=False, target_ip=_CANARY_IP, loss_pct=100.0,
                                   avg_rtt_ms=None, note="ping timed out after 15s")

    stats = parse_ping_output(result.stdout)
    if stats.sent == 0:
        return IpConnectivitySlice(ok=False, target_ip=_CANARY_IP, loss_pct=100.0,
                                   avg_rtt_ms=None, note="unrecognized output format from ping")

    ok = stats.loss_pct < 50.0
    return IpConnectivitySlice(
        ok=ok,
        target_ip=_CANARY_IP,
        loss_pct=stats.loss_pct,
        avg_rtt_ms=stats.avg_ms,
        note="" if ok else f"{stats.loss_pct:.0f}% packet loss to {_CANARY_IP}",
    )
