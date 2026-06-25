from __future__ import annotations

from dataclasses import dataclass

from boundary_probe.collectors._commands import ping_cmd
from boundary_probe.collectors._parsers import parse_ping_output
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.config import ProbeConfig, load_config


@dataclass(slots=True, frozen=True)
class IpConnectivitySlice:
    ok: bool
    target_ip: str
    loss_pct: float
    avg_rtt_ms: float | None
    note: str


def collect_ip_connectivity(
    runner: SubprocessRunner | None = None,
    *,
    cfg: ProbeConfig | None = None,
    canary_ip: str | None = None,
    loss_pct_threshold: float | None = None,
    timeout_s: float | None = None,
) -> IpConnectivitySlice:
    """Ping a canary IP directly to confirm raw IP path works independent of DNS."""
    cfg = cfg if cfg is not None else load_config()
    r = runner or DefaultRunner()
    _canary = canary_ip if canary_ip is not None else cfg.canary_ip
    _loss_pct = loss_pct_threshold if loss_pct_threshold is not None else cfg.ip_loss_pct
    _timeout = timeout_s if timeout_s is not None else cfg.ip_connectivity_s

    result = r.run(ping_cmd(_canary, 10, 1000), timeout_s=_timeout)

    if result.timed_out:
        return IpConnectivitySlice(ok=False, target_ip=_canary, loss_pct=100.0,
                                   avg_rtt_ms=None, note=f"ping timed out after {_timeout:.0f}s")

    stats = parse_ping_output(result.stdout)
    if not stats.parsed:
        return IpConnectivitySlice(ok=False, target_ip=_canary, loss_pct=100.0,
                                   avg_rtt_ms=None, note="unrecognized output format from ping")

    # sent > 0 rejects the degenerate "0 transmitted … 0% loss" line, which would
    # otherwise read as healthy connectivity off zero actual probes.
    ok = stats.sent > 0 and stats.loss_pct < _loss_pct
    return IpConnectivitySlice(
        ok=ok,
        target_ip=_canary,
        loss_pct=stats.loss_pct,
        avg_rtt_ms=stats.avg_ms,
        note="" if ok else f"{stats.loss_pct:.0f}% packet loss to {_canary}",
    )
