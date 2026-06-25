from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from boundary_probe.collectors._commands import ping_cmd
from boundary_probe.collectors._parsers import parse_ping_output
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.config import ProbeConfig, load_config
from boundary_probe.targets import ParsedTarget

_SCHEME_PORTS = {"http": 80, "https": 443}


@dataclass(slots=True, frozen=True)
class TargetServiceSlice:
    ok: bool
    method: str
    target_host: str
    target_port: int | None
    elapsed_ms: int
    note: str


def collect_target_service(
    parsed_target: ParsedTarget,
    runner: SubprocessRunner | None = None,
    *,
    cfg: ProbeConfig | None = None,
    loss_pct_threshold: float | None = None,
    timeout_s: float | None = None,
    tcp_timeout_s: float | None = None,
) -> TargetServiceSlice:
    """TCP connect if port is known; otherwise ping the host."""
    port: int | None = parsed_target.port
    if port is None and parsed_target.scheme in _SCHEME_PORTS:
        port = _SCHEME_PORTS[parsed_target.scheme]

    cfg = cfg if cfg is not None else load_config()
    if port is not None:
        _tcp = tcp_timeout_s if tcp_timeout_s is not None else cfg.target_tcp_s
        return _tcp_connect(parsed_target.host, port, _tcp)

    _loss_pct = loss_pct_threshold if loss_pct_threshold is not None else cfg.ip_loss_pct
    _timeout = timeout_s if timeout_s is not None else cfg.target_ping_s
    return _ping_host(parsed_target.host, runner or DefaultRunner(), _loss_pct, _timeout)


def _tcp_connect(host: str, port: int, timeout_s: float) -> TargetServiceSlice:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            return TargetServiceSlice(ok=True, method="tcp-connect", target_host=host,
                                      target_port=port, elapsed_ms=elapsed_ms, note="")
    except OSError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return TargetServiceSlice(ok=False, method="tcp-connect", target_host=host,
                                  target_port=port, elapsed_ms=elapsed_ms, note=str(exc))


def _ping_host(host: str, runner: SubprocessRunner, loss_pct_threshold: float, timeout_s: float) -> TargetServiceSlice:
    t0 = time.monotonic()
    result = runner.run(ping_cmd(host, 4, 1000), timeout_s=timeout_s)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    if result.timed_out:
        return TargetServiceSlice(ok=False, method="ping", target_host=host,
                                  target_port=None, elapsed_ms=elapsed_ms,
                                  note=f"ping timed out after {timeout_s:.0f}s")

    stats = parse_ping_output(result.stdout)
    if not stats.parsed:
        # Don't assert a fabricated loss % off output we couldn't read; say so.
        return TargetServiceSlice(ok=False, method="ping", target_host=host,
                                  target_port=None, elapsed_ms=elapsed_ms,
                                  note=f"unrecognized output format from ping to {host}")
    # sent > 0 rejects a degenerate "0 transmitted … 0% loss" summary reading as up.
    ok = stats.sent > 0 and stats.loss_pct < loss_pct_threshold
    return TargetServiceSlice(
        ok=ok,
        method="ping",
        target_host=host,
        target_port=None,
        elapsed_ms=elapsed_ms,
        note="" if ok else f"{stats.loss_pct:.0f}% packet loss pinging {host}",
    )
