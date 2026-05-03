from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from boundary_probe.collectors._commands import ping_cmd
from boundary_probe.collectors._parsers import parse_ping_output
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.config import load_config


@dataclass(slots=True, frozen=True)
class ControlHostResult:
    host: str
    reachable: bool
    loss_pct: float
    avg_rtt_ms: float | None


@dataclass(slots=True, frozen=True)
class ControlHostsSlice:
    all_ok: bool
    ok_count: int
    total: int
    results: list[ControlHostResult]
    note: str


def _probe_one(
    host: str,
    runner: SubprocessRunner,
    loss_pct_threshold: float,
    timeout_s: float,
) -> ControlHostResult:
    result = runner.run(ping_cmd(host, 10, 1000), timeout_s=timeout_s)
    if result.timed_out:
        return ControlHostResult(host=host, reachable=False, loss_pct=100.0, avg_rtt_ms=None)
    stats = parse_ping_output(result.stdout)
    reachable = stats.sent > 0 and stats.loss_pct < loss_pct_threshold
    return ControlHostResult(host=host, reachable=reachable, loss_pct=stats.loss_pct, avg_rtt_ms=stats.avg_ms)


def collect_control_hosts(
    runner: SubprocessRunner | None = None,
    *,
    hosts: tuple[str, ...] | None = None,
    quorum: int | None = None,
    loss_pct_threshold: float | None = None,
    timeout_s: float | None = None,
) -> ControlHostsSlice:
    """Ping all control hosts in parallel. all_ok = ≥quorum reachable."""
    cfg = load_config()
    r = runner or DefaultRunner()
    _hosts = hosts if hosts is not None else cfg.control_hosts
    _quorum = quorum if quorum is not None else cfg.control_quorum
    _loss_pct = loss_pct_threshold if loss_pct_threshold is not None else cfg.control_loss_pct
    _timeout = timeout_s if timeout_s is not None else cfg.control_hosts_s

    results: list[ControlHostResult] = []
    with ThreadPoolExecutor(max_workers=len(_hosts)) as pool:
        futures = {pool.submit(_probe_one, host, r, _loss_pct, _timeout): host for host in _hosts}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: list(_hosts).index(x.host))
    ok_count = sum(1 for result in results if result.reachable)
    all_ok = ok_count >= _quorum

    note = "" if all_ok else f"only {ok_count}/{len(_hosts)} control hosts reachable"
    return ControlHostsSlice(all_ok=all_ok, ok_count=ok_count, total=len(_hosts), results=results, note=note)
