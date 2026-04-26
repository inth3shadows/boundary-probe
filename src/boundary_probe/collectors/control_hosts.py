from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from boundary_probe.collectors._parsers import parse_ping_output
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner

CONTROL_HOSTS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "8.8.4.4", "cloudflare.com")
_QUORUM = 3


@dataclass(slots=True, frozen=True)
class ControlHostResult:
    host: str
    reachable: bool
    loss_pct: float
    avg_rtt_ms: float | None


@dataclass(slots=True, frozen=True)
class ControlHostsSlice:
    all_ok: bool
    results: list[ControlHostResult]
    note: str


def _probe_one(host: str, runner: SubprocessRunner) -> ControlHostResult:
    result = runner.run(["ping", "-4", "-n", "10", "-w", "1000", host], timeout_s=10.0)
    if result.timed_out:
        return ControlHostResult(host=host, reachable=False, loss_pct=100.0, avg_rtt_ms=None)
    stats = parse_ping_output(result.stdout)
    reachable = stats.sent > 0 and stats.loss_pct < 50.0
    return ControlHostResult(host=host, reachable=reachable, loss_pct=stats.loss_pct, avg_rtt_ms=stats.avg_ms)


def collect_control_hosts(runner: SubprocessRunner | None = None) -> ControlHostsSlice:
    """Ping all 4 control hosts in parallel. all_ok = ≥3 of 4 reachable."""
    r = runner or DefaultRunner()
    results: list[ControlHostResult] = []

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(_probe_one, host, r): host for host in CONTROL_HOSTS}
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda x: CONTROL_HOSTS.index(x.host))
    reachable_count = sum(1 for r in results if r.reachable)
    all_ok = reachable_count >= _QUORUM

    note = "" if all_ok else f"only {reachable_count}/{len(CONTROL_HOSTS)} control hosts reachable"
    return ControlHostsSlice(all_ok=all_ok, results=results, note=note)
