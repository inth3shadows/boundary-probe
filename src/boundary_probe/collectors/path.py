from __future__ import annotations

from dataclasses import dataclass

from boundary_probe.collectors._commands import traceroute_cmd
from boundary_probe.collectors._parsers import parse_tracert_output
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.config import ProbeConfig, load_config


@dataclass(slots=True, frozen=True)
class PathSlice:
    raw_hops: list[dict]
    target: str
    completed: bool
    note: str


def collect_path(
    target_host: str,
    runner: SubprocessRunner | None = None,
    *,
    cfg: ProbeConfig | None = None,
    timeout_s: float | None = None,
) -> PathSlice:
    """Run `tracert -4 -h 10 -w 500 <target>` and parse the hop table."""
    cfg = cfg if cfg is not None else load_config()
    r = runner or DefaultRunner()
    _timeout = timeout_s if timeout_s is not None else cfg.tracert_s

    result = r.run(traceroute_cmd(target_host, 10, 500), timeout_s=_timeout)

    if result.timed_out:
        return PathSlice(raw_hops=[], target=target_host, completed=False,
                         note=f"tracert timed out after {_timeout:.0f}s")

    hops = parse_tracert_output(result.stdout)
    completed = len(hops) >= 2
    note = "" if completed else "fewer than 2 hops parsed from tracert output"
    return PathSlice(raw_hops=hops, target=target_host, completed=completed, note=note)
