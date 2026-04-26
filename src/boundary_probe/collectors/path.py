from __future__ import annotations

from dataclasses import dataclass, field

from boundary_probe.collectors._parsers import parse_tracert_output
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner


@dataclass(slots=True, frozen=True)
class PathSlice:
    raw_hops: list[dict]
    target: str
    completed: bool
    note: str


def collect_path(target_host: str, runner: SubprocessRunner | None = None) -> PathSlice:
    """Run `tracert -4 -h 10 -w 500 <target>` and parse the hop table."""
    r = runner or DefaultRunner()
    result = r.run(["tracert", "-4", "-h", "10", "-w", "500", target_host], timeout_s=30.0)

    if result.timed_out:
        return PathSlice(raw_hops=[], target=target_host, completed=False,
                         note="tracert timed out after 30s")

    hops = parse_tracert_output(result.stdout)
    completed = len(hops) >= 2
    note = "" if completed else "fewer than 2 hops parsed from tracert output"
    return PathSlice(raw_hops=hops, target=target_host, completed=completed, note=note)
