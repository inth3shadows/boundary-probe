"""Path signal normalizer for tracert/pathping output.

Responsible for converting raw hop-by-hop probe data into a stable boolean
signal set before the classification engine sees it. The engine must never
receive raw per-hop tables — it consumes PathSignals only.

Key invariant this module enforces:
  Single-hop ICMP loss is NOT counted as packet_loss_after_hop1 unless loss
  *persists* at hop N+1 or N+2. Many provider edge routers de-prioritize
  ICMP TTL-exceeded responses while forwarding traffic normally. Counting
  a single non-responding hop as loss would misfire the isp-upstream rule
  on the majority of healthy corporate and residential networks.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING

from boundary_probe.config import load_config

if TYPE_CHECKING:
    from boundary_probe.collectors.path import PathSlice
    from boundary_probe.config import ProbeConfig

_LOSS_THRESHOLD_PCT = 20.0  # fallback used only when config is unavailable


@dataclass(slots=True)
class PathSignals:
    """Normalized path signals derived from raw hop data."""

    packet_loss_after_hop1: bool = False
    packet_loss_multiple_targets: bool = False


def normalize_path_signals(
    raw_hops: list[dict],
    secondary_hops: list[dict] | None = None,
    *,
    path_loss_pct: float | None = None,
) -> PathSignals:
    """Derive stable PathSignals from raw hop records.

    Args:
        raw_hops: Hop dicts from the path collector (keys: index, loss_pct, rtt_ms, host).
        secondary_hops: Optional second-target hop list for packet_loss_multiple_targets.

    Returns:
        PathSignals with conservative loss assessment.
    """
    threshold = path_loss_pct if path_loss_pct is not None else load_config().path_loss_pct

    for hop in raw_hops:
        host = hop.get("host", "")
        if ":" in host:
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                pass  # not a valid IP literal (e.g. a hostname with a colon) — ignore
            else:
                if isinstance(addr, ipaddress.IPv6Address):
                    raise ValueError(f"IPv6 hop in trace; collector should have rejected this: {host!r}")

    primary_loss = _has_persistent_loss(raw_hops, threshold)

    if not primary_loss or secondary_hops is None:
        return PathSignals(packet_loss_after_hop1=primary_loss, packet_loss_multiple_targets=False)

    secondary_loss = _has_persistent_loss(secondary_hops, threshold)
    return PathSignals(
        packet_loss_after_hop1=primary_loss,
        packet_loss_multiple_targets=secondary_loss,
    )


def _has_persistent_loss(hops: list[dict], threshold: float = _LOSS_THRESHOLD_PCT) -> bool:
    """Return True if any hop at index ≥ 2 shows persistent loss (sustained across look-ahead)."""
    if len(hops) < 2:
        return False

    hop_by_index = {h["index"]: h for h in hops}
    last_index = max(hop_by_index)

    for hop in hops:
        idx = hop["index"]
        if idx < 2:
            continue

        current_lossy = hop["loss_pct"] > threshold
        if not current_lossy:
            continue

        # The destination (final hop) showing loss is loss reaching the target;
        # count it on its own — there is nothing downstream to corroborate.
        if idx == last_index:
            return True

        # Otherwise the loss must persist into an *observed* downstream hop. An
        # absent look-ahead index means past the end of the trace, not loss —
        # treating it as lossy would re-flag an isolated mid-path hop whose
        # destination is healthy, the exact case this module exists to exclude.
        next1 = hop_by_index.get(idx + 1)
        next2 = hop_by_index.get(idx + 2)

        next1_lossy = next1 is not None and next1["loss_pct"] > threshold
        next2_lossy = next2 is not None and next2["loss_pct"] > threshold

        if next1_lossy or next2_lossy:
            return True

    return False


def normalize_from_paths(
    primary: "PathSlice",
    secondary: "PathSlice | None",
    *,
    cfg: "ProbeConfig | None" = None,
) -> PathSignals:
    """Adapter called by orchestrator. Incomplete primary trace returns no signal."""
    if not primary.completed:
        return PathSignals(packet_loss_after_hop1=False, packet_loss_multiple_targets=False)

    secondary_hops = secondary.raw_hops if secondary is not None else None
    # Reuse the orchestrator's already-loaded config when provided, else load.
    threshold = cfg.path_loss_pct if cfg is not None else load_config().path_loss_pct
    return normalize_path_signals(primary.raw_hops, secondary_hops, path_loss_pct=threshold)


def normalize_from_pings(
    gateway_reachable: bool,
    canary_loss_pct: float | None,
    control_losses: list[float],
    *,
    remote_loss_pct: float | None = None,
) -> PathSignals:
    """Derive the isp-upstream loss signals from ping loss, not traceroute hops.

    This is the load-bearing path. It replaced hop-derived signals because the two
    measurements are not equivalent in either resolution or meaning:

    * Resolution. traceroute sends 3 probes per hop, so a hop's loss is one of
      {0, 33.3, 66.7, 100} — coarser than any threshold worth setting, and the
      reason the threshold could never be calibrated (issue #41). Each ping here
      sends 10, across 5 independent destinations (canary + control hosts), so
      loss resolves to 10pp per target and roughly 2pp aggregated.
    * Meaning. A traceroute hop reports whether a router *generated* an ICMP
      TTL-expired reply, which routers commonly rate-limit on the control plane
      while forwarding traffic normally. An echo reply reports whether the data
      plane actually carried the packet — the thing the user is complaining about.

    ``packet_loss_after_hop1`` means loss that begins beyond the first hop: the
    gateway answers, but independent remote destinations do not. ``packet_loss_
    multiple_targets`` requires at least two independent destinations, so one dead
    remote host cannot alone produce an ISP verdict.
    """
    threshold = remote_loss_pct if remote_loss_pct is not None else load_config().remote_loss_pct

    losses = [l for l in ([canary_loss_pct] + list(control_losses)) if l is not None]
    lossy = [l for l in losses if l > threshold]

    # Without a working gateway the fault is at or below hop 1, and any remote
    # loss is a downstream consequence — attributing it upstream would blame the
    # ISP for a dead router. The router-gateway / local-device rules own that case.
    after_hop1 = bool(gateway_reachable and lossy)
    return PathSignals(
        packet_loss_after_hop1=after_hop1,
        packet_loss_multiple_targets=after_hop1 and len(lossy) >= 2,
    )
