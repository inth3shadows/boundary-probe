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

_LOSS_THRESHOLD_PCT = 20.0  # module-level default; overridden by config at runtime


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
                if isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address):
                    raise ValueError(f"IPv6 hop in trace; collector should have rejected this: {host!r}")
            except ValueError as exc:
                if "IPv6 hop" in str(exc):
                    raise

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

    for hop in hops:
        idx = hop["index"]
        if idx < 2:
            continue

        current_lossy = hop["loss_pct"] > threshold
        if not current_lossy:
            continue

        next1 = hop_by_index.get(idx + 1)
        next2 = hop_by_index.get(idx + 2)

        next1_lossy = next1["loss_pct"] > threshold if next1 is not None else True
        next2_lossy = next2["loss_pct"] > threshold if next2 is not None else True

        if next1_lossy or next2_lossy:
            return True

    return False


def normalize_from_paths(
    primary: "PathSlice",
    secondary: "PathSlice | None",
) -> PathSignals:
    """Adapter called by orchestrator. Incomplete primary trace returns no signal."""
    if not primary.completed:
        return PathSignals(packet_loss_after_hop1=False, packet_loss_multiple_targets=False)

    secondary_hops = secondary.raw_hops if secondary is not None else None
    return normalize_path_signals(primary.raw_hops, secondary_hops)
