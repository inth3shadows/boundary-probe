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

from dataclasses import dataclass


@dataclass(slots=True)
class PathSignals:
    """Normalized path signals derived from raw hop data.

    Matches the two path-related fields on SignalSnapshot so Phase 1 can
    substitute this type cleanly when the rich-facts model lands.
    """

    packet_loss_after_hop1: bool = False
    packet_loss_multiple_targets: bool = False


def normalize_path_signals(raw_hops: list) -> PathSignals:
    """Derive stable PathSignals from a list of raw hop records.

    Args:
        raw_hops: List of per-hop dicts as returned by the Phase 1 path
            collector. Expected keys per hop: ``index`` (int, 1-based),
            ``loss_pct`` (float 0-100), ``rtt_ms`` (float | None).

    Returns:
        PathSignals with conservative loss assessment.

    Algorithm (to be implemented in Phase 1 alongside the path collector):
        1. Skip hop 1 (local gateway — handled by gateway collector).
        2. For each hop H from index 2 onward:
           - Mark as "lossy" only if loss_pct > 20% AND at least one of
             hop H+1 or H+2 also exceeds 20% loss (or is absent, meaning
             all subsequent hops timed out — that counts as persistent loss).
        3. packet_loss_after_hop1 = True if any hop from index 2 is lossy.
        4. Requires data from at least two independent target traces to set
           packet_loss_multiple_targets = True (caller responsibility).

    Notes:
        - IPv4-only. IPv6 trace data is rejected at the collector level.
        - Windows codepage: collector must decode tracert output as cp437
          before passing raw_hops here.
        - The 20% threshold is provisional; Phase 5 calibration will tune it.
    """
    raise NotImplementedError("path normalizer lands with Phase 1 path collector")
