from __future__ import annotations

import pytest

from boundary_probe.normalizer import PathSignals, normalize_path_signals


def _hop(index: int, loss_pct: float, host: str = "10.0.0.1") -> dict:
    return {"index": index, "loss_pct": loss_pct, "rtt_ms": None if loss_pct == 100.0 else 10.0, "host": host}


# ---------------------------------------------------------------------------
# Empty / short input
# ---------------------------------------------------------------------------


def test_empty_hops_returns_no_signal():
    result = normalize_path_signals([])
    assert result == PathSignals(False, False)


def test_single_hop_returns_no_signal():
    result = normalize_path_signals([_hop(1, 0.0)])
    assert result == PathSignals(False, False)


# ---------------------------------------------------------------------------
# Single-hop loss (edge router silence) must NOT trigger
# ---------------------------------------------------------------------------


def test_single_bad_hop_does_not_trigger_when_next_is_clean():
    hops = [
        _hop(1, 0.0),
        _hop(2, 100.0),   # edge router silent
        _hop(3, 0.0),     # next hop clean
        _hop(4, 0.0),
    ]
    result = normalize_path_signals(hops)
    assert result.packet_loss_after_hop1 is False


def test_tracert_edge_router_only_does_not_trigger():
    hops = [
        _hop(1, 0.0, "192.168.1.1"),
        _hop(2, 100.0, "*"),           # silent edge router
        _hop(3, 0.0, "68.86.91.1"),
        _hop(4, 0.0, "93.184.216.34"),
    ]
    result = normalize_path_signals(hops)
    assert result.packet_loss_after_hop1 is False


# ---------------------------------------------------------------------------
# Sustained loss from hop 3 must trigger
# ---------------------------------------------------------------------------


def test_sustained_loss_from_hop3_triggers():
    hops = [
        _hop(1, 0.0),
        _hop(2, 0.0),
        _hop(3, 100.0),
        _hop(4, 100.0),
        _hop(5, 100.0),
    ]
    result = normalize_path_signals(hops)
    assert result.packet_loss_after_hop1 is True


def test_loss_above_threshold_triggers():
    hops = [
        _hop(1, 0.0),
        _hop(2, 0.0),
        _hop(3, 33.0),   # 1 of 3 probes lost — above 20% threshold
        _hop(4, 33.0),
    ]
    result = normalize_path_signals(hops)
    assert result.packet_loss_after_hop1 is True


def test_loss_below_threshold_does_not_trigger():
    hops = [
        _hop(1, 0.0),
        _hop(2, 0.0),
        _hop(3, 15.0),   # below 20% threshold
        _hop(4, 15.0),
    ]
    result = normalize_path_signals(hops)
    assert result.packet_loss_after_hop1 is False


# ---------------------------------------------------------------------------
# Loss on last hops (no look-ahead neighbours = treated as persistent)
# ---------------------------------------------------------------------------


def test_loss_on_final_hop_with_no_neighbours_triggers():
    hops = [
        _hop(1, 0.0),
        _hop(2, 0.0),
        _hop(3, 100.0),
    ]
    result = normalize_path_signals(hops)
    assert result.packet_loss_after_hop1 is True


# ---------------------------------------------------------------------------
# packet_loss_multiple_targets requires secondary trace
# ---------------------------------------------------------------------------


def test_secondary_none_keeps_multiple_targets_false():
    hops = [_hop(1, 0.0), _hop(2, 0.0), _hop(3, 100.0), _hop(4, 100.0)]
    result = normalize_path_signals(hops, secondary_hops=None)
    assert result.packet_loss_after_hop1 is True
    assert result.packet_loss_multiple_targets is False


def test_secondary_with_loss_sets_multiple_targets_true():
    lossy = [_hop(1, 0.0), _hop(2, 0.0), _hop(3, 100.0), _hop(4, 100.0)]
    result = normalize_path_signals(lossy, secondary_hops=lossy)
    assert result.packet_loss_after_hop1 is True
    assert result.packet_loss_multiple_targets is True


def test_secondary_clean_keeps_multiple_targets_false():
    lossy = [_hop(1, 0.0), _hop(2, 0.0), _hop(3, 100.0), _hop(4, 100.0)]
    clean = [_hop(1, 0.0), _hop(2, 0.0), _hop(3, 0.0), _hop(4, 0.0)]
    result = normalize_path_signals(lossy, secondary_hops=clean)
    assert result.packet_loss_after_hop1 is True
    assert result.packet_loss_multiple_targets is False


# ---------------------------------------------------------------------------
# IPv6 hop raises ValueError
# ---------------------------------------------------------------------------


def test_ipv6_hop_raises():
    hops = [
        _hop(1, 0.0, "192.168.1.1"),
        {"index": 2, "loss_pct": 0.0, "rtt_ms": 10.0, "host": "2001:db8::1"},
    ]
    with pytest.raises(ValueError, match="IPv6 hop"):
        normalize_path_signals(hops)
