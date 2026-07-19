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


def test_lossy_second_to_last_hop_with_healthy_destination_does_not_trigger():
    # A single mid-path router de-prioritizes ICMP, but the destination (final
    # hop) responds cleanly. The loss did not persist to the target, so it must
    # NOT be flagged — the absent look-ahead beyond the destination is no
    # evidence of loss, only proof the trace ended.
    hops = [
        _hop(1, 0.0),
        _hop(2, 0.0),
        _hop(3, 50.0),   # lossy, second-to-last
        _hop(4, 0.0),    # destination, healthy
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


class TestPingDerivedLossSignals:
    """The isp-upstream signals key on ping loss, not traceroute hop loss.

    Hop loss resolves to {0, 33.3, 66.7, 100} at 3 probes and reports ICMP
    generation on a rate-limited control plane; these pings send 10 per target
    across independent destinations and report the data plane (issue #41).
    """

    def _n(self, gw, canary, controls, threshold=20.0):
        from boundary_probe.normalizer import normalize_from_pings
        return normalize_from_pings(gw, canary, controls, remote_loss_pct=threshold)

    def test_partial_loss_on_two_targets_is_isp_shaped(self):
        # 30% and 40% are values hop-loss could never report; this is the case
        # the old traceroute-derived signal was blind to.
        sig = self._n(True, 30.0, [40.0, 0.0, 0.0, 0.0])
        assert sig.packet_loss_after_hop1 is True
        assert sig.packet_loss_multiple_targets is True

    def test_one_lossy_target_is_not_enough_for_breadth(self):
        # A single degraded destination is that destination's problem.
        sig = self._n(True, 0.0, [40.0, 0.0, 0.0, 0.0])
        assert sig.packet_loss_after_hop1 is True
        assert sig.packet_loss_multiple_targets is False

    def test_dead_gateway_never_reads_as_upstream_loss(self):
        # Loss with a dead gateway is downstream of a local fault; blaming the
        # ISP here is the misdiagnosis this guard exists to prevent.
        sig = self._n(False, 100.0, [100.0, 100.0, 100.0, 100.0])
        assert sig.packet_loss_after_hop1 is False
        assert sig.packet_loss_multiple_targets is False

    def test_clean_network_produces_no_loss_signals(self):
        sig = self._n(True, 0.0, [0.0, 0.0, 0.0, 0.0])
        assert sig.packet_loss_after_hop1 is False
        assert sig.packet_loss_multiple_targets is False

    def test_loss_at_or_below_threshold_does_not_fire(self):
        # Strictly greater-than: 20% loss with a 20% threshold is not "over".
        sig = self._n(True, 20.0, [20.0, 20.0, 20.0, 20.0])
        assert sig.packet_loss_after_hop1 is False

    def test_threshold_resolves_ten_point_steps(self):
        # The point of the re-key: a 10pp change in one target flips the verdict,
        # which is impossible with 3-probe hop loss.
        assert self._n(True, 10.0, [10.0], threshold=15.0).packet_loss_after_hop1 is False
        assert self._n(True, 20.0, [20.0], threshold=15.0).packet_loss_after_hop1 is True

    def test_missing_canary_measurement_is_ignored_not_counted(self):
        sig = self._n(True, None, [40.0, 40.0])
        assert sig.packet_loss_multiple_targets is True
