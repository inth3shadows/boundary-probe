from __future__ import annotations

from pathlib import Path

import pytest

from boundary_probe.collectors._parsers import (
    parse_ping_output,
    parse_route_print_default_gateway,
    parse_tracert_output,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# parse_ping_output
# ---------------------------------------------------------------------------


def test_ping_success_zero_loss():
    stats = parse_ping_output(_read("ping_success.txt"))
    assert stats.sent == 10
    assert stats.received == 10
    assert stats.loss_pct == 0.0
    assert stats.avg_ms == 4.0
    assert stats.min_ms == 4.0
    assert stats.max_ms == 5.0


def test_ping_total_loss():
    stats = parse_ping_output(_read("ping_total_loss.txt"))
    assert stats.sent == 4
    assert stats.received == 0
    assert stats.loss_pct == 100.0
    assert stats.avg_ms is None


def test_ping_partial_loss():
    stats = parse_ping_output(_read("ping_partial_loss.txt"))
    assert stats.sent == 10
    assert stats.received == 7
    assert pytest.approx(stats.loss_pct) == 30.0


def test_ping_empty_input():
    stats = parse_ping_output("")
    assert stats.sent == 0
    assert stats.received == 0
    assert stats.loss_pct == 100.0
    assert stats.avg_ms is None


# ---------------------------------------------------------------------------
# parse_tracert_output
# ---------------------------------------------------------------------------


def test_tracert_complete():
    hops = parse_tracert_output(_read("tracert_complete.txt"))
    assert len(hops) == 4
    assert hops[0]["index"] == 1
    assert hops[0]["loss_pct"] == 0.0
    assert hops[0]["rtt_ms"] is not None
    assert hops[0]["host"] == "192.168.1.1"
    assert hops[3]["host"] == "1.1.1.1"


def test_tracert_isp_loss():
    hops = parse_tracert_output(_read("tracert_isp_loss.txt"))
    assert len(hops) == 5
    assert hops[0]["loss_pct"] == 0.0   # hop 1 clean
    assert hops[1]["loss_pct"] == 0.0   # hop 2 clean
    assert hops[2]["loss_pct"] == 100.0  # hop 3 all asterisks
    assert hops[2]["host"] == "*"
    assert hops[2]["rtt_ms"] is None


def test_tracert_edge_router_only():
    hops = parse_tracert_output(_read("tracert_edge_router_only.txt"))
    assert len(hops) == 4
    assert hops[0]["loss_pct"] == 0.0   # hop 1 clean
    assert hops[1]["loss_pct"] == 100.0  # hop 2 silent (edge router)
    assert hops[2]["loss_pct"] == 0.0   # hop 3 clean again
    assert hops[3]["loss_pct"] == 0.0   # hop 4 clean


def test_tracert_timeout():
    hops = parse_tracert_output(_read("tracert_timeout.txt"))
    assert len(hops) == 10
    assert hops[0]["loss_pct"] == 0.0   # hop 1 clean
    for h in hops[1:]:
        assert h["loss_pct"] == 100.0


def test_tracert_empty():
    assert parse_tracert_output("") == []


# ---------------------------------------------------------------------------
# parse_route_print_default_gateway
# ---------------------------------------------------------------------------


def test_route_print_finds_gateway():
    gw = parse_route_print_default_gateway(_read("route_print.txt"))
    assert gw == "192.168.1.1"


def test_route_print_empty():
    assert parse_route_print_default_gateway("") is None


def test_route_print_no_default_route():
    text = "127.0.0.0  255.0.0.0  On-link  127.0.0.1  331\n"
    assert parse_route_print_default_gateway(text) is None
