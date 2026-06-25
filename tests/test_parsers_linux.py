"""Tests for the Linux-specific parser implementations.

These tests call the private _parse_*_linux functions directly so they run
on all platforms — including Windows CI — without depending on the runtime
platform dispatch in parse_ping_output / parse_tracert_output.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from boundary_probe.collectors._parsers import (
    _parse_ping_linux,
    _parse_route_linux,
    _parse_traceroute_linux,
)

LINUX_FIXTURES = Path(__file__).parent / "fixtures" / "linux"


def _read(name: str) -> str:
    return (LINUX_FIXTURES / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# _parse_ping_linux
# ---------------------------------------------------------------------------


def test_linux_ping_success_zero_loss():
    stats = _parse_ping_linux(_read("ping_success.txt"))
    assert stats.sent == 4
    assert stats.received == 4
    assert stats.loss_pct == 0.0
    assert stats.avg_ms == pytest.approx(12.150)


def test_linux_ping_total_loss():
    stats = _parse_ping_linux(_read("ping_total_loss.txt"))
    assert stats.sent == 4
    assert stats.received == 0
    assert stats.loss_pct == 100.0
    assert stats.avg_ms is None


def test_linux_ping_partial_loss():
    stats = _parse_ping_linux(_read("ping_partial_loss.txt"))
    assert stats.sent == 4
    assert stats.received == 3
    assert stats.loss_pct == 25.0
    assert stats.avg_ms is not None


def test_linux_ping_empty_input():
    stats = _parse_ping_linux("")
    assert stats.sent == 0
    assert stats.received == 0
    assert stats.loss_pct == 100.0
    assert stats.avg_ms is None
    # An unparseable statistics block must be flagged, not silently asserted as
    # a real measurement — callers say "could not parse" rather than "100% loss".
    assert stats.parsed is False


def test_linux_ping_valid_sets_parsed_true():
    stats = _parse_ping_linux(_read("ping_success.txt"))
    assert stats.parsed is True


def test_linux_ping_total_loss_with_icmp_errors():
    """iputils emits ', +N errors' before the loss% on ICMP errors (host/net
    unreachable). The summary must still parse — not collapse to the 100%-loss
    fallback, which would only coincidentally match here and fabricate sent=0."""
    out = (
        "PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.\n\n"
        "--- 192.0.2.1 ping statistics ---\n"
        "3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2002ms\n"
    )
    stats = _parse_ping_linux(out)
    assert stats.parsed is True
    assert stats.sent == 3
    assert stats.received == 0
    assert stats.loss_pct == 100.0


def test_linux_ping_partial_loss_with_icmp_errors():
    """The real regression: partial loss + errors. Pre-fix this missed entirely
    and read as sent=0 / 100% loss — a basically-healthy host marked a fault."""
    out = (
        "--- 10.0.0.9 ping statistics ---\n"
        "5 packets transmitted, 2 received, +3 errors, 60% packet loss, time 4005ms\n"
        "rtt min/avg/max/mdev = 0.5/1.0/1.5/0.2 ms\n"
    )
    stats = _parse_ping_linux(out)
    assert stats.parsed is True
    assert stats.sent == 5
    assert stats.received == 2
    assert stats.loss_pct == 60.0
    assert stats.avg_ms == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# _parse_traceroute_linux
# ---------------------------------------------------------------------------


def test_linux_traceroute_complete():
    hops = _parse_traceroute_linux(_read("traceroute_complete.txt"))
    assert len(hops) == 5
    assert hops[0]["index"] == 1
    assert hops[0]["loss_pct"] == 0.0
    assert hops[0]["rtt_ms"] is not None
    assert hops[0]["host"] == "192.168.1.1"
    assert hops[4]["host"] == "8.8.8.8"


def test_linux_traceroute_isp_loss():
    hops = _parse_traceroute_linux(_read("traceroute_isp_loss.txt"))
    assert len(hops) == 5
    assert hops[0]["loss_pct"] == 0.0   # hop 1 clean
    assert hops[1]["loss_pct"] == 0.0   # hop 2 clean
    assert hops[2]["loss_pct"] == 100.0  # hop 3 all asterisks
    assert hops[2]["host"] == "*"
    assert hops[2]["rtt_ms"] is None
    assert hops[3]["loss_pct"] == 0.0   # hop 4 clean again


def test_linux_traceroute_empty():
    assert _parse_traceroute_linux("") == []


def test_linux_traceroute_header_line_skipped():
    """The 'traceroute to ...' header line must not appear as a hop."""
    hops = _parse_traceroute_linux(_read("traceroute_complete.txt"))
    assert all(isinstance(h["index"], int) and h["index"] >= 1 for h in hops)


# ---------------------------------------------------------------------------
# _parse_route_linux
# ---------------------------------------------------------------------------


def test_linux_route_finds_gateway():
    gw = _parse_route_linux(_read("route_default.txt"))
    assert gw == "192.168.1.1"


def test_linux_route_empty():
    assert _parse_route_linux("") is None


def test_linux_route_no_default():
    text = "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50\n"
    assert _parse_route_linux(text) is None
