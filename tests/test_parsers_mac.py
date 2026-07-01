"""Tests for the macOS (BSD) parser implementations.

These call the private _parse_*_mac functions directly so they run on all
platforms — including Linux/Windows CI — without depending on the runtime
platform dispatch in parse_ping_output / parse_route_print_default_gateway.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from boundary_probe.collectors._parsers import (
    _parse_ipv6_route_present_mac,
    _parse_ping_mac,
    _parse_route_mac,
    _parse_traceroute_mac,
)

MAC_FIXTURES = Path(__file__).parent / "fixtures" / "mac"


def _read(name: str) -> str:
    return (MAC_FIXTURES / name).read_text(encoding="utf-8")


# --- _parse_ping_mac ------------------------------------------------------

def test_mac_ping_success_zero_loss():
    stats = _parse_ping_mac(_read("ping_success.txt"))
    assert stats.sent == 4
    assert stats.received == 4
    assert stats.loss_pct == 0.0
    assert stats.avg_ms == pytest.approx(12.150)


def test_mac_ping_total_loss():
    # The "packets received" wording + float "100.0%" that the Linux regex misses.
    stats = _parse_ping_mac(_read("ping_total_loss.txt"))
    assert stats.sent == 4
    assert stats.received == 0
    assert stats.loss_pct == 100.0
    assert stats.avg_ms is None


def test_mac_ping_partial_loss():
    stats = _parse_ping_mac(_read("ping_partial_loss.txt"))
    assert stats.sent == 4
    assert stats.received == 3
    assert stats.loss_pct == 25.0
    assert stats.avg_ms == pytest.approx(12.267)


def test_mac_ping_empty_input():
    stats = _parse_ping_mac("")
    assert stats.sent == 0 and stats.received == 0 and stats.loss_pct == 100.0


def test_mac_ping_with_icmp_errors():
    # BSD ping inserts ", +N errors" before the loss% on ICMP error replies
    # (host/net unreachable) — the stats line must still parse, not fall to the
    # 100%-loss / sent=0 default.
    out = (
        "PING 10.0.0.9 (10.0.0.9): 56 data bytes\n"
        "36 bytes from 10.0.0.1: Destination Host Unreachable\n"
        "\n--- 10.0.0.9 ping statistics ---\n"
        "4 packets transmitted, 0 packets received, +4 errors, 100.0% packet loss\n"
    )
    stats = _parse_ping_mac(out)
    assert stats.sent == 4 and stats.received == 0 and stats.loss_pct == 100.0


# --- _parse_route_mac -----------------------------------------------------

def test_mac_route_finds_gateway():
    assert _parse_route_mac(_read("route_default.txt")) == "192.168.1.1"


def test_mac_route_empty():
    assert _parse_route_mac("") is None


def test_mac_route_no_gateway_line():
    # `route -n get default` with no default route prints no gateway: line.
    text = "   route to: default\ndestination: default\n       mask: default\n"
    assert _parse_route_mac(text) is None


# --- _parse_ipv6_route_present_mac -----------------------------------------

def test_mac_ipv6_route_present():
    text = "   route to: default\ndestination: default\n    gateway: fe80::1%en0\n"
    assert _parse_ipv6_route_present_mac(text) is True


def test_mac_ipv6_route_absent():
    text = "   route to: default\ndestination: default\n       mask: default\n"
    assert _parse_ipv6_route_present_mac(text) is False


def test_mac_ipv6_route_empty():
    assert _parse_ipv6_route_present_mac("") is False


# --- _parse_traceroute_mac (reuses the BSD/Linux parser) ------------------

def test_mac_traceroute_complete():
    hops = _parse_traceroute_mac(_read("traceroute_complete.txt"))
    assert len(hops) == 5
    assert hops[0]["host"] == "192.168.1.1"
    assert hops[-1]["host"] == "8.8.8.8"
    assert all(h["loss_pct"] == 0.0 for h in hops)


def test_mac_traceroute_isp_loss():
    hops = _parse_traceroute_mac(_read("traceroute_isp_loss.txt"))
    assert hops[2]["host"] == "*"
    assert hops[2]["loss_pct"] == 100.0
