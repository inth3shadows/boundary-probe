from __future__ import annotations

import sys
from pathlib import Path

import pytest

from boundary_probe.collectors._commands import ping_cmd, route_cmd, traceroute_cmd
from boundary_probe.collectors._runner import CommandResult
from boundary_probe.collectors.control_hosts import collect_control_hosts
from boundary_probe.collectors.gateway import collect_gateway
from boundary_probe.collectors.ip_connectivity import collect_ip_connectivity
from boundary_probe.collectors.path import collect_path
from boundary_probe.collectors.target_service import collect_target_service
from boundary_probe.targets import ParsedTarget, parse_target

_WIN = sys.platform == "win32"

FIXTURES = Path(__file__).parent / "fixtures"
LINUX_FIXTURES = FIXTURES / "linux"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _read_linux(name: str) -> str:
    return (LINUX_FIXTURES / name).read_text(encoding="utf-8")


def _ok(stdout: str, returncode: int = 0) -> CommandResult:
    return CommandResult(returncode=returncode, stdout=stdout, stderr="", timed_out=False, duration_ms=10)


def _timeout() -> CommandResult:
    return CommandResult(returncode=-1, stdout="", stderr="", timed_out=True, duration_ms=10000)


class FakeRunner:
    def __init__(self, responses: dict[tuple, CommandResult]):
        self._resp = responses
        self.calls: list[tuple] = []

    def run(self, argv: list[str], timeout_s: float) -> CommandResult:
        self.calls.append((tuple(argv), timeout_s))
        key = tuple(argv)
        if key in self._resp:
            return self._resp[key]
        raise AssertionError(f"unexpected call: {argv}")


# ---------------------------------------------------------------------------
# Platform-appropriate fixture content
# ---------------------------------------------------------------------------

# Route output containing a default gateway (192.168.1.1)
_ROUTE_OK = _read("route_print.txt") if _WIN else _read_linux("route_default.txt")

# Route output with no default gateway entry
_ROUTE_NO_DEFAULT = (
    "127.0.0.0  255.0.0.0  On-link  127.0.0.1\n"
    if _WIN
    else "192.168.1.0/24 dev eth0 proto kernel scope link\n"
)

# 4-ping success output to 192.168.1.1 (used by gateway tests)
_PING4_GW_OK = (
    "\nPing statistics for 192.168.1.1:\n"
    "    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n"
    "Approximate round trip times in milli-seconds:\n"
    "    Minimum = 2ms, Maximum = 3ms, Average = 2ms\n"
    if _WIN
    else
    "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
    "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.1 ms\n"
    "64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=2.3 ms\n"
    "64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=2.0 ms\n"
    "64 bytes from 192.168.1.1: icmp_seq=4 ttl=64 time=2.2 ms\n"
    "\n--- 192.168.1.1 ping statistics ---\n"
    "4 packets transmitted, 4 received, 0% packet loss, time 3003ms\n"
    "rtt min/avg/max/mdev = 2.000/2.150/2.300/0.120 ms\n"
)

# 4-ping total loss to 192.168.1.1
_PING4_GW_LOSS = (
    "Pinging 192.168.1.1 with 32 bytes of data:\n"
    "Request timed out.\nRequest timed out.\nRequest timed out.\nRequest timed out.\n"
    "\nPing statistics for 192.168.1.1:\n"
    "    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),\n"
    if _WIN
    else
    "PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.\n"
    "\n--- 192.168.1.1 ping statistics ---\n"
    "4 packets transmitted, 0 received, 100% packet loss, time 3003ms\n"
)

# General-purpose ping fixtures (10 pings, various loss levels)
_PING_SUCCESS = _read("ping_success.txt") if _WIN else _read_linux("ping_success.txt")
_PING_TOTAL_LOSS = _read("ping_total_loss.txt") if _WIN else _read_linux("ping_total_loss.txt")
_PING_PARTIAL_LOSS = _read("ping_partial_loss.txt") if _WIN else _read_linux("ping_partial_loss.txt")

# Traceroute fixtures
_TRACERT_COMPLETE = _read("tracert_complete.txt") if _WIN else _read_linux("traceroute_complete.txt")
_TRACERT_ISP_LOSS = _read("tracert_isp_loss.txt") if _WIN else _read_linux("traceroute_isp_loss.txt")


# ---------------------------------------------------------------------------
# collect_gateway
# ---------------------------------------------------------------------------


def _gw_runner(route_out: str, ping_out: str) -> FakeRunner:
    gw_ip = "192.168.1.1"
    return FakeRunner({
        tuple(route_cmd()): _ok(route_out),
        tuple(ping_cmd(gw_ip, 4, 1000)): _ok(ping_out),
    })


def test_gateway_happy_path():
    runner = FakeRunner({
        tuple(route_cmd()): _ok(_ROUTE_OK),
        tuple(ping_cmd("192.168.1.1", 4, 1000)): _ok(_PING4_GW_OK),
    })
    result = collect_gateway(runner)
    assert result.reachable is True
    assert result.gateway_ip == "192.168.1.1"


def test_gateway_route_timeout():
    runner = FakeRunner({tuple(route_cmd()): _timeout()})
    result = collect_gateway(runner)
    assert result.reachable is False
    assert "timed out" in result.note


def test_gateway_no_default_route():
    runner = FakeRunner({tuple(route_cmd()): _ok(_ROUTE_NO_DEFAULT)})
    result = collect_gateway(runner)
    assert result.reachable is False
    assert result.gateway_ip is None


def test_gateway_ping_timeout():
    runner = FakeRunner({
        tuple(route_cmd()): _ok(_ROUTE_OK),
        tuple(ping_cmd("192.168.1.1", 4, 1000)): _timeout(),
    })
    result = collect_gateway(runner)
    assert result.reachable is False
    assert "timed out" in result.note


def test_gateway_ping_total_loss():
    runner = FakeRunner({
        tuple(route_cmd()): _ok(_ROUTE_OK),
        tuple(ping_cmd("192.168.1.1", 4, 1000)): _ok(_PING4_GW_LOSS),
    })
    result = collect_gateway(runner)
    assert result.reachable is False


# ---------------------------------------------------------------------------
# collect_ip_connectivity
# ---------------------------------------------------------------------------


def test_ip_connectivity_ok():
    runner = FakeRunner({tuple(ping_cmd("1.1.1.1", 10, 1000)): _ok(_PING_SUCCESS)})
    result = collect_ip_connectivity(runner)
    assert result.ok is True
    assert result.loss_pct == 0.0


def test_ip_connectivity_total_loss():
    runner = FakeRunner({tuple(ping_cmd("1.1.1.1", 10, 1000)): _ok(_PING_TOTAL_LOSS)})
    result = collect_ip_connectivity(runner)
    assert result.ok is False
    assert result.loss_pct == 100.0


def test_ip_connectivity_timeout():
    runner = FakeRunner({tuple(ping_cmd("1.1.1.1", 10, 1000)): _timeout()})
    result = collect_ip_connectivity(runner)
    assert result.ok is False
    assert "timed out" in result.note


def test_ip_connectivity_partial_loss_above_threshold():
    runner = FakeRunner({tuple(ping_cmd("1.1.1.1", 10, 1000)): _ok(_PING_PARTIAL_LOSS)})
    result = collect_ip_connectivity(runner)
    assert result.ok is True   # ~25-30% loss < 50% threshold


# ---------------------------------------------------------------------------
# collect_control_hosts
# ---------------------------------------------------------------------------


def _controls_runner(hosts_reachable: set[str]) -> FakeRunner:
    responses = {}
    for host in ("1.1.1.1", "8.8.8.8", "8.8.4.4", "cloudflare.com"):
        out = _PING_SUCCESS if host in hosts_reachable else _PING_TOTAL_LOSS
        responses[tuple(ping_cmd(host, 10, 1000))] = _ok(out)
    return FakeRunner(responses)


def test_controls_all_reachable():
    runner = _controls_runner({"1.1.1.1", "8.8.8.8", "8.8.4.4", "cloudflare.com"})
    result = collect_control_hosts(runner)
    assert result.all_ok is True


def test_controls_three_of_four_ok():
    runner = _controls_runner({"1.1.1.1", "8.8.8.8", "8.8.4.4"})
    result = collect_control_hosts(runner)
    assert result.all_ok is True   # ≥3 quorum met


def test_controls_two_of_four_fails():
    runner = _controls_runner({"1.1.1.1", "8.8.8.8"})
    result = collect_control_hosts(runner)
    assert result.all_ok is False


def test_controls_none_reachable():
    runner = _controls_runner(set())
    result = collect_control_hosts(runner)
    assert result.all_ok is False
    assert len(result.results) == 4


# ---------------------------------------------------------------------------
# collect_target_service (ping path — no port)
# ---------------------------------------------------------------------------


def _host_target(host: str) -> ParsedTarget:
    from boundary_probe.targets import parse_target
    return parse_target(host)


def test_target_service_ping_ok():
    runner = FakeRunner({tuple(ping_cmd("example.com", 4, 1000)): _ok(_PING_SUCCESS)})
    result = collect_target_service(_host_target("example.com"), runner)
    assert result.ok is True
    assert result.method == "ping"


def test_target_service_ping_loss():
    runner = FakeRunner({tuple(ping_cmd("example.com", 4, 1000)): _ok(_PING_TOTAL_LOSS)})
    result = collect_target_service(_host_target("example.com"), runner)
    assert result.ok is False


def test_target_service_ping_timeout():
    runner = FakeRunner({tuple(ping_cmd("example.com", 4, 1000)): _timeout()})
    result = collect_target_service(_host_target("example.com"), runner)
    assert result.ok is False
    assert "timed out" in result.note


# ---------------------------------------------------------------------------
# collect_path
# ---------------------------------------------------------------------------


def test_path_complete():
    runner = FakeRunner({tuple(traceroute_cmd("1.1.1.1", 10, 500)): _ok(_TRACERT_COMPLETE)})
    result = collect_path("1.1.1.1", runner)
    assert result.completed is True
    assert len(result.raw_hops) >= 2


def test_path_timeout():
    runner = FakeRunner({tuple(traceroute_cmd("192.168.99.99", 10, 500)): _timeout()})
    result = collect_path("192.168.99.99", runner)
    assert result.completed is False
    assert "timed out" in result.note


def test_path_isp_loss():
    runner = FakeRunner({tuple(traceroute_cmd("example.com", 10, 500)): _ok(_TRACERT_ISP_LOSS)})
    result = collect_path("example.com", runner)
    assert result.completed is True
    assert any(h["loss_pct"] == 100.0 for h in result.raw_hops)


# ---------------------------------------------------------------------------
# collect_target_service (TCP connect path)
# ---------------------------------------------------------------------------


def test_target_service_https_uses_port_443():
    from unittest.mock import MagicMock, patch
    target = parse_target("https://example.com")
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    with patch("socket.create_connection", return_value=mock_sock):
        result = collect_target_service(target)
    assert result.ok is True
    assert result.method == "tcp-connect"
    assert result.target_port == 443


def test_target_service_explicit_port_tcp_connect():
    from unittest.mock import MagicMock, patch
    target = parse_target("192.168.1.1:8080")
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    with patch("socket.create_connection", return_value=mock_sock):
        result = collect_target_service(target)
    assert result.ok is True
    assert result.target_port == 8080


def test_target_service_tcp_connect_refused():
    from unittest.mock import patch
    target = parse_target("https://example.com")
    with patch("socket.create_connection", side_effect=OSError("Connection refused")):
        result = collect_target_service(target)
    assert result.ok is False
    assert "Connection refused" in result.note
    assert result.method == "tcp-connect"
