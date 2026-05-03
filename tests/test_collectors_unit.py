from __future__ import annotations

from pathlib import Path

import pytest

from boundary_probe.collectors._runner import CommandResult
from boundary_probe.collectors.control_hosts import collect_control_hosts
from boundary_probe.collectors.gateway import collect_gateway
from boundary_probe.collectors.ip_connectivity import collect_ip_connectivity
from boundary_probe.collectors.path import collect_path
from boundary_probe.collectors.target_service import collect_target_service
from boundary_probe.targets import ParsedTarget, parse_target

FIXTURES = Path(__file__).parent / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


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
# collect_gateway
# ---------------------------------------------------------------------------


def _gw_runner(route_out: str, ping_out: str) -> FakeRunner:
    return FakeRunner({
        ("route", "print", "-4"): _ok(route_out),
        ("ping", "-4", "-n", "4", "-w", "1000", "192.168.1.1"): _ok(ping_out),
    })


def test_gateway_happy_path():
    runner = _gw_runner(_read("route_print.txt"), _read("ping_success.txt")[:400])
    # ping_success uses -n 10; gateway uses -n 4 — feed partial success output with 4 replies
    ping4 = (
        "\nPing statistics for 192.168.1.1:\n"
        "    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n"
        "Approximate round trip times in milli-seconds:\n"
        "    Minimum = 2ms, Maximum = 3ms, Average = 2ms\n"
    )
    runner2 = FakeRunner({
        ("route", "print", "-4"): _ok(_read("route_print.txt")),
        ("ping", "-4", "-n", "4", "-w", "1000", "192.168.1.1"): _ok(ping4),
    })
    result = collect_gateway(runner2)
    assert result.reachable is True
    assert result.gateway_ip == "192.168.1.1"


def test_gateway_route_timeout():
    runner = FakeRunner({("route", "print", "-4"): _timeout()})
    result = collect_gateway(runner)
    assert result.reachable is False
    assert "timed out" in result.note


def test_gateway_no_default_route():
    runner = FakeRunner({("route", "print", "-4"): _ok("127.0.0.0  255.0.0.0  On-link  127.0.0.1\n")})
    result = collect_gateway(runner)
    assert result.reachable is False
    assert result.gateway_ip is None


def test_gateway_ping_timeout():
    runner = FakeRunner({
        ("route", "print", "-4"): _ok(_read("route_print.txt")),
        ("ping", "-4", "-n", "4", "-w", "1000", "192.168.1.1"): _timeout(),
    })
    result = collect_gateway(runner)
    assert result.reachable is False
    assert "timed out" in result.note


def test_gateway_ping_total_loss():
    runner = FakeRunner({
        ("route", "print", "-4"): _ok(_read("route_print.txt")),
        ("ping", "-4", "-n", "4", "-w", "1000", "192.168.1.1"): _ok(_read("ping_total_loss.txt")),
    })
    result = collect_gateway(runner)
    assert result.reachable is False


# ---------------------------------------------------------------------------
# collect_ip_connectivity
# ---------------------------------------------------------------------------


def test_ip_connectivity_ok():
    runner = FakeRunner({("ping", "-4", "-n", "10", "-w", "1000", "1.1.1.1"): _ok(_read("ping_success.txt"))})
    result = collect_ip_connectivity(runner)
    assert result.ok is True
    assert result.loss_pct == 0.0


def test_ip_connectivity_total_loss():
    runner = FakeRunner({("ping", "-4", "-n", "10", "-w", "1000", "1.1.1.1"): _ok(_read("ping_total_loss.txt"))})
    result = collect_ip_connectivity(runner)
    assert result.ok is False
    assert result.loss_pct == 100.0


def test_ip_connectivity_timeout():
    runner = FakeRunner({("ping", "-4", "-n", "10", "-w", "1000", "1.1.1.1"): _timeout()})
    result = collect_ip_connectivity(runner)
    assert result.ok is False
    assert "timed out" in result.note


def test_ip_connectivity_partial_loss_above_threshold():
    runner = FakeRunner({("ping", "-4", "-n", "10", "-w", "1000", "1.1.1.1"): _ok(_read("ping_partial_loss.txt"))})
    result = collect_ip_connectivity(runner)
    assert result.ok is True   # 30% loss < 50% threshold


# ---------------------------------------------------------------------------
# collect_control_hosts
# ---------------------------------------------------------------------------


def _controls_runner(hosts_reachable: set[str]) -> FakeRunner:
    responses = {}
    for host in ("1.1.1.1", "8.8.8.8", "8.8.4.4", "cloudflare.com"):
        out = _read("ping_success.txt") if host in hosts_reachable else _read("ping_total_loss.txt")
        responses[("ping", "-4", "-n", "10", "-w", "1000", host)] = _ok(out)
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
    runner = FakeRunner({("ping", "-4", "-n", "4", "-w", "1000", "example.com"): _ok(_read("ping_success.txt"))})
    result = collect_target_service(_host_target("example.com"), runner)
    assert result.ok is True
    assert result.method == "ping"


def test_target_service_ping_loss():
    runner = FakeRunner({("ping", "-4", "-n", "4", "-w", "1000", "example.com"): _ok(_read("ping_total_loss.txt"))})
    result = collect_target_service(_host_target("example.com"), runner)
    assert result.ok is False


def test_target_service_ping_timeout():
    runner = FakeRunner({("ping", "-4", "-n", "4", "-w", "1000", "example.com"): _timeout()})
    result = collect_target_service(_host_target("example.com"), runner)
    assert result.ok is False
    assert "timed out" in result.note


# ---------------------------------------------------------------------------
# collect_path
# ---------------------------------------------------------------------------


def test_path_complete():
    runner = FakeRunner({("tracert", "-4", "-h", "10", "-w", "500", "1.1.1.1"): _ok(_read("tracert_complete.txt"))})
    result = collect_path("1.1.1.1", runner)
    assert result.completed is True
    assert len(result.raw_hops) == 4


def test_path_timeout():
    runner = FakeRunner({("tracert", "-4", "-h", "10", "-w", "500", "192.168.99.99"): _timeout()})
    result = collect_path("192.168.99.99", runner)
    assert result.completed is False
    assert "timed out" in result.note


def test_path_isp_loss():
    runner = FakeRunner({("tracert", "-4", "-h", "10", "-w", "500", "example.com"): _ok(_read("tracert_isp_loss.txt"))})
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
