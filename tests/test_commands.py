from __future__ import annotations

from unittest.mock import patch

import boundary_probe.collectors._commands as cmd_mod


def test_ping_cmd_windows():
    with patch.object(cmd_mod, "_WIN", True):
        result = cmd_mod.ping_cmd("example.com", 4, 1000)
    assert result == ["ping", "-4", "-n", "4", "-w", "1000", "example.com"]


def test_ping_cmd_linux():
    with patch.object(cmd_mod, "_WIN", False):
        result = cmd_mod.ping_cmd("example.com", 4, 1000)
    assert result == ["ping", "-c", "4", "-W", "1", "-4", "--", "example.com"]


def test_ping_cmd_linux_sub_second_timeout_rounds_to_one():
    with patch.object(cmd_mod, "_WIN", False):
        result = cmd_mod.ping_cmd("host", 10, 500)
    assert result[result.index("-W") + 1] == "1"


def test_traceroute_cmd_windows():
    with patch.object(cmd_mod, "_WIN", True):
        result = cmd_mod.traceroute_cmd("example.com", 10, 500)
    assert result == ["tracert", "-4", "-h", "10", "-w", "500", "example.com"]


def test_traceroute_cmd_linux():
    with patch.object(cmd_mod, "_WIN", False):
        result = cmd_mod.traceroute_cmd("example.com", 10, 500)
    assert result == ["traceroute", "-4", "-q", "3", "-m", "10", "-w", "1", "--", "example.com"]


def test_route_cmd_windows():
    with patch.object(cmd_mod, "_WIN", True):
        result = cmd_mod.route_cmd()
    assert result == ["route", "print", "-4"]


def test_route_cmd_linux():
    with patch.object(cmd_mod, "_WIN", False):
        result = cmd_mod.route_cmd()
    assert result == ["ip", "route", "show", "default"]
