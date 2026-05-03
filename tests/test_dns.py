from __future__ import annotations

import socket
from unittest.mock import patch

from boundary_probe.collectors.dns import collect_dns


def test_ip_address_skips_resolution():
    result = collect_dns("1.2.3.4")
    assert result.ok is True
    assert result.resolved_ips == ["1.2.3.4"]
    assert result.elapsed_ms == 0
    assert "already an IP" in result.note


def test_dns_success_deduplicates_ips():
    fake_results = [
        (socket.AF_INET, None, None, "", ("93.184.216.34", 0)),
        (socket.AF_INET, None, None, "", ("93.184.216.34", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=fake_results):
        result = collect_dns("example.com")
    assert result.ok is True
    assert result.resolved_ips == ["93.184.216.34"]
    assert result.elapsed_ms >= 0


def test_dns_gaierror_returns_not_ok():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        result = collect_dns("notareal.invalid")
    assert result.ok is False
    assert "Name or service not known" in result.note


def test_dns_oserror_returns_not_ok():
    with patch("socket.getaddrinfo", side_effect=OSError("network unreachable")):
        result = collect_dns("example.com")
    assert result.ok is False
    assert "network unreachable" in result.note
