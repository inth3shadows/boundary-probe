from __future__ import annotations

import pytest

from boundary_probe.collectors.control_hosts import collect_control_hosts
from boundary_probe.collectors.dns import collect_dns
from boundary_probe.collectors.gateway import collect_gateway
from boundary_probe.collectors.ip_connectivity import collect_ip_connectivity
from boundary_probe.collectors.target_service import collect_target_service
from boundary_probe.targets import parse_target


@pytest.mark.integration
def test_real_gateway_ping():
    result = collect_gateway()
    assert isinstance(result.reachable, bool)
    if result.gateway_ip:
        assert "." in result.gateway_ip  # basic IPv4 sanity


@pytest.mark.integration
def test_real_dns_resolves_known_host():
    result = collect_dns("one.one.one.one")
    assert result.ok is True
    assert len(result.resolved_ips) >= 1


@pytest.mark.integration
def test_real_control_hosts_quorum():
    result = collect_control_hosts()
    reachable = sum(1 for r in result.results if r.reachable)
    assert reachable >= 2, f"fewer than 2 control hosts reachable: {result.results}"


@pytest.mark.integration
def test_real_ip_connectivity():
    result = collect_ip_connectivity()
    assert isinstance(result.ok, bool)
    assert 0.0 <= result.loss_pct <= 100.0


@pytest.mark.integration
def test_real_l7_target_check():
    # Real https GET through the default fetch path — a stable, verified-cert host.
    result = collect_target_service(parse_target("https://one.one.one.one"))
    assert result.method == "http"
    assert result.ok is True
    assert result.http_status is not None and result.http_status < 500
