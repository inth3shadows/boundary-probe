from __future__ import annotations

from unittest.mock import MagicMock, patch

from boundary_probe.collectors.captive_portal import CaptivePortalSlice
from boundary_probe.collectors.control_hosts import ControlHostsSlice
from boundary_probe.collectors.dns import DnsSlice
from boundary_probe.collectors.gateway import GatewaySlice
from boundary_probe.collectors.ip_connectivity import IpConnectivitySlice
from boundary_probe.collectors.ipv6_route import Ipv6RouteSlice
from boundary_probe.collectors.orchestrator import collect_signals
from boundary_probe.collectors.path import PathSlice
from boundary_probe.collectors.target_service import TargetServiceSlice
from boundary_probe.targets import parse_target

_GATEWAY = GatewaySlice(reachable=True, gateway_ip="192.168.1.1", rtt_ms=2.0, note="")
_GATEWAY_NO_ROUTE = GatewaySlice(reachable=False, gateway_ip=None, rtt_ms=None, note="no default route")
_DNS = DnsSlice(ok=True, resolved_ips=["93.184.216.34"], resolver_used=None, elapsed_ms=5, note="")
_IP_OK = IpConnectivitySlice(ok=True, target_ip="1.1.1.1", loss_pct=0.0, avg_rtt_ms=10.0, note="")
_IP_FAIL = IpConnectivitySlice(ok=False, target_ip="1.1.1.1", loss_pct=100.0, avg_rtt_ms=None, note="timeout")
_CONTROLS_OK = ControlHostsSlice(all_ok=True, ok_count=4, total=4, results=[], note="")
_TARGET = TargetServiceSlice(ok=True, method="ping", target_host="example.com", target_port=None, elapsed_ms=50, note="")
_CAPTIVE_CLEAN = CaptivePortalSlice(checked=True, portal_detected=False, note="")
_CAPTIVE_PORTAL = CaptivePortalSlice(checked=True, portal_detected=True, note="HTTP 302")
_IPV6_ROUTE_PRESENT = Ipv6RouteSlice(present=True, note="")
_PATH = PathSlice(
    raw_hops=[
        {"index": 1, "host": "192.168.1.1", "loss_pct": 0.0, "rtt_ms": 2.0},
        {"index": 2, "host": "10.0.0.1", "loss_pct": 0.0, "rtt_ms": 10.0},
    ],
    target="example.com",
    completed=True,
    note="",
)

_MOD = "boundary_probe.collectors.orchestrator"


def test_collect_signals_happy_path_no_secondary():
    target = parse_target("example.com")
    with (
        patch(f"{_MOD}.collect_gateway", return_value=_GATEWAY),
        patch(f"{_MOD}.collect_dns", return_value=_DNS),
        patch(f"{_MOD}.collect_ip_connectivity", return_value=_IP_OK),
        patch(f"{_MOD}.collect_control_hosts", return_value=_CONTROLS_OK),
        patch(f"{_MOD}.collect_target_service", return_value=_TARGET),
        patch(f"{_MOD}.collect_captive_portal", return_value=_CAPTIVE_CLEAN),
        patch(f"{_MOD}.collect_path", return_value=_PATH),
    ):
        result = collect_signals(target, runner=MagicMock())

    assert result.snapshot.gateway_reachable is True
    assert result.snapshot.dns_ok is True
    assert result.snapshot.ip_connectivity_ok is True
    assert result.snapshot.control_hosts_ok is True
    assert result.snapshot.target_service_ok is True
    assert result.path_secondary is None
    assert result.elapsed_ms >= 0


def test_collect_signals_ip_fail_triggers_secondary_path():
    target = parse_target("example.com")
    mock_path = MagicMock(return_value=_PATH)
    with (
        patch(f"{_MOD}.collect_gateway", return_value=_GATEWAY),
        patch(f"{_MOD}.collect_dns", return_value=_DNS),
        patch(f"{_MOD}.collect_ip_connectivity", return_value=_IP_FAIL),
        patch(f"{_MOD}.collect_control_hosts", return_value=_CONTROLS_OK),
        patch(f"{_MOD}.collect_target_service", return_value=_TARGET),
        patch(f"{_MOD}.collect_captive_portal", return_value=_CAPTIVE_CLEAN),
        patch(f"{_MOD}.collect_path", mock_path),
    ):
        result = collect_signals(target, runner=MagicMock())

    assert result.snapshot.ip_connectivity_ok is False
    assert result.path_secondary is not None
    assert mock_path.call_count == 2


def test_collect_signals_skip_path():
    target = parse_target("example.com")
    mock_path = MagicMock(return_value=_PATH)
    with (
        patch(f"{_MOD}.collect_gateway", return_value=_GATEWAY),
        patch(f"{_MOD}.collect_dns", return_value=_DNS),
        patch(f"{_MOD}.collect_ip_connectivity", return_value=_IP_OK),
        patch(f"{_MOD}.collect_control_hosts", return_value=_CONTROLS_OK),
        patch(f"{_MOD}.collect_target_service", return_value=_TARGET),
        patch(f"{_MOD}.collect_captive_portal", return_value=_CAPTIVE_CLEAN),
        patch(f"{_MOD}.collect_path", mock_path),
    ):
        result = collect_signals(target, runner=MagicMock(), skip_path=True)

    mock_path.assert_not_called()
    assert result.path_secondary is None
    assert "skipped" in result.path_primary.note


def test_collect_signals_captive_portal_flows_to_snapshot():
    target = parse_target("example.com")
    with (
        patch(f"{_MOD}.collect_gateway", return_value=_GATEWAY),
        patch(f"{_MOD}.collect_dns", return_value=_DNS),
        patch(f"{_MOD}.collect_ip_connectivity", return_value=_IP_OK),
        patch(f"{_MOD}.collect_control_hosts", return_value=_CONTROLS_OK),
        patch(f"{_MOD}.collect_target_service", return_value=_TARGET),
        patch(f"{_MOD}.collect_path", return_value=_PATH),
        patch(f"{_MOD}.collect_captive_portal", return_value=_CAPTIVE_PORTAL),
    ):
        result = collect_signals(target, runner=MagicMock())

    assert result.captive.portal_detected is True
    assert result.snapshot.captive_portal_detected is True


def test_collect_signals_ipv6_route_flows_to_snapshot():
    # collect_ipv6_route is only invoked when there's no v4 default route
    # (see test_collect_signals_skips_ipv6_check_when_v4_route_present below),
    # so this needs a gateway with no route to actually exercise it.
    target = parse_target("example.com")
    with (
        patch(f"{_MOD}.collect_gateway", return_value=_GATEWAY_NO_ROUTE),
        patch(f"{_MOD}.collect_ipv6_route", return_value=_IPV6_ROUTE_PRESENT),
        patch(f"{_MOD}.collect_dns", return_value=_DNS),
        patch(f"{_MOD}.collect_ip_connectivity", return_value=_IP_OK),
        patch(f"{_MOD}.collect_control_hosts", return_value=_CONTROLS_OK),
        patch(f"{_MOD}.collect_target_service", return_value=_TARGET),
        patch(f"{_MOD}.collect_path", return_value=_PATH),
        patch(f"{_MOD}.collect_captive_portal", return_value=_CAPTIVE_CLEAN),
    ):
        result = collect_signals(target, runner=MagicMock())

    assert result.ipv6_route.present is True
    assert result.snapshot.ipv6_default_route_present is True


def test_collect_signals_skips_ipv6_check_when_v4_route_present():
    # ipv6_default_route_present is don't-care whenever a v4 default route
    # exists (the ipv6-only engine rule requires default_route_present=False)
    # - skip the extra subprocess call on the common healthy-host path.
    target = parse_target("example.com")
    ipv6_mock = MagicMock(return_value=_IPV6_ROUTE_PRESENT)
    with (
        patch(f"{_MOD}.collect_gateway", return_value=_GATEWAY),
        patch(f"{_MOD}.collect_ipv6_route", ipv6_mock),
        patch(f"{_MOD}.collect_dns", return_value=_DNS),
        patch(f"{_MOD}.collect_ip_connectivity", return_value=_IP_OK),
        patch(f"{_MOD}.collect_control_hosts", return_value=_CONTROLS_OK),
        patch(f"{_MOD}.collect_target_service", return_value=_TARGET),
        patch(f"{_MOD}.collect_path", return_value=_PATH),
        patch(f"{_MOD}.collect_captive_portal", return_value=_CAPTIVE_CLEAN),
    ):
        result = collect_signals(target, runner=MagicMock())

    ipv6_mock.assert_not_called()
    assert result.snapshot.ipv6_default_route_present is False


def test_collect_signals_skip_captive_makes_no_check():
    # skip_captive must short-circuit the captive collector entirely (no network).
    target = parse_target("example.com")
    captive = MagicMock(return_value=_CAPTIVE_CLEAN)
    with (
        patch(f"{_MOD}.collect_gateway", return_value=_GATEWAY),
        patch(f"{_MOD}.collect_dns", return_value=_DNS),
        patch(f"{_MOD}.collect_ip_connectivity", return_value=_IP_OK),
        patch(f"{_MOD}.collect_control_hosts", return_value=_CONTROLS_OK),
        patch(f"{_MOD}.collect_target_service", return_value=_TARGET),
        patch(f"{_MOD}.collect_path", return_value=_PATH),
        patch(f"{_MOD}.collect_captive_portal", captive),
    ):
        result = collect_signals(target, runner=MagicMock(), skip_captive=True)

    # called with an empty url (disabled), never the real endpoint
    captive.assert_called_once_with(check_url="")
    assert result.snapshot.captive_portal_detected is False
