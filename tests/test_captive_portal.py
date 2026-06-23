"""Captive-portal collector + the engine rule it drives.

The collector fail-opens on every error class (a dead connection is NOT a portal)
and only flags a portal on a definitive interception fingerprint. The engine rule
is the high-value fix: a detected portal must override the otherwise-green
`healthy` verdict.
"""
from __future__ import annotations

import socket
import urllib.error

import pytest

from boundary_probe.collectors.captive_portal import collect_captive_portal
from boundary_probe.engine import diagnose
from boundary_probe.models import SignalSnapshot

URL = "http://connectivitycheck.gstatic.com/generate_204"


# --- collector -------------------------------------------------------------

def test_clean_204_is_not_a_portal():
    s = collect_captive_portal(URL, 4.0, fetch_fn=lambda u, t: (204, 0))
    assert s.checked and s.portal_detected is False


def test_redirect_is_a_portal():
    # urllib surfaces a refused redirect as HTTPError(302); the collector's
    # _default_fetch maps that to a status — here we inject the status directly.
    s = collect_captive_portal(URL, 4.0, fetch_fn=lambda u, t: (302, 0))
    assert s.checked and s.portal_detected is True
    assert "302" in s.note


def test_200_with_body_is_a_portal():
    # A 200 with a splash-page body where an empty 204 was expected.
    s = collect_captive_portal(URL, 4.0, fetch_fn=lambda u, t: (200, 1500))
    assert s.checked and s.portal_detected is True


def test_204_with_unexpected_body_is_a_portal():
    s = collect_captive_portal(URL, 4.0, fetch_fn=lambda u, t: (204, 42))
    assert s.checked and s.portal_detected is True


@pytest.mark.parametrize("exc", [
    urllib.error.URLError("conn refused"),
    socket.timeout("timed out"),
    OSError("network unreachable"),
])
def test_request_error_is_not_a_portal(exc):
    # No response at all could just be a dead link — must NOT accuse a portal.
    def _raise(u, t):
        raise exc
    s = collect_captive_portal(URL, 4.0, fetch_fn=_raise)
    assert s.checked is False and s.portal_detected is False


def test_disabled_when_url_empty():
    called = []
    s = collect_captive_portal("", 4.0, fetch_fn=lambda u, t: called.append(u))
    assert s.checked is False and s.portal_detected is False
    assert called == []  # no fetch attempted


# --- engine rule -----------------------------------------------------------

def _all_green(**over) -> SignalSnapshot:
    base = dict(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=True, target_service_ok=True,
        default_route_present=True, packet_loss_after_hop1=False,
        packet_loss_multiple_targets=False,
    )
    base.update(over)
    return SignalSnapshot(**base)


def test_portal_overrides_healthy():
    # The core fix: every signal green EXCEPT the portal flag -> would be healthy,
    # but the portal verdict must win.
    assert diagnose(_all_green()).boundary == "healthy"  # sanity: green => healthy
    assert diagnose(_all_green(captive_portal_detected=True)).boundary == "captive-portal"


def test_portal_overrides_dns_and_remote():
    # Portals make DNS "resolve" and the target "reachable"; the flag still wins.
    snap = _all_green(captive_portal_detected=True, target_service_ok=False)
    assert diagnose(snap).boundary == "captive-portal"


def test_portal_not_blamed_when_gateway_down():
    # If the gateway isn't forwarding you can't reach a portal; the gateway-down
    # rules precede the portal rule, so they win even if the flag were set.
    snap = SignalSnapshot(
        gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False,
        default_route_present=True, captive_portal_detected=True,
    )
    assert diagnose(snap).boundary == "router-gateway"


def test_captive_verdict_has_remediation():
    diag = diagnose(_all_green(captive_portal_detected=True))
    assert diag.confidence == pytest.approx(0.97)
    assert any("portal" in r.lower() or "sign-in" in r.lower() for r in diag.remediation)
