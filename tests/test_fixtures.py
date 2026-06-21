from __future__ import annotations

import pytest

from boundary_probe.engine import diagnose
from boundary_probe.models import SignalSnapshot

SCENARIOS = [
    ("router-down", "router-gateway"),
    ("dns-failure", "dns"),
    ("isp-path", "isp-upstream"),
    ("remote-service", "remote-service"),
]


@pytest.mark.parametrize("name,expected_boundary", SCENARIOS)
def test_fixture_loads_and_classifies(name: str, expected_boundary: str, signal_fixture) -> None:
    snapshot = signal_fixture(name)
    assert isinstance(snapshot, SignalSnapshot)
    diagnosis = diagnose(snapshot)
    assert diagnosis.boundary == expected_boundary, (
        f"fixture '{name}': expected boundary '{expected_boundary}', got '{diagnosis.boundary}'"
    )


def test_loader_handles_v2_enriched_fixture(signal_fixture, tmp_path, monkeypatch):
    # The loader must read signals from the nested `signals` block of an enriched
    # (v2) fixture, while v1 synthetic fixtures (flat booleans) keep loading.
    import json
    import sys

    mod = sys.modules[signal_fixture.__module__]
    monkeypatch.setattr(mod, "FIXTURES_DIR", tmp_path)
    (tmp_path / "v2.json").write_text(json.dumps({
        "scenario": "v2", "captured_at": "t", "target": "x",
        "signals": {
            "gateway_reachable": False, "dns_ok": False, "ip_connectivity_ok": False,
            "control_hosts_ok": False, "target_service_ok": False,
            "default_route_present": False, "packet_loss_after_hop1": False,
            "packet_loss_multiple_targets": False,
        },
        "measurements": {"gateway": {"gateway_ip": None}},
    }), encoding="utf-8")

    snap = signal_fixture("v2")
    assert isinstance(snap, SignalSnapshot)
    assert snap.gateway_reachable is False
    assert snap.default_route_present is False
