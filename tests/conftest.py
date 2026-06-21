from __future__ import annotations

import json
from pathlib import Path

import pytest

from boundary_probe.models import SignalSnapshot

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture_raw(name: str) -> dict:
    """Return the full parsed fixture JSON (signals + measurements, if present)."""
    path = FIXTURES_DIR / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def load_signal_fixture(name: str) -> SignalSnapshot:
    data = load_fixture_raw(name)
    if "signals" in data:
        # v2 enriched fixture: signals live in their own block alongside measurements.
        return SignalSnapshot(**data["signals"])
    # v1 synthetic fixture: flat booleans, no measurements.
    data.pop("scenario", None)
    return SignalSnapshot(**data)


@pytest.fixture
def signal_fixture():
    return load_signal_fixture


@pytest.fixture
def fixture_raw():
    return load_fixture_raw


# ---------------------------------------------------------------------------
# Phase 1 fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_runs.db"
    monkeypatch.setenv("BOUNDARY_PROBE_DB", str(db_file))
    return db_file


@pytest.fixture
def fake_collection_result():
    from boundary_probe.collectors.control_hosts import ControlHostResult, ControlHostsSlice
    from boundary_probe.collectors.dns import DnsSlice
    from boundary_probe.collectors.gateway import GatewaySlice
    from boundary_probe.collectors.ip_connectivity import IpConnectivitySlice
    from boundary_probe.collectors.orchestrator import CollectionResult
    from boundary_probe.collectors.path import PathSlice
    from boundary_probe.collectors.target_service import TargetServiceSlice
    from boundary_probe.models import SignalSnapshot

    snap = SignalSnapshot(
        gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
        control_hosts_ok=True, target_service_ok=False,
    )
    return CollectionResult(
        snapshot=snap,
        gateway=GatewaySlice(reachable=True, gateway_ip="192.168.1.1", rtt_ms=2.0, note=""),
        dns=DnsSlice(ok=True, resolved_ips=["93.184.216.34"], resolver_used=None, elapsed_ms=5, note=""),
        ip=IpConnectivitySlice(ok=True, target_ip="1.1.1.1", loss_pct=0.0, avg_rtt_ms=4.0, note=""),
        controls=ControlHostsSlice(all_ok=True, ok_count=4, total=4, results=[
            ControlHostResult(host="1.1.1.1", reachable=True, loss_pct=0.0, avg_rtt_ms=4.0),
            ControlHostResult(host="8.8.8.8", reachable=True, loss_pct=0.0, avg_rtt_ms=6.0),
            ControlHostResult(host="8.8.4.4", reachable=True, loss_pct=0.0, avg_rtt_ms=6.0),
            ControlHostResult(host="cloudflare.com", reachable=True, loss_pct=0.0, avg_rtt_ms=5.0),
        ], note=""),
        target=TargetServiceSlice(ok=False, method="ping", target_host="example.com",
                                  target_port=None, elapsed_ms=100, note="100% packet loss"),
        path_primary=PathSlice(raw_hops=[], target="example.com", completed=False, note=""),
        path_secondary=None,
        elapsed_ms=5000,
    )
