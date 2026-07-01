from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from boundary_probe.models import Diagnosis, EvidenceItem, SignalSnapshot
from boundary_probe.store import (
    SCHEMA_VERSION,
    confidence_band,
    connect,
    fetch_recent,
    get_db_path,
    insert_run,
)
from boundary_probe.targets import parse_target


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    db_file = tmp_path / "test_runs.db"
    monkeypatch.setenv("BOUNDARY_PROBE_DB", str(db_file))
    return db_file


def _make_collection_result():
    from boundary_probe.collectors.captive_portal import CaptivePortalSlice
    from boundary_probe.collectors.control_hosts import ControlHostResult, ControlHostsSlice
    from boundary_probe.collectors.dns import DnsSlice
    from boundary_probe.collectors.gateway import GatewaySlice
    from boundary_probe.collectors.ip_connectivity import IpConnectivitySlice
    from boundary_probe.collectors.ipv6_route import Ipv6RouteSlice
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
        path_primary=PathSlice(raw_hops=[{"index": 1, "loss_pct": 0.0, "rtt_ms": 2.0, "host": "192.168.1.1"}],
                               target="example.com", completed=False, note=""),
        path_secondary=None,
        captive=CaptivePortalSlice(checked=True, portal_detected=False, note=""),
        ipv6_route=Ipv6RouteSlice(present=False, note=""),
        elapsed_ms=5000,
    )


def _make_diagnosis() -> Diagnosis:
    return Diagnosis(
        boundary="remote-service",
        confidence=0.95,
        summary="General internet health is good but target fails.",
        evidence=[EvidenceItem("controls", "healthy"), EvidenceItem("target", "failing")],
        remediation=["Check the service status page."],
    )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_created_on_connect(tmp_db):
    with connect() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "runs" in tables
    assert "schema_meta" in tables


def test_schema_version_written(tmp_db):
    with connect() as conn:
        row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
    assert row[0] == SCHEMA_VERSION


def test_schema_drop_recreate_on_version_mismatch(tmp_db):
    with connect() as conn:
        conn.execute("UPDATE schema_meta SET value='0' WHERE key='schema_version'")
    with connect() as conn:
        row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        assert row[0] == SCHEMA_VERSION
        count = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        assert count == 0


# ---------------------------------------------------------------------------
# insert_run / fetch_recent
# ---------------------------------------------------------------------------


def test_insert_run_returns_uuid(tmp_db):
    parsed = parse_target("example.com")
    diagnosis = _make_diagnosis()
    cr = _make_collection_result()
    with connect() as conn:
        run_uuid = insert_run(conn, parsed_target=parsed, snapshot=cr.snapshot,
                              diagnosis=diagnosis, collection_result=cr)
    assert isinstance(run_uuid, str)
    assert len(run_uuid) == 32


def test_insert_run_round_trip(tmp_db):
    parsed = parse_target("example.com")
    diagnosis = _make_diagnosis()
    cr = _make_collection_result()
    with connect() as conn:
        run_uuid = insert_run(conn, parsed_target=parsed, snapshot=cr.snapshot,
                              diagnosis=diagnosis, collection_result=cr)
        rows = fetch_recent(conn, 10)
    assert len(rows) == 1
    row = rows[0]
    assert row["run_uuid"] == run_uuid
    assert row["target_raw"] == "example.com"
    assert row["boundary"] == "remote-service"
    assert row["confidence_float"] == pytest.approx(0.95)
    assert row["confidence_band"] == "Moderate"
    assert row["gateway_reachable"] == 1
    assert row["target_service_ok"] == 0


def test_fetch_recent_ordering(tmp_db):
    parsed = parse_target("example.com")
    diagnosis = _make_diagnosis()
    cr = _make_collection_result()
    with connect() as conn:
        uuid1 = insert_run(conn, parsed_target=parsed, snapshot=cr.snapshot,
                           diagnosis=diagnosis, collection_result=cr)
        uuid2 = insert_run(conn, parsed_target=parsed, snapshot=cr.snapshot,
                           diagnosis=diagnosis, collection_result=cr)
        rows = fetch_recent(conn, 10)
    # Most recent first — uuid2 was inserted after uuid1
    assert rows[0]["run_uuid"] == uuid2
    assert rows[1]["run_uuid"] == uuid1


def test_fetch_recent_limit(tmp_db):
    parsed = parse_target("example.com")
    diagnosis = _make_diagnosis()
    cr = _make_collection_result()
    with connect() as conn:
        for _ in range(5):
            insert_run(conn, parsed_target=parsed, snapshot=cr.snapshot,
                       diagnosis=diagnosis, collection_result=cr)
        rows = fetch_recent(conn, 3)
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# confidence_band
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("conf,expected", [
    (0.99, "High"),
    (0.97, "High"),
    (0.96, "Moderate"),
    (0.90, "Moderate"),
    (0.89, "Low"),
    (0.50, "Low"),
])
def test_confidence_band_thresholds(conf, expected):
    assert confidence_band(conf) == expected


# ---------------------------------------------------------------------------
# env override
# ---------------------------------------------------------------------------


def test_env_override_path(tmp_path, monkeypatch):
    custom = tmp_path / "custom.db"
    monkeypatch.setenv("BOUNDARY_PROBE_DB", str(custom))
    assert get_db_path() == custom


def test_default_route_present_persists_both_values(tmp_db):
    """The default_route_present signal must survive a write→read round-trip
    (regression: the column and INSERT value were originally omitted, so a
    local-device run was indistinguishable from router-gateway in history)."""
    import dataclasses

    from boundary_probe.models import SignalSnapshot

    base = _make_collection_result()
    parsed = parse_target("example.com")
    diag = Diagnosis(boundary="local-device", confidence=0.97, summary="s",
                     evidence=[EvidenceItem("route", "no default route")], remediation=["fix"])

    no_route = dataclasses.replace(base, snapshot=dataclasses.replace(base.snapshot, default_route_present=False))
    with_route = dataclasses.replace(base, snapshot=dataclasses.replace(base.snapshot, default_route_present=True))

    with connect() as conn:
        insert_run(conn, parsed_target=parsed, snapshot=no_route.snapshot,
                   diagnosis=diag, collection_result=no_route)
        insert_run(conn, parsed_target=parsed, snapshot=with_route.snapshot,
                   diagnosis=diag, collection_result=with_route)
    with connect() as conn:
        rows = fetch_recent(conn, limit=2)

    values = {row["default_route_present"] for row in rows}
    assert values == {0, 1}
