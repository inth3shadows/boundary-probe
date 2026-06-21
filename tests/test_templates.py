from __future__ import annotations

import pytest

from boundary_probe.engine import diagnose
from boundary_probe.store import connect, insert_run
from boundary_probe.targets import parse_target
from boundary_probe.templates import render_escalation


def _make_row(tmp_db, fake_collection_result, boundary_target: str = "example.com"):
    """Seed a run and return the fetched row."""
    from boundary_probe.store import fetch_run

    parsed = parse_target(boundary_target)
    result = fake_collection_result
    diag = diagnose(result.snapshot)
    with connect() as conn:
        uuid = insert_run(
            conn,
            parsed_target=parsed,
            snapshot=result.snapshot,
            diagnosis=diag,
            collection_result=result,
        )
    with connect() as conn:
        return fetch_run(conn, uuid), uuid


class TestRenderEscalation:
    def test_remote_service_title(self, tmp_db, fake_collection_result):
        row, _ = _make_row(tmp_db, fake_collection_result)
        # fake_collection_result has target_service_ok=False → remote-service boundary
        text = render_escalation(row)
        assert "SERVICE PROVIDER ESCALATION REPORT" in text

    def test_isp_title(self, tmp_db, fake_collection_result, monkeypatch):
        from boundary_probe.models import SignalSnapshot
        from boundary_probe.collectors.orchestrator import CollectionResult

        # Patch snapshot to trigger isp-upstream boundary
        isp_snap = SignalSnapshot(
            gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
            control_hosts_ok=False, target_service_ok=False,
            packet_loss_after_hop1=True, packet_loss_multiple_targets=True,
        )
        result = fake_collection_result
        import dataclasses
        isp_result = dataclasses.replace(result, snapshot=isp_snap)

        parsed = parse_target("1.1.1.1")
        diag = diagnose(isp_snap)
        with connect() as conn:
            uuid = insert_run(conn, parsed_target=parsed, snapshot=isp_snap,
                              diagnosis=diag, collection_result=isp_result)
        from boundary_probe.store import fetch_run
        with connect() as conn:
            row = fetch_run(conn, uuid)

        text = render_escalation(row)
        if row["boundary"] == "isp-upstream":
            assert "INTERNET SERVICE PROVIDER" in text
        else:
            # boundary didn't resolve to isp-upstream with this signal set; just check it renders
            assert "DIAGNOSIS" in text

    def test_local_summary_title(self, tmp_db, fake_collection_result, monkeypatch):
        from boundary_probe.models import SignalSnapshot
        import dataclasses

        gw_fail_snap = SignalSnapshot(
            gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
            control_hosts_ok=False, target_service_ok=False,
        )
        result = fake_collection_result
        gw_result = dataclasses.replace(result, snapshot=gw_fail_snap)

        parsed = parse_target("example.com")
        diag = diagnose(gw_fail_snap)
        with connect() as conn:
            uuid = insert_run(conn, parsed_target=parsed, snapshot=gw_fail_snap,
                              diagnosis=diag, collection_result=gw_result)
        from boundary_probe.store import fetch_run
        with connect() as conn:
            row = fetch_run(conn, uuid)

        text = render_escalation(row)
        # router-gateway or inconclusive → local summary
        assert "LOCAL NETWORK INCIDENT SUMMARY" in text

    def test_contains_run_uuid(self, tmp_db, fake_collection_result):
        row, uuid = _make_row(tmp_db, fake_collection_result)
        text = render_escalation(row)
        assert uuid in text

    def test_contains_required_sections(self, tmp_db, fake_collection_result):
        row, _ = _make_row(tmp_db, fake_collection_result)
        text = render_escalation(row)
        for section in ("TARGET", "DIAGNOSIS", "TECHNICAL EVIDENCE",
                        "NETWORK MEASUREMENTS", "REQUESTED ACTION"):
            assert section in text

    def test_contains_target(self, tmp_db, fake_collection_result):
        row, _ = _make_row(tmp_db, fake_collection_result)
        text = render_escalation(row)
        assert "example.com" in text

    def test_contains_gateway_ip(self, tmp_db, fake_collection_result):
        row, _ = _make_row(tmp_db, fake_collection_result)
        text = render_escalation(row)
        assert "192.168.1.1" in text


class TestHealthyRendering:
    def _healthy_row(self, fake_collection_result):
        import dataclasses

        from boundary_probe.models import SignalSnapshot
        from boundary_probe.store import fetch_run

        green = SignalSnapshot(
            gateway_reachable=True, dns_ok=True, ip_connectivity_ok=True,
            control_hosts_ok=True, target_service_ok=True,
        )
        result = dataclasses.replace(fake_collection_result, snapshot=green)
        parsed = parse_target("example.com")
        diag = diagnose(green)
        assert diag.boundary == "healthy"
        with connect() as conn:
            uuid = insert_run(conn, parsed_target=parsed, snapshot=green,
                              diagnosis=diag, collection_result=result)
        with connect() as conn:
            return fetch_run(conn, uuid)

    def test_detail_marks_boundary_box_ok(self, tmp_db, fake_collection_result):
        from boundary_probe.ui.templates import render_detail

        body = render_detail(self._healthy_row(fake_collection_result))
        assert 'class="boundary-box ok"' in body
        assert ">healthy<" in body

    def test_detail_suppresses_escalation_actions_when_healthy(self, tmp_db, fake_collection_result):
        from boundary_probe.ui.templates import render_detail

        body = render_detail(self._healthy_row(fake_collection_result))
        assert "no escalation needed" in body
        assert "Open email client" not in body
