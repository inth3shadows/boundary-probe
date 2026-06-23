from __future__ import annotations

import sqlite3
from contextlib import closing, redirect_stdout
from io import StringIO

import pytest

from boundary_probe.cli import main


def _run(argv: list[str]) -> str:
    stream = StringIO()
    with redirect_stdout(stream):
        main(argv)
    return stream.getvalue()


# ---------------------------------------------------------------------------
# Phase 0 tests (kept; adapted for new CLI)
# ---------------------------------------------------------------------------


def test_diagnose_outputs_expected_boundary(monkeypatch, tmp_db, fake_collection_result):
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    output = _run(["diagnose", "remote-service"])
    assert "Boundary:   remote-service" in output


def test_diagnose_confidence_is_band_first_with_prior_label(monkeypatch, tmp_db, fake_collection_result):
    # Confidence leads with the band; the float is demoted and labeled a prior,
    # not a measured rate (calibration decision — see docs/CALIBRATION.md).
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    output = _run(["diagnose", "remote-service"])
    # remote-service is 0.95 -> Moderate band
    assert "Confidence: Moderate (0.95 prior)" in output


def test_roadmap_command_runs():
    output = _run(["roadmap"])
    assert "Boundary Probe roadmap:" in output



def test_diagnose_with_url_target(monkeypatch, tmp_db, fake_collection_result):
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    output = _run(["diagnose", "https://example.com"])
    assert "Target:     https://example.com (url)" in output
    assert "Run saved:" in output


def test_diagnose_with_ip_target(monkeypatch, tmp_db, fake_collection_result):
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    output = _run(["diagnose", "1.1.1.1"])
    assert "(ip)" in output


# ---------------------------------------------------------------------------
# Phase 1 tests
# ---------------------------------------------------------------------------


def test_diagnose_persists_run(monkeypatch, tmp_db, fake_collection_result):
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    output = _run(["diagnose", "example.com"])
    assert "Run saved:" in output
    # `with sqlite3.connect(...)` is a transaction context, not a resource one —
    # it does not close the connection. Use closing() so the handle is released.
    with closing(sqlite3.connect(str(tmp_db))) as c:
        rows = list(c.execute("SELECT boundary FROM runs"))
    assert len(rows) == 1
    assert rows[0][0] == "remote-service"


def test_diagnose_json_output(monkeypatch, tmp_db, fake_collection_result):
    import json
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    output = _run(["diagnose", "example.com", "--json"])
    data = json.loads(output)
    assert data["boundary"] == "remote-service"
    assert "run_uuid" in data
    assert "collector_facts" in data
    facts = data["collector_facts"]
    assert facts["gateway_ip"] == "192.168.1.1"
    assert facts["controls_ok"] == 4
    assert facts["controls_total"] == 4


def test_diagnose_collector_details_in_text_output(monkeypatch, tmp_db, fake_collection_result):
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    output = _run(["diagnose", "example.com"])
    assert "Collector details:" in output
    assert "Gateway:" in output
    assert "Controls:" in output


def test_config_subcommand_runs():
    output = _run(["config"])
    assert "Config file:" in output
    assert "[probes]" in output
    assert "[timeouts]" in output
    assert "control_hosts" in output


def test_history_empty_db_prints_message(tmp_db):
    output = _run(["diagnose", "--history", "5"])
    assert "no runs recorded yet" in output


def test_history_with_rows_prints_table(monkeypatch, tmp_db, fake_collection_result):
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    _run(["diagnose", "example.com"])
    output = _run(["diagnose", "--history", "5"])
    assert "TIMESTAMP" in output
    assert "remote-service" in output


def test_history_zero_errors(tmp_db, capsys):
    import sys
    with pytest.raises(SystemExit) as exc:
        main(["diagnose", "--history", "0"])
    assert exc.value.code == 2


def test_build_capture_payload_includes_signals_and_measurements(fake_collection_result):
    # Exercises the REAL payload builder (the old test asserted against a copy).
    from boundary_probe.cli import _build_capture_payload
    from boundary_probe.targets import parse_target

    parsed = parse_target("example.com")
    payload = _build_capture_payload("scn", parsed, fake_collection_result, "2026-06-21T00:00:00Z")

    # signals block reconstructs the snapshot (all flags present)
    assert payload["signals"] == {
        "gateway_reachable": True, "dns_ok": True, "ip_connectivity_ok": True,
        "control_hosts_ok": True, "target_service_ok": False, "default_route_present": True,
        "packet_loss_after_hop1": False, "packet_loss_multiple_targets": False,
        "captive_portal_detected": False,
    }
    # measurements preserve the raw per-collector data the booleans discard
    m = payload["measurements"]
    assert m["gateway"]["rtt_ms"] == 2.0
    assert m["gateway"]["gateway_ip"] == "192.168.1.1"
    assert m["dns"]["resolved_ips"] == ["93.184.216.34"]
    assert m["ip_connectivity"]["loss_pct"] == 0.0
    assert len(m["control_hosts"]["results"]) == 4
    assert "raw_hops" in m["path_primary"]
    assert payload["captured_at"] == "2026-06-21T00:00:00Z"
    assert payload["target"] == "example.com"


def test_capture_writes_enriched_fixture(monkeypatch, tmp_db, fake_collection_result, tmp_path):
    # End-to-end through the real _print_capture: signals + measurements written and round-tripped.
    import json

    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)

    output = _run(["capture", "scn", "--target", "1.1.1.1"])
    assert "captured fixture" in output
    data = json.loads((tmp_path / "tests" / "fixtures" / "scn.json").read_text(encoding="utf-8"))
    assert set(data) == {"scenario", "captured_at", "capture_method", "target", "signals", "measurements"}
    assert data["measurements"]["gateway"]["rtt_ms"] == 2.0
    # default capture_method is "real"; no expected_boundary unless asked for
    assert data["capture_method"] == "real"
    assert "expected_boundary" not in data


def test_capture_records_label_and_injected_method(monkeypatch, tmp_db, fake_collection_result, tmp_path):
    # The calibration flags round-trip into the fixture (issue #11).
    import json

    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)

    _run(["capture", "dns-broken", "--target", "1.1.1.1",
          "--expected-boundary", "dns", "--capture-method", "injected"])
    data = json.loads((tmp_path / "tests" / "fixtures" / "dns-broken.json").read_text(encoding="utf-8"))
    assert data["expected_boundary"] == "dns"
    assert data["capture_method"] == "injected"


def test_scrub_measurements_redacts_public_keeps_private():
    from boundary_probe.cli import _SCRUB_PLACEHOLDER, _scrub_measurements

    measurements = {
        "gateway": {"gateway_ip": "8.8.8.8"},          # public -> scrub
        "path_primary": {"raw_hops": [
            {"index": 1, "host": "10.0.0.1"},          # private -> keep
            {"index": 2, "host": "1.2.3.4"},           # public -> scrub
            {"index": 3, "host": "*"},                 # non-IP -> keep
        ]},
        "path_secondary": None,
    }
    scrubbed, hits = _scrub_measurements(measurements, scrub=True)
    assert len(hits) == 2
    assert scrubbed["gateway"]["gateway_ip"] == _SCRUB_PLACEHOLDER
    hops = scrubbed["path_primary"]["raw_hops"]
    assert hops[0]["host"] == "10.0.0.1"
    assert hops[1]["host"] == _SCRUB_PLACEHOLDER
    assert hops[2]["host"] == "*"
    # original is untouched (deep-copied)
    assert measurements["gateway"]["gateway_ip"] == "8.8.8.8"

    # scrub=False reports the public IPs found but changes nothing
    same, found = _scrub_measurements(measurements, scrub=False)
    assert len(found) == 2
    assert same["gateway"]["gateway_ip"] == "8.8.8.8"


def _result_with_public_hop(fake_collection_result):
    from dataclasses import replace
    return replace(
        fake_collection_result,
        path_primary=replace(
            fake_collection_result.path_primary,
            raw_hops=[{"index": 2, "host": "1.2.3.4", "loss_pct": 0.0, "rtt_ms": 1.0}],
        ),
    )


def test_capture_scrubs_public_hop_by_default(monkeypatch, tmp_db, fake_collection_result, tmp_path):
    import json
    from boundary_probe.cli import _SCRUB_PLACEHOLDER

    res = _result_with_public_hop(fake_collection_result)
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: res)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)

    _run(["capture", "scn", "--target", "1.1.1.1"])
    data = json.loads((tmp_path / "tests" / "fixtures" / "scn.json").read_text(encoding="utf-8"))
    assert data["measurements"]["path_primary"]["raw_hops"][0]["host"] == _SCRUB_PLACEHOLDER


def test_capture_no_scrub_blocks_public_ip(monkeypatch, tmp_db, fake_collection_result, tmp_path):
    res = _result_with_public_hop(fake_collection_result)
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: res)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)

    with pytest.raises(SystemExit) as exc:
        main(["capture", "scn", "--target", "1.1.1.1", "--no-scrub"])
    assert exc.value.code == 5
    assert not (tmp_path / "tests" / "fixtures" / "scn.json").exists()


def test_capture_no_scrub_allow_public_writes_raw(monkeypatch, tmp_db, fake_collection_result, tmp_path):
    import json

    res = _result_with_public_hop(fake_collection_result)
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: res)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)

    _run(["capture", "scn", "--target", "1.1.1.1", "--no-scrub", "--allow-public-ips"])
    data = json.loads((tmp_path / "tests" / "fixtures" / "scn.json").read_text(encoding="utf-8"))
    assert data["measurements"]["path_primary"]["raw_hops"][0]["host"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# Phase 4 tests — escalate subcommand
# ---------------------------------------------------------------------------


def _seed_run(monkeypatch, tmp_db, fake_collection_result) -> str:
    """Seed one run; return its uuid."""
    from boundary_probe.engine import diagnose
    from boundary_probe.store import connect, insert_run
    from boundary_probe.targets import parse_target

    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: fake_collection_result)
    _run(["diagnose", "example.com"])
    with connect() as conn:
        rows = conn.execute("SELECT run_uuid FROM runs").fetchall()
    return rows[0]["run_uuid"]


def test_escalate_prints_report(monkeypatch, tmp_db, fake_collection_result):
    uuid = _seed_run(monkeypatch, tmp_db, fake_collection_result)
    output = _run(["escalate", uuid, "--no-file"])
    assert "DIAGNOSIS" in output
    assert uuid in output


def test_escalate_writes_file(monkeypatch, tmp_db, fake_collection_result, tmp_path):
    import os
    uuid = _seed_run(monkeypatch, tmp_db, fake_collection_result)
    out_file = tmp_path / "report.txt"
    _run(["escalate", uuid, "--output", str(out_file)])
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "DIAGNOSIS" in content
    assert uuid in content


def test_escalate_missing_uuid(tmp_db, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["escalate", "doesnotexist"])
    assert exc.value.code == 2


def test_escalate_help():
    buf = StringIO()
    with pytest.raises(SystemExit) as exc:
        with redirect_stdout(buf):
            main(["escalate", "--help"])
    assert exc.value.code == 0
    assert "--copy" in buf.getvalue()


def test_capture_rejects_path_traversal_name(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["capture", "../evil", "--target", "example.com"])
    assert exc.value.code == 2
    assert "fixture name" in capsys.readouterr().err


def test_capture_rejects_slash_in_name(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["capture", "foo/bar", "--target", "example.com"])
    assert exc.value.code == 2
    assert "fixture name" in capsys.readouterr().err


def test_capture_real_roundtrip_with_no_default_route(monkeypatch, tmp_db, fake_collection_result, tmp_path):
    # Regression for #3: capturing a snapshot with default_route_present=False must
    # pass the real _print_capture round-trip validation. Originally the payload
    # omitted the field, so reload defaulted it to True != False, failing validation
    # and deleting the fixture with exit 4. Exercises the real code path, not a copy.
    import dataclasses
    import json

    no_route = dataclasses.replace(
        fake_collection_result,
        snapshot=dataclasses.replace(fake_collection_result.snapshot, default_route_present=False),
    )
    monkeypatch.setattr("boundary_probe.cli.collect_signals", lambda *a, **kw: no_route)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)

    output = _run(["capture", "localdev", "--target", "1.1.1.1"])
    assert "captured fixture" in output
    data = json.loads((tmp_path / "tests" / "fixtures" / "localdev.json").read_text(encoding="utf-8"))
    assert data["signals"]["default_route_present"] is False
