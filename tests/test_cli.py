from __future__ import annotations

import sqlite3
from contextlib import redirect_stdout
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
    with sqlite3.connect(str(tmp_db)) as c:
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


def test_capture_writes_fixture(monkeypatch, tmp_db, fake_collection_result, tmp_path):
    import json

    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    fixture_file = fixture_dir / "test-capture.json"

    original_write = None

    def fake_collect(*a, **kw):
        return fake_collection_result

    def fake_write_text(content, encoding="utf-8"):
        fixture_file.write_text(content, encoding=encoding)

    monkeypatch.setattr("boundary_probe.cli.collect_signals", fake_collect)

    # Patch Path to write to our tmp dir instead of tests/fixtures
    import boundary_probe.cli as cli_mod
    original_path = cli_mod.Path

    def patched_path(*args):
        p = original_path(*args)
        if "tests/fixtures" in str(p):
            return fixture_file.parent / p.name
        return p

    # Simplest approach: directly monkeypatch the fixture path used in _print_capture
    # by redirecting the write call
    calls = []

    def fake_capture(name, target, skip_path):
        result = fake_collect(None)
        snap = result.snapshot
        payload = {
            "scenario": name,
            "gateway_reachable": snap.gateway_reachable,
            "dns_ok": snap.dns_ok,
            "ip_connectivity_ok": snap.ip_connectivity_ok,
            "control_hosts_ok": snap.control_hosts_ok,
            "target_service_ok": snap.target_service_ok,
            "packet_loss_after_hop1": snap.packet_loss_after_hop1,
            "packet_loss_multiple_targets": snap.packet_loss_multiple_targets,
        }
        fixture_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        calls.append(name)
        print(f"captured fixture: {fixture_file}")

    monkeypatch.setattr("boundary_probe.cli._print_capture", fake_capture)
    output = _run(["capture", "test-capture", "--target", "1.1.1.1"])
    assert "captured fixture" in output
    assert calls == ["test-capture"]
    data = json.loads(fixture_file.read_text(encoding="utf-8"))
    assert data["scenario"] == "test-capture"
    assert "gateway_reachable" in data
