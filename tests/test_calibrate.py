from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "calibrate.py"


def _load_calibrate():
    spec = importlib.util.spec_from_file_location("calibrate", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_calibrate_runs_and_reports_per_boundary(capsys):
    # Smoke test: the harness loads the shipped fixtures, classifies each, and
    # prints one row per boundary. No assertion on the *values* — those are not
    # meaningful until enough real captures exist (see docs/CALIBRATION.md).
    mod = _load_calibrate()
    rc = mod.main(["calibrate.py"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "hardcoded" in out and "empirical" in out
    # every rule's boundary appears in the report
    from boundary_probe.engine import BOUNDARIES
    for boundary in BOUNDARIES:
        assert boundary in out


def test_calibrate_uses_expected_boundary_field(tmp_path, capsys):
    # A captured fixture with an explicit ground-truth label is scored against it.
    import json
    (tmp_path / "case.json").write_text(json.dumps({
        "scenario": "case",
        "expected_boundary": "healthy",
        "signals": {
            "gateway_reachable": True, "dns_ok": True, "ip_connectivity_ok": True,
            "control_hosts_ok": True, "target_service_ok": True,
            "default_route_present": True,
            "packet_loss_after_hop1": False, "packet_loss_multiple_targets": False,
        },
    }), encoding="utf-8")
    mod = _load_calibrate()
    rc = mod.main(["calibrate.py", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    # the labeled healthy fixture is counted (n=1 for healthy, 100% empirical)
    assert "healthy" in out
    assert "skipped" not in out


def test_calibrate_warns_on_injected_only_high_harm(tmp_path, capsys):
    # A high-harm boundary (router-gateway) backed only by an injected fixture
    # must trigger the trust warning — injected fingerprints are not real outages.
    import json
    (tmp_path / "router.json").write_text(json.dumps({
        "scenario": "router-down",
        "expected_boundary": "router-gateway",
        "capture_method": "injected",
        "signals": {
            "gateway_reachable": False, "dns_ok": False, "ip_connectivity_ok": False,
            "control_hosts_ok": False, "target_service_ok": False,
            "default_route_present": True,
            "packet_loss_after_hop1": False, "packet_loss_multiple_targets": False,
        },
    }), encoding="utf-8")
    mod = _load_calibrate()
    rc = mod.main(["calibrate.py", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "router-gateway" in out


def test_cohort_classification():
    # Explicit field wins; otherwise a measurements block marks a real capture
    # and a known v1 name (or no measurements) marks a synthetic fixture.
    mod = _load_calibrate()
    assert mod._cohort("anything", {"capture_method": "injected"}) == "injected"
    assert mod._cohort("anything", {"capture_method": "real"}) == "real"
    # known v1 synthetic name, no method, no measurements
    assert mod._cohort("isp-path", {}) == "synthetic"
    # no method, no measurements, unknown name -> synthetic
    assert mod._cohort("mystery", {}) == "synthetic"
    # no method but HAS measurements (the *-real.json fingerprint) -> real
    assert mod._cohort("healthy-real", {"measurements": {"gateway": {}}}) == "real"


def test_calibrate_warns_on_synthetic_only_high_harm(tmp_path, capsys):
    # Regression for the masking bug: a high-harm boundary backed ONLY by a
    # synthetic v1 fixture (no capture_method) used to default into the "real"
    # cohort and silence the warning. It must now be classified 'syn' and warn.
    import json
    (tmp_path / "isp-path.json").write_text(json.dumps({
        "scenario": "isp-path",
        "signals": {
            "gateway_reachable": True, "dns_ok": True, "ip_connectivity_ok": True,
            "control_hosts_ok": False, "target_service_ok": True,
            "default_route_present": True,
            "packet_loss_after_hop1": True, "packet_loss_multiple_targets": True,
        },
    }), encoding="utf-8")
    mod = _load_calibrate()
    rc = mod.main(["calibrate.py", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "WARNING" in out
    assert "isp-upstream" in out
    # header carries the new synthetic column
    assert "syn" in out


def test_measurement_pass_detects_consistency_mismatch(tmp_path, capsys):
    # A stored boolean that disagrees with its raw measurement is a capture
    # pipeline bug — the measurement pass must surface it as a MISMATCH.
    import json
    (tmp_path / "broken.json").write_text(json.dumps({
        "scenario": "broken",
        "expected_boundary": "healthy",
        "signals": {
            "gateway_reachable": False,  # disagrees with measurements below
            "dns_ok": True, "ip_connectivity_ok": True,
            "control_hosts_ok": True, "target_service_ok": True,
            "default_route_present": True,
            "packet_loss_after_hop1": False, "packet_loss_multiple_targets": False,
        },
        "measurements": {
            "gateway": {"reachable": True, "rtt_ms": 1.0},
            "dns": {"ok": True},
            "ip_connectivity": {"ok": True},
            "control_hosts": {"all_ok": True, "ok_count": 4, "total": 4},
            "target_service": {"ok": True},
            "path_primary": {"raw_hops": []},
        },
    }), encoding="utf-8")
    mod = _load_calibrate()
    rc = mod.main(["calibrate.py", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "MISMATCH" in out
    assert "gateway_reachable" in out


def test_accuracy_reports_overall_and_recall(capsys):
    mod = _load_calibrate()
    rc = mod.main(["calibrate.py"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Classification accuracy" in out
    assert "overall:" in out and "recall" in out


def test_accuracy_surfaces_misclassification(tmp_path, capsys):
    # A fixture whose ground truth differs from what the engine predicts must
    # show up as an off-diagonal error (recall 0.00, "misclassified as ...").
    import json
    # All-green signals classify as `healthy`, but we label it remote-service.
    (tmp_path / "mislabel.json").write_text(json.dumps({
        "scenario": "mislabel",
        "expected_boundary": "remote-service",
        "signals": {
            "gateway_reachable": True, "dns_ok": True, "ip_connectivity_ok": True,
            "control_hosts_ok": True, "target_service_ok": True,
            "default_route_present": True,
            "packet_loss_after_hop1": False, "packet_loss_multiple_targets": False,
        },
    }), encoding="utf-8")
    mod = _load_calibrate()
    rc = mod.main(["calibrate.py", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "overall: 0/1 correct (0.0%)" in out
    assert "healthy×1" in out  # predicted healthy where truth was remote-service
    assert "misclassification" in out


def test_measurement_pass_reports_the_thresholds_real_resolution(monkeypatch, tmp_path, capsys):
    # Was: "flags a hop in the ambiguous band". That band ([10,30] around the 20%
    # threshold) is unreachable — traceroute sends 3 probes, so a hop's loss is
    # one of {0, 33.3, 66.7, 100} and never lands in it (issue #41). The old test
    # only passed because it hand-wrote a 22.0% hop the capture pipeline cannot
    # produce, which is precisely how the dead band went unnoticed. The pass now
    # reports the instrument's real resolution instead of a band nothing reaches.
    # Pin to defaults: main() reads the ambient config otherwise.
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "no-config.toml"))
    import json
    (tmp_path / "ambig.json").write_text(json.dumps({
        "scenario": "ambig",
        "expected_boundary": "isp-upstream",
        "capture_method": "real",
        "signals": {
            "gateway_reachable": True, "dns_ok": True, "ip_connectivity_ok": True,
            "control_hosts_ok": False, "target_service_ok": True,
            "default_route_present": True,
            "packet_loss_after_hop1": True, "packet_loss_multiple_targets": True,
        },
        "measurements": {
            "gateway": {"reachable": True, "rtt_ms": 1.0},
            "control_hosts": {"all_ok": False, "ok_count": 1, "total": 4},
            "path_primary": {"raw_hops": [
                {"index": 1, "loss_pct": 0.0, "rtt_ms": 0.5, "host": "10.0.0.1"},
                {"index": 2, "loss_pct": 22.0, "rtt_ms": 5.0, "host": "100.0.0.1"},
            ]},
        },
    }), encoding="utf-8")
    mod = _load_calibrate()
    rc = mod.main(["calibrate.py", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "measurable hop-loss values" in out
    assert "[0.0, 33.33, 66.67, 100.0]" in out
    # The honest statement of what the configured 20% actually means.
    assert ">= 1 of 3 probes lost" in out
    # The hand-written 22.0% hop still counts as over-threshold; it is simply not
    # a value any real capture can yield.
    assert "hop-loss>thr=1" in out
    # And the pass now reports the threshold that CAN be calibrated: ping loss to
    # independent destinations, which is what the isp-upstream verdict keys on.
    assert "remote-loss threshold" in out
