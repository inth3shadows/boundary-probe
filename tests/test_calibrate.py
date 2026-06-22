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
