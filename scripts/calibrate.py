#!/usr/bin/env python
"""Confidence-calibration harness for boundary-probe.

The engine emits a hardcoded ``confidence`` per boundary (e.g. router-gateway
0.99, isp-upstream 0.93). Those are heuristic priors, not measured hit rates.
This script scores them against captured fixtures in two passes:

1. **Boolean pass** — run each fixture's recorded ``signals`` through
   ``diagnose`` and compare the predicted boundary to ground truth, reporting
   per boundary the hardcoded confidence next to the empirical hit-rate. Fixtures
   are split into three cohorts — ``real`` / ``syn`` (synthetic) / ``inj``
   (injected) — because a high-harm prior backed only by non-real evidence is
   not yet trustworthy (see the warning at the end).
2. **Measurement pass** — compare the captured raw ``measurements`` against the
   engine's *one* tunable numeric threshold (path-loss %), and recompute the core
   booleans from the raw measurements to catch capture-pipeline bugs. This
   surfaces miscalibration at the measurement layer, before the boolean layer
   fires wrong. RTT / hop counts have no engine threshold and are shown as
   context only — inventing a cutoff the engine does not use would fabricate
   calibration.

This is a *reporting* tool. It does not change the engine. Recalibration is a
human decision made once enough real fixtures exist — see docs/CALIBRATION.md.

Usage:
    python scripts/calibrate.py [fixtures_dir]   # default: tests/fixtures
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

# Import the real engine — calibration must score the shipping classifier.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from boundary_probe.config import load_config  # noqa: E402
from boundary_probe.engine import RULES, diagnose  # noqa: E402
from boundary_probe.models import SignalSnapshot  # noqa: E402

# Ground-truth boundary for the synthetic fixtures that predate the
# expected_boundary field. Mirrors tests/test_fixtures.py::SCENARIOS.
_KNOWN_SCENARIOS = {
    "router-down": "router-gateway",
    "dns-failure": "dns",
    "isp-path": "isp-upstream",
    "remote-service": "remote-service",
}

# High-confidence/high-harm boundaries: a wrong call here is the most damaging,
# and these are the hardest to fixture from real outages. If their only evidence
# is non-real (synthetic or injected) fixtures, the empirical rate is not yet
# trustworthy — calibration warns rather than letting a convincing table mislead.
_HIGH_HARM = {"router-gateway", "isp-upstream"}

# Half-width of the "ambiguous" band around the path-loss threshold. A captured
# hop whose loss% lands within this margin of the threshold is where a real
# capture would first expose a mis-set threshold; injected netem loss clears the
# bar cleanly and so never lands here.
_AMBIGUOUS_MARGIN_PP = 10.0

# Map each core boolean signal to where it lives in the raw measurements, so the
# measurement pass can re-derive it and assert it matches what was stored. A
# mismatch means the capture pipeline lied — the highest-value thing this finds.
_BOOL_FROM_MEASUREMENT = {
    "gateway_reachable": ("gateway", "reachable"),
    "dns_ok": ("dns", "ok"),
    "ip_connectivity_ok": ("ip_connectivity", "ok"),
    "control_hosts_ok": ("control_hosts", "all_ok"),
    "target_service_ok": ("target_service", "ok"),
}


def _snapshot_from(data: dict) -> SignalSnapshot:
    """Load a SignalSnapshot from either a v1 (flat) or v2 (enriched) fixture."""
    signals = data["signals"] if "signals" in data else data
    field_names = {f for f in SignalSnapshot.__dataclass_fields__}
    return SignalSnapshot(**{k: v for k, v in signals.items() if k in field_names})


def _ground_truth(name: str, data: dict) -> str | None:
    if "expected_boundary" in data:
        return data["expected_boundary"]
    return _KNOWN_SCENARIOS.get(name)


def _cohort(name: str, data: dict) -> str:
    """Classify a fixture as 'real', 'injected', or 'synthetic'.

    Explicit field first, structure second. The ``capture_method`` key is
    unreliably populated — the two ``*-real.json`` captures carry no method but
    DO carry a ``measurements`` block, which is the real-capture fingerprint. So
    a fixture with measurements and no method is treated as real, while the v1
    synthetics (known by name, no measurements) are kept apart. Defaulting
    everything-without-a-method to 'real' (the old behaviour) masked the
    synthetic fixtures as real and silenced the high-harm warning.
    """
    method = data.get("capture_method")
    if method == "injected":
        return "injected"
    if method == "real":
        return "real"
    if name in _KNOWN_SCENARIOS or "measurements" not in data:
        return "synthetic"
    return "real"


def _hardcoded_confidences() -> dict[str, float]:
    """Map boundary -> its hardcoded confidence, by invoking each rule's builder."""
    out: dict[str, float] = {}
    # A snapshot that satisfies nothing; builders ignore signals for confidence.
    blank = SignalSnapshot(
        gateway_reachable=False, dns_ok=False, ip_connectivity_ok=False,
        control_hosts_ok=False, target_service_ok=False,
    )
    for rule in RULES:
        out[rule.boundary] = rule.build(blank).confidence
    return out


def _recompute_core_booleans(measurements: dict) -> dict[str, bool]:
    """Re-derive the core booleans from raw measurements, where determinable.

    Only the directly-stored fields are recomputed (e.g. ``gateway.reachable``);
    the normalizer-derived path flags (packet_loss_*) are not re-derived here.
    """
    out: dict[str, bool] = {}
    for signal, (block, key) in _BOOL_FROM_MEASUREMENT.items():
        sub = measurements.get(block)
        if isinstance(sub, dict) and key in sub:
            out[signal] = bool(sub[key])
    return out


def _path_loss_hops(measurements: dict, threshold: float) -> list[tuple[int, float, float]]:
    """Return (hop_index, loss_pct, margin) for every hop with non-zero loss.

    ``margin`` is ``loss_pct - threshold``; a hop within +/- the ambiguous band
    of zero margin is where a real capture would first expose a mis-set
    threshold.
    """
    path = measurements.get("path_primary") or {}
    hops = path.get("raw_hops") or []
    out: list[tuple[int, float, float]] = []
    for hop in hops:
        loss = hop.get("loss_pct")
        if loss is None or loss <= 0:
            continue
        out.append((hop.get("index", -1), float(loss), float(loss) - threshold))
    return out


def _boolean_pass(files: list[Path]) -> tuple[
    dict[str, list[int]], dict[str, dict[str, int]], int
]:
    """Run the boolean classification pass; return (tally, cohorts, unlabeled)."""
    tally: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    # per predicted boundary: {"real": n, "synthetic": n, "injected": n}
    cohorts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"real": 0, "synthetic": 0, "injected": 0}
    )
    unlabeled = 0
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        snap = _snapshot_from(data)
        predicted = diagnose(snap).boundary
        truth = _ground_truth(f.stem, data)
        if truth is None:
            unlabeled += 1
            continue
        tally[predicted][1] += 1
        if predicted == truth:
            tally[predicted][0] += 1
        cohorts[predicted][_cohort(f.stem, data)] += 1
    return tally, cohorts, unlabeled


def _print_boolean_pass(
    hardcoded: dict[str, float],
    tally: dict[str, list[int]],
    cohorts: dict[str, dict[str, int]],
    unlabeled: int,
    total_files: int,
    fixtures_dir: Path,
) -> list[str]:
    print(f"Calibration over {total_files} fixture(s) in {fixtures_dir}")
    if unlabeled:
        print(f"  ({unlabeled} fixture(s) skipped — no ground-truth "
              f"boundary; add an 'expected_boundary' key)")
    print()
    print(f"{'boundary':<16}{'hardcoded':>10}{'n':>5}{'real':>6}{'syn':>5}"
          f"{'inj':>5}{'empirical':>11}{'gap':>8}")
    print("-" * 66)
    warnings: list[str] = []
    for boundary in sorted(set(hardcoded) | set(tally)):
        hc = hardcoded.get(boundary)
        correct, total = tally.get(boundary, [0, 0])
        c = cohorts.get(boundary, {"real": 0, "synthetic": 0, "injected": 0})
        real, syn, inj = c["real"], c["synthetic"], c["injected"]
        hc_str = f"{hc:.2f}" if hc is not None else "—"
        if total:
            emp = correct / total
            gap = (emp - hc) if hc is not None else 0.0
            print(f"{boundary:<16}{hc_str:>10}{total:>5}{real:>6}{syn:>5}"
                  f"{inj:>5}{emp:>11.2f}{gap:>+8.2f}")
        else:
            print(f"{boundary:<16}{hc_str:>10}{0:>5}{real:>6}{syn:>5}"
                  f"{inj:>5}{'—':>11}{'—':>8}")
        if boundary in _HIGH_HARM and real == 0 and (syn > 0 or inj > 0):
            warnings.append(boundary)
    print()
    print("Note: 'empirical' is fixture hit-rate, not a true accuracy estimate "
          "until enough real captures exist per boundary.")
    if warnings:
        print()
        print("WARNING: high-harm boundary backed by NO real fixtures (synthetic "
              "and/or injected only) — the empirical rate is NOT yet trustworthy "
              "(synthetic fingerprints, no sample diversity). Capture real outages "
              "before recalibrating:")
        for b in warnings:
            print(f"  - {b}")
    return warnings


def _print_measurement_pass(files: list[Path], threshold: float) -> None:
    lo = threshold - _AMBIGUOUS_MARGIN_PP
    hi = threshold + _AMBIGUOUS_MARGIN_PP
    print()
    print("Measurement-layer calibration (raw measurements vs engine thresholds)")
    print(f"  path-loss threshold = {threshold:.1f}%  |  "
          f"ambiguous band = [{lo:.1f}, {hi:.1f}]%")
    print(f"  RTT and hop-count have no engine threshold — shown as context only.")
    print()
    any_rows = False
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        measurements = data.get("measurements")
        if not isinstance(measurements, dict):
            continue
        any_rows = True
        snap = _snapshot_from(data)

        # Consistency: re-derive the core booleans and compare to what was stored.
        recomputed = _recompute_core_booleans(measurements)
        mismatches = [
            f"{sig}: stored={getattr(snap, sig)} measured={val}"
            for sig, val in recomputed.items()
            if getattr(snap, sig) != val
        ]
        consistency = "OK" if not mismatches else "MISMATCH"

        # Path-loss margins.
        hops = _path_loss_hops(measurements, threshold)
        ambiguous = [(i, loss) for (i, loss, _m) in hops if lo <= loss <= hi]

        # FYI context (no threshold).
        gw = measurements.get("gateway") or {}
        ctrl = measurements.get("control_hosts") or {}
        path = measurements.get("path_primary") or {}
        gw_rtt = gw.get("rtt_ms")
        gw_rtt_s = f"{gw_rtt:.1f}ms" if isinstance(gw_rtt, (int, float)) else "—"
        hop_n = len(path.get("raw_hops") or [])
        ctrl_s = f"{ctrl.get('ok_count', '?')}/{ctrl.get('total', '?')}"

        print(f"  {f.stem:<24} consistency={consistency:<8} "
              f"lossy-hops={len(hops):<2} ambiguous={len(ambiguous):<2} "
              f"[gw {gw_rtt_s}, hops {hop_n}, ctrl {ctrl_s}]")
        for sig in mismatches:
            print(f"      ! {sig}")
        for idx, loss in ambiguous:
            print(f"      ~ hop {idx}: {loss:.1f}% loss is within the ambiguous "
                  f"band — a real capture here would test the threshold")
    if not any_rows:
        print("  (no fixtures carry a 'measurements' block)")
    print()
    print("A consistency MISMATCH means the stored boolean disagrees with the raw "
          "measurement — a capture-pipeline bug, not a calibration signal. "
          f"Ambiguous hops are where the {threshold:.0f}% threshold is worth "
          "field-testing.")


def main(argv: list[str]) -> int:
    fixtures_dir = Path(argv[1]) if len(argv) > 1 else Path("tests/fixtures")
    files = sorted(fixtures_dir.glob("*.json"))
    if not files:
        print(f"no fixtures found in {fixtures_dir}", file=sys.stderr)
        return 1

    hardcoded = _hardcoded_confidences()
    tally, cohorts, unlabeled = _boolean_pass(files)
    _print_boolean_pass(
        hardcoded, tally, cohorts, unlabeled, len(files), fixtures_dir
    )

    threshold = load_config().path_loss_pct
    _print_measurement_pass(files, threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
