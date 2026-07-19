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

# traceroute sends a fixed number of probes per hop, so a hop's measured loss is
# quantized to multiples of 100/_TRACEROUTE_PROBES. This is the resolution of the
# instrument, and it is coarser than the threshold it feeds — see issue #41. An
# earlier version of this pass flagged hops within +/-10pp of the threshold as
# "ambiguous"; that band is unreachable at 3 probes ([10,30] never intersects
# {0, 33.3, 66.7, 100}), so it reported 0 for every capture and read as
# "threshold well-placed" when it meant "cannot be measured".
_TRACEROUTE_PROBES = 3

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

    ``margin`` is ``loss_pct - threshold`` — how far the hop sits from the
    decision boundary. With only 3 probes per hop the margin is one of a handful
    of fixed values, so read it as "which side, and by how much", not as a
    precise distance.
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


def _remote_losses(measurements: dict) -> list[float]:
    """Per-destination ping loss: the canary plus every control host.

    Unlike hop loss these are real sent/received counts over 10 probes each, so
    they can land near a threshold and actually calibrate it.
    """
    out: list[float] = []
    ip = measurements.get("ip_connectivity") or {}
    if isinstance(ip.get("loss_pct"), (int, float)):
        out.append(float(ip["loss_pct"]))
    ctrl = measurements.get("control_hosts") or {}
    results = ctrl.get("results") if isinstance(ctrl, dict) else None
    for r in results or []:
        if isinstance(r, dict) and isinstance(r.get("loss_pct"), (int, float)):
            out.append(float(r["loss_pct"]))
    return out


def _print_measurement_pass(files: list[Path], threshold: float, remote_threshold: float) -> None:
    step = 100.0 / _TRACEROUTE_PROBES
    resolvable = sorted({round(i * step, 2) for i in range(_TRACEROUTE_PROBES + 1)})
    effective = sum(1 for v in resolvable if v > threshold)
    print()
    print("Measurement-layer calibration (raw measurements vs engine thresholds)")
    print(f"  path-loss threshold = {threshold:.1f}%")
    print(f"  measurable hop-loss values = {resolvable} ({_TRACEROUTE_PROBES} probes/hop)")
    print(f"  => the threshold is in effect '>= {_TRACEROUTE_PROBES - effective + 1} "
          f"of {_TRACEROUTE_PROBES} probes lost'; any value in "
          f"({resolvable[-effective - 1] if effective < len(resolvable) else 0}, "
          f"{resolvable[-effective]:.2f}] behaves identically. See issue #41.")
    print(f"  remote-loss threshold = {remote_threshold:.1f}% (canary + control hosts,")
    print("    10 probes per target across ~5 independent destinations => ~10pp per")
    print("    target, ~2pp aggregated. THIS is what the isp-upstream verdict keys")
    print("    on, and the threshold worth calibrating against real captures.")
    print("  RTT and hop-count have no engine threshold — shown as context only.")
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
        over = [(i, loss) for (i, loss, m) in hops if m > 0]

        # FYI context (no threshold).
        gw = measurements.get("gateway") or {}
        ctrl = measurements.get("control_hosts") or {}
        path = measurements.get("path_primary") or {}
        gw_rtt = gw.get("rtt_ms")
        gw_rtt_s = f"{gw_rtt:.1f}ms" if isinstance(gw_rtt, (int, float)) else "—"
        hop_n = len(path.get("raw_hops") or [])
        ctrl_s = f"{ctrl.get('ok_count', '?')}/{ctrl.get('total', '?')}"

        remote = _remote_losses(measurements)
        near = [l for l in remote if abs(l - remote_threshold) <= 10.0]
        print(f"  {f.stem:<24} consistency={consistency:<8} "
              f"hop-loss>thr={len(over):<2} remote-loss>thr="
              f"{sum(1 for l in remote if l > remote_threshold):<2} near-thr={len(near):<2} "
              f"[gw {gw_rtt_s}, hops {hop_n}, ctrl {ctrl_s}]")
        for l in near:
            print(f"      ~ remote target at {l:.1f}% loss is within 10pp of the "
                  f"{remote_threshold:.0f}% threshold — this is a calibration data point")
        for sig in mismatches:
            print(f"      ! {sig}")
    if not any_rows:
        print("  (no fixtures carry a 'measurements' block)")
    print()
    print("A consistency MISMATCH means the stored boolean disagrees with the raw "
          "measurement — a capture-pipeline bug, and the highest-value thing this "
          "pass finds. The path-loss threshold itself cannot be field-tested at "
          "this probe count (issue #41): no capture can produce a hop-loss value "
          "near it, so collecting more fixtures will not calibrate it.")


def _accuracy(files: list[Path]) -> tuple[int, int, dict[str, dict]]:
    """Score predictions against ground truth, keyed by the TRUE boundary.

    The boolean pass reports hit-rate per *predicted* boundary, which hides
    misclassifications: if every router-gateway fixture is called wan-gateway,
    `router-gateway` simply shows n=0 there. Keying on truth exposes those
    off-diagonal errors — the confusion an accuracy number must reflect.
    Returns (overall_correct, overall_total, per_truth) where per_truth maps a
    truth boundary to {"n", "correct", "wrong": {predicted: count}}.
    """
    per_truth: dict[str, dict] = defaultdict(
        lambda: {"n": 0, "correct": 0, "wrong": defaultdict(int)}
    )
    correct = total = 0
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        truth = _ground_truth(f.stem, data)
        if truth is None:
            continue
        predicted = diagnose(_snapshot_from(data)).boundary
        total += 1
        rec = per_truth[truth]
        rec["n"] += 1
        if predicted == truth:
            correct += 1
            rec["correct"] += 1
        else:
            rec["wrong"][predicted] += 1
    return correct, total, per_truth


def _print_accuracy(correct: int, total: int, per_truth: dict[str, dict]) -> None:
    print()
    print("Classification accuracy (predicted vs ground truth)")
    pct = (correct / total * 100.0) if total else 0.0
    print(f"  overall: {correct}/{total} correct ({pct:.1f}%)")
    print()
    print(f"  {'truth boundary':<16}{'n':>4}{'recall':>9}   misclassified as")
    print("  " + "-" * 54)
    misfires = 0
    for truth in sorted(per_truth):
        rec = per_truth[truth]
        recall = (rec["correct"] / rec["n"]) if rec["n"] else 0.0
        if rec["wrong"]:
            wrong_str = ", ".join(f"{p}×{c}" for p, c in sorted(rec["wrong"].items()))
            misfires += sum(rec["wrong"].values())
        else:
            wrong_str = "—"
        print(f"  {truth:<16}{rec['n']:>4}{recall:>9.2f}   {wrong_str}")
    print()
    if misfires:
        print(f"  {misfires} misclassification(s) above — off-diagonal errors the "
              "boolean-pass hit-rate (keyed on the predicted label) hides.")
    else:
        print("  No misclassifications across the labeled fixtures.")
    print("  Recall is over fixtures, not field outcomes — trustworthy only once "
          "the real cohort is large (see the cohort warning above).")


def cohort_counts(files: list[Path]) -> dict[str, dict[str, int]]:
    """Real/injected/synthetic counts keyed by GROUND-TRUTH boundary.

    Deliberately a different axis from the table `_print_boolean_pass` shows,
    which keys on the *predicted* boundary because it is scoring the classifier.
    For "how many real captures of boundary X do I still owe?", truth is the
    right key — a real router-gateway outage the engine misread is still a real
    router-gateway capture. Exposed so `scripts/capture_real.sh` can report
    progress without keeping its own copy of `_cohort`, which drifted from this
    one the moment it was written.
    """
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"real": 0, "synthetic": 0, "injected": 0}
    )
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        truth = _ground_truth(f.stem, data)
        if truth is None:
            continue
        counts[truth][_cohort(f.stem, data)] += 1
    return dict(counts)


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a != "--cohorts-json"]
    fixtures_dir = Path(args[0]) if args else Path("tests/fixtures")
    files = sorted(fixtures_dir.glob("*.json"))
    if not files:
        print(f"no fixtures found in {fixtures_dir}", file=sys.stderr)
        return 1

    if "--cohorts-json" in argv[1:]:
        # Machine-readable, truth-keyed. Consumed by scripts/capture_real.sh.
        print(json.dumps(cohort_counts(files), sort_keys=True))
        return 0

    hardcoded = _hardcoded_confidences()
    tally, cohorts, unlabeled = _boolean_pass(files)
    _print_boolean_pass(
        hardcoded, tally, cohorts, unlabeled, len(files), fixtures_dir
    )

    correct, total, per_truth = _accuracy(files)
    _print_accuracy(correct, total, per_truth)

    cfg = load_config()
    _print_measurement_pass(files, cfg.path_loss_pct, cfg.remote_loss_pct)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
