#!/usr/bin/env python
"""Confidence-calibration harness for boundary-probe.

The engine emits a hardcoded ``confidence`` per boundary (e.g. router-gateway
0.99, isp-upstream 0.93). Those are heuristic priors, not measured hit rates.
This script scores them against captured fixtures: for each fixture it runs the
recorded ``signals`` through ``diagnose`` and compares the predicted boundary to
the fixture's ground-truth boundary, then reports — per boundary — the hardcoded
confidence next to the empirical accuracy observed in the fixtures.

Ground truth per fixture is taken from an ``expected_boundary`` key if present,
else from the known-scenario map below (the four synthetic v1 fixtures). Real
captures (``boundary-probe capture``) should add ``expected_boundary`` so they
feed calibration.

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
# is injected (synthetic-fingerprint) fixtures, the empirical rate is not yet
# trustworthy — calibration warns rather than letting a convincing table mislead.
_HIGH_HARM = {"router-gateway", "isp-upstream"}


def _snapshot_from(data: dict) -> SignalSnapshot:
    """Load a SignalSnapshot from either a v1 (flat) or v2 (enriched) fixture."""
    signals = data["signals"] if "signals" in data else data
    field_names = {f for f in SignalSnapshot.__dataclass_fields__}
    return SignalSnapshot(**{k: v for k, v in signals.items() if k in field_names})


def _ground_truth(name: str, data: dict) -> str | None:
    if "expected_boundary" in data:
        return data["expected_boundary"]
    return _KNOWN_SCENARIOS.get(name)


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


def main(argv: list[str]) -> int:
    fixtures_dir = Path(argv[1]) if len(argv) > 1 else Path("tests/fixtures")
    files = sorted(fixtures_dir.glob("*.json"))
    if not files:
        print(f"no fixtures found in {fixtures_dir}", file=sys.stderr)
        return 1

    hardcoded = _hardcoded_confidences()
    # per predicted boundary: [correct, total]
    tally: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    # per predicted boundary: count of real vs injected captures behind it
    real_n: dict[str, int] = defaultdict(int)
    injected_n: dict[str, int] = defaultdict(int)
    rows_unlabeled = 0

    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        snap = _snapshot_from(data)
        predicted = diagnose(snap).boundary
        truth = _ground_truth(f.stem, data)
        if truth is None:
            rows_unlabeled += 1
            continue
        tally[predicted][1] += 1
        if predicted == truth:
            tally[predicted][0] += 1
        # Default to "real": the pre-existing synthetic v1 fixtures carry no
        # capture_method and are treated as the reference cohort.
        if data.get("capture_method") == "injected":
            injected_n[predicted] += 1
        else:
            real_n[predicted] += 1

    print(f"Calibration over {len(files)} fixture(s) in {fixtures_dir}")
    if rows_unlabeled:
        print(f"  ({rows_unlabeled} fixture(s) skipped — no ground-truth "
              f"boundary; add an 'expected_boundary' key)")
    print()
    print(f"{'boundary':<16}{'hardcoded':>10}{'n':>5}{'real':>6}{'inj':>5}{'empirical':>11}{'gap':>8}")
    print("-" * 61)
    warnings: list[str] = []
    for boundary in sorted(set(hardcoded) | set(tally)):
        hc = hardcoded.get(boundary)
        correct, total = tally.get(boundary, [0, 0])
        real, inj = real_n.get(boundary, 0), injected_n.get(boundary, 0)
        hc_str = f"{hc:.2f}" if hc is not None else "—"
        if total:
            emp = correct / total
            gap = (emp - hc) if hc is not None else 0.0
            print(f"{boundary:<16}{hc_str:>10}{total:>5}{real:>6}{inj:>5}{emp:>11.2f}{gap:>+8.2f}")
        else:
            print(f"{boundary:<16}{hc_str:>10}{0:>5}{real:>6}{inj:>5}{'—':>11}{'—':>8}")
        if boundary in _HIGH_HARM and inj > 0 and real == 0:
            warnings.append(boundary)
    print()
    print("Note: 'empirical' is fixture hit-rate, not a true accuracy estimate "
          "until enough real captures exist per boundary.")
    if warnings:
        print()
        print("WARNING: high-harm boundary backed by injected-only fixtures — the "
              "empirical rate is NOT yet trustworthy here (synthetic fingerprints, "
              "no sample diversity). Capture real outages before recalibrating:")
        for b in warnings:
            print(f"  - {b}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
