#!/usr/bin/env bash
# Guided REAL-outage capture helper for boundary-probe calibration (issue #13).
#
# The calibration rig is complete; what it lacks is real captures. Issue #13's
# close criteria need n >= ~10 real fixtures per boundary, gathered across
# different networks and times — data that cannot be built, only collected.
# This wraps `boundary-probe capture` so collecting one is a single command
# during the ~90 seconds an outage is actually happening.
#
#   scripts/capture_real.sh --status               # how far off is each boundary?
#   scripts/capture_real.sh dns                    # capture, auto-named
#   scripts/capture_real.sh isp-upstream --label cafe --target example.com
#
# What it does that a bare `capture` does not:
#   - names the fixture uniquely, so a second capture never overwrites the first
#     (the default `capture <name>` overwrites silently)
#   - stamps --capture-method real and --expected-boundary for you, the two flags
#     that decide which cohort calibrate.py counts it in
#   - reports whether the engine actually agreed with you, which is the
#     calibration signal itself, not a failure
#
# NOT for injected faults: use `sudo scripts/inject_fault.sh` for those. A fixture
# mislabeled `real` poisons exactly the cohort this issue exists to build.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$REPO_ROOT/tests/fixtures"
TARGET_N=10   # issue #13 close criterion, per boundary

if [[ -x "$REPO_ROOT/.venv/bin/boundary-probe" ]]; then
  BP=("$REPO_ROOT/.venv/bin/boundary-probe")
  PY=("$REPO_ROOT/.venv/bin/python")
elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  BP=("$REPO_ROOT/.venv/bin/python" -m boundary_probe.cli)
  PY=("$REPO_ROOT/.venv/bin/python")
else
  BP=(python -m boundary_probe.cli)
  PY=(python)
fi

# Boundaries worth capturing in the field, and a sensible default target for
# each. DNS-sensitive boundaries need a hostname so resolution is exercised;
# the rest use an IP so the probe does not depend on DNS working.
declare -A DEFAULT_TARGET=(
  [healthy]=example.com
  [dns]=example.com
  [captive-portal]=example.com
  [remote-service]=example.com
  [isp-upstream]=1.1.1.1
  [router-gateway]=1.1.1.1
  [wan-gateway]=1.1.1.1
  [local-device]=1.1.1.1
  [ipv6-only]=1.1.1.1
)

usage() {
  cat >&2 <<EOF
usage: $0 <boundary> [--label NAME] [--target HOST] [--no-path]
       $0 --status

boundaries: ${!DEFAULT_TARGET[*]}

  --label NAME   where/what this capture is (home, cafe, hotel, phone-hotspot).
                 Recorded in the filename; network diversity is what makes the
                 real cohort worth more than the injected one.
  --target HOST  override the default probe target for this boundary.
  --no-path      skip traceroute (faster; drops the isp-upstream evidence).
EOF
  exit 2
}

status() {
  echo "Real-capture progress toward issue #13 (target: n >= $TARGET_N per boundary)"
  echo
  "${PY[@]}" - "$FIXTURES" "$TARGET_N" <<'PYEOF'
import json, pathlib, sys
from collections import Counter

fixtures, target_n = pathlib.Path(sys.argv[1]), int(sys.argv[2])
real, other = Counter(), Counter()
for path in sorted(fixtures.glob("*.json")):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        continue
    boundary = data.get("expected_boundary")
    if not boundary:
        continue
    # Mirrors scripts/calibrate.py's _cohort: explicit method first, then the
    # presence of a measurements block as the real-capture fingerprint.
    method = data.get("capture_method")
    if method == "real" or (method is None and "measurements" in data):
        real[boundary] += 1
    else:
        other[boundary] += 1

boundaries = sorted(set(real) | set(other) | {
    "healthy", "dns", "captive-portal", "remote-service", "isp-upstream",
    "router-gateway", "wan-gateway", "local-device",
})
print(f"{'boundary':<16}{'real':>6}{'other':>7}{'still needed':>14}")
print("-" * 43)
for b in boundaries:
    need = max(0, target_n - real[b])
    flag = "  <- high-harm" if b in ("router-gateway", "isp-upstream") and real[b] == 0 else ""
    print(f"{b:<16}{real[b]:>6}{other[b]:>7}{need:>14}{flag}")
print()
missing = [b for b in ("router-gateway", "isp-upstream") if real[b] == 0]
if missing:
    print("Start here — these carry the highest priors (0.99 / 0.93) on the")
    print("weakest evidence, and calibrate.py refuses to trust them:")
    for b in missing:
        print(f"  {b}")
PYEOF
}

main() {
  [[ $# -gt 0 ]] || usage
  if [[ "$1" == "--status" || "$1" == "status" ]]; then
    status
    exit 0
  fi

  local boundary="$1"; shift
  [[ -n "${DEFAULT_TARGET[$boundary]:-}" ]] || {
    echo "error: unknown boundary '$boundary'" >&2
    usage
  }

  local label="" target="" path_args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --label)  label="${2:?--label needs a value}"; shift 2 ;;
      --target) target="${2:?--target needs a value}"; shift 2 ;;
      --no-path) path_args=(--no-path); shift ;;
      *) echo "error: unexpected argument '$1'" >&2; usage ;;
    esac
  done

  [[ -n "$target" ]] || target="${DEFAULT_TARGET[$boundary]}"
  # `capture` restricts names to [A-Za-z0-9_-], so sanitize rather than reject:
  # being told the label is invalid is not useful mid-outage.
  local safe_label=""
  [[ -n "$label" ]] && safe_label="-$(printf '%s' "$label" | tr -c '[:alnum:]_-' '-')"
  local stamp name
  stamp="$(date +%Y%m%d-%H%M%S)"
  name="${boundary}-real${safe_label}-${stamp}"

  echo ">> capturing '$name'"
  echo "   boundary (your ground truth): $boundary"
  echo "   target:                       $target"
  echo

  ( cd "$REPO_ROOT" && "${BP[@]}" capture "$name" \
      --target "$target" \
      "${path_args[@]}" \
      --expected-boundary "$boundary" \
      --capture-method real )

  local fixture="$FIXTURES/$name.json"
  [[ -f "$fixture" ]] || { echo "error: capture wrote no fixture" >&2; exit 1; }

  # Report agreement, do not enforce it. A capture where the engine disagreed
  # with the operator is the single most valuable fixture in the set — it is a
  # labeled misclassification, which is what recall is computed from.
  "${PY[@]}" - "$fixture" "$boundary" <<'PYEOF'
import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parents[2] / "src"))
from boundary_probe.engine import diagnose
from boundary_probe.models import SignalSnapshot

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = sys.argv[2]
signals = data.get("signals", data)
fields = set(SignalSnapshot.__dataclass_fields__)
verdict = diagnose(SignalSnapshot(**{k: v for k, v in signals.items() if k in fields}))
print()
if verdict.boundary == expected:
    print(f"   engine agreed: {verdict.boundary} ({verdict.confidence:.2f} prior)")
else:
    print(f"   engine said '{verdict.boundary}', you said '{expected}'.")
    print("   KEEP THIS FIXTURE — a labeled disagreement is what recall is")
    print("   measured from, and it is worth more than an agreeing one.")
PYEOF

  echo
  echo ">> saved tests/fixtures/$(basename "$fixture")"
  echo ">> progress:"
  status | sed -n '3,$p' | head -14
}

main "$@"
