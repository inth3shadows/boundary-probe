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
elif command -v boundary-probe >/dev/null 2>&1; then
  # Installed from PyPI rather than run out of a checkout.
  BP=(boundary-probe)
  PY=(python)
else
  # Last resort: a bare `python -m boundary_probe.cli` cannot work against this
  # src-layout package without help, and failing here with ModuleNotFoundError
  # halfway through a capture is the worst possible moment.
  BP=(env "PYTHONPATH=$REPO_ROOT/src" python -m boundary_probe.cli)
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
  # Cohort classification comes from calibrate.py itself. An earlier version of
  # this script reimplemented it here; the copy disagreed with the original in
  # both directions on constructible fixtures, which would have told an operator
  # a high-harm boundary was covered when calibrate refused to count it. The tool
  # that consumes the data decides what counts as real.
  local cohorts_json
  cohorts_json="$("${PY[@]}" "$REPO_ROOT/scripts/calibrate.py" --cohorts-json "$FIXTURES")"
  # Passed as argv, not stdin, so the script below can be a QUOTED heredoc: it
  # needs both quote characters, and nesting them inside an f-string in a
  # `python -c '...'` one-liner is a syntax error before Python 3.12.
  "${PY[@]}" - "$TARGET_N" "$cohorts_json" <<'PYEOF'
import json
import sys

target_n = int(sys.argv[1])
counts = json.loads(sys.argv[2])
seed = ["healthy", "dns", "captive-portal", "remote-service", "isp-upstream",
        "router-gateway", "wan-gateway", "local-device", "ipv6-only"]
high_harm = ("router-gateway", "isp-upstream")

header = ("boundary", "real", "other", "still needed")
print(f"{header[0]:<16}{header[1]:>6}{header[2]:>7}{header[3]:>14}")
print("-" * 43)
for b in sorted(set(counts) | set(seed)):
    c = counts.get(b, {})
    real = c.get("real", 0)
    other = c.get("synthetic", 0) + c.get("injected", 0)
    flag = "  <- high-harm" if b in high_harm and real == 0 else ""
    print(f"{b:<16}{real:>6}{other:>7}{max(0, target_n - real):>14}{flag}")

missing = [b for b in high_harm if counts.get(b, {}).get("real", 0) == 0]
if missing:
    print()
    print("Start here - these carry the highest priors (0.99 / 0.93) on the")
    print("weakest evidence, and calibrate.py refuses to trust them:")
    for b in missing:
        print(f"  {b}")

print()
print("Counts key on the ground-truth boundary you labelled. The table in")
print("calibrate.py keys on the PREDICTED boundary, so the two diverge wherever")
print("the engine disagreed with a label - the interesting case, not a bug.")
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
  # No `head` here: truncating this silently cut the "start here" list short,
  # dropping the second high-harm boundary — the one thing the summary exists
  # to surface. The table grows by a line per boundary, so any fixed cap rots.
  status | sed -n '3,$p'
}

main "$@"
