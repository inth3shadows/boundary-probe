#!/usr/bin/env bash
# Fault-injection capture harness for boundary-probe (issue #11).
#
# Reproducibly induces each of the 5 boundaries a healthy machine cannot
# reproduce, inside an isolated Linux network namespace, and captures a labeled,
# scrubbed fixture for each — WITHOUT taking the host offline. Linux/WSL2 only;
# requires root (ip netns / iptables / tc).
#
#   sudo scripts/inject_fault.sh run-all          # all 5 -> tests/fixtures/
#   sudo scripts/inject_fault.sh capture dns-broken
#   sudo scripts/inject_fault.sh setup|teardown   # manual topology control
#
# Topology built by `setup`:
#
#     host                         netns "bp-ns"
#   ┌────────────┐  veth pair   ┌────────────────┐
#   │ bp-h       │<------------>│ bp-c           │
#   │ 10.200.0.1 │  (gateway)   │ 10.200.0.2     │
#   │  MASQUERADE -> real uplink -> internet      │
#   └────────────┘              └────────────────┘
#
# Every probe runs `ip netns exec bp-ns <boundary-probe> capture ...`, so faults
# injected into the namespace never touch the host's own connectivity.
#
# IMPORTANT (issue #11): captures made here are tagged `capture_method=injected`.
# Their signal *fingerprints are synthetic* — an iptables DROP is a silent
# timeout, not the ICMP-unreachable a real dead router may emit; netem loss is
# not the jitter shape of a real congested ISP. calibrate.py keeps the injected
# cohort separate and refuses to trust injected-only evidence for the high-harm
# boundaries. These fixtures bootstrap the mechanics; real captures supersede
# them.
set -euo pipefail

# sudo can strip /usr/sbin from PATH; ip/iptables/tc live there.
export PATH="/usr/sbin:/sbin:$PATH"

NS=bp-ns
VETH_H=bp-h          # host side (acts as the namespace's gateway)
VETH_C=bp-c          # namespace side
SUBNET=10.200.0.0/24
GW_IP=10.200.0.1
NS_IP=10.200.0.2
RESOLVER=1.1.1.1     # in-namespace DNS + a known-good control target (an IP)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAST_CFG=/tmp/bp-capture-fast.toml   # short probe timeouts for total-loss captures
# Prefer the repo venv's console script, else fall back to a module invocation.
if [[ -x "$REPO_ROOT/.venv/bin/boundary-probe" ]]; then
  BP=("$REPO_ROOT/.venv/bin/boundary-probe")
elif [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
  BP=("$REPO_ROOT/.venv/bin/python" -m boundary_probe.cli)
else
  BP=(python -m boundary_probe.cli)
fi

# scenario -> ground-truth boundary
declare -A BOUNDARY=(
  [healthy]=healthy
  [local-device]=local-device
  [router-down]=router-gateway
  [wan-down]=wan-gateway
  [dns-broken]=dns
  [isp-loss]=isp-upstream
)
# healthy first: it captures the no-fault baseline and proves NAT+ICMP work end
# to end. If `healthy` does not classify as healthy, the topology is broken and
# every connectivity-dependent scenario below it is suspect.
SCENARIOS=(healthy local-device router-down wan-down dns-broken isp-loss)

# Per-scenario target override (default is $RESOLVER, an IP).
#  - DNS-sensitive scenarios need a HOSTNAME so the lookup is actually exercised
#    (the DNS collector short-circuits to ok when the target is already an IP).
#  - isp-loss must target a NON-spared IP so its traceroute path is lossy; the
#    resolver/gateway are spared from netem, so targeting them would be loss-free.
declare -A TARGET_HOST=(
  [wan-down]=example.com
  [dns-broken]=example.com
  [isp-loss]=8.8.4.4
)

require_root() {
  [[ "$(id -u)" -eq 0 ]] || { echo "error: must run as root (sudo)" >&2; exit 1; }
}

require_tools() {
  local missing=()
  for t in ip iptables tc; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if (( ${#missing[@]} )); then
    echo "error: missing required tool(s): ${missing[*]}" >&2
    echo "       install with: sudo apt install -y iptables iproute2" >&2
    exit 1
  fi
}

uplink() {
  # The host's real default-route interface — MASQUERADE egresses here.
  ip route show default | awk '{print $5; exit}'
}

teardown() {
  # Order matters but every step is best-effort; deleting the ns also drops the
  # veth peer, the ns's own iptables/tc, and any in-ns injection.
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$VETH_H" 2>/dev/null || true
  local up; up="$(uplink || true)"
  if [[ -n "${up:-}" ]]; then
    # Loop-delete: a rule may have been inserted more than once across runs.
    while iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$up" -j MASQUERADE 2>/dev/null; do :; done
    while iptables -D FORWARD -i "$VETH_H" -o "$up" -j ACCEPT 2>/dev/null; do :; done
    while iptables -D FORWARD -i "$up" -o "$VETH_H" -j ACCEPT 2>/dev/null; do :; done
  fi
  # Scrub any host FORWARD DROP rules leaked by an older wan-down injection
  # (the drop now lives inside the namespace and is removed with it).
  while iptables -D FORWARD -i "$VETH_H" ! -d "$SUBNET" -j DROP 2>/dev/null; do :; done
  rm -rf "/etc/netns/$NS" 2>/dev/null || true
  rm -f "$FAST_CFG" 2>/dev/null || true
}

setup() {
  require_root
  teardown   # idempotent: start from a clean slate
  trap teardown ERR

  local up; up="$(uplink)"
  [[ -n "$up" ]] || { echo "error: no default route on host; cannot NAT" >&2; exit 1; }

  ip netns add "$NS"
  ip link add "$VETH_H" type veth peer name "$VETH_C"
  ip link set "$VETH_C" netns "$NS"

  ip addr add "$GW_IP/24" dev "$VETH_H"
  ip link set "$VETH_H" up

  ip netns exec "$NS" ip addr add "$NS_IP/24" dev "$VETH_C"
  ip netns exec "$NS" ip link set "$VETH_C" up
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip route add default via "$GW_IP"

  # Reverse-path filtering drops the NAT'd ICMP replies coming back to the
  # namespace (the reply's source route is not via bp-h), so ping beyond the
  # gateway silently fails while UDP/TCP work. Disable rp_filter on the paths
  # the NAT'd traffic crosses.
  sysctl -q -w net.ipv4.conf.all.rp_filter=0
  sysctl -q -w net.ipv4.conf.default.rp_filter=0
  sysctl -q -w "net.ipv4.conf.$VETH_H.rp_filter=0" 2>/dev/null || true
  sysctl -q -w "net.ipv4.conf.$up.rp_filter=0" 2>/dev/null || true
  ip netns exec "$NS" sysctl -q -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true

  # NAT the namespace out to the real internet so the healthy/control baseline works.
  sysctl -q -w net.ipv4.ip_forward=1
  iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$up" -j MASQUERADE
  iptables -A FORWARD -i "$VETH_H" -o "$up" -j ACCEPT
  iptables -A FORWARD -i "$up" -o "$VETH_H" -j ACCEPT

  # Per-namespace resolver (ip netns exec reads /etc/netns/<ns>/resolv.conf).
  mkdir -p "/etc/netns/$NS"
  printf 'nameserver %s\n' "$RESOLVER" > "/etc/netns/$NS/resolv.conf"

  trap - ERR
}

# --- per-scenario injection (topology already up via setup) -----------------

inject() {
  local scenario="$1"
  case "$scenario" in
    healthy)
      : # no fault injected — captures the working baseline
      ;;
    local-device)
      # No default route -> traffic cannot leave the device.
      ip netns exec "$NS" ip route del default
      ;;
    router-down)
      # Gateway silent and unreachable: bring the host side of the veth down so
      # nothing (gateway ICMP or forwarding) answers.
      ip link set "$VETH_H" down
      ;;
    wan-down)
      # Gateway answers (it is in-subnet), but nothing beyond it: drop the
      # namespace's egress to any non-local destination. Done INSIDE the ns so
      # `ip netns del` removes it — a host FORWARD rule leaks across runs and
      # silently breaks NAT for every later scenario (the original bug here).
      ip netns exec "$NS" iptables -I OUTPUT ! -d "$SUBNET" -j DROP
      ;;
    dns-broken)
      # Connectivity intact, name resolution dead: drop port-53 in the namespace.
      ip netns exec "$NS" iptables -I OUTPUT -p udp --dport 53 -j DROP
      ip netns exec "$NS" iptables -I OUTPUT -p tcp --dport 53 -j DROP
      ;;
    isp-loss)
      # Hop 1 (gateway) and DNS clean, loss begins beyond: a prio qdisc sends
      # gateway+resolver traffic to a lossless band and everything else through
      # netem loss, so packet_loss_after_hop1 fires across multiple targets
      # while dns_ok / gateway stay green.
      #
      # The netem loss % is overridable:
      #   sudo BP_ISP_LOSS_PCT=22 scripts/inject_fault.sh capture isp-loss
      # Do NOT expect the captured per-hop loss to match the value set here.
      # traceroute sends 3 probes per hop, so a hop's measured loss can only be
      # 0/33/67/100% regardless of the injected rate — see issue #41. The knob
      # varies the fault's severity; it does not set a measured percentage.
      local isp_loss_pct="${BP_ISP_LOSS_PCT:-50}"
      # 10# forces base-10 so a leading zero is not read as octal (`08` raises an
      # arithmetic error whose non-zero status the `||` would swallow).
      if ! [[ "$isp_loss_pct" =~ ^[0-9]+$ ]] || (( 10#$isp_loss_pct < 1 || 10#$isp_loss_pct > 100 )); then
        echo "error: BP_ISP_LOSS_PCT must be an integer 1-100 (got '$isp_loss_pct')" >&2
        exit 2
      fi
      ip netns exec "$NS" tc qdisc add dev "$VETH_C" root handle 1: prio bands 3
      ip netns exec "$NS" tc qdisc add dev "$VETH_C" parent 1:3 handle 30: netem loss "${isp_loss_pct}%" 25%
      ip netns exec "$NS" tc filter add dev "$VETH_C" protocol ip parent 1:0 prio 1 \
        u32 match ip dst "$GW_IP/32" flowid 1:1
      ip netns exec "$NS" tc filter add dev "$VETH_C" protocol ip parent 1:0 prio 1 \
        u32 match ip dst "$RESOLVER/32" flowid 1:1
      ip netns exec "$NS" tc filter add dev "$VETH_C" protocol ip parent 1:0 prio 2 \
        u32 match u8 0 0 flowid 1:3
      ;;
    *)
      echo "error: unknown scenario '$scenario' (one of: ${SCENARIOS[*]})" >&2
      exit 2
      ;;
  esac
}

capture() {
  local scenario="$1"
  local boundary="${BOUNDARY[$scenario]:-}"
  [[ -n "$boundary" ]] || { echo "error: unknown scenario '$scenario'" >&2; exit 2; }

  setup
  inject "$scenario"
  echo ">> capturing '$scenario' (expected boundary: $boundary)" >&2
  # Only isp-upstream depends on the traceroute path (loss-after-hop1). The other
  # four skip it: faster, no needless traceroute dependency, and nothing real to
  # scrub. For isp-loss the path is recorded and scrub redacts the real ISP hops.
  local path_args=(--no-path)
  [[ "$scenario" == "isp-loss" ]] && path_args=()
  # Use the default probe config. A short-timeout "fast" config was tried and
  # removed: boundary-probe pings with `-c 10` (~9s wall-time), so any timeout
  # under ~10s kills a *successful* multi-packet ping and is misread as
  # unreachable. Total-loss scenarios therefore take ~30-40s each — that is the
  # honest cost of a real probe run, not a hang.
  unset BOUNDARY_PROBE_CONFIG
  # DNS-sensitive scenarios use a hostname so the lookup is actually exercised;
  # the rest use an IP so ip-connectivity does not depend on DNS.
  local target="${TARGET_HOST[$scenario]:-$RESOLVER}"
  # Run from the repo root: capture writes tests/fixtures/<name>.json relative to CWD.
  ( cd "$REPO_ROOT" && ip netns exec "$NS" "${BP[@]}" capture "$scenario" \
      --target "$target" \
      "${path_args[@]}" \
      --expected-boundary "$boundary" \
      --capture-method injected ) || {
      echo "!! capture failed for '$scenario'" >&2
      teardown
      return 1
    }
  # The fixture was written as root; hand it back to the invoking user so it is
  # editable/committable without sudo.
  if [[ -n "${SUDO_UID:-}" ]]; then
    chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$REPO_ROOT/tests/fixtures/$scenario.json" 2>/dev/null || true
  fi
  teardown
}

run_all() {
  for s in "${SCENARIOS[@]}"; do
    capture "$s"
  done
  echo ">> done. Run: python scripts/calibrate.py" >&2
}

# Ground-truth dump of the freshly-built topology — no probing through
# boundary-probe, just raw kernel state and two pings. Run this when captures
# misbehave to see whether the namespace baseline itself is broken.
diag() {
  setup
  echo "== ns interfaces ==";        ip netns exec "$NS" ip -br addr
  echo "== ns routes ==";            ip netns exec "$NS" ip route
  echo "== host veth $VETH_H ==";    ip -br addr show "$VETH_H"
  echo "== ns -> gateway ($GW_IP) =="; ip netns exec "$NS" ping -c 3 -W 1 "$GW_IP" || true
  echo "== ns -> 8.8.8.8 (NAT) ==";  ip netns exec "$NS" ping -c 3 -W 1 8.8.8.8 || true
  echo "== rp_filter ==";            sysctl net.ipv4.conf.all.rp_filter "net.ipv4.conf.$VETH_H.rp_filter" 2>/dev/null || true
  echo "== nat MASQUERADE ==";       iptables -t nat -S 2>/dev/null | grep -i masq || echo "(none)"
  echo "== FORWARD chain ==";        iptables -S FORWARD 2>/dev/null | head
  echo "== iptables backend ==";     iptables --version
  teardown
}

main() {
  require_root
  require_tools
  local cmd="${1:-}"
  case "$cmd" in
    setup)    setup ;;
    teardown) teardown ;;
    diag)     diag ;;
    inject)   setup; inject "${2:?scenario required}" ;;
    capture)  capture "${2:?scenario required}" ;;
    run-all)  run_all ;;
    *)
      echo "usage: sudo $0 {run-all|capture <scenario>|diag|setup|teardown|inject <scenario>}" >&2
      echo "scenarios: ${SCENARIOS[*]}" >&2
      exit 2 ;;
  esac
}

main "$@"
