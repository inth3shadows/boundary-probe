# Rules Engine Notes

## Boundary Categories

- local-device
- router-gateway
- wan-gateway
- dns
- isp-upstream
- remote-service
- healthy
- inconclusive

The vocabulary is defined once in code as `engine.BOUNDARIES` (derived from the
decision table). This list is descriptive; the table is the source of truth.

## Initial Heuristic Set

### Local Device

Classify as `local-device` when:
- no default route is present (the route table has no default gateway)

This is distinct from `router-gateway`: a gateway that is configured but
unresponsive is a router boundary, whereas the *absence* of a default route is a
local fault (interface down, no DHCP lease, loopback-only). Both surface as
`gateway_reachable = False`, so the `default_route_present` signal is what
separates them.

Suggested confidence:
- `0.97` when the route table has no default gateway

### Router / Gateway

Classify as `router-gateway` when:
- the default gateway is present but unreachable or highly unstable
- failures begin before or at hop 1
- multiple external targets fail in the same run

Suggested confidence:
- `0.99` if gateway reachability itself fails
- `0.95` if gateway is reachable but hop-1 loss is severe and repeated

### WAN / Gateway

Classify as `wan-gateway` when:
- the local gateway is reachable
- both direct IP connectivity and DNS fail

This is the "router is fine, the line is down" case — the LAN side is healthy but
nothing reaches the internet.

Suggested confidence:
- `0.94` when the gateway responds but IP and DNS both fail

### DNS

Classify as `dns` when:
- direct IP reachability works
- hostname-based requests fail
- resolver checks fail or diverge across resolvers

Suggested confidence:
- `0.96` when both raw IP success and DNS failure are present

### ISP / Upstream

Classify as `isp-upstream` when:
- local gateway is healthy
- DNS works
- multiple off-LAN targets show elevated loss or latency
- degradation begins after the provider edge or persists across unrelated targets

Suggested confidence:
- `0.93` when several external paths show the same pattern

### Remote Service

Classify as `remote-service` when:
- local controls are healthy
- general internet reachability is healthy
- only the target service fails

Suggested confidence:
- `0.95` when control hosts pass and the target repeatedly fails

### Healthy

Classify as `healthy` when every signal is green: gateway reachable, DNS working,
direct IP connectivity working, control hosts reachable, target service reachable,
and no path loss.

This is a deliberate *positive* verdict, not the absence of a fault. Without it,
an all-green run falls through to `inconclusive` (0.5) and reads as "I couldn't
tell" — indistinguishable from a genuinely ambiguous result. `healthy` asserts the
green path was actively probed.

Suggested confidence:
- `0.90` — strong but point-in-time; a later run can revise it, so it stays below
  the `0.99` tier reserved for direct, repeated evidence.

## Rule Ordering

The engine is a decision table (`engine.RULES`): an ordered list of rows, each a
set of required signal values plus the diagnosis it produces. The first row whose
conditions all match wins, so narrower, higher-certainty boundaries come first:

1. local-device
2. router-gateway
3. wan-gateway
4. dns
5. isp-upstream
6. remote-service
7. healthy
8. inconclusive (catch-all)

This avoids softer internet-wide inferences overriding direct local failure
evidence — and because `inconclusive` matches everything, the table is total.
`tests/test_engine_coverage.py` enumerates every signal combination to prove the
table is total and that no declared boundary is unreachable.

## Remediation Standard

Each rule should map to next steps that are:
- specific
- low-regret
- ordered
- understandable without network jargon

Bad remediation:
- "Check your network."

Good remediation:
- "Connect directly to the modem or ONT to separate router failure from ISP failure."
- "Repeat the lookup using a known-good resolver such as `1.1.1.1` to confirm the issue is DNS-specific."
- "Collect two more runs five minutes apart before escalating to the ISP."

