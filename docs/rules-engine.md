# Rules Engine Notes

## Boundary Categories

- local-device
- router-gateway
- dns
- isp-upstream
- remote-service
- inconclusive

## Initial Heuristic Set

### Router / Gateway

Classify as `router-gateway` when:
- the default gateway is unreachable or highly unstable
- failures begin before or at hop 1
- multiple external targets fail in the same run

Suggested confidence:
- `0.99` if gateway reachability itself fails
- `0.95` if gateway is reachable but hop-1 loss is severe and repeated

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

## Rule Ordering

Start with the narrowest high-certainty boundary first:
1. router-gateway
2. dns
3. isp-upstream
4. remote-service
5. inconclusive

This avoids softer internet-wide inferences overriding direct local failure evidence.

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

