# Product Brief

## One-Sentence Product

Boundary Probe is a local-first diagnostic tool that decides where a network problem most likely lives and tells the operator what to do next.

## Why This Exists

There are already good tools for raw measurements:
- `ping`
- `traceroute`
- `mtr`
- PingPlotter
- Speedtest CLI

Those tools expose evidence. They do not consistently answer the operator's real question:

"Is this my device, my router, my DNS, my ISP, or the service itself?"

Boundary Probe focuses on the decision layer above the raw checks.

## Target User

Primary user for v1:
- technically capable home user
- homelab operator
- small self-hosting operator

This target is intentional. It keeps the product grounded in actionable diagnostics without requiring enterprise integrations too early.

## Core Promise

Given a target and a local machine, Boundary Probe should:
1. run a bounded set of diagnostics
2. isolate the likely failure boundary
3. explain the evidence behind that conclusion
4. recommend concrete next actions

## Non-Goals For V1

- building another graphing dashboard
- replacing mature packet-level tools
- diagnosing every application-layer issue on day one
- hiding evidence behind opaque AI summaries

## V1 Diagnostic Domains

- gateway reachability
- local DNS resolution
- HTTP reachability
- baseline latency and packet loss
- upstream path degradation
- target-specific service failure

## V1 Output Shape

Every diagnosis should produce:
- likely boundary
- confidence score
- short summary
- evidence list
- next-step remediation list

## Example Outcomes

- `Local / Router`
  The default gateway is intermittently unreachable and packet loss starts before the first hop.

- `DNS`
  Known-good hosts work by IP, but hostname resolution fails across configured resolvers.

- `ISP / Upstream`
  Local gateway is healthy, DNS works, but loss and latency begin after the provider edge.

- `Remote Service`
  Control destinations are healthy while the specific service target fails consistently.

## Product Standard

The project should optimize for decision quality, not volume of checks. A smaller number of well-chosen diagnostics with defensible rules is better than a noisy tool that produces low-trust guesses.

