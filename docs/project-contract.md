# Project Contract

## Mission

Build a tool that can diagnose the likely boundary of a network problem and recommend concrete next actions with evidence-backed confidence.

The project is successful if it can answer:
- is the problem on the local device or LAN
- is the router or gateway the likely boundary
- is DNS the actual failure point
- is the ISP or upstream path degraded
- is the remote service failing while the broader network is healthy

## What We Are Building

We are building:
- a local-first diagnostic product
- a deterministic rules engine over normalized diagnostics
- operator-facing output that explains the finding and the remediation

We are not building:
- a generic traceroute clone
- a graph-first monitoring dashboard
- an LLM-first black-box diagnosis engine
- a wide enterprise network management suite

## Primary User

The default user is:
- a technical home user
- a homelab operator
- a self-hosting or small-operator user who can run local diagnostics and act on specific remediation steps

We are not optimizing first for:
- non-technical consumer support
- large enterprise network teams
- MSP-style multi-tenant fleet management

## Product Standard

The standard is not "run many checks."

The standard is:
- isolate the boundary as cleanly as possible
- show the evidence behind the conclusion
- avoid overclaiming
- recommend low-regret next actions in a sensible order

If the evidence is weak, the tool must say `inconclusive` rather than invent confidence.

## Confidence Contract

`99% confidence` does not mean cosmetic precision. It means the finding is supported by direct, repeated, boundary-specific evidence.

For this project:
- `0.99` is reserved for very tight evidence, such as direct gateway failure or similarly strong causal isolation
- `0.95` is strong but may still be missing one corroborating signal
- anything materially lower should be framed as probable, not certain
- inconclusive outcomes are acceptable and preferred over false certainty

We will not present arbitrary percentages that cannot be defended by the evidence model.

## Decision Contract

Project decisions should default to:
- deterministic over magical
- testable over clever
- narrow and trustworthy over broad and noisy
- useful remediation over decorative output

When a choice is unclear, the tie-breaker is:
1. increases diagnostic trust
2. improves reproducibility
3. reduces scope creep
4. keeps the path open for later UI or remote checks

## V1 Boundaries

V1 focuses on:
- local connectivity
- gateway or router failure
- DNS failure
- upstream or ISP degradation
- target-specific remote service failure

V1 does not need:
- historical storage
- accounts
- SaaS orchestration
- automated router configuration
- remote agent deployment

## Build Contract

Implementation should proceed in this order:
1. normalized signal collection
2. deterministic classification rules
3. clear remediation output
4. real-world fixtures and calibration
5. optional local UI only after rule quality is trusted

No UI expansion should outrun the evidence model.

## Truthfulness Contract

The tool must always make it clear:
- what it knows
- what it inferred
- what it still cannot prove

If two boundaries remain plausible, the output should say so and prescribe the next step that best separates them.

## Current Working Name

The working repo and product name is `boundary-probe`.

This is a functional name, not a permanent branding commitment.
