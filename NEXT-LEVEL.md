# Next-Level Backlog — boundary-probe
<!-- Generated 2026-06-21 by portfolio review. -->
<!-- Updated 2026-06-21: checked off items completed on branch claude-resume-check-git-then. -->
<!-- POLICY: this is a living backlog — delete the file once every item is checked off. -->

**Now:** Complete, well-tested CLI tool (90%+ coverage) with a deterministic rule engine (decision-table classifier), SQLite history, local web UI, and cross-platform (Windows + Linux) support. Stdlib + Rich. Beta-quality (0.1.0). The `.ai/` directory is untracked — minor dirty state.

**Next level:** Field-calibrated rules with real failure fixtures, a publishable PyPI release, and the LLM/expert overlay that was explicitly deferred until the rules were proven. The Phase 2 (evidence hardening) and Phase 3 (remote vantage, hosted workflow) work is fully planned but unstarted.

## Must happen (blockers)
- [x] ~~**BUG (false positive, calibration): gateway-ICMP-filtered → false `router-gateway` @ 0.99.**~~ **Fixed 2026-06-22.** Was: on a healthy network where the gateway does not answer ICMP (WSL2 NAT, cloud VMs, hardened/corporate routers), `gateway_reachable=False` alone fired `router-gateway` at 0.99 while DNS, canary, controls (4/4), and target were all green; the evidence text also hardcoded a contradicting "External reachability also failed". Fix (Beyond/calibration): added derived `SignalSnapshot.gateway_functional` (`gateway_reachable OR ip_connectivity_ok OR control_hosts_ok` — answered ICMP *or* traffic provably traversed it); all gateway rules now key on it, so the gateway is blamed only when external reachability *also* fails. Evidence is now signal-aware via `_gateway_evidence()`. Exhaustive regression (`test_forwarding_gateway_is_never_blamed_locally`) pins the invariant across all 2^8 combos. Mirrors the wisdom `normalizer.py:8-13` already applied to hop-1 ICMP. `diagnose 1.1.1.1 --no-path` now → `healthy 0.90`. 208 tests pass.
- [ ] Capture real-world failure fixtures — `boundary-probe capture` exists but no fixtures have been committed; the rule engine has never been validated against actual failure cases, making confidence scores unverified assertions.
- [x] ~~No virtual environment or test runner available in the repo~~ — **done** (`75c81d3`): `make test` self-bootstraps `.venv`, installs the package editable with dev extras, then runs pytest. One idempotent command.
- [x] ~~The `local-device` boundary is defined in the docs but is not reachable by `diagnose()`~~ — **done** (`31abd59`): split from `router-gateway` via a `default_route_present` signal the gateway collector already produced. `tests/test_engine_coverage.py` enumerates all 2^8 signal combos to prove no declared boundary is unreachable.
- [ ] `asciinema` demo is a TODO comment in the README — first impression for any evaluator or potential user is a broken placeholder.

## Should happen
- [ ] Phase 2 rule calibration: tune `_LOSS_THRESHOLD_PCT` and confidence tiers against captured failure fixtures; the 20% threshold and 0.93/0.95/0.96/0.99 confidence values are design estimates, not field-validated.
- [ ] PyPI release pipeline: the `pyproject.toml` is complete and the classifier says Beta, but there is no publish workflow in CI and no tagged release on GitHub.
- [ ] Remote vantage check (Phase 3): a single-machine diagnosis cannot distinguish ISP-local degradation from widespread outage; even a single HTTP probe to a known-good external vantage point would close this gap.
- [x] ~~Config file documentation~~ — **done** (2026-06-22): `USAGE.md` now has a `## Configuration` section documenting the full TOML schema (all 14 `ProbeConfig` fields across `[probes]`/`[thresholds]`/`[timeouts]` with defaults + validation), the platform-default paths, the `BOUNDARY_PROBE_CONFIG` override, and missing/invalid-file behavior. README Quick Start links to it. All 14 fields verified consumed (no dead knobs).
- [x] ~~Add `local-device` detection rule~~ — **done** (`31abd59`): the route table with no default gateway now classifies as `local-device` instead of mis-classifying as `router-gateway`.

## Post-v1: confidence calibration (the real maturity gate)

The per-verdict confidence floats (0.90–0.99) are **heuristic priors, not measured
rates**. v1 ships honest about this: the UI/CLI/escalation report lead with the
**band** and label the float a "prior" (done 2026-06-22). What remains, deferred
post-v1 (decided 2026-06-22 via coach + expert panel — chose "ship honest,
calibrate continuously" over blocking the release):

- [ ] **Fault-injection capture harness (option C).** Produce ground-truth fixtures
  for the 5 boundaries a healthy machine can't reproduce (`local-device`,
  `router-gateway`, `wan-gateway`, `dns`, `isp-upstream`) by *inducing* the fault:
  `tc/netem` (loss/latency), `iptables`/firewall drop (gateway/WAN), blackhole DNS.
  **Ground truth is valid because the human knows what they broke** — NOT from the
  classifier's own verdict (that would be circular). Caveat (data-eng): injected
  signal fingerprints may differ from real outages (silent drop vs ICMP-unreachable
  from the router) — watch the `path_primary`/traceroute fingerprint.
- [ ] **Calibrate the raw `measurements`, not just the 5 booleans.** `scripts/calibrate.py`
  currently reconstructs the snapshot and re-runs `diagnose` — only 5 bits per fixture.
  Add a pass checking whether captured measurement distributions (RTT, loss %, hop
  counts) match the engine's threshold assumptions — miscalibration shows up there
  first, before the boolean layer fires wrong.
- [ ] **Mind the sampling bias (statistician's warning).** The easy-to-capture
  boundaries (`healthy`, `remote-service`) are where calibration is *least* needed;
  the high-confidence/high-harm ones (`router-gateway` 0.99, `isp-upstream` 0.93) are
  hardest to fixture. Don't mistake a convincing table with blank rows for evidence.

## Nice-to-have
- [ ] LLM/expert overlay — **backlogged (cost-gated)**: deferred until a better plan exists; consistent with `docs/technical-direction.md` (LLM layer comes after rules are calibrated). It also costs per-call LLM spend, so it waits on a clear value case.
- [ ] Exportable support bundle: `boundary-probe escalate <uuid>` produces a report but there is no single-file export (JSON + evidence + run metadata) that a user could attach to a support ticket.
- [x] ~~`--watch` mode~~ — **done** (pre-existing): continuous live probe panel via Rich.
- [ ] Track the `.ai/ir.json` file or add it to `.gitignore` — currently untracked and polluting `git status`.

## Done beyond the original backlog
- [x] **Decision-table classifier** (`31abd59`): `diagnose()` refactored from a hand-ordered if-ladder into a declarative table (`engine.RULES`); `BOUNDARIES` derived as the single source of truth. Closes a whole class of "documented-but-unreachable boundary" via the coverage test.
- [x] **`healthy` verdict** (`31abd59`, rendered in `dde9609`): an all-green connection now gets a positive verdict instead of falling through to `inconclusive` (0.5). Rendered green in `watch` and the web UI; escalation suppressed for healthy runs.

## Skills to run
- `/audit` — the rule engine, normalizer confidence calibration, and the remaining fixture/calibration work warrant a structured module-by-module correctness pass before a PyPI release.
- `/build-and-test` — now satisfied by `make test`; use to confirm the suite passes on a given host.
