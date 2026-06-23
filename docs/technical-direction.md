# Technical Direction

## Chosen Starting Architecture

The project starts with a Python backend, a deterministic rule engine, and a local web UI on Windows.

Reasons:
- easy local execution on Windows
- straightforward subprocess access to system diagnostics later
- good fit for typed models and test fixtures
- portable enough to support a local web UI now and hosted workflows later

## Phase Model

### Phase 0

Planning and bootstrap:
- product framing
- initial rules
- testable domain models
- CLI entrypoint

### Phase 1

Deterministic local diagnostics plus local product surface:
- collect signals from local commands
- normalize results into stable Python models
- run boundary classification rules
- persist local runs in SQLite
- emit human-readable remediation and escalation output
- expose the workflow through a local web UI

### Phase 2

Evidence hardening:
- capture fixtures from real failure cases
- tune rule weights and thresholds
- build confidence calibration around repeated signals

### Phase 3

Optional product surface expansion:
- remote vantage checks — **shipped (opt-in).** A user-configured external
  endpoint (`--vantage` / `[vantage].url`) breaks the single-machine tie between
  "down for everyone" and "just my path." Applied as a pure post-classification
  refinement (`engine.refine`) so the deterministic table and its exhaustive
  coverage test are untouched; advisory only (adjusts confidence + evidence,
  never the verdict); fail-open. See USAGE.md → "Remote vantage".
- hosted analysis and presentation
- exportable support bundles

## Rule Engine First

The first implementation should prefer explicit rules over model-generated reasoning.

Why:
- easier to test
- easier to trust
- easier to revise from field evidence
- safer than pretending confidence without defensible logic

An expert or LLM layer can be added later, but only after structured evidence and deterministic conclusions already exist.

## Early System Components

- `collector`
  Executes and normalizes diagnostics.

- `models`
  Stable types for signals, evidence, findings, and remediation.

- `engine`
  Applies ordered classification rules.

- `formatter`
  Turns structured findings into UI, CLI, and export output.

- `store`
  Persists runs, evidence, and generated escalation artifacts in local SQLite.

- `api`
  Serves the local web UI and orchestrates collection, diagnosis, history, and exports.

## Likely External Commands Later

The project will likely wrap or inspect:
- `ping`
- `tracert` or `traceroute`
- `pathping` on Windows
- DNS resolution APIs or `nslookup`
- HTTP probes

`mtr` support is valuable, but it should stay optional because installation varies by platform.

## Confidence Model

Confidence should be an output of evidence quality, not a random percentage.

Early rule guidance:
- `0.99`
  Direct and repeated evidence with a tight causal boundary.

- `0.95`
  Strong correlated evidence with one missing corroborating signal.

- `0.85`
  Plausible but not yet isolated cleanly.

Anything below that should probably be reported as inconclusive rather than overclaimed.

## Persistence

Introduce a local SQLite database in the first implementation.

Reasons:
- repeated evidence improves confidence
- users need before and after comparisons
- escalation cases are stronger with timestamps and historical runs
- saved runs create a natural foundation for future hosted uploads
