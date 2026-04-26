# Architecture Decision

## Decision

Boundary Probe will be built in phases:

1. local-first UI application
2. local persistence for historical runs
3. optional hosted second phase for public use

The core diagnosis engine must remain shared across every surface.

## Why This Is The Right Shape

A browser-only product is too constrained for the first version.

Deep local diagnostics need capabilities that the open web does not reliably provide:
- gateway reachability checks
- route and hop analysis
- local interface and adapter facts
- repeatable path diagnostics

That means a serious diagnostic product needs either:
- a local application, or
- a hosted product with an installed helper agent

For this project, the best sequence is to prove the diagnosis engine locally first, then extend outward.

## Product Phases

### Phase 1: Local UI First

Deliver:
- deterministic collectors
- structured diagnosis engine
- evidence rendering
- remediation guidance
- templated escalation output
- saved local history

Recommended implementation shape:
- Python backend and shared diagnosis engine
- local SQLite database
- local web UI served on the machine

This keeps packaging simple while preserving a path to a richer desktop wrapper later if needed.

### Phase 2: Public-Facing Second

After the local product is trustworthy:
- allow users to upload a signed diagnostic bundle to a hosted site, or
- provide a small local helper for richer live public workflows

The hosted experience should start as analysis and presentation, not as a replacement for local evidence collection.

### Phase 3: Remote Confirmation

Later additions may include:
- remote vantage checks
- comparison against public outages
- support-case export bundles

These are valuable, but they should not arrive before the local boundary model is reliable.

## Persistence Decision

Historical runs should be stored from the start.

Reason:
- repeated evidence matters for confidence
- users need before/after comparisons
- ISP escalation is stronger with timestamps and repeated measurements

The default local store should be SQLite.

## Shared Engine Rule

There must be one diagnosis engine, not separate logic for:
- CLI
- local UI
- future hosted flow

Every interface should feed the same normalized signals into the same classifier and remediation generator.

## Email / Escalation Decision

V1 should ship with three templated outputs:

1. ISP escalation
2. Hosting provider or service operator escalation
3. Local network incident summary

Each template should include:
- concise summary
- evidence bullets
- timestamps
- suggested requested action

The UI should provide:
- `mailto:` launch
- copyable plain-text body
- copyable support report

## Immediate Next Build Choices

The next implementation choices are now locked:
- target OS scope for v1: Windows first
- local UI stack: Python backend plus local web UI
- local database boundary: SQLite on the local machine
- first collector set:
  - gateway reachability
  - DNS resolution
  - control-host HTTP and connectivity checks
  - target-specific checks
  - basic path diagnostics
  - local interface facts
