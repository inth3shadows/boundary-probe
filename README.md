# Boundary Probe

`boundary-probe` is a Windows-first CLI tool for deterministic network boundary diagnosis. It runs a targeted set of probes, classifies the most likely failure boundary with a confidence score, and gives the operator specific remediation steps — not generic advice.

The five boundaries it answers: **local device / LAN**, **router-gateway**, **DNS**, **ISP upstream path**, and **remote service**. Every result is backed by evidence collected in the same run and stored locally in SQLite for history review.

## How It Works

`boundary-probe diagnose <target>` runs six collectors sequentially — gateway ping, DNS resolution, IP-level canary ping, control-host quorum check, target-service reachability, and a traceroute path analysis — then feeds the results into a deterministic rule engine. The engine emits a boundary classification, a confidence score, and an evidence-backed remediation list. Every run is persisted to a local SQLite database.

The rule engine is intentionally deterministic: same signals → same result, every time. Probabilistic layers and LLM-assisted diagnosis are deferred until the rules are calibrated on real-world captures.

## Prerequisites

- Windows 10 or 11 (64-bit)
- Python 3.11 or newer
- `ping.exe` and `tracert.exe` on PATH (standard on all supported Windows versions)
- No additional runtime dependencies — stdlib only

## Quick Start

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

Diagnose a target:

```powershell
boundary-probe diagnose example.com
boundary-probe diagnose https://app.example.com
boundary-probe diagnose 1.1.1.1
```

Skip the traceroute for a faster result:

```powershell
boundary-probe diagnose example.com --no-path
```

View recent run history:

```powershell
boundary-probe diagnose --history 10
```

Capture a fixture from a live run (for testing or sharing):

```powershell
boundary-probe capture my-snapshot --target example.com
```

Run tests:

```powershell
pytest
pytest -m integration   # requires live network
```

## Project Structure

```
src/boundary_probe/
    cli.py              Entry point — subcommands: diagnose, capture, roadmap
    engine.py           Deterministic rule engine and confidence tiers
    models.py           SignalSnapshot (7 booleans), Diagnosis, EvidenceItem
    targets.py          Target parser — host / IP / URL classification
    normalizer.py       Path signal normalizer — persistent-loss detection
    collectors/         Windows subprocess collectors (ping, tracert, DNS, TCP)
    store/              SQLite persistence — schema, insert, fetch
    templates/          Escalation template generators (Phase 4)
tests/
    fixtures/           JSON signal snapshots and raw ping/tracert text fixtures
    test_engine.py      Rule engine unit tests
    test_parsers.py     ping/tracert/route-print parser tests
    test_collectors_unit.py  Per-collector tests with FakeRunner (no network)
    test_normalizer.py  Path normalizer algorithm tests
    test_store.py       SQLite schema and round-trip tests
    test_cli.py         CLI integration tests (monkeypatched collectors)
    test_collectors_integration.py  Live-network tests (gated: -m integration)
docs/
    product-brief.md          Product framing and scope
    architecture-decision.md  Chosen product shape and phased delivery
    technical-direction.md    Architecture and implementation path
    rules-engine.md           Rule model and confidence design
```

## Phase Status

| Phase | Scope | Status |
|-------|-------|--------|
| 0 | Scaffold — rule engine, CLI stub, target parser, fixtures | Done |
| 1 | Real collectors, path normalizer, SQLite persistence | Done |
| 2 | Rich signal facts, config file, collector details output | Done |
| 3 | Local web UI | Planned |
| 4 | Escalation output (clipboard + .txt) | Planned |
| 5 | Hardening and calibration | Planned |

## Related Documentation

- [Technical Reference](TECHNICAL.md) — architecture, collector design, deployment, maintenance
- [Usage Guide](USAGE.md) — end-user guide for running diagnoses and reading results
