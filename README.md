# Boundary Probe

`boundary-probe` is a new project for deterministic network boundary diagnosis.

The product goal is narrow on purpose:
- run a small set of high-value diagnostics
- identify the most likely failure boundary
- attach evidence and a confidence score
- tell the operator what to do next

This is not meant to be another raw `ping` or `traceroute` wrapper. The differentiator is interpretation: local device vs router vs DNS vs ISP upstream vs remote service, with remediation that is operational instead of generic.

## Product Direction

The repo started as a CLI-first bootstrap because that was the fastest way to lock the core diagnosis model.

The chosen v1 product shape is now:
- Windows-first
- local web UI
- Python backend with a shared deterministic engine
- local SQLite persistence
- future hosted second phase after the local product is trustworthy

The CLI remains useful because it supports:
- deterministic rules
- reproducible test fixtures
- low-friction local execution
- reuse inside the local web UI and later hosted workflows

Current baseline:
- product brief
- technical direction
- initial rule-model notes
- minimal Python package
- a demo diagnosis engine with early boundary rules

## Initial Scope

The first useful version should answer:
- Is the problem on the local device or LAN?
- Is the router or gateway the likely boundary?
- Is DNS the real issue?
- Is the ISP or upstream path degraded?
- Is the remote service failing while the broader internet is healthy?

The first useful version should not try to solve everything:
- no SaaS control plane yet
- no LLM-first diagnosis path
- no vendor-specific router integrations
- no decorative graph-heavy UI

## Repo Layout

- `docs/product-brief.md` - product framing, user, scope, and why this project exists
- `docs/project-contract.md` - operating contract for scope, confidence, and decision standards
- `docs/architecture-decision.md` - chosen product shape and phased delivery model
- `docs/expert-review-framework.md` - how major build decisions are reviewed and weighted
- `docs/technical-direction.md` - architecture choice and implementation path
- `docs/rules-engine.md` - early rules and confidence model
- `src/boundary_probe` - package code
- `tests` - smoke coverage for the deterministic engine and CLI

## Quick Start

Create a virtual environment and install in editable mode:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

Run the demo diagnosis scenarios:

```powershell
python -m boundary_probe.cli demo dns-failure
python -m boundary_probe.cli demo router-down
python -m boundary_probe.cli roadmap
```

Run tests:

```powershell
pytest
```

## Working Decisions

- Repo name: `boundary-probe`
- V1 OS scope: Windows first
- V1 surface: local web UI
- Language: Python 3.11+
- Storage: local SQLite from day one
- Collector set: gateway, DNS, control-host, target-specific, path, and interface facts
- Escalation outputs: ISP email, hosting/service email, local network incident summary
- Diagnosis style: deterministic rules before any probabilistic or LLM layer
- Product promise: confidence-backed findings with explicit remediation
