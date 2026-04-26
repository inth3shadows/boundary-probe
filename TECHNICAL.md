# Technical Reference: Boundary Probe

## Architecture

```
CLI (cli.py)
  └─ parse_target()          # host / ip / url classification
  └─ collect_signals()       # orchestrates all collectors
       ├─ collect_gateway()       # route print → ping gateway
       ├─ collect_dns()           # socket.getaddrinfo
       ├─ collect_ip_connectivity() # canary ping to 1.1.1.1
       ├─ collect_control_hosts() # parallel ping: 1.1.1.1, 8.8.8.8, 8.8.4.4, cloudflare.com
       ├─ collect_target_service() # TCP connect or ping
       └─ collect_path()          # tracert → normalize_from_paths()
  └─ diagnose(snapshot)      # deterministic rule engine
  └─ insert_run()            # SQLite persistence
```

Data flow: `CLI → collectors → SignalSnapshot (7 booleans) → engine → Diagnosis → store + stdout`

The rule engine never sees raw subprocess output. Collectors reduce observations to booleans; the normalizer reduces path hop tables to two booleans. The engine sees only `SignalSnapshot`.

## File Descriptions

| File | Purpose | Dependencies |
|------|---------|-------------|
| `cli.py` | Argument parsing, output formatting, orchestration | collectors, engine, store, targets |
| `engine.py` | Deterministic boundary rules + confidence tiers | models |
| `models.py` | `SignalSnapshot`, `Diagnosis`, `EvidenceItem` dataclasses | — |
| `targets.py` | `parse_target()` → `ParsedTarget` (raw, kind, host, port, scheme) | stdlib |
| `normalizer.py` | `normalize_path_signals()` — persistent-loss detection with look-ahead | — |
| `collectors/_runner.py` | `SubprocessRunner` protocol + `DefaultRunner` (cp437, CREATE_NO_WINDOW) | subprocess |
| `collectors/_parsers.py` | Pure regex parsers for ping, tracert, route-print stdout | re, ipaddress |
| `collectors/gateway.py` | `route print -4` → gateway IP → 4-ping reachability | _runner, _parsers |
| `collectors/dns.py` | `socket.getaddrinfo` — no subprocess; IP targets bypass resolution | socket |
| `collectors/ip_connectivity.py` | Canary ping to 1.1.1.1 (10 packets) | _runner, _parsers |
| `collectors/control_hosts.py` | 4-host parallel ping via `ThreadPoolExecutor`; ≥3/4 quorum | _runner, _parsers |
| `collectors/target_service.py` | TCP connect (if port known) or ping fallback | _runner, _parsers, socket |
| `collectors/path.py` | `tracert -4 -h 10 -w 500`; 30s ceiling | _runner, _parsers |
| `collectors/orchestrator.py` | Sequential collection → secondary trace if degradation detected → `SignalSnapshot` | all collectors, normalizer |
| `store/__init__.py` | SQLite schema, `connect()`, `insert_run()`, `fetch_recent()`, `confidence_band()` | sqlite3, models |

## Rule Engine

Five boundaries, deterministic priority order:

| Boundary | Trigger condition | Confidence |
|----------|------------------|------------|
| `router-gateway` | `not gateway_reachable` | 0.99 |
| `dns` | `gateway_reachable AND ip_connectivity_ok AND NOT dns_ok` | 0.96 |
| `isp-upstream` | `dns_ok AND packet_loss_after_hop1 AND packet_loss_multiple_targets` | 0.93 |
| `remote-service` | `gateway_reachable AND dns_ok AND control_hosts_ok AND NOT target_service_ok` | 0.95 |
| `inconclusive` | fallback | 0.50 |

Confidence bands (persisted in SQLite, surfaced in Phase 3 UI):
- `≥ 0.97` → High
- `≥ 0.90` → Moderate
- `< 0.90` → Low

## Path Normalizer

`normalize_path_signals()` implements the persistent-loss invariant:

1. Skip hop 1 (handled by the gateway collector).
2. For each hop at index ≥ 2: mark as `persistent_lossy` only if `loss_pct > 20%` AND at least one of the next two hops also exceeds 20% (absent hops count as lossy).
3. `packet_loss_after_hop1 = True` if any hop is `persistent_lossy`.
4. `packet_loss_multiple_targets = True` only if a second independent trace (to 8.8.8.8) also produces `packet_loss_after_hop1 = True`.
5. Incomplete traces (`path.completed = False`) return `PathSignals(False, False)` — no signal rather than a false positive.

The 20% threshold is `_LOSS_THRESHOLD_PCT` at module scope for Phase 5 calibration.

## Subprocess Invariants

All subprocess calls go through `DefaultRunner.run()`. Rules enforced throughout:

- `shell=False` always — argv is a list, never a joined string
- `creationflags=CREATE_NO_WINDOW` — suppresses console flicker on Windows
- `stdout/stderr` decoded as `cp437, errors="replace"` — Windows OEM console encoding
- `FileNotFoundError` (missing `ping.exe` / `tracert.exe`) is re-raised — surfaces as `sys.exit(3)` in the CLI
- Timeouts: gateway route=5s, gateway ping=8s, DNS=10s (OS socket), IP canary=15s, control hosts=10s each, target ping=8s, tracert=30s

Control hosts are hardcoded in Phase 1: `1.1.1.1`, `8.8.8.8`, `8.8.4.4`, `cloudflare.com`. Config file support is planned for Phase 2.

## SQLite Schema

Database location: `%LOCALAPPDATA%\boundary-probe\runs.db`  
Override: `BOUNDARY_PROBE_DB` environment variable (used by tests).

One row per `diagnose` invocation. Wide-denormalized — no joins needed for history queries. Schema version tracked in `schema_meta`; mismatch triggers drop-and-recreate (pre-1.0 policy).

Key columns: `run_uuid` (uuid4 hex), `started_at` (ISO 8601 UTC), `boundary`, `confidence_float`, `confidence_band`, the 7 signal booleans, and JSON blobs for evidence, remediation, collector notes, and path hops.

## Testing

```powershell
# Unit tests only (default — no network required, <1s)
pytest

# Integration tests (live network required)
pytest -m integration
```

Unit tests use `FakeRunner` — a test double that returns canned stdout from fixture `.txt` files without touching the network. Monkeypatching `collect_signals` in CLI tests keeps them fast and network-independent.

Adding new parser fixtures: capture real `ping` / `tracert` output, save to `tests/fixtures/<name>.txt`, reference in `test_parsers.py`.

## Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `BOUNDARY_PROBE_DB` | `%LOCALAPPDATA%\boundary-probe\runs.db` | Override SQLite path (used in tests) |
| `BOUNDARY_PROBE_DEBUG` | unset | Set to `1` to print unrecognized subprocess output to stderr |

## Known Limitations

- **Windows only.** `ping.exe`, `tracert.exe`, and `route.exe` are assumed to be on `PATH`. No Linux or macOS support in Phase 1.
- **IPv6 not supported.** `parse_target()` rejects IPv6 literals. IPv6 hops in tracert output raise `ValueError` in the normalizer.
- **Antivirus / firewall interference.** Raw ICMP may be blocked. Affected collectors return `False` with a note; the engine falls back to `inconclusive` rather than misfiring.
- **Tracert reliability.** Some networks return very few hops before timing out. If `path.completed = False` consistently, the isp-upstream rule cannot fire — check Phase 2 entry condition 6.
- **Windows console encoding.** Non-cp437 locales (cp850, cp932) get `?` substitution on non-ASCII hostnames. IP-anchored regexes are unaffected.
- **No retries.** Collectors make one attempt each. A transient spike can produce `inconclusive`. Run again or use `--history` to compare.
- **Schema migrations.** Drop-and-recreate on version mismatch until 1.0. Run history is lost on schema upgrades.

## Maintenance

```powershell
# Run full unit suite
pytest

# Run live-network integration tests
pytest -m integration

# Install in editable mode (required after changing pyproject.toml)
pip install -e .[dev]

# Check no shell=True crept in
Select-String -Path src\**\*.py -Pattern "shell=True"

# Inspect the local run database
sqlite3 "$env:LOCALAPPDATA\boundary-probe\runs.db" "SELECT started_at, target_raw, boundary, confidence_float FROM runs ORDER BY started_at DESC LIMIT 10;"
```
