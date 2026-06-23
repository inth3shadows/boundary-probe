# Confidence Calibration

The classifier emits a `confidence` per verdict (e.g. `router-gateway` 0.99,
`isp-upstream` 0.93). Today these are **hardcoded heuristic priors** in
`engine.py`, not rates measured against real outcomes. Calibration is the
process of replacing those priors with values backed by captured evidence —
roadmap step 3 (`boundary-probe roadmap`).

This cannot be done from synthetic data: it requires real measurements from real
networks in each failure state. The `capture` command exists to gather them.

## 1. Capture fixtures

Run `capture` while a network is genuinely in each state below. Induce the state
however is safe in your environment (suggestions in parentheses).

| Scenario name | True boundary | How to induce |
|---|---|---|
| `local-device` | local-device | disconnect Wi-Fi / unplug Ethernet (no default route) |
| `router-down` | router-gateway | power off the router/AP (LAN unreachable) |
| `wan-down` | wan-gateway | unplug the modem/ONT WAN, router still up |
| `dns-broken` | dns | set an unreachable resolver in OS/router DNS |
| `isp-loss` | isp-upstream | capture during real multi-target upstream loss |
| `service-down` | remote-service | target a service that is down while internet is healthy |
| `healthy` | healthy | a normal, working connection |

```
boundary-probe capture <name> --target <a-real-target> \
    --expected-boundary <true-boundary> --capture-method real
```

This writes `tests/fixtures/<name>.json` with the recorded `signals`, raw
`measurements`, the ground-truth `expected_boundary`, and a `capture_method`.
**Aim for several captures per boundary**, across different networks/times, so the
empirical rate means something. Public IPs in the traceroute hops and the gateway
address are redacted on write (this repo is public — see *Scrub*, below).

### 1a. Automated fault injection (Linux/WSL2)

The five boundaries a healthy machine cannot reproduce can be induced
reproducibly in an isolated network namespace, without taking the host offline:

```
sudo scripts/inject_fault.sh run-all        # all 5 -> tests/fixtures/*.json
sudo scripts/inject_fault.sh capture dns-broken   # just one
```

Each capture is tagged `capture_method=injected`. **Injected fingerprints are
synthetic** — an `iptables` DROP is a silent timeout, not the ICMP-unreachable a
real dead router may emit; `netem` loss is not a real ISP's jitter shape. The
harness bootstraps the *mechanics* and the boolean-layer wiring; it does **not**
substitute for real captures on the high-harm boundaries. `calibrate.py` keeps
the cohorts apart (see §3) and warns when a high-harm prior is backed by
injected-only fixtures.

### 1b. Scrub (public repo)

By default `capture` redacts globally-routable IPs from the traceroute hops and
the gateway address (private/CGNAT/WSL2-NAT addresses are kept — they are not
identifying). `--no-scrub` disables this and refuses to write if a public IP is
present unless you also pass `--allow-public-ips` (use only for a fixture you have
confirmed leaks nothing identifying).

## 2. Label the ground truth

`--expected-boundary` (above) writes the label at capture time — no hand-editing
needed. If a fixture predates the flag, add an `expected_boundary` key manually
(the true boundary from the table). Without a label the fixture is skipped. (The
four original synthetic fixtures are mapped by name in `scripts/calibrate.py` and
need no key.)

## 3. Run the harness

```
python scripts/calibrate.py            # default: tests/fixtures
python scripts/calibrate.py <dir>      # a separate capture dir
```

It prints, per boundary: the hardcoded confidence, the number of labeled
fixtures (split into `real` and injected `inj` cohorts), the empirical hit-rate,
and the gap. Example:

```
boundary         hardcoded    n  real  inj  empirical     gap
router-gateway        0.99    8     6    2       0.88   -0.11
```

A persistent negative gap with a healthy `real` count (say ≥ 10) is evidence the
prior is too confident; a tight match is evidence it is well-set. The harness
also emits a WARNING when a high-harm boundary (`router-gateway`, `isp-upstream`)
has `real=0` and `inj>0` — its rate is not yet trustworthy because injected
fingerprints are synthetic and lack cross-network sample diversity.

## 4. Recalibrate (human decision)

Once `n` is large enough per boundary, adjust the constants in `engine.py`
toward the observed rates — or, if the second decimal is not justified, collapse
the user-facing number to the existing `confidence_band` (High / Moderate / Low).
This is a deliberate, reviewed change, not an automatic one: the harness informs
it; a human makes it.

Until then, treat the displayed confidence as a heuristic prior, and say so in
user-facing copy.
