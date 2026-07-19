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

Use the helper rather than the raw command — an outage is a bad moment to be
recalling flags, and a bare `capture <name>` silently overwrites a fixture of the
same name, destroying the previous data point:

```
scripts/capture_real.sh --status                       # what is still needed
scripts/capture_real.sh dns --label home               # capture one
scripts/capture_real.sh isp-upstream --label cafe
```

It names the fixture uniquely (`<boundary>-real-<label>-<timestamp>`), stamps
`--expected-boundary` and `--capture-method real` (the two flags that decide
which cohort `calibrate.py` counts it in), and afterwards reports whether the
engine agreed with your label and how far the boundary still is from n=10.

**A capture where the engine disagreed with you is the most valuable fixture in
the set** — keep it. It is a labeled misclassification, which is what recall is
computed from; a set containing only agreements cannot measure accuracy.

The `--label` matters: network diversity is what makes the real cohort worth more
than the injected one. Ten captures from one router mostly measure that router.

The equivalent raw command, if you need it:

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

**The path-loss threshold cannot be field-tested (issue #41).** The `isp-loss`
scenario's netem rate is overridable (`BP_ISP_LOSS_PCT=22`), but do **not** expect
the captured per-hop loss to match it. `traceroute` sends 3 probes per hop, so a
hop's measured loss is always one of `{0, 33.33, 66.67, 100}%`. The engine's 20%
threshold therefore means "at least 1 of 3 probes lost", and any configured value
in `(0, 33.33]` behaves identically.

An earlier version of this document told you to sweep the rate to land in a
"[10, 30]% ambiguous band" that `calibrate.py` flagged. That band does not
intersect the set of measurable values, so it reported zero for every capture —
reading as "threshold well-placed" when it meant "threshold unmeasurable". Both
the instruction and the band have been removed. The measurement pass now prints
the instrument's real resolution instead.

Collecting more fixtures will not calibrate this threshold. See #41 for the
options (more probes per hop, keying the verdict on ping loss instead, or
documenting the real semantics).

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

The harness runs two passes.

**Boolean pass.** Per boundary: the hardcoded confidence, the number of labeled
fixtures split into three cohorts — `real` (genuine captures), `syn` (the v1
synthetic reference fixtures), and `inj` (fault-injected) — the empirical
hit-rate, and the gap. Example:

```
boundary         hardcoded    n  real  syn  inj  empirical     gap
router-gateway        0.99    8     6    0    2       0.88   -0.11
```

A persistent negative gap with a healthy `real` count (say ≥ 10) is evidence the
prior is too confident; a tight match is evidence it is well-set. The harness
emits a WARNING when a high-harm boundary (`router-gateway`, `isp-upstream`) has
`real=0` while `syn` and/or `inj` are non-zero — its rate is not yet trustworthy
because synthetic and injected fingerprints lack cross-network sample diversity.
(The cohorts are kept apart deliberately: a synthetic fixture defaulting into the
`real` count would silently silence this warning.)

**Measurement pass.** The engine has exactly one tunable numeric threshold that
fixtures exercise: path-loss % (`path_loss_pct`, default 20). For every fixture
carrying a `measurements` block the harness:

- **recomputes the core booleans** from the raw measurements and flags any
  `MISMATCH` with the stored signal — a capture-pipeline bug, not a calibration
  signal, but the highest-value thing this pass can find;
- **reports path-loss hops**, how many sit over the threshold, and — the point of
  the section — the set of loss values the instrument can actually produce. With
  3 probes per hop that set is `{0, 33.33, 66.67, 100}`, so the configured 20%
  threshold is really "≥1 of 3 probes lost" and no capture can land near it.
  This replaces an earlier "ambiguous band" flag that could never fire (#41).

RTT and hop counts have **no** engine threshold and are shown as context only —
inventing a cutoff the engine does not use would fabricate calibration.

## 4. Recalibrate (human decision)

Once `n` is large enough per boundary, adjust the constants in `engine.py`
toward the observed rates — or, if the second decimal is not justified, collapse
the user-facing number to the existing `confidence_band` (High / Moderate / Low).
This is a deliberate, reviewed change, not an automatic one: the harness informs
it; a human makes it.

Until then, treat the displayed confidence as a heuristic prior, and say so in
user-facing copy.
