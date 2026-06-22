# Confidence Calibration

The classifier emits a `confidence` per verdict (e.g. `router-gateway` 0.99,
`isp-upstream` 0.93). Today these are **hardcoded heuristic priors** in
`engine.py`, not rates measured against real outcomes. Calibration is the
process of replacing those priors with values backed by captured evidence —
roadmap step 3 (`boundary-probe roadmap`).

This cannot be done from synthetic data: it requires real measurements from real
networks in each failure state. The `capture` command exists to gather them.

## 1. Capture real fixtures

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
boundary-probe capture <name> --target <a-real-target>
```

This writes `tests/fixtures/<name>.json` with the recorded `signals` and raw
`measurements`. **Aim for several captures per boundary**, across different
networks/times, so the empirical rate means something.

## 2. Label the ground truth

Add an `expected_boundary` key to each captured fixture (the true boundary from
the table above). The calibration harness reads it; without it the fixture is
skipped. (The four original synthetic fixtures are mapped by name in
`scripts/calibrate.py` and need no key.)

## 3. Run the harness

```
python scripts/calibrate.py            # default: tests/fixtures
python scripts/calibrate.py <dir>      # a separate capture dir
```

It prints, per boundary: the hardcoded confidence, the number of labeled
fixtures, the empirical hit-rate, and the gap. Example:

```
boundary         hardcoded    n  empirical     gap
router-gateway        0.99    8       0.88   -0.11
```

A persistent negative gap with a healthy `n` (say ≥ 10) is evidence the prior is
too confident; a tight match is evidence it is well-set.

## 4. Recalibrate (human decision)

Once `n` is large enough per boundary, adjust the constants in `engine.py`
toward the observed rates — or, if the second decimal is not justified, collapse
the user-facing number to the existing `confidence_band` (High / Moderate / Low).
This is a deliberate, reviewed change, not an automatic one: the harness informs
it; a human makes it.

Until then, treat the displayed confidence as a heuristic prior, and say so in
user-facing copy.
