# Usage Guide: Boundary Probe

## What This Does

Boundary Probe tells you **where** a network problem is, not just that one exists. When a website, service, or connection is failing, it runs a series of checks and tells you: is the problem on your machine, your router, your DNS, your ISP, or the remote service itself?

Every result includes a confidence level and a short list of what to do next — steps that are specific to that type of failure, not generic "have you tried turning it off and on again" advice.

## Installation

Open PowerShell and run:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

You only need to do this once. After that, the `boundary-probe` command is available whenever the virtual environment is active.

## Running a Diagnosis

```powershell
boundary-probe diagnose example.com
boundary-probe diagnose https://app.example.com
boundary-probe diagnose 1.1.1.1
```

A typical result looks like this:

```
Target:     example.com (host)
Boundary:   remote-service
Confidence: 0.95
Summary:    General internet health is good, but the target service is failing specifically.

Evidence:
- controls: Known-good internet controls are healthy.
- target: The target service still fails.

Next steps:
- Check the target service status page or origin health before changing local network settings.
- Try a second network only to confirm the target-specific failure pattern, not as the first step.
- If you operate the service, inspect TLS, DNS, reverse proxy, and origin availability.

Run saved: a3f92c1b...
```

The diagnosis takes 25–60 seconds on a normal network. Each run is saved automatically — you can review it later with `--history`.

### Faster Diagnosis (Skip Traceroute)

If you want a quicker result and don't need path analysis:

```powershell
boundary-probe diagnose example.com --no-path
```

This skips the `tracert` step and completes in 15–25 seconds. The ISP-upstream boundary cannot be detected without path data, so use this only when you already suspect a non-ISP issue.

### JSON Output

For scripting or logging:

```powershell
boundary-probe diagnose example.com --json
```

## Understanding the Results

### Boundary Types

| Boundary | What it means |
|----------|--------------|
| `router-gateway` | Your local gateway (router) is not responding. The problem is between your device and the router. |
| `dns` | Your device can reach the internet by IP, but name resolution is failing. Something is wrong with your DNS configuration. |
| `isp-upstream` | Your LAN and DNS are healthy, but packet loss begins after the first hop and affects multiple destinations. Your ISP or the path beyond it is degraded. |
| `remote-service` | Everything between you and the internet is healthy. The specific service or website you're reaching is the problem. |
| `inconclusive` | The checks don't isolate the problem cleanly. Run again to rule out a transient issue, or use `--no-path` to get a result faster and compare. |

### Confidence Levels

The confidence score (0.00–1.00) reflects how strongly the collected signals point to one boundary:

- **0.97 and above (High)** — Multiple independent signals agree. Act on this.
- **0.90–0.96 (Moderate)** — Signals mostly agree, but one or two are ambiguous. Follow the remediation steps; re-run if in doubt.
- **Below 0.90 (Low)** — Signals are insufficient or conflicting. The `inconclusive` result always falls here. Re-run or collect more information.

## Viewing Run History

```powershell
boundary-probe diagnose --history 10
```

Shows the 10 most recent runs across all targets:

```
TIMESTAMP             TARGET                    BOUNDARY          CONF  BAND      DURATION
2026-04-26T15:32:11Z  example.com               remote-service    0.95  Moderate  31.2s
2026-04-26T15:18:04Z  https://app.acme.com      remote-service    0.95  Moderate  28.7s
2026-04-26T14:55:30Z  1.1.1.1                   inconclusive      0.50  Low       12.4s
```

History is stored locally on your machine. It is never uploaded anywhere.

## Capturing a Fixture

If you want to save a snapshot of current network conditions for sharing or later analysis:

```powershell
boundary-probe capture my-snapshot --target example.com
```

This saves a small JSON file to `tests/fixtures/my-snapshot.json`. It contains the seven true/false signals that describe your network state at the time of capture — not raw packet data.

## What to Do When Something Breaks

**"The command isn't found after activating the virtual environment"**  
Re-run `pip install -e .[dev]` from the repo root. The `boundary-probe` command is registered during installation.

**"error: required Windows tool not found"**  
`ping.exe` or `tracert.exe` is not on your PATH. This is unusual — both ship with Windows. Check that you haven't removed them from `C:\Windows\System32`.

**"The result says 'inconclusive' every time"**  
Run `boundary-probe diagnose --history 5` to see if this is consistent or just one run. If consistent, try `boundary-probe diagnose <target> --no-path` to see if tracert is the blocking step. Antivirus or firewall software blocking ICMP can cause this.

**"The diagnosis takes much longer than expected"**  
The tracert step has a 30-second ceiling and can be slow on some networks. Use `--no-path` to skip it.

**"The boundary says 'isp-upstream' but my ISP says everything is fine"**  
The ISP boundary fires when packet loss appears after the first hop across two independent targets. Run again — if it was a transient spike it won't repeat. If it persists, use `--history 5` to confirm it's consistent before escalating.

For anything not covered here, check the [Technical Reference](TECHNICAL.md) or open an issue in the repository.

## FAQ

**Does this send any data outside my machine?**  
No. All probes go to standard public addresses (1.1.1.1, 8.8.8.8, etc.) as part of the diagnosis, the same as running `ping` manually. Results are stored only in a local SQLite file on your machine.

**Can I run this on a problem that isn't affecting a specific website?**  
Yes. Use an IP address or a hostname that represents the service or segment you want to test. For general internet health, `boundary-probe diagnose 1.1.1.1` is a good check.

**Why does it take 30–60 seconds?**  
It's running real probes: 10-packet pings to multiple hosts, DNS resolution, a TCP connection attempt, and a traceroute. Speed is bounded by the probe timeouts, not by computation.

**Can I use this to diagnose someone else's network remotely?**  
No. The probes run from your machine. It measures the path from your device to the target.

**Where is my history stored?**  
At `%LOCALAPPDATA%\boundary-probe\runs.db` — typically `C:\Users\<you>\AppData\Local\boundary-probe\runs.db`. You can open this file with any SQLite browser if you want to inspect raw data.
