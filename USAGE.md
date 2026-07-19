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
Confidence: Moderate (0.95 prior)
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
| `captive-portal` | A captive portal (hotel/airport/café wifi, or an intercepting proxy) is gating the connection — you need to sign in or accept terms before real traffic passes. Detected even when DNS and pings look healthy, because the portal fakes them. |
| `dns` | Your device can reach the internet by IP, but name resolution is failing. Something is wrong with your DNS configuration. |
| `isp-upstream` | Your LAN and DNS are healthy, but packet loss begins after the first hop and affects multiple destinations. Your ISP or the path beyond it is degraded. |
| `remote-service` | Everything between you and the internet is healthy. The specific service or website you're reaching is the problem. |
| `inconclusive` | The checks don't isolate the problem cleanly. Run again to rule out a transient issue, or use `--no-path` to get a result faster and compare. |

### Confidence Levels

Confidence is shown as a **band** (the value to act on), with the underlying
number in parentheses labeled a *prior*. That number reflects how tightly the
signal pattern isolates one boundary — it is a **heuristic prior, not a measured
error rate**. The priors have not yet been calibrated against real-world outcomes
(see `docs/CALIBRATION.md`); treat the band, not the second decimal, as the signal.

- **High (0.97 and above)** — Multiple independent signals agree. Act on this.
- **Moderate (0.90–0.96)** — Signals mostly agree, but one or two are ambiguous. Follow the remediation steps; re-run if in doubt.
- **Low (below 0.90)** — Signals are insufficient or conflicting. The `inconclusive` result always falls here. Re-run or collect more information.

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

## Escalating: the Report and the Support Bundle

```powershell
boundary-probe escalate <run-uuid>
```

Prints a plain-text report written for the party you are escalating to (ISP,
service provider, IT desk, or yourself) and saves it as
`escalation_<uuid8>.txt`. `--copy` puts it on the clipboard; `--no-file` skips
the file.

### Attaching a support bundle

```powershell
boundary-probe escalate <run-uuid> --export
```

Also writes `escalation_<uuid8>.json` — one self-contained file to attach to a
ticket. Pass a path (`--export ticket-4711.json`) to name it yourself. It holds
everything the report shows *plus* what the report summarizes away: the signal
snapshot, every raw collector measurement (gateway RTT, per-hop traceroute data,
control-host loss, DNS timings), the collector notes, and the rendered report
text itself, so the recipient never has to ask you to re-run anything.

Two fields make it verifiable rather than just readable:

- `bundle_version` and `tool.version` — so a recipient can parse against a known
  schema instead of guessing when the shape changes.
- `integrity.payload_sha256` — a hash over the document with the `integrity` key
  removed and the rest serialized with `sort_keys=True`, `(",", ":")` separators
  and `ensure_ascii=True`, then hashed as UTF-8 bytes. All three settings are
  part of the contract: the report text contains an em dash, so a verifier using
  `ensure_ascii=False` computes a different digest for an identical bundle.

  It detects corruption or truncation in transit. It is an unkeyed digest and the
  tool that computes it ships with the bundle, so it does not prove that nobody
  deliberately edited the file and recomputed the hash.

### Public IPs in the bundle

Unlike `capture`, the bundle **keeps public IPs by default** — your gateway's
address and the traceroute hops through your ISP. That is deliberate: for an
`isp-upstream` verdict the WAN path *is* the evidence, and a redacted bundle is
one your ISP cannot act on. The command prints a note when public IPs are
present.

Posting to a public forum instead of a support ticket? Redact them:

```powershell
boundary-probe escalate <run-uuid> --export --scrub
```

Private, CGNAT, and unanswered (`*`) hops survive scrubbing — they reveal nothing
about you, and dropping them would erase the local-versus-upstream boundary the
report depends on. Scrubbed bundles are re-hashed, so they still verify.

Redaction covers the **whole document**: the same address is removed from the
structured measurements, from the prose collector notes, and from the copy of the
report embedded in the bundle — including the dash-separated form an ISP bakes
into a reverse-DNS name (`cpe-1-2-3-4.example.net`).

Two limits worth knowing before you post a bundle publicly:

- `--scrub` redacts **your** network's addresses, not the target's. Resolved
  target addresses, the canary IP, and control hosts stay — they identify what you
  were probing, not where you are. If you diagnosed a self-hosted host, its
  resolved address may be your own WAN address.
- `target.raw` is exported exactly as you typed it. Diagnosing a URL with a
  session token or signed query string puts that string in the bundle. Scrubbing
  does not touch it.

The `.txt` report is **never** redacted — `--scrub` applies only to the exported
bundle. `escalate <uuid> --scrub` without `--export` is refused rather than
silently ignored.

## Capturing a Fixture

If you want to save a snapshot of current network conditions for sharing or later analysis:

```powershell
boundary-probe capture my-snapshot --target example.com
```

This saves a JSON file to `tests/fixtures/my-snapshot.json`. It records both the
diagnostic signals (the true/false flags the engine reads) and the underlying
measurements — gateway RTT, packet-loss percentages, resolved DNS addresses,
traceroute hops, and timings — so the capture can be replayed for analysis or used
to calibrate confidence. It does not store raw packet captures.

## Configuration

Boundary Probe works out of the box with no configuration — the defaults target
general internet health. Configuration is optional and only needed if you want to
change which hosts are probed, tune the failure thresholds, or adjust timeouts.

### Where the config lives

There is no config file until you create one. To see the effective settings and
the exact path Boundary Probe looks for:

```bash
boundary-probe config
```

The default location is inside the app data directory:

| Platform | Default config path |
|----------|---------------------|
| Windows  | `%LOCALAPPDATA%\boundary-probe\config.toml` |
| Linux    | `$XDG_DATA_HOME/boundary-probe/config.toml` (typically `~/.local/share/boundary-probe/config.toml`) |

To point at a config file elsewhere, set the `BOUNDARY_PROBE_CONFIG` environment
variable to the file path — it overrides the default location entirely.

### What happens when the file is missing or wrong

- **Missing file** → built-in defaults are used (no error).
- **Unparseable TOML** → a warning is printed and defaults are used.
- **Valid TOML, invalid values** (e.g. a negative timeout) → an error is printed
  and the command exits non-zero. Fix the value rather than ignoring it.

### Schema

The file has three optional tables. Any key you omit keeps its default; any table
you omit keeps all its defaults.

```toml
[probes]
# Known-good public hosts used as the internet-health quorum.
control_hosts = ["1.1.1.1", "8.8.8.8", "8.8.4.4", "cloudflare.com"]
# Single IP pinged directly to test raw IP connectivity, bypassing DNS.
canary_ip = "1.1.1.1"
# A second, independent target. ISP-upstream loss is only reported when loss
# appears on both the primary target and this one (avoids blaming the ISP for a
# single flaky destination).
secondary_target = "8.8.8.8"
# How many of control_hosts must be healthy to call the internet controls OK.
# Must be >= 1 and <= the number of control_hosts.
control_quorum = 3
# For an http/https target, verify the TLS certificate so an expired/invalid
# cert reads as the service being DOWN. Set false only for an internal target
# with a self-signed cert (e.g. a homelab service).
target_tls_verify = true

[thresholds]
# Per-hop loss % above which a traceroute hop counts as lossy (0–100).
path_loss_pct = 20.0
# Loss % above which a control host is considered failed (0–100).
control_loss_pct = 50.0
# Loss % above which the canary IP ping is considered failed (0–100).
ip_loss_pct = 50.0
# Minimum ping replies (out of 4) for the gateway to count as reachable. >= 1.
gateway_min_replies = 2

[timeouts]
# All values are seconds and must be > 0.
gateway_route_s = 5.0      # default-route lookup
gateway_ping_s = 8.0       # gateway ping
ip_connectivity_s = 15.0   # canary IP ping
control_hosts_s = 10.0     # control-host probes
target_ping_s = 8.0        # target ping (bare hostname)
target_tcp_s = 5.0         # target TCP connect (explicit non-web port)
target_http_s = 5.0        # target HTTP GET (http/https URL — L7 status check)
tracert_s = 60.0           # traceroute ceiling

[vantage]
# Opt-in. Leave unset (the default) and boundary-probe makes NO outbound call.
# url      = "https://probe.example.com/check"   # your external vantage endpoint
# timeout_s = 4.0                                 # must be > 0; https only

[captive]
# Captive-portal detection (on by default). Sends no user data — just an HTTP
# GET to a fixed public 204 endpoint, exactly as every OS does. Set check_url
# to "" to disable, or per-run with `diagnose --no-captive-check`.
check_url = "http://connectivitycheck.gstatic.com/generate_204"  # must be http://
timeout_s = 4.0                                                   # must be > 0
```

The values shown above are the defaults — copy only the lines you want to change.

### Remote vantage (opt-in)

A single machine cannot tell "the target is down for everyone" from "just my
connection's path." If you run an external endpoint (e.g. a tiny service on a
homelab over a Cloudflare Tunnel), boundary-probe can consult it to break that
tie. It is **off by default** and only ever runs for the `isp-upstream` and
`remote-service` verdicts.

```
boundary-probe diagnose github.com --vantage https://probe.example.com/check
```

(or set `[vantage].url` in the config above). When it reaches out, it prints a
one-line `note:` to stderr naming the destination — the outbound call from an
otherwise-local tool is never silent.

**What is sent / safety:**
- Only the **target** you are diagnosing is sent (as `?target=<host[:port]>`) —
  never your history, gateway, local subnet, or config.
- The URL **must be `https`** (the target is not sent in cleartext), TLS is
  always verified, redirects are **not** followed, and the response is
  size-capped and must be JSON.
- The vantage result is **advisory**: it adjusts confidence and adds an evidence
  line, but never changes the verdict — a misbehaving vantage cannot mislead the
  diagnosis. If the vantage is unreachable or misbehaves, the run proceeds
  exactly as if it were off (fail-open).

**Reference endpoint** — the contract is one query param in, one JSON field out
(`{"reachable": <bool>}`; optional `latency_ms`). A minimal implementation:

```python
# Flask reference vantage — checks whether <target> is reachable from here.
# WARNING for operators: this connects to an arbitrary ?target=. Restrict who
# can reach this endpoint (e.g. Cloudflare Access) and/or refuse RFC-1918 and
# link-local targets so it is not an open relay into your LAN.
import socket
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.get("/check")
def check():
    target = request.args.get("target", "")
    host, _, port = target.partition(":")
    try:
        socket.create_connection((host, int(port or 443)), timeout=4)
        return jsonify(reachable=True)
    except OSError:
        return jsonify(reachable=False)
```

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
