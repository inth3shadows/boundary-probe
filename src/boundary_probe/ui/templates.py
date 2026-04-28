from __future__ import annotations

import html
import json
import sqlite3
import urllib.parse

_BAND_CLASS = {"High": "band-high", "Moderate": "band-moderate", "Low": "band-low"}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  font-size: 14px; color: #1a1a1a; background: #f5f5f5; padding: 24px;
}
h1 { font-size: 20px; font-weight: 600; margin-bottom: 16px; }
h2 { font-size: 14px; font-weight: 600; margin: 20px 0 8px; color: #444;
     text-transform: uppercase; letter-spacing: 0.04em; }
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; }
.card { background: #fff; border: 1px solid #ddd; border-radius: 6px;
        padding: 20px; margin-bottom: 20px; }
.run-form { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.run-form input[type=text] {
  padding: 6px 10px; border: 1px solid #ccc; border-radius: 4px;
  font-size: 14px; width: 300px;
}
.run-form label { display: flex; align-items: center; gap: 4px; cursor: pointer; }
.run-form button {
  padding: 6px 16px; background: #0066cc; color: #fff; border: none;
  border-radius: 4px; font-size: 14px; cursor: pointer;
}
.run-form button:hover { background: #0055aa; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 10px; border-bottom: 2px solid #ddd;
     color: #555; font-weight: 600; white-space: nowrap; }
td { padding: 7px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #fafafa; }
.band-high     { color: #1a7a40; font-weight: 600; }
.band-moderate { color: #a06000; font-weight: 600; }
.band-low      { color: #c0392b; font-weight: 600; }
.meta { color: #555; font-size: 13px; margin-bottom: 16px; }
.meta span { margin-right: 24px; }
.boundary-box {
  display: inline-block; padding: 10px 18px; border-radius: 6px;
  border: 1px solid #ddd; background: #f9f9f9; margin-bottom: 12px;
}
.boundary-box .blabel { font-size: 11px; text-transform: uppercase;
                         color: #888; margin-bottom: 4px; }
.boundary-box .bvalue { font-size: 18px; font-weight: 700; }
.conf-note { font-size: 13px; color: #555; margin-left: 14px; vertical-align: middle; }
ul.evidence { list-style: none; padding: 0; }
ul.evidence li { padding: 4px 0 4px 0; border-bottom: 1px solid #f0f0f0; }
ul.evidence li:last-child { border-bottom: none; }
ul.evidence li::before { content: "\\2022\\00a0 "; color: #888; }
.lbl { font-weight: 600; }
ol.remed { padding-left: 18px; }
ol.remed li { padding: 3px 0; }
.sig-grid { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px; }
.sig-pill { padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.sig-ok   { background: #e6f4ea; color: #1a7a40; }
.sig-fail { background: #fce8e8; color: #c0392b; }
.back { margin-bottom: 16px; }
.errmsg { color: #c0392b; font-weight: 600; }
.esc-actions { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.esc-actions a, .esc-actions button {
  padding: 5px 12px; border-radius: 4px; font-size: 13px; cursor: pointer;
  border: 1px solid #ccc; background: #fff; color: #333; text-decoration: none;
}
.esc-actions a:hover, .esc-actions button:hover { background: #f0f0f0; }
#esc-text {
  white-space: pre-wrap; font-family: "Consolas", "Courier New", monospace;
  font-size: 12px; background: #f8f8f8; border: 1px solid #ddd;
  border-radius: 4px; padding: 14px; overflow-x: auto; max-height: 400px;
  overflow-y: auto;
}
.coll-tbl { width: auto; }
.coll-tbl th { color: #555; border-bottom: 1px solid #ddd; }
.coll-tbl td { border-bottom: 1px solid #f0f0f0; }
.coll-tbl tr:last-child td { border-bottom: none; }
"""


def _h(s: object) -> str:
    return html.escape(str(s) if s is not None else "", quote=True)


def _page(title: str, body: str) -> str:
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f"<title>{_h(title)} — Boundary Probe</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        f"<body>\n{body}\n</body>\n</html>"
    )


def render_history(rows: list) -> str:
    form = (
        '<div class="card">\n'
        '  <form class="run-form" method="POST" action="/diagnose">\n'
        '    <input type="text" name="target" placeholder="hostname, IP, or URL"'
        " required autofocus>\n"
        '    <label><input type="checkbox" name="no_path"> Skip traceroute</label>\n'
        '    <button type="submit">Run Diagnosis</button>\n'
        "  </form>\n"
        "</div>"
    )

    if not rows:
        table = "<p style='color:#888;margin-top:8px'>No runs recorded yet.</p>"
    else:
        header = (
            "<table>\n<thead>\n<tr>\n"
            "  <th>Timestamp</th><th>Target</th><th>Boundary</th>"
            "<th>Conf</th><th>Band</th><th>Duration</th><th></th>\n"
            "</tr>\n</thead>\n<tbody>\n"
        )
        rows_html = []
        for row in rows:
            target = row["target_raw"]
            if len(target) > 30:
                target = target[:29] + "…"
            dur = f"{row['duration_ms'] / 1000:.1f}s"
            band = row["confidence_band"]
            bc = _BAND_CLASS.get(band, "")
            uuid = row["run_uuid"]
            rows_html.append(
                f"<tr>"
                f"<td>{_h(row['started_at'])}</td>"
                f"<td>{_h(target)}</td>"
                f"<td>{_h(row['boundary'])}</td>"
                f"<td>{row['confidence_float']:.2f}</td>"
                f'<td class="{bc}">{_h(band)}</td>'
                f"<td>{_h(dur)}</td>"
                f'<td><a href="/run/{_h(uuid)}">detail →</a></td>'
                "</tr>"
            )
        table = header + "\n".join(rows_html) + "\n</tbody>\n</table>"

    body = (
        "<h1>Boundary Probe</h1>\n"
        f"{form}\n"
        '<div class="card">\n'
        "<h2>Recent Runs</h2>\n"
        f"{table}\n"
        "</div>"
    )
    return _page("History", body)


def _mailto_subject(boundary: str, target_host: str) -> str:
    if boundary == "isp-upstream":
        return urllib.parse.quote("Network Issue: Suspected ISP Upstream Problem", safe="")
    if boundary == "remote-service":
        return urllib.parse.quote(f"Service Availability Issue: {target_host}", safe="")
    return urllib.parse.quote("Local Network Incident Report", safe="")


def render_detail(row: sqlite3.Row) -> str:
    target_raw = row["target_raw"]
    ts = row["started_at"]
    dur = f"{row['duration_ms'] / 1000:.1f}s"
    boundary = row["boundary"]
    conf = row["confidence_float"]
    band = row["confidence_band"]
    bc = _BAND_CLASS.get(band, "")
    summary = row["summary"]

    evidence = json.loads(row["evidence_json"])
    remediation = json.loads(row["remediation_json"])
    controls = json.loads(row["controls_json"])
    dns_ips = json.loads(row["dns_resolved_ips_json"])
    notes = json.loads(row["collector_notes_json"])

    ev_items = "".join(
        f'<li><span class="lbl">{_h(e["label"])}</span>: {_h(e["detail"])}</li>'
        for e in evidence
    )
    ev_section = f'<ul class="evidence">{ev_items}</ul>' if ev_items else "<p>—</p>"

    rem_items = "".join(f"<li>{_h(r)}</li>" for r in remediation)
    rem_section = f'<ol class="remed">{rem_items}</ol>' if rem_items else "<p>—</p>"

    gw_ip = row["gateway_ip"] or "—"
    gw_rtt = f"{row['gateway_rtt_ms']:.1f} ms" if row["gateway_rtt_ms"] is not None else "—"
    gw_status = "reachable" if row["gateway_reachable"] else "unreachable"

    dns_ok_str = "ok" if row["dns_ok"] else "failed"
    if dns_ips:
        dns_ips_str = ", ".join(dns_ips[:3])
        if len(dns_ips) > 3:
            dns_ips_str += f" +{len(dns_ips) - 3} more"
    else:
        dns_ips_str = "—"

    ip_rtt = f"{row['ip_avg_rtt_ms']:.1f} ms" if row["ip_avg_rtt_ms"] is not None else "—"
    ctrl_ok = sum(1 for c in controls if c["reachable"])
    ctrl_total = len(controls)

    path_hops = json.loads(row["path_primary_json"])
    path_note = notes.get("path_primary", "")
    if path_hops:
        path_status = f"{len(path_hops)} hops"
    elif "skipped" in path_note.lower():
        path_status = "skipped"
    elif path_note:
        path_status = f"incomplete — {path_note}"
    else:
        path_status = "incomplete"

    coll_rows = [
        ("Gateway", f"{_h(gw_ip)} — {gw_status}, {gw_rtt}"),
        ("DNS", f"{dns_ok_str} — {_h(dns_ips_str)} ({row['dns_elapsed_ms']} ms)"),
        ("Canary IP", f"{_h(row['ip_target'])} — {row['ip_loss_pct']:.0f}% loss, avg {ip_rtt}"),
        ("Controls", f"{ctrl_ok}/{ctrl_total} healthy"),
        ("Target", f"{_h(row['target_method'])} ({row['target_elapsed_ms']} ms)"),
        ("Path", _h(path_status)),
    ]
    coll_html = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in coll_rows)
    coll_table = f'<table class="coll-tbl"><tbody>{coll_html}</tbody></table>'

    signals = [
        ("gateway_reachable", bool(row["gateway_reachable"])),
        ("dns_ok", bool(row["dns_ok"])),
        ("ip_connectivity_ok", bool(row["ip_connectivity_ok"])),
        ("control_hosts_ok", bool(row["control_hosts_ok"])),
        ("target_service_ok", bool(row["target_service_ok"])),
        ("packet_loss_after_hop1", bool(row["packet_loss_after_hop1"])),
        ("packet_loss_multiple_targets", bool(row["packet_loss_multiple_targets"])),
    ]
    pills = "".join(
        f'<span class="sig-pill {"sig-ok" if v else "sig-fail"}">'
        f"{_h(k)}={1 if v else 0}</span>"
        for k, v in signals
    )
    sig_section = f'<div class="sig-grid">{pills}</div>'

    from boundary_probe.templates import render_escalation
    esc_text = render_escalation(row)
    esc_uuid_short = row["run_uuid"][:8]
    mailto_subj = _mailto_subject(boundary, row["target_host"])
    esc_section = (
        "<h2>Escalation Report</h2>\n"
        '<div class="esc-actions">\n'
        f'  <a href="/run/{_h(row["run_uuid"])}/escalation.txt" download>'
        f"Download escalation_{esc_uuid_short}.txt</a>\n"
        f'  <a href="mailto:?subject={mailto_subj}">Open email client</a>\n'
        '  <button onclick="navigator.clipboard.writeText('
        "document.getElementById('esc-text').innerText"
        ')">Copy to clipboard</button>\n'
        "</div>\n"
        f'<pre id="esc-text">{_h(esc_text)}</pre>\n'
    )

    body = (
        '<div class="back"><a href="/">← Back to history</a></div>\n'
        '<div class="card">\n'
        '<p class="meta">\n'
        f'  <span><strong>Target:</strong> {_h(target_raw)}</span>\n'
        f'  <span><strong>Time:</strong> {_h(ts)}</span>\n'
        f'  <span><strong>Duration:</strong> {_h(dur)}</span>\n'
        "</p>\n"
        '<div class="boundary-box">\n'
        '  <div class="blabel">Boundary</div>\n'
        f'  <div class="bvalue">{_h(boundary)}</div>\n'
        "</div>\n"
        f'<span class="conf-note">Confidence {conf:.2f} — '
        f'<span class="{bc}">{_h(band)}</span></span>\n'
        "<h2>Summary</h2>\n"
        f"<p>{_h(summary)}</p>\n"
        "<h2>Evidence</h2>\n"
        f"{ev_section}\n"
        "<h2>Next Steps</h2>\n"
        f"{rem_section}\n"
        "<h2>Collector Details</h2>\n"
        f"{coll_table}\n"
        "<h2>Signal Flags</h2>\n"
        f"{sig_section}\n"
        f"{esc_section}"
        "</div>"
    )
    return _page(f"Run — {target_raw}", body)


def render_loading(target: str, no_path: bool) -> str:
    import json as _json
    target_js = _json.dumps(target)
    no_path_js = "true" if no_path else "false"
    body_val = urllib.parse.urlencode({"target": target, **({"no_path": "on"} if no_path else {})})
    body_js = _json.dumps(body_val)

    script = f"""
const TARGET = {target_js};
const BODY   = {body_js};

const STEPS = [
  "Probing gateway…",
  "Resolving DNS…",
  "Pinging canary IP…",
  "Checking control hosts…",
  "Reaching target service…",
  "Tracing path…",
  "Analyzing signals…",
  "Almost there…",
];
let stepIdx = 0;
const statusEl = document.getElementById("status");
const stepTimer = setInterval(() => {{
  stepIdx = (stepIdx + 1) % STEPS.length;
  statusEl.textContent = STEPS[stepIdx];
}}, 5000);

// Elapsed clock
const startTime = Date.now();
const clockEl = document.getElementById("clock");
setInterval(() => {{
  const s = Math.floor((Date.now() - startTime) / 1000);
  clockEl.textContent = s + "s";
}}, 1000);

// Minigame — catch the packet
let score = 0;
const scoreEl = document.getElementById("score");
const pkt = document.getElementById("packet");
const arena = document.getElementById("arena");
let px = 50, py = 50, vx = 2.2, vy = 1.7;
function movePacket() {{
  const W = arena.clientWidth  - pkt.offsetWidth;
  const H = arena.clientHeight - pkt.offsetHeight;
  px += vx; py += vy;
  if (px <= 0 || px >= W) {{ vx *= -1; px = Math.max(0, Math.min(px, W)); }}
  if (py <= 0 || py >= H) {{ vy *= -1; py = Math.max(0, Math.min(py, H)); }}
  pkt.style.left = px + "px";
  pkt.style.top  = py + "px";
}}
const gameTimer = setInterval(movePacket, 16);
pkt.addEventListener("click", () => {{
  score++;
  scoreEl.textContent = score;
  vx *= 1.08; vy *= 1.08;
  pkt.style.transform = "scale(1.4)";
  setTimeout(() => pkt.style.transform = "", 120);
}});

// Fire the real diagnosis
fetch("/api/diagnose", {{
  method: "POST",
  headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
  body: BODY,
}})
.then(r => r.json())
.then(data => {{
  clearInterval(stepTimer); clearInterval(gameTimer);
  if (data.run_uuid) {{
    statusEl.textContent = "Done! Redirecting…";
    window.location.href = "/run/" + data.run_uuid;
  }} else {{
    statusEl.textContent = "Error: " + (data.error || "unknown error");
    statusEl.style.color = "#c0392b";
  }}
}})
.catch(err => {{
  statusEl.textContent = "Request failed: " + err;
  statusEl.style.color = "#c0392b";
}});
"""

    body = (
        '<div class="back"><a href="/">← Cancel</a></div>\n'
        '<div class="card" style="max-width:520px">\n'
        f'  <h2 style="margin-bottom:6px">Diagnosing</h2>\n'
        f'  <p class="meta" style="margin-bottom:16px">'
        f'<strong>{_h(target)}</strong></p>\n'
        '  <p id="status" style="font-size:13px;color:#555;min-height:1.4em">'
        'Probing gateway…</p>\n'
        '  <p style="font-size:12px;color:#aaa;margin-top:4px">'
        'elapsed: <span id="clock">0s</span></p>\n'
        '  <div id="arena" style="position:relative;width:100%;height:160px;'
        'background:#f0f4ff;border-radius:6px;margin-top:16px;overflow:hidden;'
        'border:1px solid #dde4f5;cursor:crosshair">\n'
        '    <span id="packet" style="position:absolute;left:50px;top:50px;'
        'font-size:22px;user-select:none;transition:transform 0.1s;cursor:pointer"'
        '>&#x1F4E6;</span>\n'
        '  </div>\n'
        '  <p style="font-size:12px;color:#888;margin-top:8px">'
        'Catch the packets while you wait — score: <strong id="score">0</strong></p>\n'
        f'  <script>{script}</script>\n'
        '</div>'
    )
    return _page(f"Diagnosing {target}…", body)


def render_error(msg: str, back: str = "/") -> str:
    body = (
        f'<div class="back"><a href="{_h(back)}">← Back</a></div>\n'
        '<div class="card">\n'
        f'<p class="errmsg">{_h(msg)}</p>\n'
        "</div>"
    )
    return _page("Error", body)
