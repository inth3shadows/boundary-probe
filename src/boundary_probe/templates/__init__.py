from __future__ import annotations

import json
import sqlite3

_SEP = "-" * 60


def render_escalation(row: sqlite3.Row) -> str:
    """Select and render the appropriate escalation template for a run."""
    boundary = row["boundary"]

    # The engine returns the `healthy` verdict when every signal is green:
    # nothing failed, so there is nothing to escalate.
    if boundary == "healthy":
        title = "NETWORK STATUS REPORT — ALL PROBES HEALTHY"
        action = (
            "All probes returned healthy results. No network boundary failure was detected.\n"
            "If you are experiencing application-level issues, they are likely unrelated\n"
            "to basic network connectivity (e.g. authentication, rate limiting, app errors).\n"
            "Run again with a specific failing target to capture a fault state."
        )
        return _format_body(title, action, row)

    if boundary == "isp-upstream":
        title = "INTERNET SERVICE PROVIDER ESCALATION REPORT"
        action = (
            "Please investigate upstream routing and packet loss from my connection.\n"
            "The evidence shows consistent packet loss beyond my local gateway,\n"
            "affecting multiple independent targets simultaneously.\n"
            "I am requesting a line quality check and path investigation."
        )
    elif boundary == "remote-service":
        host = row["target_host"]
        title = "SERVICE PROVIDER ESCALATION REPORT"
        action = (
            f"The target service ({host}) is unreachable from my connection despite\n"
            "confirmed internet connectivity. DNS, gateway, IP-level canary pings, and\n"
            "control hosts are all healthy. Please investigate your service availability\n"
            "and routing from residential/business connections."
        )
    else:
        title = "LOCAL NETWORK INCIDENT SUMMARY"
        action = (
            "This report documents a local network issue for internal reference.\n"
            "Please review the evidence and collector measurements below to guide\n"
            "router, DNS, or device-level troubleshooting steps."
        )
    return _format_body(title, action, row)


def _format_body(title: str, action: str, row: sqlite3.Row) -> str:
    boundary = row["boundary"]
    conf = row["confidence_float"]
    band = row["confidence_band"]
    summary = row["summary"]
    ts = row["started_at"]
    run_uuid = row["run_uuid"]
    target_raw = row["target_raw"]
    target_kind = row["target_kind"]

    evidence = json.loads(row["evidence_json"])
    dns_ips = json.loads(row["dns_resolved_ips_json"])
    controls = json.loads(row["controls_json"])
    notes = json.loads(row["collector_notes_json"])
    path_hops = json.loads(row["path_primary_json"])

    gw_ip = row["gateway_ip"] or "unknown"
    gw_status = "reachable" if row["gateway_reachable"] else "unreachable"
    gw_rtt = f"{row['gateway_rtt_ms']:.1f} ms RTT" if row["gateway_rtt_ms"] is not None else "no RTT data"
    gateway_line = f"{gw_ip} — {gw_status} ({gw_rtt})"

    dns_ok_str = "ok" if row["dns_ok"] else "failed"
    if dns_ips:
        ips_str = ", ".join(dns_ips[:3])
        if len(dns_ips) > 3:
            ips_str += f" +{len(dns_ips) - 3} more"
    else:
        ips_str = "no addresses"
    dns_line = f"{dns_ok_str} — {ips_str} ({row['dns_elapsed_ms']} ms)"

    ip_rtt = f"{row['ip_avg_rtt_ms']:.1f} ms avg" if row["ip_avg_rtt_ms"] is not None else "no RTT"
    canary_line = f"{row['ip_target']} — {row['ip_loss_pct']:.0f}% loss, {ip_rtt}"

    ctrl_ok = sum(1 for c in controls if c["reachable"])
    ctrl_total = len(controls)
    controls_line = f"{ctrl_ok}/{ctrl_total} healthy"

    svc_status = "ok" if row["target_service_ok"] else "failed"
    target_line = f"{row['target_method']} — {svc_status} ({row['target_elapsed_ms']} ms)"

    path_note = notes.get("path_primary", "")
    if path_hops:
        path_line = f"{len(path_hops)} hops recorded"
    elif "skipped" in path_note.lower():
        path_line = "skipped (--no-path)"
    elif path_note:
        path_line = f"incomplete — {path_note}"
    else:
        path_line = "incomplete"

    ev_lines = "\n".join(f"  - {e['label']}: {e['detail']}" for e in evidence) or "  (none)"

    lines = [
        title,
        _SEP,
        f"Generated: {ts}",
        f"Run ID:    {run_uuid}",
        "",
        "TARGET",
        f"  {target_raw} ({target_kind})",
        "",
        "DIAGNOSIS",
        f"  Boundary:   {boundary}",
        f"  Confidence: {band} ({conf:.2f} prior — signal-isolation strength, not a measured rate)",
        f"  Summary:    {summary}",
        "",
        "TECHNICAL EVIDENCE",
        ev_lines,
        "",
        "NETWORK MEASUREMENTS",
        f"  Gateway:       {gateway_line}",
        f"  DNS:           {dns_line}",
        f"  Canary IP:     {canary_line}",
        f"  Control hosts: {controls_line}",
        f"  Target:        {target_line}",
        f"  Path:          {path_line}",
        "",
        "REQUESTED ACTION",
        action,
        "",
        _SEP,
        f"Boundary Probe | Run ID: {run_uuid}",
    ]
    return "\n".join(lines) + "\n"
