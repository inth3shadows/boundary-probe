from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

# Re-exported under their historical private names: the scrubber moved to
# `bundle` so the fixture capture and the support bundle share one implementation.
from boundary_probe.bundle import SCRUB_PLACEHOLDER as _SCRUB_PLACEHOLDER
from boundary_probe.bundle import build_bundle
from boundary_probe.bundle import is_public_ip as _is_public_ip  # noqa: F401  (kept for callers/tests)
from boundary_probe.bundle import scrub_measurements as _scrub_measurements
from boundary_probe.collectors import collect_signals
from boundary_probe.collectors.orchestrator import CollectionResult
from boundary_probe.config import get_config_path, load_config
from boundary_probe.engine import BOUNDARIES, diagnose
from boundary_probe.models import SignalSnapshot
from boundary_probe.store import confidence_band, connect, fetch_recent, fetch_run, insert_run
from boundary_probe.targets import ParsedTarget, parse_target


_PLATFORM: str = sys.platform
_WIN: bool = _PLATFORM == "win32"


def _copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard. Returns True on success."""
    if _WIN:
        cmds: tuple[list[str], ...] = (["clip"],)
    else:
        cmds = (["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"])
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, input=text.encode("utf-8"), capture_output=True, timeout=3)
            if r.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return False


def _bp_version() -> str:
    """Installed distribution version, falling back to the package `__version__` when run
    from an un-built source tree. importlib.metadata reflects the ACTUAL installed dist."""
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _dist_version
    try:
        return _dist_version("boundary-probe")
    except PackageNotFoundError:
        from boundary_probe import __version__
        return __version__


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="boundary-probe")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {_bp_version()}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("roadmap", help="Print the current implementation sequence.")
    subparsers.add_parser("config", help="Print the effective configuration and config file path.")

    diagnose_parser = subparsers.add_parser(
        "diagnose",
        help="Diagnose a target (hostname, IP, or URL).",
    )
    diagnose_parser.add_argument(
        "target", nargs="?",
        help="Target to diagnose: hostname, IPv4 address, or URL. Required unless --history is used.",
    )
    diagnose_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output.")
    diagnose_parser.add_argument("--history", type=int, metavar="N", default=None,
                                 help="Print N most recent runs and exit.")
    diagnose_parser.add_argument("--no-path", action="store_true", dest="no_path",
                                 help="Skip tracert (faster, less signal).")
    diagnose_parser.add_argument("--vantage", metavar="URL", default=None,
                                 help="Opt-in external vantage URL (https). When the "
                                      "verdict is isp-upstream/remote-service, asks this "
                                      "endpoint whether the target is reachable from "
                                      "elsewhere. Sends only the target. Overrides config.")
    diagnose_parser.add_argument("--no-captive-check", action="store_true", dest="no_captive",
                                 help="Skip the captive-portal connectivity check "
                                      "(an HTTP request to a fixed public 204 endpoint).")

    escalate_parser = subparsers.add_parser(
        "escalate",
        help="Generate an escalation report for a saved run.",
    )
    escalate_parser.add_argument("run_uuid", help="Run UUID to generate the report for.")
    escalate_parser.add_argument("--copy", action="store_true",
                                 help="Copy the report to the clipboard (Windows clip.exe).")
    escalate_parser.add_argument("--output", metavar="PATH", default=None,
                                 help="Write the report to PATH instead of the default file.")
    escalate_parser.add_argument("--no-file", action="store_true", dest="no_file",
                                 help="Do not write a .txt file.")
    escalate_parser.add_argument("--export", metavar="PATH", nargs="?", const=True, default=None,
                                 help="Also write a JSON support bundle (run metadata, signals, "
                                      "diagnosis, raw measurements, and the report) for attaching "
                                      "to a ticket. Optional PATH overrides the default filename.")
    escalate_parser.add_argument("--scrub", action="store_true",
                                 help="Redact public IPs (gateway, traceroute hops) from the "
                                      "exported bundle. Off by default: the WAN path is the "
                                      "evidence an ISP needs. Use before posting publicly.")

    ui_parser = subparsers.add_parser("ui", help="Launch the local web UI.")
    ui_parser.add_argument("--port", type=int, default=8787,
                           help="Port to listen on (default: 8787).")
    ui_parser.add_argument("--no-open", action="store_true", dest="no_open",
                           help="Do not open the browser automatically.")

    watch_parser = subparsers.add_parser(
        "watch",
        help="Continuously probe a target and display live results.",
    )
    watch_parser.add_argument("target", help="Target to probe: hostname, IPv4, or URL.")
    watch_parser.add_argument("--interval", type=int, default=60, metavar="S",
                              help="Seconds between polls (default: 60). Use --no-path for intervals < 45s.")
    watch_parser.add_argument("--no-path", action="store_true", dest="no_path",
                              help="Skip tracert (faster; recommended for short intervals).")
    watch_parser.add_argument("--count", type=int, default=None, metavar="N",
                              help="Stop after N polls (default: run until Ctrl-C).")

    capture_parser = subparsers.add_parser(
        "capture",
        help="Capture a SignalSnapshot fixture from a live run.",
    )
    capture_parser.add_argument("name", help="Name for the captured fixture.")
    capture_parser.add_argument("--target", required=True, help="Target to probe for the fixture.")
    capture_parser.add_argument("--no-path", action="store_true", dest="no_path",
                                help="Skip tracert.")
    capture_parser.add_argument("--expected-boundary", dest="expected_boundary",
                                choices=BOUNDARIES, default=None,
                                help="Ground-truth boundary for calibration (writes the "
                                     "'expected_boundary' key so scripts/calibrate.py scores it).")
    capture_parser.add_argument("--capture-method", dest="capture_method",
                                choices=("real", "injected"), default="real",
                                help="How the fault state was produced. 'injected' marks a "
                                     "fixture made by fault injection (synthetic fingerprint) so "
                                     "calibration can separate it from real captures.")
    capture_parser.add_argument("--no-scrub", action="store_true", dest="no_scrub",
                                help="Do not redact public IPs from the captured measurements. "
                                     "Refuses to write if a public IP is present unless "
                                     "--allow-public-ips is also given.")
    capture_parser.add_argument("--allow-public-ips", action="store_true", dest="allow_public_ips",
                                help="Permit public IPs in the written fixture (use only for a "
                                     "fixture you have confirmed leaks nothing identifying).")

    return parser


def _print_roadmap() -> None:
    print("Boundary Probe roadmap:")
    print("1. Normalize local diagnostics into stable signal models.")
    print("2. Expand the deterministic rules for router, DNS, ISP, and remote-service boundaries.")
    print("3. Capture real-world fixtures and calibrate confidence from repeated evidence.")
    print("4. Add optional saved runs and a local UI after the rules are trustworthy.")


def _print_config() -> None:
    path = get_config_path()
    cfg = load_config()
    source = "[loaded]" if path.exists() else "[not found — using defaults]"
    print(f"Config file: {path}  {source}")
    print()
    print("[probes]")
    print(f"  control_hosts    {', '.join(cfg.control_hosts)}")
    print(f"  canary_ip        {cfg.canary_ip}")
    print(f"  secondary_target {cfg.secondary_target}")
    print(f"  control_quorum   {cfg.control_quorum}")
    print(f"  target_tls_verify {cfg.target_tls_verify}")
    print()
    print("[thresholds]")
    print(f"  path_loss_pct      {cfg.path_loss_pct}%")
    print(f"  control_loss_pct   {cfg.control_loss_pct}%")
    print(f"  ip_loss_pct        {cfg.ip_loss_pct}%")
    print(f"  gateway_min_replies {cfg.gateway_min_replies}")
    print()
    print("[timeouts]")
    print(f"  gateway_route     {cfg.gateway_route_s}s")
    print(f"  gateway_ping      {cfg.gateway_ping_s}s")
    print(f"  ip_connectivity   {cfg.ip_connectivity_s}s")
    print(f"  control_hosts     {cfg.control_hosts_s}s")
    print(f"  target_ping       {cfg.target_ping_s}s")
    print(f"  target_tcp        {cfg.target_tcp_s}s")
    print(f"  target_http       {cfg.target_http_s}s")
    print(f"  tracert           {cfg.tracert_s}s")
    print()
    print("[vantage]")
    print(f"  url               {cfg.vantage_url or '(disabled)'}")
    print(f"  timeout           {cfg.vantage_timeout_s}s")
    print()
    print("[captive]")
    print(f"  check_url         {cfg.captive_check_url or '(disabled)'}")
    print(f"  timeout           {cfg.captive_check_s}s")


def _format_collector_details(result: CollectionResult) -> str:
    lines = ["Collector details:"]

    gw = result.gateway
    if gw.gateway_ip:
        status = "reachable" if gw.reachable else "unreachable"
        rtt = f"RTT {gw.rtt_ms:.1f}ms" if gw.rtt_ms is not None else "RTT —"
        lines.append(f"  Gateway:  {gw.gateway_ip} — {status} ({rtt})")
    else:
        lines.append("  Gateway:  — (not determined)")

    v6 = result.ipv6_route
    v6_str = "route present" if v6.present else (v6.note or "no route")
    lines.append(f"  IPv6:     {v6_str}")

    dns = result.dns
    if dns.resolved_ips:
        ips = ", ".join(dns.resolved_ips[:3])
        if len(dns.resolved_ips) > 3:
            ips += f" +{len(dns.resolved_ips) - 3} more"
        lines.append(f"  DNS:      {ips} resolved ({dns.elapsed_ms}ms)")
    else:
        lines.append(f"  DNS:      failed ({dns.elapsed_ms}ms)")

    ip = result.ip
    rtt_str = f", avg {ip.avg_rtt_ms:.1f}ms" if ip.avg_rtt_ms is not None else ""
    lines.append(f"  Canary:   {ip.target_ip} — {ip.loss_pct:.0f}% loss{rtt_str}")

    ctrl = result.controls
    lines.append(f"  Controls: {ctrl.ok_count}/{ctrl.total} healthy")

    cap = result.captive
    if not cap.checked:
        cap_str = "not checked"
    elif cap.portal_detected:
        cap_str = "PORTAL DETECTED"
    else:
        cap_str = "clean (no portal)"
    lines.append(f"  Captive:  {cap_str}")

    tgt = result.target
    status = f" HTTP {tgt.http_status}" if tgt.http_status is not None else ""
    verdict = "" if tgt.ok else " — FAILED"
    lines.append(f"  Target:   {tgt.method}{status}{verdict} ({tgt.elapsed_ms}ms)")

    pp = result.path_primary
    if pp.completed:
        hop_count = len(pp.raw_hops)
        lines.append(f"  Path:     {hop_count} hops, primary trace complete")
    elif pp.note == "skipped via --no-path":
        lines.append("  Path:     skipped (--no-path)")
    else:
        lines.append(f"  Path:     incomplete ({pp.note})")

    return "\n".join(lines)


def _collector_facts_dict(result: CollectionResult) -> dict:
    pp = result.path_primary
    ps = result.path_secondary
    return {
        "gateway_ip": result.gateway.gateway_ip,
        "gateway_rtt_ms": result.gateway.rtt_ms,
        "dns_resolved_ips": result.dns.resolved_ips,
        "dns_elapsed_ms": result.dns.elapsed_ms,
        "ip_loss_pct": result.ip.loss_pct,
        "ip_avg_rtt_ms": result.ip.avg_rtt_ms,
        "controls_ok": result.controls.ok_count,
        "controls_total": result.controls.total,
        "target_method": result.target.method,
        "target_http_status": result.target.http_status,
        "target_elapsed_ms": result.target.elapsed_ms,
        "path_hop_count": len(pp.raw_hops) if pp.completed else None,
        "path_completed": pp.completed,
        "path_secondary_hop_count": len(ps.raw_hops) if ps is not None else None,
    }


def _print_history(n: int) -> None:
    with connect() as conn:
        rows = fetch_recent(conn, n)
    if not rows:
        print("no runs recorded yet.")
        return
    print(f"{'TIMESTAMP':<20}  {'TARGET':<24}  {'BOUNDARY':<16}  {'CONF':<4}  {'BAND':<8}  DURATION")
    for row in rows:
        target = row["target_raw"]
        if len(target) > 23:
            target = target[:22] + "…"
        dur = f"{row['duration_ms'] / 1000:.1f}s"
        print(
            f"{row['started_at']:<20}  {target:<24}  {row['boundary']:<16}  "
            f"{row['confidence_float']:.2f}  {row['confidence_band']:<8}  {dur}"
        )


def _maybe_consult_vantage(diagnosis, parsed, vantage_override: str | None):
    """Opt-in: fold an external vantage check into the diagnosis (fail-open).

    The URL comes from --vantage or [vantage].url in config. Only consulted for
    the isp-upstream/remote-service verdicts. Prints a one-line stderr notice
    naming the destination whenever it reaches out, so the outbound call from an
    otherwise-local tool is never silent.
    """
    from boundary_probe.collectors.vantage import apply_vantage
    from boundary_probe.engine import _VANTAGE_REFINABLE

    cfg = load_config()
    url = vantage_override if vantage_override is not None else cfg.vantage_url
    if not url or diagnosis.boundary not in _VANTAGE_REFINABLE:
        return diagnosis

    target_str = parsed.host if parsed.port is None else f"{parsed.host}:{parsed.port}"
    print(f"note: consulting external vantage {url} (sends target '{target_str}')",
          file=sys.stderr)
    refined, slice_ = apply_vantage(diagnosis, target_str, url, cfg.vantage_timeout_s)
    if slice_ is not None and not slice_.consulted:
        print(f"note: external vantage not consulted ({slice_.note})", file=sys.stderr)
    return refined


def _print_diagnose(target: str, as_json: bool, history: int | None, skip_path: bool,
                    vantage_url: str | None = None, skip_captive: bool = False) -> None:
    if history is not None:
        if history <= 0:
            print("error: --history N must be positive", file=sys.stderr)
            sys.exit(2)
        _print_history(history)
        return

    try:
        parsed = parse_target(target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        result = collect_signals(parsed, skip_path=skip_path, skip_captive=skip_captive)
    except FileNotFoundError as exc:
        print(f"error: required network tool not found ({exc}).", file=sys.stderr)
        sys.exit(3)

    diagnosis = diagnose(result.snapshot)
    diagnosis = _maybe_consult_vantage(diagnosis, parsed, vantage_url)

    with connect() as conn:
        run_uuid = insert_run(
            conn,
            parsed_target=parsed,
            snapshot=result.snapshot,
            diagnosis=diagnosis,
            collection_result=result,
        )

    if as_json:
        print(json.dumps({
            **asdict(diagnosis),
            "run_uuid": run_uuid,
            "collector_facts": _collector_facts_dict(result),
        }, indent=2))
        return

    print(f"Target:     {parsed.raw} ({parsed.kind})")
    print(f"Boundary:   {diagnosis.boundary}")
    # Lead with the band; the float is a heuristic prior (signal-isolation
    # strength), not a measured error rate — see docs/CALIBRATION.md.
    print(f"Confidence: {confidence_band(diagnosis.confidence)} ({diagnosis.confidence:.2f} prior)")
    print(f"Summary:    {diagnosis.summary}")
    print("")
    print("Evidence:")
    for item in diagnosis.evidence:
        print(f"- {item.label}: {item.detail}")
    print("")
    print("Next steps:")
    for step in diagnosis.remediation:
        print(f"- {step}")
    print("")
    print(_format_collector_details(result))
    print("")
    print(f"Run saved: {run_uuid}")


def _escalate(run_uuid: str, copy: bool, output: str | None, no_file: bool,
              export: str | bool | None = None, scrub: bool = False) -> None:
    from boundary_probe.templates import render_escalation

    with connect() as conn:
        row = fetch_run(conn, run_uuid)
    if row is None:
        print(f"error: run not found: {run_uuid}", file=sys.stderr)
        sys.exit(2)

    text = render_escalation(row)
    print(text)

    if not no_file:
        out_path = Path(output) if output else Path(f"escalation_{run_uuid[:8]}.txt")
        out_path.write_text(text, encoding="utf-8")
        print(f"Saved: {out_path}")

    if export is not None:
        _write_bundle(row, text, export, scrub=scrub)

    if copy:
        if _copy_to_clipboard(text):
            print("Copied to clipboard.")
        else:
            print("warning: clipboard tool not found; copy skipped.", file=sys.stderr)


def _write_bundle(row, report_text: str, export: str | bool, *, scrub: bool) -> None:
    """Write the JSON support bundle and report what it does or does not contain."""
    bundle, hits = build_bundle(row, report_text, scrub=scrub)
    run_uuid = row["run_uuid"]
    path = Path(export) if isinstance(export, str) else Path(f"escalation_{run_uuid[:8]}.json")
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    print(f"Saved bundle: {path}")

    if scrub:
        for h in hits:
            print(f"  scrubbed: {h} -> {_SCRUB_PLACEHOLDER}", file=sys.stderr)
    elif hits:
        # Not an error: the WAN path is what makes an isp-upstream bundle
        # actionable. Name the exposure so the choice to forward it is informed.
        print(f"note: bundle contains {len(hits)} public IP(s) from your network path "
              f"(gateway/traceroute). Re-run with --scrub before posting it publicly.",
              file=sys.stderr)


def _build_capture_payload(
    name: str,
    parsed: ParsedTarget,
    result: CollectionResult,
    captured_at: str,
    *,
    expected_boundary: str | None = None,
    capture_method: str = "real",
) -> dict:
    """Serialize a collection run into an enriched fixture payload.

    ``signals`` reconstructs the SignalSnapshot (the engine's input); ``measurements``
    preserves the raw per-collector data — RTT, packet loss %, resolved IPs, traceroute
    hops, timings — so captured fixtures can later validate the collector layer and
    calibrate confidence scores. The booleans alone cannot support either: they are
    the engine's *output* of the measurements, not the measurements themselves.

    ``expected_boundary`` (optional) labels the ground truth for calibration;
    ``capture_method`` records whether the fault was real or injected so calibration
    can keep the two cohorts apart. Measurements here are raw — the caller scrubs
    public IPs before writing (see ``_scrub_measurements``).
    """
    payload = {
        "scenario": name,
        "captured_at": captured_at,
        "capture_method": capture_method,
        "target": parsed.raw,
        "signals": asdict(result.snapshot),
        "measurements": {
            "gateway": asdict(result.gateway),
            "dns": asdict(result.dns),
            "ip_connectivity": asdict(result.ip),
            "control_hosts": asdict(result.controls),
            "target_service": asdict(result.target),
            "path_primary": asdict(result.path_primary),
            "path_secondary": asdict(result.path_secondary) if result.path_secondary else None,
        },
    }
    if expected_boundary is not None:
        payload["expected_boundary"] = expected_boundary
    return payload


def _print_capture(
    name: str,
    target: str,
    skip_path: bool,
    *,
    expected_boundary: str | None = None,
    capture_method: str = "real",
    no_scrub: bool = False,
    allow_public_ips: bool = False,
) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
        print("error: fixture name must contain only letters, digits, hyphens, and underscores", file=sys.stderr)
        sys.exit(2)
    try:
        parsed = parse_target(target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        result = collect_signals(parsed, skip_path=skip_path)
    except FileNotFoundError as exc:
        print(f"error: required network tool not found ({exc}).", file=sys.stderr)
        sys.exit(3)

    snap = result.snapshot
    captured_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = _build_capture_payload(
        name, parsed, result, captured_at,
        expected_boundary=expected_boundary, capture_method=capture_method,
    )

    # Public-repo safety: redact (or refuse to write) public IPs in the capture.
    scrubbed, hits = _scrub_measurements(payload["measurements"], scrub=not no_scrub)
    if no_scrub:
        if hits and not allow_public_ips:
            for h in hits:
                print(f"  would leak: {h}", file=sys.stderr)
            print("error: --no-scrub would write public IP(s); re-run with --allow-public-ips "
                  "only if you have confirmed the fixture leaks nothing identifying.", file=sys.stderr)
            sys.exit(5)
    else:
        payload["measurements"] = scrubbed
        for h in hits:
            print(f"  scrubbed: {h} -> {_SCRUB_PLACEHOLDER}", file=sys.stderr)

    fixture_path = Path("tests/fixtures") / f"{name}.json"
    fixture_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # Round-trip validation: the signals block must reconstruct the snapshot.
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    reloaded = SignalSnapshot(**data["signals"])
    if reloaded != snap:
        fixture_path.unlink(missing_ok=True)
        print("error: fixture round-trip validation failed", file=sys.stderr)
        sys.exit(4)

    print(f"captured fixture: {fixture_path}")


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "roadmap":
        _print_roadmap()
        return
    if args.command == "config":
        _print_config()
        return
    if args.command == "diagnose":
        history = args.history
        if history is None and not args.target:
            print("error: target is required unless --history is used", file=sys.stderr)
            sys.exit(2)
        _print_diagnose(
            target=args.target or "",
            as_json=args.as_json,
            history=history,
            skip_path=args.no_path,
            vantage_url=args.vantage,
            skip_captive=args.no_captive,
        )
        return
    if args.command == "escalate":
        _escalate(args.run_uuid, copy=args.copy, output=args.output, no_file=args.no_file,
                  export=args.export, scrub=args.scrub)
        return
    if args.command == "ui":
        from boundary_probe.ui import launch_server
        launch_server(port=args.port, open_browser=not args.no_open)
        return
    if args.command == "watch":
        from boundary_probe.watch import run_watch
        try:
            parsed = parse_target(args.target)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)
        run_watch(parsed, interval_s=args.interval, skip_path=args.no_path, max_polls=args.count)
        return
    if args.command == "capture":
        _print_capture(
            args.name, args.target, args.no_path,
            expected_boundary=args.expected_boundary,
            capture_method=args.capture_method,
            no_scrub=args.no_scrub,
            allow_public_ips=args.allow_public_ips,
        )
        return
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
