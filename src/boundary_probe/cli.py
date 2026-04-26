from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from boundary_probe.collectors import collect_signals
from boundary_probe.engine import diagnose
from boundary_probe.store import connect, fetch_recent, insert_run
from boundary_probe.targets import parse_target


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="boundary-probe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("roadmap", help="Print the current implementation sequence.")

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

    capture_parser = subparsers.add_parser(
        "capture",
        help="Capture a SignalSnapshot fixture from a live run.",
    )
    capture_parser.add_argument("name", help="Name for the captured fixture.")
    capture_parser.add_argument("--target", required=True, help="Target to probe for the fixture.")
    capture_parser.add_argument("--no-path", action="store_true", dest="no_path",
                                help="Skip tracert.")

    return parser


def _print_roadmap() -> None:
    print("Boundary Probe roadmap:")
    print("1. Normalize local diagnostics into stable signal models.")
    print("2. Expand the deterministic rules for router, DNS, ISP, and remote-service boundaries.")
    print("3. Capture real-world fixtures and calibrate confidence from repeated evidence.")
    print("4. Add optional saved runs and a local UI after the rules are trustworthy.")


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


def _print_diagnose(target: str, as_json: bool, history: int | None, skip_path: bool) -> None:
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
        result = collect_signals(parsed, skip_path=skip_path)
    except FileNotFoundError as exc:
        print(f"error: required Windows tool not found ({exc}).", file=sys.stderr)
        sys.exit(3)

    diagnosis = diagnose(result.snapshot)

    with connect() as conn:
        run_uuid = insert_run(
            conn,
            parsed_target=parsed,
            snapshot=result.snapshot,
            diagnosis=diagnosis,
            collection_result=result,
        )

    if as_json:
        print(json.dumps({**asdict(diagnosis), "run_uuid": run_uuid}, indent=2))
        return

    print(f"Target:     {parsed.raw} ({parsed.kind})")
    print(f"Boundary:   {diagnosis.boundary}")
    print(f"Confidence: {diagnosis.confidence:.2f}")
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
    print(f"Run saved: {run_uuid}")


def _print_capture(name: str, target: str, skip_path: bool) -> None:
    try:
        parsed = parse_target(target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        result = collect_signals(parsed, skip_path=skip_path)
    except FileNotFoundError as exc:
        print(f"error: required Windows tool not found ({exc}).", file=sys.stderr)
        sys.exit(3)

    snap = result.snapshot
    payload = {
        "scenario": name,
        "gateway_reachable": snap.gateway_reachable,
        "dns_ok": snap.dns_ok,
        "ip_connectivity_ok": snap.ip_connectivity_ok,
        "control_hosts_ok": snap.control_hosts_ok,
        "target_service_ok": snap.target_service_ok,
        "packet_loss_after_hop1": snap.packet_loss_after_hop1,
        "packet_loss_multiple_targets": snap.packet_loss_multiple_targets,
    }

    fixture_path = Path("tests/fixtures") / f"{name}.json"
    fixture_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # Round-trip validation
    import json as _json
    data = _json.loads(fixture_path.read_text(encoding="utf-8"))
    data.pop("scenario", None)
    from boundary_probe.models import SignalSnapshot
    reloaded = SignalSnapshot(**data)
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
        )
        return
    if args.command == "capture":
        _print_capture(args.name, args.target, args.no_path)
        return
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
