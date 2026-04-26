from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from boundary_probe.engine import demo_signals, diagnose
from boundary_probe.targets import parse_target

_KNOWN_SCENARIOS = {"router-down", "dns-failure", "isp-path", "remote-service"}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="boundary-probe")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("roadmap", help="Print the current implementation sequence.")

    diagnose_parser = subparsers.add_parser(
        "diagnose",
        help="Diagnose a target (hostname, IP, or URL). Phase 0 returns a demo result; real collectors land in Phase 1.",
    )
    diagnose_parser.add_argument("target", help="Target to diagnose: hostname, IPv4 address, or URL.")
    diagnose_parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output.")

    capture_parser = subparsers.add_parser(
        "capture",
        help="Capture a normalized SignalSnapshot fixture for testing. Stub in Phase 0.",
    )
    capture_parser.add_argument("name", help="Name for the captured fixture.")

    return parser


def _print_roadmap() -> None:
    print("Boundary Probe roadmap:")
    print("1. Normalize local diagnostics into stable signal models.")
    print("2. Expand the deterministic rules for router, DNS, ISP, and remote-service boundaries.")
    print("3. Capture real-world fixtures and calibrate confidence from repeated evidence.")
    print("4. Add optional saved runs and a local UI after the rules are trustworthy.")


def _print_diagnose(target: str, as_json: bool) -> None:
    try:
        parsed = parse_target(target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)

    scenario = parsed.host if parsed.host in _KNOWN_SCENARIOS else "remote-service"
    if parsed.host not in _KNOWN_SCENARIOS:
        print(f"# Phase 0: real collectors not implemented. Returning placeholder diagnosis.")

    diagnosis = diagnose(demo_signals(scenario))
    payload = asdict(diagnosis)

    if as_json:
        print(json.dumps(payload, indent=2))
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


def _print_capture(name: str) -> None:
    print(f"capture not yet implemented (would have captured fixture '{name}')")


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "roadmap":
        _print_roadmap()
        return
    if args.command == "diagnose":
        _print_diagnose(args.target, args.as_json)
        return
    if args.command == "capture":
        _print_capture(args.name)
        return
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
