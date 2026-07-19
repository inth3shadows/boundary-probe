"""Support-bundle export: one self-describing JSON document per saved run.

A user attaches this to a support ticket. It carries everything the CLI knows
about a run — target, signal snapshot, diagnosis, raw collector measurements,
and the rendered escalation report — so the recipient can act on it without
asking the user to re-run anything.

Two deliberate contracts make it an artifact rather than a dump:

* ``bundle_version`` plus the producing tool's version, so a consumer can key
  off the schema instead of guessing at it when the shape changes.
* ``integrity.payload_sha256``, computed over the canonical serialization of
  the document *with the ``integrity`` key absent*, so a recipient can confirm
  the bundle was forwarded unedited. Recompute by deleting ``integrity``,
  re-serializing with ``sort_keys=True`` and ``(",", ":")`` separators, and
  hashing the UTF-8 bytes.

Redaction default is the inverse of ``capture``'s: see ``build_bundle``.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import ipaddress
import json
import sqlite3

from boundary_probe import __version__

BUNDLE_VERSION = 1

SCRUB_PLACEHOLDER = "<scrubbed-public-ip>"

_CANONICAL = {"sort_keys": True, "separators": (",", ":")}


def is_public_ip(value: object) -> bool:
    """True if ``value`` is a globally-routable IP (the kind that leaks a location).

    Private/CGNAT/loopback/link-local (RFC1918, 100.64/10, 127/8, the WSL2 172.31.x
    NAT) are non-identifying and kept. Non-IP strings ("*", a hostname) return False.
    """
    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def scrub_measurements(measurements: dict, *, scrub: bool) -> tuple[dict, list[str]]:
    """Redact public IPs from a ``measurements`` block before it is written.

    With ``scrub=True`` the public IPs in traceroute hops and the gateway address
    are replaced with a placeholder and the redactions are returned. With
    ``scrub=False`` nothing is changed and the returned list reports the public IPs
    that were *found*, so the caller can warn about them (support bundle) or refuse
    to write them (public-repo fixture capture). See issues #11 and #17.

    Resolved target addresses and the canary IP are intentionally left alone: they
    identify the *destination*, not the reporting user's location.
    """
    out = copy.deepcopy(measurements)
    hits: list[str] = []

    gw = out.get("gateway")
    if isinstance(gw, dict) and is_public_ip(gw.get("gateway_ip")):
        hits.append(f"gateway.gateway_ip={gw['gateway_ip']}")
        if scrub:
            gw["gateway_ip"] = SCRUB_PLACEHOLDER

    for key in ("path_primary", "path_secondary"):
        slice_ = out.get(key)
        if not isinstance(slice_, dict):
            continue
        for hop in slice_.get("raw_hops", []):
            if isinstance(hop, dict) and is_public_ip(hop.get("host")):
                hits.append(f"{key}.hop[{hop.get('index')}].host={hop['host']}")
                if scrub:
                    hop["host"] = SCRUB_PLACEHOLDER

    return out, hits


def _measurements_from_row(row: sqlite3.Row) -> dict:
    """Rebuild the collector measurements from a stored run row.

    Shaped to match ``capture``'s ``measurements`` block — same keys, same
    ``path_*.raw_hops`` nesting — so ``scrub_measurements`` and any downstream
    consumer treat a bundle and a fixture identically.
    """
    secondary = row["path_secondary_json"]
    return {
        "gateway": {
            "gateway_ip": row["gateway_ip"],
            "reachable": bool(row["gateway_reachable"]),
            "rtt_ms": row["gateway_rtt_ms"],
        },
        "dns": {
            "ok": bool(row["dns_ok"]),
            "resolved_ips": json.loads(row["dns_resolved_ips_json"]),
            "elapsed_ms": row["dns_elapsed_ms"],
        },
        "ip_connectivity": {
            "target_ip": row["ip_target"],
            "loss_pct": row["ip_loss_pct"],
            "avg_rtt_ms": row["ip_avg_rtt_ms"],
        },
        "control_hosts": json.loads(row["controls_json"]),
        "target_service": {
            "ok": bool(row["target_service_ok"]),
            "method": row["target_method"],
            "elapsed_ms": row["target_elapsed_ms"],
        },
        "path_primary": {"raw_hops": json.loads(row["path_primary_json"])},
        "path_secondary": {"raw_hops": json.loads(secondary)} if secondary else None,
    }


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_bundle(row: sqlite3.Row, report_text: str, *, scrub: bool = False) -> tuple[dict, list[str]]:
    """Build the support bundle for a saved run.

    Returns ``(bundle, hits)``. ``hits`` lists the public IPs found — redacted when
    ``scrub=True``, otherwise still present in the document and reported so the
    caller can warn.

    ``scrub`` defaults to False, the inverse of ``capture``'s default, because the
    recipient here is a support desk rather than a public repository: the public
    traceroute path *is* the evidence for an ``isp-upstream`` verdict, and a bundle
    with it redacted is one the ISP cannot act on.
    """
    measurements, hits = scrub_measurements(_measurements_from_row(row), scrub=scrub)

    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "tool": {"name": "boundary-probe", "version": __version__},
        "generated_at": _utc_now(),
        "run": {
            "uuid": row["run_uuid"],
            "started_at": row["started_at"],
            "duration_ms": row["duration_ms"],
        },
        "target": {
            "raw": row["target_raw"],
            "kind": row["target_kind"],
            "host": row["target_host"],
            "port": row["target_port"],
            "scheme": row["target_scheme"],
        },
        "diagnosis": {
            "boundary": row["boundary"],
            # A signal-isolation prior, not a measured success rate — named here
            # the way the rendered report names it so the two cannot be read
            # as different numbers.
            "confidence_prior": row["confidence_float"],
            "confidence_band": row["confidence_band"],
            "summary": row["summary"],
            "evidence": json.loads(row["evidence_json"]),
            "remediation": json.loads(row["remediation_json"]),
        },
        "signals": {
            "gateway_reachable": bool(row["gateway_reachable"]),
            "dns_ok": bool(row["dns_ok"]),
            "ip_connectivity_ok": bool(row["ip_connectivity_ok"]),
            "control_hosts_ok": bool(row["control_hosts_ok"]),
            "target_service_ok": bool(row["target_service_ok"]),
            "default_route_present": bool(row["default_route_present"]),
            "packet_loss_after_hop1": bool(row["packet_loss_after_hop1"]),
            "packet_loss_multiple_targets": bool(row["packet_loss_multiple_targets"]),
        },
        "measurements": measurements,
        "collector_notes": json.loads(row["collector_notes_json"]),
        "redacted": bool(scrub and hits),
        "report_text": report_text,
    }
    bundle["integrity"] = {
        "algorithm": "sha256",
        "payload_sha256": payload_sha256(bundle),
    }
    return bundle, hits


def payload_sha256(bundle: dict) -> str:
    """Hash a bundle's canonical serialization, ignoring any ``integrity`` key.

    Verification and generation share this function so the two can never drift.
    """
    payload = {k: v for k, v in bundle.items() if k != "integrity"}
    return hashlib.sha256(json.dumps(payload, **_CANONICAL).encode("utf-8")).hexdigest()


def verify_bundle(bundle: dict) -> bool:
    """True if the bundle's recorded hash matches its current payload."""
    recorded = bundle.get("integrity", {}).get("payload_sha256")
    return bool(recorded) and recorded == payload_sha256(bundle)
