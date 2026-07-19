"""Support-bundle export: one self-describing JSON document per saved run.

A user attaches this to a support ticket. It carries everything the CLI knows
about a run — target, signal snapshot, diagnosis, raw collector measurements,
and the rendered escalation report — so the recipient can act on it without
asking the user to re-run anything.

Two deliberate contracts make it an artifact rather than a dump:

* ``bundle_version`` plus the producing tool's version, so a consumer can key
  off the schema instead of guessing at it when the shape changes.
* ``integrity.payload_sha256``, computed over the canonical serialization of
  the document *with the ``integrity`` key absent*, so a recipient can detect
  corruption or truncation in transit. Recompute by deleting ``integrity``,
  re-serializing with ``sort_keys=True``, ``(",", ":")`` separators and
  ``ensure_ascii=True``, and hashing the UTF-8 bytes. This is an unkeyed digest
  and the tool that computes it ships with the bundle, so it detects damage, not
  deliberate editing by someone who wants the hash to agree.

Redaction default is the inverse of ``capture``'s: see ``build_bundle``.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import ipaddress
import json
import re
import sqlite3

from boundary_probe import __version__

BUNDLE_VERSION = 1

SCRUB_PLACEHOLDER = "<scrubbed-public-ip>"

# `ensure_ascii` is pinned rather than left to the default because it is part of
# the published hash contract: `report_text` always contains an em dash, so a
# verifier that serializes with ensure_ascii=False computes a different digest
# for a byte-identical bundle. See the module docstring.
_CANONICAL = {"sort_keys": True, "separators": (",", ":"), "ensure_ascii": True}


def is_public_ip(value: object) -> bool:
    """True if ``value`` is a globally-routable IP (the kind that leaks a location).

    Private/CGNAT/loopback/link-local (RFC1918, 100.64/10, 127/8, the WSL2 172.31.x
    NAT) are non-identifying and kept. Non-IP strings ("*", a hostname) return False.
    """
    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def public_ips_in(value: object) -> list[str]:
    """Every globally-routable IPv4 address appearing anywhere in ``value``.

    A bare address is the common case, but a hop host can be a composite such as
    ``cpe-1-2-3-4.example.net [1.2.3.4]`` and a collector note embeds addresses in
    prose ("ping to 1.2.3.4 timed out"). Matching on substrings rather than
    parsing the whole field is what lets redaction reach both.
    """
    return [m for m in _IPV4_RE.findall(str(value)) if is_public_ip(m)]


def _redact_in_text(text: str, ips: list[str]) -> str:
    """Replace each address in ``ips`` wherever it appears in ``text``.

    Dotted form and the dash-separated form an ISP bakes into a reverse-DNS name
    (``cpe-1-2-3-4.example.net``) are both replaced: the PTR spells out the same
    address, so redacting only the dotted form leaves it legible.
    """
    for ip in ips:
        text = text.replace(ip, SCRUB_PLACEHOLDER).replace(ip.replace(".", "-"), SCRUB_PLACEHOLDER)
    return text


def redact_everywhere(obj, ips: list[str]):
    """Recursively replace ``ips`` in every string reachable from ``obj``.

    The bundle carries the same address in several shapes — a structured field, a
    prose collector note, and the pre-rendered report text. Redacting only the
    structured field is what made ``--scrub`` claim more than it delivered, so the
    pass walks the whole document instead of an allowlist of keys.
    """
    if not ips:
        return obj
    if isinstance(obj, str):
        return _redact_in_text(obj, ips)
    if isinstance(obj, dict):
        return {k: redact_everywhere(v, ips) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_everywhere(v, ips) for v in obj]
    return obj


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
    if isinstance(gw, dict) and public_ips_in(gw.get("gateway_ip")):
        hits.append(f"gateway.gateway_ip={gw['gateway_ip']}")
        if scrub:
            gw["gateway_ip"] = SCRUB_PLACEHOLDER

    for key in ("path_primary", "path_secondary"):
        slice_ = out.get(key)
        if not isinstance(slice_, dict):
            continue
        for hop in slice_.get("raw_hops", []):
            # `public_ips_in` rather than `is_public_ip`: a host may be a
            # `name [1.2.3.4]` composite (Windows tracert without -d, and any
            # fixture captured before that was normalized away), which does not
            # parse as an address but still exposes one. The whole field goes,
            # since a reverse-DNS name spells the address out anyway.
            if isinstance(hop, dict) and public_ips_in(hop.get("host")):
                hits.append(f"{key}.hop[{hop.get('index')}].host={hop['host']}")
                if scrub:
                    hop["host"] = SCRUB_PLACEHOLDER

    return out, hits


def _measurements_from_row(row: sqlite3.Row) -> dict:
    """Rebuild the collector measurements from a stored run row.

    Top-level keys and the ``path_*.raw_hops`` nesting match ``capture``'s
    ``measurements`` block, which is what lets ``scrub_measurements`` walk both.
    The blocks are *not* otherwise interchangeable, because this is rebuilt from
    stored columns rather than from the live collector slices: ``control_hosts``
    is the results list here and a slice dict in a fixture, and the fields the
    schema does not persist (``path_*.completed``, ``dns.resolver_used``,
    ``target_service.target_host``) are absent. Widening the bundle means
    widening the ``runs`` table first.
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

    When ``scrub`` is set the addresses found in the gateway and traceroute fields
    are redacted from the *whole* document, not just from those fields — they also
    appear in the prose collector notes and in the pre-rendered ``report_text``,
    and a redaction that leaves them there is worse than none, because the bundle
    still says it was redacted. Addresses that identify the *destination* rather
    than the reporting user (resolved target addresses, the canary, control hosts)
    are deliberately left alone.
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

    if scrub:
        # Second pass over the assembled document. `measurements` is already
        # redacted; this catches the same addresses where they were re-rendered
        # into prose — `collector_notes` ("ping to 1.2.3.4 timed out") and
        # `report_text` ("Gateway: 1.2.3.4 — reachable"). The hash below is taken
        # after this, so a scrubbed bundle still verifies.
        leaked = sorted({ip for h in hits for ip in public_ips_in(h)})
        bundle = redact_everywhere(bundle, leaked)

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
    """True if the bundle's recorded hash matches its current payload.

    Tolerates a malformed ``integrity`` block by returning False: a truncated or
    hand-mangled bundle is exactly what this is meant to catch, so it must not
    raise on one.
    """
    integrity = bundle.get("integrity")
    if not isinstance(integrity, dict):
        return False
    recorded = integrity.get("payload_sha256")
    return bool(recorded) and recorded == payload_sha256(bundle)
