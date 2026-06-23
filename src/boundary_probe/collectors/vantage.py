"""Optional external-vantage reachability probe.

Asks a USER-CONFIGURED endpoint "can you reach <target>?" so the engine can tell
"the target is down for everyone" from "just this connection's path." Strictly
opt-in (no `vantage_url` → never called) and fail-open (any error → not
consulted, diagnosis proceeds unchanged).

Security floor (single-user local CLI; the URL is operator-supplied config, not
attacker input — so an internal/RFC-1918 destination is intentional, e.g. a
homelab over Cloudflare Tunnel):
  - https only (the target travels off-box; never in cleartext);
  - TLS verification on, no opt-out (urllib's default context verifies);
  - redirects are NOT followed (a redirect is the back-door into metadata IPs);
  - the response body is byte-capped before parse and must be JSON;
  - ONLY the target string is sent — never history, gateway IPs, or local config.

Contract (deliberately trivial to implement behind any reverse proxy):
    GET <vantage_url>?target=<host[:port]>  ->  {"reachable": <bool>, ...}
``reachable`` is the only load-bearing field; ``latency_ms`` is used if present.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

from boundary_probe.engine import _VANTAGE_REFINABLE, refine
from boundary_probe.models import Diagnosis, VantageSlice

_MAX_RESPONSE_BYTES = 64 * 1024
_USER_AGENT = "boundary-probe"

# (status, content_type, body) — the seam a test injects to avoid real network.
FetchFn = Callable[[str, float], "tuple[int, str, bytes]"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any redirect — closes the metadata-endpoint pivot."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _default_fetch(url: str, timeout_s: float) -> tuple[int, str, bytes]:
    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": _USER_AGENT, "Accept": "application/json"}
    )
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(req, timeout=timeout_s) as resp:  # default TLS context verifies certs
        ctype = resp.headers.get("Content-Type", "")
        body = resp.read(_MAX_RESPONSE_BYTES + 1)
        return getattr(resp, "status", 200), ctype, body


def collect_vantage(
    vantage_url: str,
    target: str,
    timeout_s: float,
    *,
    fetch_fn: FetchFn = _default_fetch,
) -> VantageSlice:
    """Probe ``target`` reachability via ``vantage_url``. Never raises (fail-open)."""
    parts = urllib.parse.urlsplit(vantage_url)
    if parts.scheme != "https":
        return VantageSlice(False, None, "vantage url must be https")

    query = urllib.parse.urlencode({"target": target})
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))

    try:
        status, ctype, body = fetch_fn(url, timeout_s)
    except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout,
            TimeoutError, OSError, ValueError) as exc:
        return VantageSlice(False, None, f"vantage unreachable: {exc}")

    if status != 200:
        return VantageSlice(False, None, f"vantage returned HTTP {status}")
    if len(body) > _MAX_RESPONSE_BYTES:
        return VantageSlice(False, None, "vantage response too large")
    if "application/json" not in ctype.lower():
        return VantageSlice(False, None, "vantage response was not JSON")

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return VantageSlice(False, None, "vantage response was not parseable JSON")

    reachable = data.get("reachable") if isinstance(data, dict) else None
    if not isinstance(reachable, bool):
        return VantageSlice(False, None, "vantage response missing boolean 'reachable'")

    raw_latency = data.get("latency_ms") if isinstance(data, dict) else None
    latency = float(raw_latency) if isinstance(raw_latency, (int, float)) else None
    return VantageSlice(True, reachable, "", latency)


def apply_vantage(
    diagnosis: Diagnosis,
    target: str,
    vantage_url: str | None,
    timeout_s: float,
    *,
    fetch_fn: FetchFn = _default_fetch,
) -> tuple[Diagnosis, VantageSlice | None]:
    """Conditionally consult the vantage and fold it into the diagnosis.

    Only runs when a vantage is configured AND the base boundary is one a vantage
    can disambiguate — saves the latency on healthy/dns/router verdicts. Returns
    the (possibly refined) diagnosis and the VantageSlice (or None if not
    consulted) so callers can surface what happened.
    """
    if not vantage_url or diagnosis.boundary not in _VANTAGE_REFINABLE:
        return diagnosis, None
    slice_ = collect_vantage(vantage_url, target, timeout_s, fetch_fn=fetch_fn)
    return refine(diagnosis, slice_), slice_
