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
import urllib.parse
import urllib.request
from collections.abc import Callable

from boundary_probe.collectors._http import FETCH_ERRORS, USER_AGENT, no_redirect_opener
from boundary_probe.engine import _VANTAGE_REFINABLE, refine
from boundary_probe.models import Diagnosis, VantageSlice

_MAX_RESPONSE_BYTES = 64 * 1024

# (status, content_type, body) — the seam a test injects to avoid real network.
FetchFn = Callable[[str, float], "tuple[int, str, bytes]"]


def _default_fetch(url: str, timeout_s: float) -> tuple[int, str, bytes]:
    req = urllib.request.Request(
        url, method="GET", headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    with no_redirect_opener().open(req, timeout=timeout_s) as resp:  # default TLS context verifies certs
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

    # Preserve any query already on the configured URL (e.g. an auth token) and
    # append the target rather than overwriting it.
    params = urllib.parse.parse_qsl(parts.query)
    params.append(("target", target))
    query = urllib.parse.urlencode(params)
    url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))

    try:
        status, ctype, body = fetch_fn(url, timeout_s)
    except FETCH_ERRORS as exc:
        return VantageSlice(False, None, f"vantage unreachable: {exc}")

    # The real _default_fetch never reaches here for a non-2xx response — urllib
    # raises HTTPError (caught above) — so this primarily guards injected
    # fetch_fns in tests; it is cheap insurance either way.
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
    # bool is a subclass of int — exclude it so a JSON `true` isn't read as 1.0ms.
    latency = (float(raw_latency)
               if isinstance(raw_latency, (int, float)) and not isinstance(raw_latency, bool)
               else None)
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
