"""Captive-portal detection via a known-content connectivity check.

A captive portal (hotel/airport/café wifi, or an intercepting proxy) hijacks DNS
and HTTP, so the gateway forwards, DNS "resolves", and ICMP to public IPs may
even succeed — every signal the other collectors read goes green, and the engine
would call a hijacked network ``healthy``. This collector closes that hole the
same way every OS does: fetch a URL whose response is known in advance (an empty
HTTP 204) and check the answer is exactly that.

- 204 + empty body  -> clean internet (no portal).
- a redirect, or a 200 with a body where 204 was expected -> portal intercepted.
- request error (timeout / connection refused / DNS failure) -> NOT a portal
  (there may simply be no internet); leave classification to the other signals.

The check uses HTTP on purpose — portals intercept clear HTTP and redirect to
their sign-in page; an HTTPS request would just fail the TLS handshake and tell
us nothing. No user data is sent (a fixed public endpoint), so unlike the remote
vantage this runs by default. Redirects are not followed (the redirect itself is
the signal) and the body read is byte-capped.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

_MAX_BODY_BYTES = 4096
_USER_AGENT = "boundary-probe"
# Google's Android connectivity-check endpoint: returns 204 No Content when the
# path to the internet is clean. Widely reachable and stable; overridable in config.
DEFAULT_CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"

# (status, body_len) — the seam a test injects to avoid real network.
FetchFn = Callable[[str, float], "tuple[int, int]"]


@dataclass(slots=True, frozen=True)
class CaptivePortalSlice:
    checked: bool          # did the connectivity check complete (clean OR portal)?
    portal_detected: bool  # was traffic intercepted?
    note: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Don't follow redirects — a redirect to a sign-in page IS the portal signal."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _default_fetch(url: str, timeout_s: float) -> tuple[int, int]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": _USER_AGENT})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=timeout_s) as resp:
            body = resp.read(_MAX_BODY_BYTES + 1)
            return getattr(resp, "status", 200), len(body)
    except urllib.error.HTTPError as exc:
        # A 3xx surfaces here because redirects are refused; 4xx/5xx also. The
        # status is what matters; body length is irrelevant for these.
        return exc.code, 0


def collect_captive_portal(
    check_url: str = DEFAULT_CHECK_URL,
    timeout_s: float = 4.0,
    *,
    fetch_fn: FetchFn = _default_fetch,
) -> CaptivePortalSlice:
    """Run the connectivity check. Never raises (fail-open)."""
    if not check_url:
        return CaptivePortalSlice(checked=False, portal_detected=False, note="captive check disabled")
    try:
        status, body_len = fetch_fn(check_url, timeout_s)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # No response at all — could be a dead connection, not a portal. Do not
        # accuse a portal; let the other signals classify.
        return CaptivePortalSlice(checked=False, portal_detected=False, note=f"check failed: {exc}")

    if status == 204 and body_len == 0:
        return CaptivePortalSlice(checked=True, portal_detected=False, note="")
    # Anything else for a generate_204 endpoint — a redirect (3xx), or a 200 with
    # a body — means something answered in the portal's place.
    return CaptivePortalSlice(
        checked=True, portal_detected=True,
        note=f"connectivity check returned HTTP {status} ({body_len} body bytes), expected empty 204",
    )
