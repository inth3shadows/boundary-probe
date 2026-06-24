"""Shared HTTP primitives for the outbound collectors (vantage, captive-portal).

Both collectors make a single GET with redirects refused — a redirect is itself
a signal (a portal sign-in page; or a back-door SSRF for the vantage), never
something to follow. Centralised so the redirect/UA behaviour is fixed in one
place. Stdlib only — the project ships no HTTP dependency.
"""
from __future__ import annotations

import http.client
import socket
import urllib.error
import urllib.request

USER_AGENT = "boundary-probe"

# Exceptions a fail-open outbound probe must swallow: transport errors
# (URLError/HTTPError/timeout/OSError), malformed HTTP that urllib surfaces as
# http.client.HTTPException (BadStatusLine, IncompleteRead, LineTooLong — NOT
# subclasses of OSError), and decode/parse errors (ValueError).
FETCH_ERRORS: tuple[type[BaseException], ...] = (
    urllib.error.HTTPError,
    urllib.error.URLError,
    http.client.HTTPException,
    socket.timeout,
    TimeoutError,
    OSError,
    ValueError,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow any redirect — the redirect itself is the signal."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def no_redirect_opener() -> urllib.request.OpenerDirector:
    """An opener that raises HTTPError on 3xx instead of following it."""
    return urllib.request.build_opener(_NoRedirect())
