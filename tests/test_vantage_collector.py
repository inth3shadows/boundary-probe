"""The vantage collector — fail-open across every error class, no real network.

Every failure mode (timeout, conn refused, non-200, non-JSON, oversized, bad
schema, http://) must degrade to a not-consulted VantageSlice so the diagnosis
proceeds unchanged. Tests inject a fake fetch_fn via the DI seam — no sockets.
"""

from __future__ import annotations

import json
import socket
import urllib.error

import pytest

from boundary_probe.collectors.vantage import apply_vantage, collect_vantage
from boundary_probe.models import Diagnosis


def _fetch_ok(reachable: bool, *, latency=None, ctype="application/json"):
    payload = {"reachable": reachable}
    if latency is not None:
        payload["latency_ms"] = latency
    body = json.dumps(payload).encode("utf-8")

    def _fetch(url, timeout_s):
        return 200, ctype, body
    return _fetch


def _fetch_raises(exc):
    def _fetch(url, timeout_s):
        raise exc
    return _fetch


def test_consulted_true_when_reachable():
    s = collect_vantage("https://v.example/check", "example.com", 4.0,
                        fetch_fn=_fetch_ok(True, latency=12.5))
    assert s.consulted and s.target_reachable_externally is True
    assert s.latency_ms == 12.5


def test_consulted_false_when_unreachable():
    s = collect_vantage("https://v.example/check", "example.com", 4.0,
                        fetch_fn=_fetch_ok(False))
    assert s.consulted and s.target_reachable_externally is False
    assert s.latency_ms is None


def test_http_scheme_rejected():
    # never consulted; the call must not even build a request
    called = []

    def _fetch(url, timeout_s):
        called.append(url)
        return 200, "application/json", b'{"reachable": true}'
    s = collect_vantage("http://v.example/check", "example.com", 4.0, fetch_fn=_fetch)
    assert not s.consulted and s.target_reachable_externally is None
    assert called == []  # short-circuited before any fetch


@pytest.mark.parametrize("exc", [
    urllib.error.URLError("conn refused"),
    socket.timeout("timed out"),
    TimeoutError("timed out"),
    OSError("network unreachable"),
    urllib.error.HTTPError("https://v.example", 503, "err", {}, None),
])
def test_fail_open_on_network_errors(exc):
    s = collect_vantage("https://v.example/check", "example.com", 4.0,
                        fetch_fn=_fetch_raises(exc))
    assert not s.consulted and s.target_reachable_externally is None


def test_fail_open_on_non_200():
    s = collect_vantage("https://v.example/check", "example.com", 4.0,
                        fetch_fn=lambda u, t: (500, "application/json", b"{}"))
    assert not s.consulted and "HTTP 500" in s.note


def test_fail_open_on_non_json_content_type():
    s = collect_vantage("https://v.example/check", "example.com", 4.0,
                        fetch_fn=lambda u, t: (200, "text/html", b"<html>"))
    assert not s.consulted and "not JSON" in s.note


def test_fail_open_on_garbage_body():
    s = collect_vantage("https://v.example/check", "example.com", 4.0,
                        fetch_fn=lambda u, t: (200, "application/json", b"not json{"))
    assert not s.consulted


def test_fail_open_on_oversized_body():
    big = b'{"reachable": true, "pad": "' + b"x" * (64 * 1024 + 10) + b'"}'
    s = collect_vantage("https://v.example/check", "example.com", 4.0,
                        fetch_fn=lambda u, t: (200, "application/json", big))
    assert not s.consulted and "too large" in s.note


def test_fail_open_on_missing_or_non_bool_reachable():
    s = collect_vantage("https://v.example/check", "example.com", 4.0,
                        fetch_fn=lambda u, t: (200, "application/json", b'{"reachable": "yes"}'))
    assert not s.consulted and "reachable" in s.note


def test_target_is_sent_as_query_param():
    seen = {}

    def _fetch(url, timeout_s):
        seen["url"] = url
        return 200, "application/json", b'{"reachable": true}'
    collect_vantage("https://v.example/check", "example.com:443", 4.0, fetch_fn=_fetch)
    assert "target=example.com" in seen["url"] and "443" in seen["url"]


# --- apply_vantage orchestration -------------------------------------------

def _diag(boundary):
    return Diagnosis(boundary=boundary, confidence=0.95, summary="s")


def test_apply_vantage_skips_when_no_url():
    d = _diag("remote-service")
    out, slice_ = apply_vantage(d, "example.com", None, 4.0)
    assert out is d and slice_ is None


def test_apply_vantage_skips_non_refinable_boundary():
    d = _diag("dns")
    called = []
    out, slice_ = apply_vantage(d, "example.com", "https://v.example", 4.0,
                                fetch_fn=lambda u, t: called.append(u))
    assert out is d and slice_ is None and called == []


def test_apply_vantage_refines_remote_service():
    d = _diag("remote-service")
    out, slice_ = apply_vantage(d, "example.com", "https://v.example", 4.0,
                                fetch_fn=_fetch_ok(False))
    assert slice_ is not None and slice_.consulted
    assert out.confidence > 0.95  # confirmed down -> higher confidence


@pytest.mark.integration
def test_default_fetch_real_https():
    # Exercises the real urllib path (TLS verify + GET + no-redirect handling).
    # example.com returns HTML, so collect_vantage degrades to not-consulted —
    # but the fetch itself must succeed end-to-end over real https.
    from boundary_probe.collectors.vantage import _default_fetch
    status, ctype, body = _default_fetch("https://example.com", 10.0)
    assert status == 200 and isinstance(body, bytes) and body
