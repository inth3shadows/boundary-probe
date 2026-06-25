from __future__ import annotations

import socket
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from boundary_probe.collectors._commands import ping_cmd
from boundary_probe.collectors._http import FETCH_ERRORS, USER_AGENT, no_redirect_opener
from boundary_probe.collectors._parsers import parse_ping_output
from boundary_probe.collectors._runner import DefaultRunner, SubprocessRunner
from boundary_probe.config import ProbeConfig, load_config
from boundary_probe.targets import ParsedTarget

_SCHEME_PORTS = {"http": 80, "https": 443}
_MAX_BODY_BYTES = 4096  # we key on the status line, not the body; drain a little and stop

# (url, timeout_s, verify_tls) -> HTTP status code. The seam a test injects to
# avoid real network. Transport failures (TLS/conn/timeout) raise FETCH_ERRORS.
HttpFetchFn = Callable[[str, float, bool], int]


@dataclass(slots=True, frozen=True)
class TargetServiceSlice:
    ok: bool
    method: str
    target_host: str
    target_port: int | None
    elapsed_ms: int
    note: str
    http_status: int | None = None  # set only for the L7 (http/https) method


def collect_target_service(
    parsed_target: ParsedTarget,
    runner: SubprocessRunner | None = None,
    *,
    cfg: ProbeConfig | None = None,
    loss_pct_threshold: float | None = None,
    timeout_s: float | None = None,
    tcp_timeout_s: float | None = None,
    http_timeout_s: float | None = None,
    http_fetch_fn: HttpFetchFn | None = None,
) -> TargetServiceSlice:
    """Probe the target: L7 HTTP check for http/https URLs, TCP connect for any
    other explicit port, ping for a bare host.

    The L7 check exists because a TCP handshake is not service health: a 503, a
    hung origin, or an expired TLS cert all answer the connect yet are 'down' to
    a user. For web schemes we read the HTTP status (5xx / TLS-fail = down; 2xx,
    3xx, 4xx = up — a 4xx means the origin is responding, which is not a network
    boundary). See docs/CALIBRATION.md / the engine remote-service rule.
    """
    cfg = cfg if cfg is not None else load_config()
    port: int | None = parsed_target.port

    if parsed_target.scheme in _SCHEME_PORTS:
        _http_t = http_timeout_s if http_timeout_s is not None else cfg.target_http_s
        # Probe the path the user gave, not the bare root — else a 200 at "/"
        # masks a 503 at "/v2/health" (the same false-up this check exists to
        # kill). Take path+query from the raw URL; the netloc is rebuilt from the
        # validated host below, so a userinfo/host trick in raw cannot leak through.
        split = urlsplit(parsed_target.raw)
        path_q = split.path or "/"
        if split.query:
            path_q = f"{path_q}?{split.query}"
        return _http_check(
            parsed_target.host, port, parsed_target.scheme, _http_t,
            cfg.target_tls_verify, path_q, fetch_fn=http_fetch_fn or _default_http_fetch,
        )

    if port is not None:
        _tcp = tcp_timeout_s if tcp_timeout_s is not None else cfg.target_tcp_s
        return _tcp_connect(parsed_target.host, port, _tcp)

    _loss_pct = loss_pct_threshold if loss_pct_threshold is not None else cfg.ip_loss_pct
    _timeout = timeout_s if timeout_s is not None else cfg.target_ping_s
    return _ping_host(parsed_target.host, runner or DefaultRunner(), _loss_pct, _timeout)


def _default_http_fetch(url: str, timeout_s: float, verify_tls: bool) -> int:
    """GET ``url`` and return the HTTP status. A 3xx/4xx/5xx comes back as the
    code (no-redirect opener raises HTTPError, which carries it); transport
    failures (TLS verify, connection refused, timeout) propagate as FETCH_ERRORS."""
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with no_redirect_opener(verify_tls=verify_tls).open(req, timeout=timeout_s) as resp:
            resp.read(_MAX_BODY_BYTES)
            return getattr(resp, "status", 200)
    except urllib.error.HTTPError as exc:
        return exc.code


def _http_check(
    host: str,
    port: int | None,
    scheme: str,
    timeout_s: float,
    verify_tls: bool,
    path_q: str = "/",
    *,
    fetch_fn: HttpFetchFn,
) -> TargetServiceSlice:
    default_port = _SCHEME_PORTS[scheme]
    netloc = host if (port is None or port == default_port) else f"{host}:{port}"
    url = f"{scheme}://{netloc}{path_q}"
    shown_port = port if port is not None else default_port

    t0 = time.monotonic()
    try:
        status = fetch_fn(url, timeout_s, verify_tls)
    except FETCH_ERRORS as exc:
        # TLS verification failure, connection refused, or timeout — no HTTP
        # answer at all, so the service is unreachable on this path.
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return TargetServiceSlice(ok=False, method="http", target_host=host,
                                  target_port=shown_port, elapsed_ms=elapsed_ms,
                                  note=f"{scheme} request failed: {exc}", http_status=None)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    ok = status < 500  # 2xx/3xx/4xx up; 5xx down (origin failing)
    note = "" if 200 <= status < 300 else f"HTTP {status} from {host}"
    return TargetServiceSlice(ok=ok, method="http", target_host=host,
                              target_port=shown_port, elapsed_ms=elapsed_ms,
                              note=note, http_status=status)


def _tcp_connect(host: str, port: int, timeout_s: float) -> TargetServiceSlice:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            return TargetServiceSlice(ok=True, method="tcp-connect", target_host=host,
                                      target_port=port, elapsed_ms=elapsed_ms, note="")
    except OSError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return TargetServiceSlice(ok=False, method="tcp-connect", target_host=host,
                                  target_port=port, elapsed_ms=elapsed_ms, note=str(exc))


def _ping_host(host: str, runner: SubprocessRunner, loss_pct_threshold: float, timeout_s: float) -> TargetServiceSlice:
    t0 = time.monotonic()
    result = runner.run(ping_cmd(host, 4, 1000), timeout_s=timeout_s)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    if result.timed_out:
        return TargetServiceSlice(ok=False, method="ping", target_host=host,
                                  target_port=None, elapsed_ms=elapsed_ms,
                                  note=f"ping timed out after {timeout_s:.0f}s")

    stats = parse_ping_output(result.stdout)
    if not stats.parsed:
        # Don't assert a fabricated loss % off output we couldn't read; say so.
        return TargetServiceSlice(ok=False, method="ping", target_host=host,
                                  target_port=None, elapsed_ms=elapsed_ms,
                                  note=f"unrecognized output format from ping to {host}")
    # sent > 0 rejects a degenerate "0 transmitted … 0% loss" summary reading as up.
    ok = stats.sent > 0 and stats.loss_pct < loss_pct_threshold
    return TargetServiceSlice(
        ok=ok,
        method="ping",
        target_host=host,
        target_port=None,
        elapsed_ms=elapsed_ms,
        note="" if ok else f"{stats.loss_pct:.0f}% packet loss pinging {host}",
    )
