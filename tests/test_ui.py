from __future__ import annotations

import http.client
import socket
import threading
import urllib.parse

import pytest

from boundary_probe.engine import diagnose
from boundary_probe.store import connect, insert_run
from boundary_probe.targets import parse_target
from boundary_probe.ui.server import ProbeRequestHandler, ThreadingProbeServer


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def seeded_run(tmp_db, fake_collection_result):
    """Seed one run into the tmp DB; return the run_uuid."""
    parsed = parse_target("example.com")
    result = fake_collection_result
    diag = diagnose(result.snapshot)
    with connect() as conn:
        uuid = insert_run(
            conn,
            parsed_target=parsed,
            snapshot=result.snapshot,
            diagnosis=diag,
            collection_result=result,
        )
    return uuid


@pytest.fixture
def ui_server(seeded_run):
    """Start a ThreadingProbeServer on an ephemeral port. Yields (host, port, run_uuid)."""
    port = _free_port()
    srv = ThreadingProbeServer(("127.0.0.1", port), ProbeRequestHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield "127.0.0.1", port, seeded_run
    srv.shutdown()
    srv.server_close()


def _get(host: str, port: int, path: str) -> tuple[int, str]:
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    conn.close()
    return resp.status, body


def _post(host: str, port: int, path: str, fields: dict) -> tuple[int, str, str]:
    conn = http.client.HTTPConnection(host, port, timeout=30)
    body = urllib.parse.urlencode(fields)
    conn.request(
        "POST", path, body,
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = conn.getresponse()
    resp.read()
    location = resp.getheader("Location", "")
    conn.close()
    return resp.status, location, resp.getheader("Content-Type", "")


class TestUIRoutes:
    def test_history_ok(self, ui_server):
        host, port, run_uuid = ui_server
        status, body = _get(host, port, "/")
        assert status == 200
        assert "Recent Runs" in body
        assert "example.com" in body

    def test_history_detail_link(self, ui_server):
        host, port, run_uuid = ui_server
        _, body = _get(host, port, "/")
        assert f"/run/{run_uuid}" in body

    def test_detail_ok(self, ui_server):
        host, port, run_uuid = ui_server
        status, body = _get(host, port, f"/run/{run_uuid}")
        assert status == 200
        assert "example.com" in body
        assert "Boundary" in body
        assert "Evidence" in body

    def test_detail_not_found(self, ui_server):
        host, port, _ = ui_server
        status, body = _get(host, port, "/run/nonexistentrunid")
        assert status == 404
        assert "not found" in body.lower()

    def test_unknown_path_404(self, ui_server):
        host, port, _ = ui_server
        status, _ = _get(host, port, "/no/such/page")
        assert status == 404

    def test_diagnose_post_returns_loading_page(self, ui_server):
        host, port, _ = ui_server
        # POST /diagnose now returns a loading page immediately (no blocking)
        status, location, ct = _post(host, port, "/diagnose", {"target": "8.8.8.8"})
        assert status == 200
        assert "text/html" in ct

    def test_api_diagnose_returns_json(self, ui_server, monkeypatch, fake_collection_result):
        host, port, _ = ui_server
        monkeypatch.setattr(
            "boundary_probe.ui.server.collect_signals",
            lambda *a, **kw: fake_collection_result,
        )
        conn = http.client.HTTPConnection(host, port, timeout=30)
        body = urllib.parse.urlencode({"target": "8.8.8.8"})
        conn.request("POST", "/api/diagnose", body,
                     {"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        import json
        data = json.loads(resp.read())
        conn.close()
        assert resp.status == 200
        assert "run_uuid" in data

    def test_diagnose_empty_target_400(self, ui_server):
        host, port, _ = ui_server
        status, location, _ = _post(host, port, "/diagnose", {"target": ""})
        assert status == 400

    def test_diagnose_bad_target_400(self, ui_server, monkeypatch):
        host, port, _ = ui_server
        monkeypatch.setattr(
            "boundary_probe.ui.server.parse_target",
            lambda *a, **kw: (_ for _ in ()).throw(ValueError("bad")),
        )
        status, location, _ = _post(host, port, "/diagnose", {"target": "triggers-error"})
        assert status == 400

    def test_post_unknown_path_404(self, ui_server):
        host, port, _ = ui_server
        status, location, _ = _post(host, port, "/no/such/post", {"x": "y"})
        assert status == 404


class TestEscalationRoute:
    def test_escalation_txt_ok(self, ui_server):
        host, port, run_uuid = ui_server
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", f"/run/{run_uuid}/escalation.txt")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
        assert resp.status == 200
        assert "text/plain" in resp.getheader("Content-Type", "")
        assert "DIAGNOSIS" in body
        assert run_uuid in body

    def test_escalation_txt_not_found(self, ui_server):
        host, port, _ = ui_server
        status, _ = _get(host, port, "/run/unknownuuid/escalation.txt")
        assert status == 404

    def test_detail_page_contains_escalation_section(self, ui_server):
        host, port, run_uuid = ui_server
        _, body = _get(host, port, f"/run/{run_uuid}")
        assert "Escalation Report" in body
        assert "escalation.txt" in body


class TestSecurityHeaders:
    def test_html_response_has_csp(self, ui_server):
        host, port, _ = ui_server
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert "Content-Security-Policy" in {k for k, v in resp.getheaders()}

    def test_html_response_has_x_frame_options(self, ui_server):
        host, port, _ = ui_server
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.getheader("X-Frame-Options") == "DENY"

    def test_html_response_has_nosniff(self, ui_server):
        host, port, _ = ui_server
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.getheader("X-Content-Type-Options") == "nosniff"


class TestCSRFProtection:
    def _post_with_origin(self, host: str, port: int, path: str, fields: dict, origin: str) -> int:
        conn = http.client.HTTPConnection(host, port, timeout=5)
        body = urllib.parse.urlencode(fields)
        conn.request("POST", path, body, {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": origin,
        })
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status

    def test_cross_origin_post_rejected(self, ui_server):
        host, port, _ = ui_server
        status = self._post_with_origin(host, port, "/diagnose",
                                        {"target": "example.com"}, "http://evil.com")
        assert status == 403

    def test_localhost_origin_allowed(self, ui_server):
        host, port, _ = ui_server
        status = self._post_with_origin(host, port, "/diagnose",
                                        {"target": "example.com"},
                                        f"http://localhost:{port}")
        assert status == 200

    def test_no_origin_header_allowed(self, ui_server):
        # Direct HTTP tools (curl, httpie) don't send Origin — must not be blocked
        host, port, _ = ui_server
        status, _, _ = _post(host, port, "/diagnose", {"target": "example.com"})
        assert status == 200


class TestLoadingPageXSS:
    def test_render_loading_has_no_script_breakout(self):
        from boundary_probe.ui.templates import render_loading
        payload = "</script><img src=x onerror=alert(document.domain)>"
        html = render_loading(payload, no_path=False, nonce="testnonce")
        # The attacker's </script> must not survive verbatim to break out of the
        # inline <script> and inject following markup.
        assert "</script><img" not in html

    def test_diagnose_loading_csp_uses_nonce_not_unsafe_inline(self, ui_server):
        host, port, _ = ui_server
        conn = http.client.HTTPConnection(host, port, timeout=5)
        body = urllib.parse.urlencode({"target": "8.8.8.8"})
        conn.request("POST", "/diagnose", body,
                     {"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        page = resp.read().decode("utf-8")
        csp = resp.getheader("Content-Security-Policy", "")
        conn.close()
        assert "nonce-" in csp
        # script-src must no longer rely on 'unsafe-inline'
        script_src = next((d for d in csp.split(";") if "script-src" in d), "")
        assert "'unsafe-inline'" not in script_src
        # the inline script carries the matching nonce
        assert "<script nonce=" in page


class TestUICLI:
    def test_ui_help(self):
        from io import StringIO
        import sys
        from boundary_probe.cli import main
        buf = StringIO()
        with pytest.raises(SystemExit) as exc:
            sys.stdout = buf
            try:
                main(["ui", "--help"])
            finally:
                sys.stdout = sys.__stdout__
        assert exc.value.code == 0
        assert "--port" in buf.getvalue()


class TestMailtoSubject:
    """The mail body is the escalation report, so the subject must not
    contradict its title (#22)."""

    def test_dns_subject_is_not_local_incident(self):
        from boundary_probe.ui.templates import _mailto_subject

        subj = _mailto_subject("dns", "example.com")
        assert "DNS" in urllib.parse.unquote(subj)
        assert "Local Network Incident" not in urllib.parse.unquote(subj)

    def test_captive_portal_subject_is_not_local_incident(self):
        from boundary_probe.ui.templates import _mailto_subject

        subj = urllib.parse.unquote(_mailto_subject("captive-portal", "example.com"))
        assert "Captive Portal" in subj
        assert "Local Network Incident" not in subj

    def test_router_gateway_keeps_local_incident_subject(self):
        from boundary_probe.ui.templates import _mailto_subject

        subj = urllib.parse.unquote(_mailto_subject("router-gateway", "example.com"))
        assert subj == "Local Network Incident Report"
