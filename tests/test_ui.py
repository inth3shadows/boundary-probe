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

    def test_diagnose_post_redirects(self, ui_server, monkeypatch, fake_collection_result):
        host, port, _ = ui_server
        monkeypatch.setattr(
            "boundary_probe.ui.server.collect_signals",
            lambda *a, **kw: fake_collection_result,
        )
        status, location, _ = _post(host, port, "/diagnose", {"target": "8.8.8.8"})
        assert status == 303
        assert location.startswith("/run/")

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
