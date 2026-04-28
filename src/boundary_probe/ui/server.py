from __future__ import annotations

import http.server
import socketserver
import urllib.parse
from http import HTTPStatus

from boundary_probe.collectors import collect_signals
from boundary_probe.engine import diagnose
from boundary_probe.store import connect, fetch_recent, fetch_run, insert_run
from boundary_probe.targets import parse_target
from boundary_probe.templates import render_escalation
from boundary_probe.ui.templates import render_detail, render_error, render_history, render_loading

_MAX_HISTORY = 50


class ProbeRequestHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass  # suppress default stderr chatter

    def _send_html(self, code: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _send_redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._handle_history()
        elif path.endswith("/escalation.txt") and path.startswith("/run/"):
            run_uuid = path[len("/run/"):-len("/escalation.txt")]
            self._handle_escalation_txt(run_uuid)
        elif path.startswith("/run/"):
            self._handle_detail(path[len("/run/"):])
        else:
            self._send_html(404, render_error("Page not found.", "/"))

    def _send_json(self, code: int, data: dict) -> None:
        import json
        encoded = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/diagnose":
            self._handle_diagnose_loading()
        elif path == "/api/diagnose":
            self._handle_api_diagnose()
        else:
            self._send_html(404, render_error("Not found.", "/"))

    def _handle_history(self) -> None:
        with connect() as conn:
            rows = fetch_recent(conn, _MAX_HISTORY)
        self._send_html(200, render_history(rows))

    def _handle_detail(self, run_uuid: str) -> None:
        with connect() as conn:
            row = fetch_run(conn, run_uuid)
        if row is None:
            self._send_html(404, render_error(f"Run not found: {run_uuid}", "/"))
            return
        self._send_html(200, render_detail(row))

    def _handle_escalation_txt(self, run_uuid: str) -> None:
        with connect() as conn:
            row = fetch_run(conn, run_uuid)
        if row is None:
            self._send_html(404, render_error(f"Run not found: {run_uuid}", "/"))
            return
        text = render_escalation(row)
        encoded = text.encode("utf-8")
        fname = f"escalation_{run_uuid[:8]}.txt"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_params(self) -> tuple[str, bool]:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        params = urllib.parse.parse_qs(raw, keep_blank_values=False)
        target_str = (params.get("target") or [""])[0].strip()
        no_path = "no_path" in params
        return target_str, no_path

    def _handle_diagnose_loading(self) -> None:
        target_str, no_path = self._read_params()
        if not target_str:
            self._send_html(400, render_error("Target is required.", "/"))
            return
        try:
            parse_target(target_str)
        except ValueError as exc:
            self._send_html(400, render_error(f"Invalid target: {exc}", "/"))
            return
        self._send_html(200, render_loading(target_str, no_path))

    def _handle_api_diagnose(self) -> None:
        target_str, no_path = self._read_params()
        if not target_str:
            self._send_json(400, {"error": "Target is required."})
            return
        try:
            parsed = parse_target(target_str)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        try:
            result = collect_signals(parsed, skip_path=no_path)
        except FileNotFoundError as exc:
            self._send_json(500, {"error": f"Required system tool not found: {exc}"})
            return
        diag = diagnose(result.snapshot)
        with connect() as conn:
            run_uuid = insert_run(
                conn,
                parsed_target=parsed,
                snapshot=result.snapshot,
                diagnosis=diag,
                collection_result=result,
            )
        self._send_json(200, {"run_uuid": run_uuid})


class ThreadingProbeServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
