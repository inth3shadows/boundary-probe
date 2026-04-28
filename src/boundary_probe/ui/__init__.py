from __future__ import annotations

import webbrowser

from boundary_probe.ui.server import ProbeRequestHandler, ThreadingProbeServer


def launch_server(port: int = 8787, open_browser: bool = True) -> None:
    server = ThreadingProbeServer(("127.0.0.1", port), ProbeRequestHandler)
    url = f"http://localhost:{port}/"
    print(f"Boundary Probe UI: {url}")
    print("Press Ctrl-C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
