from contextlib import redirect_stdout
from io import StringIO

from boundary_probe.cli import main


def test_diagnose_outputs_expected_boundary() -> None:
    stream = StringIO()
    with redirect_stdout(stream):
        main(["diagnose", "remote-service"])
    assert "Boundary:   remote-service" in stream.getvalue()


def test_roadmap_command_runs() -> None:
    stream = StringIO()
    with redirect_stdout(stream):
        main(["roadmap"])
    assert "Boundary Probe roadmap:" in stream.getvalue()


def test_capture_stub_runs() -> None:
    stream = StringIO()
    with redirect_stdout(stream):
        main(["capture", "test-fixture"])
    assert "capture not yet implemented" in stream.getvalue()


def test_diagnose_with_url_target() -> None:
    stream = StringIO()
    with redirect_stdout(stream):
        main(["diagnose", "https://example.com"])
    output = stream.getvalue()
    assert "Target:     https://example.com (url)" in output
    assert "Phase 0: real collectors not implemented" in output


def test_diagnose_with_ip_target() -> None:
    stream = StringIO()
    with redirect_stdout(stream):
        main(["diagnose", "1.1.1.1"])
    output = stream.getvalue()
    assert "(ip)" in output
