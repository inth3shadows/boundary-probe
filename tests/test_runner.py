from __future__ import annotations

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from boundary_probe.collectors._runner import DefaultRunner


def _make_proc(stdout: bytes = b"out", stderr: bytes = b"err", returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def test_successful_run_returns_decoded_output():
    encoding = "cp437" if sys.platform == "win32" else "utf-8"
    proc = _make_proc(stdout="hello".encode(encoding), stderr="".encode(encoding))
    with patch("subprocess.run", return_value=proc) as mock_run:
        result = DefaultRunner().run(["echo", "hello"], timeout_s=5.0)
    assert result.stdout == "hello"
    assert result.stderr == ""
    assert result.returncode == 0
    assert not result.timed_out
    mock_run.assert_called_once()


def test_timeout_returns_empty_strings():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["ping"], timeout=1)):
        result = DefaultRunner().run(["ping", "1.1.1.1"], timeout_s=1.0)
    assert result.stdout == ""
    assert result.stderr == ""
    assert result.returncode == -1
    assert result.timed_out


def test_file_not_found_propagates():
    with patch("subprocess.run", side_effect=FileNotFoundError("not found")):
        with pytest.raises(FileNotFoundError):
            DefaultRunner().run(["tracert", "1.1.1.1"], timeout_s=5.0)


def test_duration_ms_is_non_negative():
    proc = _make_proc()
    with patch("subprocess.run", return_value=proc):
        result = DefaultRunner().run(["cmd"], timeout_s=5.0)
    assert result.duration_ms >= 0


def test_debug_mode_prints_to_stderr(capsys, monkeypatch):
    import boundary_probe.collectors._runner as runner_mod
    monkeypatch.setattr(runner_mod, "_DEBUG", True)
    proc = _make_proc(stdout=b"pong", stderr=b"")
    with patch("subprocess.run", return_value=proc):
        DefaultRunner().run(["ping", "host"], timeout_s=5.0)
    err = capsys.readouterr().err
    assert "[boundary-probe debug]" in err
    assert "ping" in err


def test_run_forces_c_locale():
    """ping/traceroute output must be English for the parsers; the runner pins
    LC_ALL/LANG=C so a localized environment can't produce false 100% loss."""
    proc = _make_proc()
    with patch("subprocess.run", return_value=proc) as mock_run:
        DefaultRunner().run(["ping", "1.1.1.1"], timeout_s=5.0)
    _, kwargs = mock_run.call_args
    env = kwargs.get("env")
    assert env is not None
    assert env.get("LC_ALL") == "C"
    assert env.get("LANG") == "C"
    # existing environment is preserved (e.g. PATH), not replaced wholesale
    import os
    if "PATH" in os.environ:
        assert "PATH" in env


def test_creationflags_on_windows_only():
    """CREATE_NO_WINDOW is passed as creationflags on Windows; 0 on Linux."""
    proc = _make_proc()
    with patch("subprocess.run", return_value=proc) as mock_run:
        DefaultRunner().run(["cmd"], timeout_s=5.0)
    _, kwargs = mock_run.call_args
    if sys.platform == "win32":
        assert kwargs.get("creationflags", 0) != 0
    else:
        assert kwargs.get("creationflags", 0) == 0
