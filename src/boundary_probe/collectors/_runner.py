from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Protocol

# Windows-only flag; getattr returns 0 on Linux (0 is safe to pass as creationflags)
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_ENCODING = "cp437" if sys.platform == "win32" else "utf-8"
_DEBUG = os.environ.get("BOUNDARY_PROBE_DEBUG") == "1"


@dataclass(slots=True, frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


class SubprocessRunner(Protocol):
    def run(self, argv: list[str], timeout_s: float) -> CommandResult: ...


class DefaultRunner:
    """Production runner. shell=False always. Platform-appropriate output encoding."""

    def run(self, argv: list[str], timeout_s: float) -> CommandResult:
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout_s,
                shell=False,
                creationflags=_CREATE_NO_WINDOW,
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            result = CommandResult(
                returncode=proc.returncode,
                stdout=proc.stdout.decode(_ENCODING, errors="replace"),
                stderr=proc.stderr.decode(_ENCODING, errors="replace"),
                timed_out=False,
                duration_ms=elapsed_ms,
            )
            if _DEBUG:
                print(f"[boundary-probe debug] {argv[0]} rc={result.returncode} "
                      f"({elapsed_ms}ms) stdout={result.stdout[:120]!r}", file=sys.stderr)
            return result
        except subprocess.TimeoutExpired:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            if _DEBUG:
                print(f"[boundary-probe debug] {argv[0]} timed out after {timeout_s}s", file=sys.stderr)
            return CommandResult(
                returncode=-1,
                stdout="",
                stderr="",
                timed_out=True,
                duration_ms=elapsed_ms,
            )
        # FileNotFoundError is intentionally not caught here: callers (CLI, UI server)
        # handle it to produce a "required tool not found" message instead of letting
        # it surface as a confusing "unrecognized output format" parse failure.
