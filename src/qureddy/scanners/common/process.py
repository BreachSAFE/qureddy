# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bounded execution for external scanner processes."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExternalProcessOutput:
    """Captured process streams and bounded termination state."""

    return_code: int
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool = False
    output_limited: bool = False


def run_bounded(argv: list[str], *, timeout_seconds: int, output_limit: int) -> ExternalProcessOutput:
    """Run list-form argv with a time and combined-output bound."""
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 -- argv is list-form; shell is disabled
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _coerce(exc.stdout)
        stderr = _coerce(exc.stderr)
        return ExternalProcessOutput(
            return_code=124,
            stdout=stdout[:output_limit],
            stderr=stderr[:output_limit],
            duration_ms=_elapsed_ms(started),
            timed_out=True,
            output_limited=len(stdout) + len(stderr) > output_limit,
        )
    except OSError as exc:
        return ExternalProcessOutput(
            return_code=127,
            stdout=b"",
            stderr=str(exc).encode("utf-8", errors="replace"),
            duration_ms=_elapsed_ms(started),
        )
    output_limited = len(completed.stdout) + len(completed.stderr) > output_limit
    if output_limited:
        remaining = max(output_limit - len(completed.stdout), 0)
        stdout = completed.stdout[:remaining]
        stderr = completed.stderr[: max(output_limit - len(stdout), 0)]
    else:
        stdout, stderr = completed.stdout, completed.stderr
    return ExternalProcessOutput(
        return_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=_elapsed_ms(started),
        output_limited=output_limited,
    )


def _coerce(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
