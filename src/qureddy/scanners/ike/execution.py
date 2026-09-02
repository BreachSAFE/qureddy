# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Runtime and output-bounded subprocess execution for the IKE adapter."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, cast

from qureddy.core.logging import get_logger

_READ_SIZE = 4096
_KILL_WAIT_SECONDS = 2
_LOG = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ProcessOutput:
    """Bounded bytes and typed termination state from one child process."""

    return_code: int
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool = False
    output_limited: bool = False


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Force-stop the isolated process group rooted at ``process``."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            if process.poll() is None:
                process.kill()
        return
    if os.name == "nt":
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        taskkill = Path(system_root) / "System32" / "taskkill.exe"
        try:
            # Fixed Windows system utility plus a numeric child PID, never user input.
            subprocess.run(  # noqa: S603  # nosec B603
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                timeout=_KILL_WAIT_SECONDS,
            )
        except OSError, subprocess.TimeoutExpired:
            if process.poll() is None:
                process.kill()
        return
    if process.poll() is None:
        process.kill()


def _terminate(process: subprocess.Popen[bytes], *, tree: bool = False) -> int:
    """Stop a process or its isolated tree and reap the leader within a fixed bound."""
    if tree:
        _kill_process_tree(process)
    elif process.poll() is None:
        process.kill()
    try:
        return process.wait(timeout=_KILL_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        _kill_process_tree(process)
        return process.wait(timeout=_KILL_WAIT_SECONDS)


def _register_pipes(
    selector: selectors.BaseSelector, process: subprocess.Popen[bytes]
) -> dict[str, bytearray]:
    """Register both child streams for nonblocking bounded reads."""
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        if stream is None:
            continue
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, data=name)
    return buffers


def _read_ready(
    selector: selectors.BaseSelector,
    buffers: dict[str, bytearray],
    *,
    remaining: int,
) -> tuple[int, bool]:
    """Read currently available child bytes, returning count and overflow state."""
    consumed = 0
    overflow = False
    for key, _events in selector.select(timeout=0.05):
        stream = cast("IO[bytes]", key.fileobj)
        chunk = os.read(stream.fileno(), _READ_SIZE)
        if not chunk:
            selector.unregister(stream)
            stream.close()
            continue
        keep = min(len(chunk), max(remaining - consumed, 0))
        buffers[str(key.data)].extend(chunk[:keep])
        consumed += keep
        overflow = overflow or len(chunk) > keep
    return consumed, overflow


def run_bounded(argv: list[str], *, timeout_seconds: int, output_limit: int) -> ProcessOutput:
    """Execute list-form argv while bounding runtime and combined output bytes."""
    started = time.monotonic()
    _LOG.debug(
        "ike_scan.process_started",
        executable=argv[0],
        timeout_seconds=timeout_seconds,
        output_limit=output_limit,
    )
    with subprocess.Popen(  # noqa: S603 -- argv is list-form and executable is resolved
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        shell=False,
        start_new_session=os.name == "posix",
        creationflags=(
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        ),
    ) as process:
        output = _collect_process_output(
            process,
            started=started,
            timeout_seconds=timeout_seconds,
            output_limit=output_limit,
        )
    _LOG.debug(
        "ike_scan.process_completed",
        return_code=output.return_code,
        duration_ms=output.duration_ms,
        timed_out=output.timed_out,
        output_limited=output.output_limited,
    )
    return output


def _collect_process_output(
    process: subprocess.Popen[bytes],
    *,
    started: float,
    timeout_seconds: int,
    output_limit: int,
) -> ProcessOutput:
    """Drain a child process under combined runtime and output limits."""
    selector = selectors.DefaultSelector()
    buffers = _register_pipes(selector, process)
    total = 0
    timed_out = False
    output_limited = False
    deadline = started + timeout_seconds
    return_code = 0
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                _terminate(process, tree=True)
                break
            consumed, overflow = _read_ready(
                selector, buffers, remaining=max(output_limit - total, 0)
            )
            total += consumed
            if overflow:
                output_limited = True
                _terminate(process, tree=True)
                break
    finally:
        selector.close()
        return_code = _terminate(process)
    return ProcessOutput(
        return_code=return_code,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
        duration_ms=round((time.monotonic() - started) * 1000),
        timed_out=timed_out,
        output_limited=output_limited,
    )
