# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Runtime and output-bounded subprocess execution for the IKE adapter."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Literal

from qureddy.core.logging import get_logger

_READ_SIZE = 4096
_KILL_WAIT_SECONDS = 2
_LOG = get_logger(__name__)

StreamName = Literal["stdout", "stderr"]


@dataclass(frozen=True, slots=True)
class ProcessOutput:
    """Bounded bytes and typed termination state from one child process."""

    return_code: int
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool = False
    output_limited: bool = False


class _BoundedCapture:
    """Own the synchronized combined-output budget for two pipe readers."""

    def __init__(self, limit: int, reader_count: int) -> None:
        self._limit = limit
        self._buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self._total = 0
        self._active_readers = reader_count
        self._condition = threading.Condition()
        self._stopped = False
        self._output_limited = False

    def append(self, name: StreamName, chunk: bytes) -> bool:
        """Append within the shared limit and return whether reading may continue."""
        with self._condition:
            if self._stopped:
                return False
            remaining = max(self._limit - self._total, 0)
            keep = min(len(chunk), remaining)
            self._buffers[name].extend(chunk[:keep])
            self._total += keep
            if keep != len(chunk):
                self._output_limited = True
                self._condition.notify_all()
                return False
            return True

    def reader_finished(self) -> None:
        """Record a closed child pipe and wake the controller."""
        with self._condition:
            self._active_readers -= 1
            self._condition.notify_all()

    def wait(self, timeout: float) -> tuple[bool, bool]:
        """Wait for all readers or the output limit and return both states."""
        with self._condition:
            self._condition.wait_for(
                lambda: self._active_readers == 0 or self._output_limited,
                timeout=max(timeout, 0),
            )
            return self._active_readers == 0, self._output_limited

    def stop(self) -> None:
        """Prevent readers from mutating the final snapshot."""
        with self._condition:
            self._stopped = True
            self._condition.notify_all()

    def snapshot(self, name: StreamName) -> bytes:
        """Return immutable bytes captured for one child stream."""
        with self._condition:
            return bytes(self._buffers[name])


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


def _drain_pipe(stream: IO[bytes], name: StreamName, capture: _BoundedCapture) -> None:
    """Drain one child pipe until EOF, stop, or the shared byte limit."""
    try:
        while True:
            chunk = stream.read(_READ_SIZE)
            if not chunk or not capture.append(name, chunk):
                return
    except OSError:
        # The controller closes the process tree when a timeout or limit wins the race.
        return
    finally:
        stream.close()
        capture.reader_finished()


def _start_readers(
    process: subprocess.Popen[bytes], capture: _BoundedCapture
) -> tuple[threading.Thread, ...]:
    """Start one bounded reader for each available child pipe."""
    readers: list[threading.Thread] = []
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        if stream is None:
            continue
        reader = threading.Thread(
            target=_drain_pipe,
            args=(stream, name, capture),
            name=f"qureddy-ike-{name}",
            daemon=True,
        )
        reader.start()
        readers.append(reader)
    return tuple(readers)


def run_bounded(argv: list[str], *, timeout_seconds: int, output_limit: int) -> ProcessOutput:
    """Execute list-form argv while bounding runtime and combined output bytes."""
    started = time.monotonic()
    _LOG.info(
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
    _LOG.info(
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
    reader_count = sum(stream is not None for stream in (process.stdout, process.stderr))
    capture = _BoundedCapture(output_limit, reader_count)
    readers = _start_readers(process, capture)
    timed_out = False
    deadline = started + timeout_seconds
    return_code: int | None = None
    try:
        readers_done, output_limited = capture.wait(deadline - time.monotonic())
        if output_limited:
            return_code = _terminate(process, tree=True)
        elif not readers_done:
            timed_out = True
            return_code = _terminate(process, tree=True)
        else:
            try:
                return_code = process.wait(timeout=max(deadline - time.monotonic(), 0))
            except subprocess.TimeoutExpired:
                timed_out = True
                return_code = _terminate(process, tree=True)
    finally:
        if return_code is None:
            return_code = _terminate(process, tree=True)
        capture.stop()
        for reader in readers:
            reader.join(timeout=_KILL_WAIT_SECONDS)
    return ProcessOutput(
        return_code=return_code,
        stdout=capture.snapshot("stdout"),
        stderr=capture.snapshot("stderr"),
        duration_ms=round((time.monotonic() - started) * 1000),
        timed_out=timed_out,
        output_limited=output_limited,
    )
