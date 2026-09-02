# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Runtime and output-bound tests for the IKE subprocess boundary."""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

from qureddy.scanners.ike.adapter import IkeScanAdapter
from qureddy.scanners.ike.execution import _BoundedCapture, _terminate, run_bounded
from qureddy.scanners.ike.types import IKEMode


@pytest.mark.parametrize(
    ("nat_t", "configured", "expected"),
    [(False, 0, "500"), (True, 0, "4500"), (False, 32000, "32000"), (True, 32000, "32000")],
)
def test_adapter_uses_protocol_source_port_defaults(
    nat_t: bool, configured: int, expected: str
) -> None:
    """Use UDP/500 direct and UDP/4500 NAT-T unless explicitly overridden (#719)."""
    adapter = IkeScanAdapter(sys.executable, source_port=configured)

    argv = adapter._argv(  # noqa: SLF001 - executable argument contract under test.
        IKEMode.IKEV1_MAIN,
        host="192.0.2.1",
        port=4500 if nat_t else 500,
        nat_t=nat_t,
        timeout=2,
    )

    assert argv[argv.index("--sport") + 1] == expected


def test_run_bounded_keeps_stdout_and_stderr_separate() -> None:
    """Prevent synthetic seam lines between child output streams."""
    output = run_bounded(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
        timeout_seconds=2,
        output_limit=1024,
    )

    assert output.return_code == 0
    assert output.stdout.splitlines() == [b"out"]
    assert output.stderr.splitlines() == [b"err"]
    assert not output.timed_out
    assert not output.output_limited


def test_run_bounded_stops_excess_output() -> None:
    """Kill a child once combined output exceeds its byte budget."""
    output = run_bounded(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 8192)"],
        timeout_seconds=2,
        output_limit=128,
    )

    assert output.output_limited
    assert len(output.stdout) + len(output.stderr) == 128


def test_run_bounded_stops_a_hung_child() -> None:
    """Represent a child timeout as typed process state."""
    output = run_bounded(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_seconds=1,
        output_limit=1024,
    )

    assert output.timed_out


def test_run_bounded_stops_descendants_holding_output_pipes() -> None:
    """Keep a real child-plus-grandchild tree within the timeout on every OS (#720)."""
    code = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable,'-c','import time; time.sleep(5)']); "
        "time.sleep(5)"
    )
    started = time.monotonic()
    output = run_bounded(
        [sys.executable, "-c", code],
        timeout_seconds=1,
        output_limit=1024,
    )

    assert output.timed_out
    assert time.monotonic() - started < 2.5


def test_bounded_capture_rejects_writes_after_stop() -> None:
    """Freeze the final output snapshot before the controller returns it."""
    capture = _BoundedCapture(4, 0)
    capture.stop()
    assert not capture.append("stdout", b"late")


def test_terminate_stops_and_reaps_real_child() -> None:
    """Exercise the single-process termination path without mocks."""
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    return_code = _terminate(process)
    assert return_code != 0
    assert process.poll() is not None
