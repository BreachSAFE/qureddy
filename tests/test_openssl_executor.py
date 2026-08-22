# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The single OpenSSL subprocess boundary — executor.run_openssl (#296).

These drive the real ``subprocess`` boundary (no ``openssl`` binary and no
network needed — a Python subprocess stands in for any external tool) plus a
patched partial-output timeout, and cover the launch-status classification and
``raise_for_launch`` typed-error mapping.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from qureddy.core.errors import LocalOpenSSLBroken, LocalOpenSSLMissing
from qureddy.core.models import FailureCategory
from qureddy.scanners.tls.openssl_probe.executor import (
    LaunchStatus,
    OpenSSLOutcome,
    raise_for_launch,
    run_openssl,
)

_EXECUTOR_RUN = "qureddy.scanners.tls.openssl_probe.executor.subprocess.run"


def _py(code: str) -> list[str]:
    """A self-contained subprocess command that needs no external binary."""
    return [sys.executable, "-c", code]


class TestRunOpenSSLProcessOutcomes:
    def test_success_returns_ok_launch_and_stdout(self) -> None:
        outcome = run_openssl(_py("print('hello-out')"), timeout_seconds=30)
        assert outcome.launch is LaunchStatus.OK
        assert outcome.returncode == 0
        assert outcome.timed_out is False
        assert "hello-out" in outcome.stdout
        assert outcome.duration_ms >= 0

    def test_nonzero_exit_is_reported_not_raised(self) -> None:
        outcome = run_openssl(_py("import sys; sys.exit(3)"), timeout_seconds=30)
        assert outcome.launch is LaunchStatus.OK
        assert outcome.returncode == 3
        assert outcome.timed_out is False

    def test_real_timeout_sets_timed_out_flag(self) -> None:
        outcome = run_openssl(_py("import time; time.sleep(10)"), timeout_seconds=1)
        assert outcome.timed_out is True
        assert outcome.returncode is None
        # A timeout means the binary launched then hung — launch stays OK.
        assert outcome.launch is LaunchStatus.OK

    def test_timeout_preserves_partial_output_and_coerces_none(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["openssl"], timeout=1, output=b"partial-bytes", stderr=None
        )
        with patch(_EXECUTOR_RUN, side_effect=timeout):
            outcome = run_openssl(["openssl", "version"], timeout_seconds=1)
        assert outcome.timed_out is True
        assert outcome.stdout == "partial-bytes"  # bytes decoded to str
        assert outcome.stderr == ""  # None coerced to ""
        assert outcome.returncode is None

    def test_missing_binary_is_missing_launch(self) -> None:
        outcome = run_openssl(["/nonexistent/path/openssl"], timeout_seconds=5)
        assert outcome.launch is LaunchStatus.MISSING
        assert outcome.returncode is None
        assert outcome.stdout == ""

    def test_unlaunchable_path_is_unlaunchable_launch(self, tmp_path: Path) -> None:
        # A directory exists but cannot be exec()'d -> OSError, not
        # FileNotFoundError -> UNLAUNCHABLE (distinct from MISSING).
        outcome = run_openssl([str(tmp_path)], timeout_seconds=5)
        assert outcome.launch is LaunchStatus.UNLAUNCHABLE
        assert outcome.returncode is None


class TestStdinHandling:
    def test_stdin_input_is_piped_to_the_process(self) -> None:
        outcome = run_openssl(
            _py("import sys; sys.stdout.write(sys.stdin.read())"),
            timeout_seconds=30,
            stdin_input="piped-payload",
        )
        assert outcome.stdout == "piped-payload"

    def test_no_stdin_input_uses_devnull(self) -> None:
        outcome = run_openssl(
            _py("import sys; sys.stdout.write(repr(sys.stdin.read()))"),
            timeout_seconds=30,
        )
        # DEVNULL yields EOF immediately: read() returns "".
        assert outcome.stdout == "''"


class TestRaiseForLaunch:
    @staticmethod
    def _outcome(launch: LaunchStatus, *, timed_out: bool = False) -> OpenSSLOutcome:
        return OpenSSLOutcome(
            returncode=None if launch is not LaunchStatus.OK else 0,
            stdout="",
            stderr="",
            timed_out=timed_out,
            duration_ms=1,
            launch=launch,
        )

    def test_missing_raises_local_openssl_missing(self) -> None:
        with pytest.raises(LocalOpenSSLMissing):
            raise_for_launch(self._outcome(LaunchStatus.MISSING), "/x/openssl")

    def test_unlaunchable_raises_local_openssl_broken_with_dependency(self) -> None:
        with pytest.raises(LocalOpenSSLBroken) as excinfo:
            raise_for_launch(self._outcome(LaunchStatus.UNLAUNCHABLE), "/x/openssl")
        dependency = excinfo.value.dependency
        assert dependency is not None
        assert dependency.path == "/x/openssl"
        assert dependency.failure_category is FailureCategory.LOCAL_OPENSSL_BROKEN

    def test_ok_launch_does_not_raise(self) -> None:
        raise_for_launch(self._outcome(LaunchStatus.OK), "/x/openssl")

    def test_timeout_on_ok_launch_does_not_raise(self) -> None:
        # A timeout is a per-site policy decision, not a launch failure.
        raise_for_launch(self._outcome(LaunchStatus.OK, timed_out=True), "/x/openssl")


class TestCoerceStream:
    """_coerce_stream normalizes partial timeout output to str (#296)."""

    def test_none_becomes_empty_string(self) -> None:
        from qureddy.scanners.tls.openssl_probe.executor import _coerce_stream

        assert _coerce_stream(None) == ""

    def test_bytes_are_utf8_decoded_replacing_errors(self) -> None:
        from qureddy.scanners.tls.openssl_probe.executor import _coerce_stream

        assert _coerce_stream(b"ok\xff") == "ok�"

    def test_str_passes_through_unchanged(self) -> None:
        # The real text=True TimeoutExpired path: partial output is already str.
        from qureddy.scanners.tls.openssl_probe.executor import _coerce_stream

        assert _coerce_stream("already text") == "already text"
