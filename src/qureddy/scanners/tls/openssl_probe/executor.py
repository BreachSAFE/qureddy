# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The single OpenSSL subprocess boundary for the whole TLS scanner tree.

Every ``openssl`` invocation in ``src/qureddy/scanners/tls/`` funnels through
``run_openssl`` here. It owns the list-form / ``shell=False`` / captured /
timed / ``check=False`` contract (coding-rules.md §7) in one place, times the
call, and — crucially — NEVER raises for a *process* outcome. A binary that is
missing, unlaunchable, times out, or exits nonzero is reported as data on the
returned ``OpenSSLOutcome`` so each caller can apply its own long-standing
policy (return "", return None, build a partial ProbeResult, or raise a typed
local-dependency error) without duplicating the raw ``subprocess.run`` call.

Enforced by ``scripts/check_openssl_boundary.py`` (wired into the release
gate): no module under the TLS tree except this one may call
``subprocess.run`` / ``Popen`` / ``call``.

Security: ``stdin_input`` may carry certificate PEM; it is never logged.
"""

from __future__ import annotations

import enum
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime

from qureddy.core.errors import LocalOpenSSLBroken, LocalOpenSSLMissing
from qureddy.core.models import FailureCategory, OpenSSLDependency


class LaunchStatus(enum.Enum):
    """Whether the OS was able to start the ``openssl`` process at all."""

    OK = "ok"
    MISSING = "missing"
    UNLAUNCHABLE = "unlaunchable"


@dataclass(frozen=True, slots=True)
class OpenSSLOutcome:
    """Everything one ``openssl`` invocation produced, as data — never raised.

    ``returncode`` is ``None`` when the process never produced an exit code
    (missing binary, unlaunchable, or timeout). ``stdout`` / ``stderr`` are
    always decoded ``str`` (partial bytes from a timeout are decoded here so
    every consumer sees text). ``timed_out`` and ``launch`` are orthogonal:
    a timeout means the binary launched then hung, so ``launch`` stays ``OK``.
    """

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    launch: LaunchStatus


def run_openssl(
    args: list[str],
    *,
    timeout_seconds: int,
    stdin_input: str | None = None,
) -> OpenSSLOutcome:
    """Run one ``openssl`` command and classify its outcome without raising.

    This is the ONLY ``subprocess.run`` in the TLS scanner tree. When
    ``stdin_input`` is provided it is piped to the process; otherwise stdin is
    ``DEVNULL`` (so ``openssl`` never blocks reading a terminal). ``stdin_input``
    is never logged — it may contain certificate PEM.
    """
    started = datetime.now(UTC)
    try:
        completed = subprocess.run(  # noqa: S603 -- validated list-form command, shell=False
            args,
            input=stdin_input if stdin_input is not None else None,
            stdin=subprocess.DEVNULL if stdin_input is None else None,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return _launch_failure(started, LaunchStatus.MISSING)
    except subprocess.TimeoutExpired as exc:
        return OpenSSLOutcome(
            returncode=None,
            stdout=_coerce_stream(exc.stdout),
            stderr=_coerce_stream(exc.stderr),
            timed_out=True,
            duration_ms=_elapsed_ms(started),
            launch=LaunchStatus.OK,
        )
    except OSError:
        # A path that exists but cannot be executed (e.g. Windows WinError 193,
        # exec format error) surfaces as OSError, not FileNotFoundError.
        return _launch_failure(started, LaunchStatus.UNLAUNCHABLE)
    return OpenSSLOutcome(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        duration_ms=_elapsed_ms(started),
        launch=LaunchStatus.OK,
    )


def raise_for_launch(outcome: OpenSSLOutcome, path: str) -> None:
    """Raise the typed local-dependency error for a failed launch; else no-op.

    ``MISSING`` becomes :class:`LocalOpenSSLMissing`; ``UNLAUNCHABLE`` becomes
    :class:`LocalOpenSSLBroken` carrying the populated ``OpenSSLDependency`` so
    callers land on the exit-3 surface instead of leaking a raw ``OSError``.
    An ``OK`` launch (including a timeout or a nonzero exit) returns quietly —
    those are per-site policy decisions, not launch failures.
    """
    if outcome.launch is LaunchStatus.MISSING:
        raise LocalOpenSSLMissing(f"openssl binary not found: {path}")
    if outcome.launch is LaunchStatus.UNLAUNCHABLE:
        raise LocalOpenSSLBroken(
            f"openssl could not be launched: {path}",
            dependency=OpenSSLDependency(
                path=path,
                failure_category=FailureCategory.LOCAL_OPENSSL_BROKEN,
            ),
        )


def _launch_failure(started: datetime, launch: LaunchStatus) -> OpenSSLOutcome:
    return OpenSSLOutcome(
        returncode=None,
        stdout="",
        stderr="",
        timed_out=False,
        duration_ms=_elapsed_ms(started),
        launch=launch,
    )


def _coerce_stream(value: bytes | str | None) -> str:
    """Decode partial timeout output to ``str`` (``None`` -> ``""``)."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _elapsed_ms(started: datetime) -> int:
    return int((datetime.now(UTC) - started).total_seconds() * 1000)
