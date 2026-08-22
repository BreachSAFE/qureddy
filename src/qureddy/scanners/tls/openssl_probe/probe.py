# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""TLS handshake probes executed through OpenSSL."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qureddy.core.errors import LocalOpenSSLBroken, LocalOpenSSLMissing
from qureddy.core.models import FailureCategory, OpenSSLDependency
from qureddy.scanners.tls._classify import classify_failure
from qureddy.scanners.tls._net import build_connect_target
from qureddy.scanners.tls.openssl_probe._constants import (
    CLASSICAL_GROUP,
    DEFAULT_TIMEOUT_SECONDS,
    HYBRID_GROUP,
)
from qureddy.scanners.tls.openssl_probe._logging import (
    log_subprocess_complete,
    log_subprocess_start,
)
from qureddy.scanners.tls.openssl_probe._results import (
    build_probe_result,
    combined_probe_output,
    result_from_timeout,
)

if TYPE_CHECKING:
    from qureddy.core.models import ProbeResult


def run_hybrid_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    attempt_number: int = 1,
    group: str = HYBRID_GROUP,
) -> ProbeResult:
    """Probe the endpoint forcing one hybrid key-exchange group.

    #337: defaults to X25519MLKEM768, or a supplementary standardized group for per-group
    coverage.
    """
    args = _build_probe_args(openssl_path, host, port, sni, group=group)
    return _run_probe(args, timeout_seconds=timeout_seconds, attempt_number=attempt_number)


def run_classical_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    attempt_number: int = 1,
) -> ProbeResult:
    """Probe the endpoint with the classical fallback key-exchange group."""
    args = _build_probe_args(openssl_path, host, port, sni, group=CLASSICAL_GROUP)
    return _run_probe(args, timeout_seconds=timeout_seconds, attempt_number=attempt_number)


def _build_probe_args(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    group: str,
) -> list[str]:
    args = [
        openssl_path,
        "s_client",
        "-connect",
        build_connect_target(host, port),
        "-tls1_3",
        "-groups",
        group,
        "-brief",
    ]
    if sni is not None:
        args.extend(["-servername", sni])
    return args


def _run_probe(
    args: list[str],
    *,
    timeout_seconds: int,
    attempt_number: int,
) -> ProbeResult:
    started = datetime.now(UTC)
    log_subprocess_start(args, timeout_seconds, attempt_number)
    try:
        completed = subprocess.run(  # noqa: S603 -- validated list-form command
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return result_from_timeout(args, exc, started, timeout_seconds, attempt_number)
    except FileNotFoundError as exc:
        raise LocalOpenSSLMissing(str(exc)) from exc
    except OSError as exc:
        raise LocalOpenSSLBroken(
            f"openssl became unlaunchable after capability detection: {exc}",
            dependency=OpenSSLDependency(
                path=args[0],
                failure_category=FailureCategory.LOCAL_OPENSSL_BROKEN,
            ),
        ) from exc
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    failure = classify_failure(completed.stderr) if completed.returncode else None
    log_subprocess_complete(args, completed.returncode, duration_ms, attempt_number, failure)
    parser_input = combined_probe_output(completed.stdout, completed.stderr)
    return build_probe_result(
        args=args,
        stdout=completed.stdout,
        stderr=completed.stderr,
        parser_input=parser_input,
        return_code=completed.returncode,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        timeout_seconds=timeout_seconds,
        failure_category=failure,
    )
