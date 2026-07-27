# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""OpenSSL 3.5+ subprocess probe.

Per docs/contributors/coding-rules.md §7 and the mvp-implement skill, this module is
the only place in the codebase that calls `openssl` via `subprocess`.
Other modules consume typed `OpenSSLDependency` and `ProbeResult` values.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime

from qureddy.core.errors import LocalOpenSSLMissing
from qureddy.core.logging import get_logger
from qureddy.core.models import (
    FailureCategory,
    ProbeCommand,
    ProbeResult,
)
from qureddy.scanners.tls._classify import classify_failure
from qureddy.scanners.tls._net import build_connect_target
from qureddy.scanners.tls.capability import (
    CLASSICAL_GROUP,
    DEFAULT_TIMEOUT_SECONDS,
    HYBRID_GROUP,
    probe_capability,
    raise_if_unusable,
    resolve_openssl_path,
)

__all__ = [
    "CLASSICAL_GROUP",
    "DEFAULT_TIMEOUT_SECONDS",
    "HYBRID_GROUP",
    "probe_capability",
    "raise_if_unusable",
    "resolve_openssl_path",
    "run_classical_probe",
    "run_hybrid_probe",
]

_log = get_logger(__name__)

EXCERPT_LIMIT = 4096


def run_hybrid_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    attempt_number: int = 1,
) -> ProbeResult:
    """Run X25519MLKEM768 probe against host:port."""
    args = _build_probe_args(openssl_path, host, port, sni, group=HYBRID_GROUP)
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
    """Run classical X25519 control probe."""
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
    """Execute a single OpenSSL probe and return a typed `ProbeResult`."""
    started = datetime.now(UTC)
    _log_subprocess_start(args, timeout_seconds, attempt_number)
    try:
        completed = subprocess.run(  # noqa: S603 -- list-form, shell=False, validated args
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        return _probe_result_from_timeout(args, exc, started, timeout_seconds, attempt_number)
    except FileNotFoundError as exc:
        raise LocalOpenSSLMissing(str(exc)) from exc

    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    failure = classify_failure(completed.stderr) if completed.returncode != 0 else None
    _log_subprocess_complete(args, completed.returncode, duration_ms, attempt_number, failure)
    parser_input = _combined_probe_output(completed.stdout, completed.stderr)
    return _build_probe_result(
        args=args,
        stdout=completed.stdout,
        stderr=completed.stderr,
        parser_input=parser_input,
        stdout_excerpt=parser_input[:EXCERPT_LIMIT],
        return_code=completed.returncode,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        timeout_seconds=timeout_seconds,
        failure_category=failure,
    )


def _log_subprocess_start(args: list[str], timeout_seconds: int, attempt_number: int) -> None:
    _log.debug(
        "subprocess.start",
        executable=args[0],
        args=tuple(args[1:]),
        timeout_seconds=timeout_seconds,
        attempt_number=attempt_number,
    )


def _log_subprocess_complete(
    args: list[str],
    return_code: int,
    duration_ms: int,
    attempt_number: int,
    failure: FailureCategory | None,
) -> None:
    _log.debug(
        "subprocess.complete",
        executable=args[0],
        args=tuple(args[1:]),
        return_code=return_code,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        failure_category=failure.value if failure else None,
    )


def _probe_result_from_timeout(
    args: list[str],
    exc: subprocess.TimeoutExpired,
    started: datetime,
    timeout_seconds: int,
    attempt_number: int,
) -> ProbeResult:
    """Build a ProbeResult from a TimeoutExpired, preserving partial output.

    `subprocess.TimeoutExpired` carries any output the process produced
    before the kill. Preserve it for forensics — a connection that wrote
    half a handshake before stalling tells a different story from one
    that wrote nothing.
    """
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    partial_stdout = _decode_partial(exc.stdout)
    partial_stderr = _decode_partial(exc.stderr)
    timeout_marker = f"\n[qureddy] timeout after {timeout_seconds}s"
    stderr_with_marker = (
        partial_stderr + timeout_marker if partial_stderr else timeout_marker.lstrip("\n")
    )
    return _build_probe_result(
        args=args,
        stdout=partial_stdout,
        stderr=partial_stderr,
        parser_input=_combined_probe_output(partial_stdout, partial_stderr),
        stdout_excerpt=partial_stdout[:EXCERPT_LIMIT],
        stderr_excerpt_override=stderr_with_marker[:EXCERPT_LIMIT],
        return_code=-1,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        timeout_seconds=timeout_seconds,
        failure_category=FailureCategory.TLS_HANDSHAKE_FAILED,
    )


def _build_probe_result(
    *,
    args: list[str],
    stdout: str,
    stderr: str,
    parser_input: str,
    stdout_excerpt: str,
    return_code: int,
    duration_ms: int,
    attempt_number: int,
    timeout_seconds: int,
    failure_category: FailureCategory | None,
    stderr_excerpt_override: str | None = None,
) -> ProbeResult:
    """Build a ProbeResult from raw bytes + status fields.

    Hashes the unmodified stdout/stderr (so SHA-256 reflects what the
    process emitted, not our annotations). The caller may override
    `stderr_excerpt` (e.g., to append a `[qureddy] timeout after Ns`
    marker) without affecting the hash.
    """
    return ProbeResult(
        command=ProbeCommand(
            executable=args[0],
            args=tuple(args[1:]),
            timeout_seconds=timeout_seconds,
        ),
        return_code=return_code,
        stdout_sha256=hashlib.sha256(stdout.encode("utf-8", "replace")).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode("utf-8", "replace")).hexdigest(),
        parser_input=parser_input,
        stdout_excerpt=stdout_excerpt,
        stderr_excerpt=stderr_excerpt_override
        if stderr_excerpt_override is not None
        else stderr[:EXCERPT_LIMIT],
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        failure_category=failure_category,
    )


def _combined_probe_output(stdout: str, stderr: str) -> str:
    """Return parser input with an explicit stdout/stderr line boundary.

    `openssl s_client -brief` summary lines can appear on either stream.
    Joining with a newline preserves the parser's line-boundary contract
    so regex anchors cannot match across the stream boundary.
    """
    return f"{stdout}\n{stderr}"


# Re-exported so existing tests at tests/test_openssl_probe.py that
# import _classify_failure from this module keep working unchanged.
# Canonical implementation lives in `_classify.py`.
_classify_failure = classify_failure


def _decode_partial(value: bytes | str | None) -> str:
    """Decode partial subprocess output captured on TimeoutExpired.

    `subprocess.run(..., text=True)` normally returns str, but when
    `TimeoutExpired` fires `exc.stdout`/`exc.stderr` may be bytes (the
    default capture type) regardless of `text=True` — the conversion
    only runs on successful completion. We accept all three shapes
    (bytes, str, None) so the timeout branch never crashes when
    different Python or platform versions surface different types.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
