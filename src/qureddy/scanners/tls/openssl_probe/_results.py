# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Construction of immutable OpenSSL probe results."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from qureddy.core.models import FailureCategory, ProbeCommand, ProbeResult
from qureddy.scanners.tls.openssl_probe._constants import EXCERPT_LIMIT


def result_from_timeout(
    args: list[str],
    stdout: bytes | str | None,
    stderr: bytes | str | None,
    started: datetime,
    timeout_seconds: int,
    attempt_number: int,
) -> ProbeResult:
    """Preserve partial output from a timed-out handshake.

    ``stdout`` / ``stderr`` are the partial streams captured before the kill
    (already decoded ``str`` when they come from ``OpenSSLOutcome``, or the raw
    ``bytes`` / ``None`` a ``TimeoutExpired`` carries) — ``decode_partial``
    normalizes either shape.
    """
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    stdout = decode_partial(stdout)
    stderr = decode_partial(stderr)
    marker = f"\n[qureddy] timeout after {timeout_seconds}s"
    annotated_stderr = stderr + marker if stderr else marker.lstrip("\n")
    parser_input = combined_probe_output(stdout, stderr)
    # A timeout with no "CONNECTED(...)" line means openssl never completed the TCP
    # connect: the target is unreachable (a firewall black-hole), not a handshake
    # failure. Classifying that as TARGET_CONNECT_FAILED lets the unreachable
    # short-circuit skip the remaining probes instead of timing out on each one; a
    # timeout after CONNECTED is a genuine handshake stall and stays HANDSHAKE (#138).
    handshake_started = "CONNECTED" in parser_input
    return build_probe_result(
        args=args,
        stdout=stdout,
        stderr=stderr,
        parser_input=parser_input,
        stderr_excerpt_override=annotated_stderr[:EXCERPT_LIMIT],
        return_code=-1,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        timeout_seconds=timeout_seconds,
        failure_category=(
            FailureCategory.TLS_HANDSHAKE_FAILED
            if handshake_started
            else FailureCategory.TARGET_CONNECT_FAILED
        ),
    )


def build_probe_result(
    *,
    args: list[str],
    stdout: str,
    stderr: str,
    parser_input: str,
    return_code: int,
    duration_ms: int,
    attempt_number: int,
    timeout_seconds: int,
    failure_category: FailureCategory | None,
    stderr_excerpt_override: str | None = None,
) -> ProbeResult:
    """Build a result, deriving each stream's sha256 and excerpt from one value.

    Evidence-integrity contract (issue #202): for each stream the sha256 and
    the excerpt are computed here from one local value — ``stdout_sha256`` and
    ``stdout_excerpt`` both come from ``stdout``, and the excerpt is exactly
    its first ``EXCERPT_LIMIT`` characters. A consumer given the excerpt and
    the full stream can therefore verify that every byte shown in the excerpt
    is covered by the attesting hash: the excerpt is a verifiable prefix of the
    hashed stream. The same holds for stderr, except the timeout branch may
    pass ``stderr_excerpt_override`` to append a clearly namespaced
    ``[qureddy] ...`` annotation AFTER the raw stderr; the raw stderr stays a
    prefix of the shown excerpt, so no target byte is left unattested.

    ``parser_input`` (combined stdout+stderr) is a SEPARATE field the parser
    consumes; it is deliberately NEVER used to derive an excerpt. The #202 bug
    was exactly that: the caller passed ``parser_input[:EXCERPT_LIMIT]`` as the
    stdout excerpt, so an empty-stdout probe emitted the empty-string hash next
    to an excerpt showing the stderr transcript — the hash attested a different
    byte stream than the excerpt was derived from.
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
        stdout_excerpt=stdout[:EXCERPT_LIMIT],
        stderr_excerpt=stderr_excerpt_override
        if stderr_excerpt_override is not None
        else stderr[:EXCERPT_LIMIT],
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        failure_category=failure_category,
    )


def combined_probe_output(stdout: str, stderr: str) -> str:
    """Join streams with an explicit parser line boundary."""
    return f"{stdout}\n{stderr}"


def decode_partial(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
