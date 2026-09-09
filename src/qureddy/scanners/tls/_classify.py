# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""OpenSSL stderr classifier.

Maps a nonzero OpenSSL run's stderr to a `FailureCategory` via a
substring-signature table. Returns the most specific category whose
needle is present in stderr (case-insensitive); falls back to
`TLS_HANDSHAKE_FAILED` for unknown shapes and emits a WARNING with a
SHA-256 fingerprint so novel failure modes can be added to the table
over time.

Pattern order is significant: more-specific patterns come first. Every
specific category (`TARGET_CONNECT_FAILED`, `SNI_REQUIRED_OR_WRONG`,
`MIDDLEBOX_OR_MTU_FAILURE`) drives retry policy and produces more
actionable findings than the generic `TLS_HANDSHAKE_FAILED` fallback.
"""

from __future__ import annotations

import hashlib

from qureddy.core.logging import get_logger
from qureddy.core.models import FailureCategory

_log = get_logger(__name__)
_FINGERPRINT_LEN = 16
_STDERR_PREVIEW_LEN = 120


# These signatures identify a peer alerting that a forced capability offer is
# unacceptable. Keep them separate from ambiguous local errors such as
# ``no shared cipher``; those do not prove that the peer made the decision.
_DECLINE_SIGNATURES: tuple[str, ...] = (
    "ssl alert number 40",  # handshake_failure
    "alert handshake failure",
    "ssl alert number 70",  # protocol_version
    "alert protocol version",
    "ssl alert number 71",  # insufficient_security
    "alert insufficient security",
)
_UNKNOWN_FAILURE_MARKERS: tuple[str, ...] = (
    "error",
    "failure",
    "failed",
    "errno",
    "timeout",
    "reset",
    "eof",
)


def is_server_decline(transcript: str) -> bool:
    """Return whether a forced capability probe was declined by the peer.

    OpenSSL reports a peer rejecting an offered TLS 1.3 group with a protocol
    alert. This is a valid result for a capability probe, not evidence that
    the endpoint or the local probe failed. Keep the predicate separate from
    ``classify_failure`` because these alerts remain genuine handshake
    failures when no deliberate capability offer is in scope.
    """
    normalized = transcript.casefold()
    return any(signature in normalized for signature in _DECLINE_SIGNATURES)


def _is_unambiguous_decline(transcript: str) -> bool:
    """Require every non-empty transcript line to carry a decline signature.

    A decline substring embedded beside an otherwise unknown error is not
    enough to turn a failed probe into negative capability evidence. Known
    OpenSSL alert lines may include their normal error prefix on the same
    line, so line-level matching preserves those transcripts while keeping
    unfamiliar companion output conservative.
    """
    lines = tuple(line.casefold() for line in transcript.splitlines() if line.strip())
    return bool(lines) and all(
        any(signature in line for signature in _DECLINE_SIGNATURES)
        or not any(marker in line for marker in _UNKNOWN_FAILURE_MARKERS)
        for line in lines
    )


_STDERR_SIGNATURES: tuple[tuple[str, FailureCategory], ...] = (
    # DNS / resolver failures → connect failed
    ("name or service not known", FailureCategory.TARGET_CONNECT_FAILED),
    ("could not resolve", FailureCategory.TARGET_CONNECT_FAILED),
    ("nodename nor servname provided", FailureCategory.TARGET_CONNECT_FAILED),
    ("temporary failure in name resolution", FailureCategory.TARGET_CONNECT_FAILED),
    ("getaddrinfo", FailureCategory.TARGET_CONNECT_FAILED),
    # TCP-layer connect failures
    ("connection refused", FailureCategory.TARGET_CONNECT_FAILED),
    ("connect:errno", FailureCategory.TARGET_CONNECT_FAILED),
    ("connect: errno", FailureCategory.TARGET_CONNECT_FAILED),
    ("connection timed out", FailureCategory.TARGET_CONNECT_FAILED),
    ("operation timed out", FailureCategory.TARGET_CONNECT_FAILED),
    ("no route to host", FailureCategory.TARGET_CONNECT_FAILED),
    ("network is unreachable", FailureCategory.TARGET_CONNECT_FAILED),
    ("host is down", FailureCategory.TARGET_CONNECT_FAILED),
    ("host unreachable", FailureCategory.TARGET_CONNECT_FAILED),
    # SNI failures
    ("unrecognized name", FailureCategory.SNI_REQUIRED_OR_WRONG),
    ("tlsv1 unrecognized name", FailureCategory.SNI_REQUIRED_OR_WRONG),
    ("alert unrecognized name", FailureCategory.SNI_REQUIRED_OR_WRONG),
    ("ssl alert number 112", FailureCategory.SNI_REQUIRED_OR_WRONG),
    # Middlebox / MTU patterns — listed before the generic handshake
    # alerts because broken pipe / connection reset are reset-shaped,
    # not handshake-shaped, and matter for hybrid-PQ MTU bugs in the wild.
    ("epipe", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ("broken pipe", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ("connection reset by peer", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ("ssl_read returned 0", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ("ssl_read_internal", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ("unexpected eof while reading", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ("message too long", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ("fragmentation needed", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ("premature close", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    # TLS handshake-level alerts (client + server)
    *((signature, FailureCategory.TLS_HANDSHAKE_FAILED) for signature in _DECLINE_SIGNATURES),
    ("inappropriate fallback", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("ssl alert number 86", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("no shared cipher", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("no ciphers available", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("no shared groups", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("no protocols available", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("wrong version number", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("unsupported protocol", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("internal error", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("ssl alert number 80", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("decode error", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("ssl alert number 50", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("decrypt error", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("ssl alert number 51", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("bad record mac", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("tlsv1 alert", FailureCategory.TLS_HANDSHAKE_FAILED),
)


def classify_failure(stderr: str) -> FailureCategory:
    """Map a nonzero OpenSSL run's stderr to a `FailureCategory`.

    On unknown shapes, logs a WARNING with a SHA-256 fingerprint, the
    stderr length, and the first 120 bytes so operators can grep for
    novel failure signatures and add them to the table over time.

    Falls back to `TLS_HANDSHAKE_FAILED` because every handshake failure
    is at least a handshake failure.
    """
    category, _ = classify_failure_detail(stderr)
    return category


def classify_failure_detail(stderr: str) -> tuple[FailureCategory, bool]:
    """Return the failure category and whether a known signature matched.

    The boolean preserves the distinction between a known handshake failure
    and the conservative ``TLS_HANDSHAKE_FAILED`` fallback. Probe capability
    handling may reinterpret only the former as a peer decline; treating the
    fallback as a match would turn an unfamiliar failure transcript into
    positive capability evidence.
    """
    if not stderr:
        return FailureCategory.TLS_HANDSHAKE_FAILED, False
    lower = stderr.lower()
    for needle, category in _STDERR_SIGNATURES:
        if needle in lower:
            matched = not (
                category is FailureCategory.TLS_HANDSHAKE_FAILED
                and needle in _DECLINE_SIGNATURES
                and not _is_unambiguous_decline(stderr)
            )
            return category, matched
    fingerprint = hashlib.sha256(stderr.encode("utf-8", errors="replace")).hexdigest()[
        :_FINGERPRINT_LEN
    ]
    _log.warning(
        "openssl.unrecognized_stderr_signature",
        stderr_fingerprint=fingerprint,
        stderr_length=len(stderr),
        stderr_first_120=stderr[:_STDERR_PREVIEW_LEN],
        defaulted_to=FailureCategory.TLS_HANDSHAKE_FAILED.value,
    )
    return FailureCategory.TLS_HANDSHAKE_FAILED, False
