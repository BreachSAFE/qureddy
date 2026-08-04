# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
    ("alert handshake failure", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("ssl alert number 40", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("alert protocol version", FailureCategory.TLS_HANDSHAKE_FAILED),
    ("ssl alert number 70", FailureCategory.TLS_HANDSHAKE_FAILED),
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
    if not stderr:
        return FailureCategory.TLS_HANDSHAKE_FAILED
    lower = stderr.lower()
    for needle, category in _STDERR_SIGNATURES:
        if needle in lower:
            return category
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
    return FailureCategory.TLS_HANDSHAKE_FAILED
