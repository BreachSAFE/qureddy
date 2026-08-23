# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Domain-specific exception hierarchy for QuReddy."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from qureddy.core.models import OpenSSLDependency


class QureddyError(Exception):
    """Base class for all QuReddy errors."""


class CbomError(QureddyError):
    """CBOM construction or semantic validation failed internally.

    This is an implementation/output failure, not a target or local-tool
    failure, and therefore maps to the CLI's internal-error exit code (70).
    """


class CertificateParseError(QureddyError):
    """The certificate parser received an invalid internal input."""


class TargetParseError(QureddyError):
    """User input could not be parsed into a valid ScanTarget."""


class _LocalOpenSSLProblem(QureddyError):
    """Base for local-OpenSSL failure modes.

    Each subclass carries the populated `OpenSSLDependency` from the
    capability check that detected the problem so consumers don't need
    to re-probe. Avoids a wasted subprocess invocation and a TOCTOU
    window where a second probe could observe different state.
    """

    def __init__(self, message: str, *, dependency: OpenSSLDependency | None = None) -> None:
        super().__init__(message)
        self.dependency = dependency


class LocalOpenSSLMissing(_LocalOpenSSLProblem):
    """OpenSSL binary not found at any expected path.

    Maps to FailureCategory.LOCAL_OPENSSL_MISSING. Triggers exit code 3.
    """


class LocalOpenSSLBroken(_LocalOpenSSLProblem):
    """OpenSSL exists but exits nonzero during capability detection.

    Maps to FailureCategory.LOCAL_OPENSSL_BROKEN. Triggers exit code 3.
    """


class LocalOpenSSLVersionUnreadable(_LocalOpenSSLProblem):
    """OpenSSL version output could not be parsed.

    Maps to FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE. Triggers exit code 3.
    """


class LocalOpenSSLIsLibreSSL(_LocalOpenSSLProblem):
    """The binary at the resolved path is LibreSSL, not OpenSSL.

    Maps to FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL. Triggers exit code 3.
    Distinct from LocalOpenSSLVersionUnreadable: LibreSSL's version string
    parses fine, it's just a different product that doesn't support the
    PQC groups this scanner requires. Apple ships it as /usr/bin/openssl
    on every macOS install by default (issue #188).
    """


class LocalOpenSSLTooOld(_LocalOpenSSLProblem):
    """OpenSSL is below 3.5.7.

    Maps to FailureCategory.LOCAL_OPENSSL_TOO_OLD. Triggers exit code 3.
    """


class LocalOpenSSLVersionMismatch(_LocalOpenSSLProblem):
    """OpenSSL is parseable but does not match the pinned 3.5.7 release.

    Maps to FailureCategory.LOCAL_OPENSSL_VERSION_MISMATCH. Triggers exit code 3.
    """


class LocalOpenSSLLacksGroup(_LocalOpenSSLProblem):
    """OpenSSL does not list X25519MLKEM768 as a TLS 1.3 group.

    Maps to FailureCategory.LOCAL_OPENSSL_LACKS_GROUP. Triggers exit code 3.
    """


class RetryConfigError(QureddyError):
    """Retry configuration is invalid (unknown category, out-of-range value)."""


# Note on architecture: target-connect / TLS-handshake / parser-classification
# failures are NOT modeled as raised exceptions. They flow as typed values
# on `ProbeResult.failure_category` and `ParsedNegotiation.failure_category`
# (the FailureCategory enum), classified at the probe/parser layer and
# carried through to the JSON `summary.failure_category`. Keep that as
# the project's failure model — failures-as-data — instead of failures-
# as-control-flow. New failure modes go in the enum, not here.


class SSHProbeError(QureddyError):
    """An SSH probe failed: connect/timeout, or a malformed/oversized response."""
