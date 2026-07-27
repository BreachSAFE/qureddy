# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Public OpenSSL capability and TLS-probe API."""

from qureddy.scanners.tls._classify import classify_failure as _classify_failure
from qureddy.scanners.tls.openssl_probe._constants import (
    CLASSICAL_GROUP,
    DEFAULT_TIMEOUT_SECONDS,
    EXCERPT_LIMIT,
    HYBRID_GROUP,
    MIN_OPENSSL_VERSION,
)
from qureddy.scanners.tls.openssl_probe.capability import (
    probe_capability,
    raise_if_unusable,
    resolve_openssl_path,
)
from qureddy.scanners.tls.openssl_probe.probe import (
    run_classical_probe,
    run_hybrid_probe,
)

__all__ = [
    "CLASSICAL_GROUP",
    "DEFAULT_TIMEOUT_SECONDS",
    "EXCERPT_LIMIT",
    "HYBRID_GROUP",
    "MIN_OPENSSL_VERSION",
    "_classify_failure",
    "probe_capability",
    "raise_if_unusable",
    "resolve_openssl_path",
    "run_classical_probe",
    "run_hybrid_probe",
]
