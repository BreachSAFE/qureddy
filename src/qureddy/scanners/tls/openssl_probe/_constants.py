# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""OpenSSL probe constants."""

from __future__ import annotations

from packaging.version import Version

DEFAULT_TIMEOUT_SECONDS = 30
PINNED_OPENSSL_VERSION = Version("3.5.7")
# Public compatibility alias for the 0.2 API. The validated baseline remains
# 3.5.7, while the runtime contract accepts patched releases on the 3.5 LTS
# series (issue #358).
MIN_OPENSSL_VERSION = PINNED_OPENSSL_VERSION
OPENSSL_LTS_SERIES = (3, 5)
OPENSSL_LTS_LABEL = ".".join(str(part) for part in OPENSSL_LTS_SERIES)
OPENSSL_LTS_FORMULA = f"openssl@{OPENSSL_LTS_LABEL}"


def is_supported_series(version: Version) -> bool:
    """Return whether ``version`` is a supported OpenSSL LTS release."""
    return (version.major, version.minor) == OPENSSL_LTS_SERIES


HYBRID_GROUP = "X25519MLKEM768"
# #337: the standardized PQ hybrid TLS groups (draft-ietf-tls-ecdhe-mlkem / RFC 9370 era),
# all supported by the pinned OpenSSL 3.5.7. HYBRID_GROUP (first) stays the primary readiness
# probe; the rest are supplementary coverage probes so a server that supports only a
# non-default hybrid is still detected. Order = primary first.
HYBRID_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
# OpenSSL 3.5 supports these pure ML-KEM TLS groups independently of the hybrid groups.
# Force each one so server preference cannot hide support for another parameter set (#521).
PURE_PQ_GROUPS = ("MLKEM512", "MLKEM768", "MLKEM1024")
CLASSICAL_GROUP = "X25519"
ENV_OVERRIDE = "QUREDDY_OPENSSL"
LEGACY_ENV_OVERRIDE = "QUREDDY_LEGACY_OPENSSL"
EXCERPT_LIMIT = 4096
