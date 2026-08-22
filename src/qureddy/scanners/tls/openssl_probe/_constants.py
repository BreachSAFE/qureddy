# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""OpenSSL probe constants."""

from packaging.version import Version

DEFAULT_TIMEOUT_SECONDS = 30
PINNED_OPENSSL_VERSION = Version("3.5.7")
# Public compatibility alias for the 0.2 API. The runtime contract is an
# exact pin, not a minimum-version range; remove this alias only in a
# deliberate breaking release.
MIN_OPENSSL_VERSION = PINNED_OPENSSL_VERSION
HYBRID_GROUP = "X25519MLKEM768"
# #337: the standardized PQ hybrid TLS groups (draft-ietf-tls-ecdhe-mlkem / RFC 9370 era),
# all supported by the pinned OpenSSL 3.5.7. HYBRID_GROUP (first) stays the primary readiness
# probe; the rest are supplementary coverage probes so a server that supports only a
# non-default hybrid is still detected. Order = primary first.
HYBRID_GROUPS = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
CLASSICAL_GROUP = "X25519"
ENV_OVERRIDE = "QUREDDY_OPENSSL"
EXCERPT_LIMIT = 4096
