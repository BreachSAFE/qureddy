# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""OpenSSL probe constants."""

from packaging.version import Version

DEFAULT_TIMEOUT_SECONDS = 30
PINNED_OPENSSL_VERSION = Version("3.5.7")
# Public compatibility alias for the 0.2 API. The runtime contract is an
# exact pin, not a minimum-version range; remove this alias only in a
# deliberate breaking release.
MIN_OPENSSL_VERSION = PINNED_OPENSSL_VERSION
HYBRID_GROUP = "X25519MLKEM768"
CLASSICAL_GROUP = "X25519"
ENV_OVERRIDE = "QUREDDY_OPENSSL"
EXCERPT_LIMIT = 4096
