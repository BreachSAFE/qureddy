# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""OpenSSL probe constants."""

from packaging.version import Version

DEFAULT_TIMEOUT_SECONDS = 30
MIN_OPENSSL_VERSION = Version("3.5.0")
HYBRID_GROUP = "X25519MLKEM768"
CLASSICAL_GROUP = "X25519"
ENV_OVERRIDE = "QUREDDY_OPENSSL"
EXCERPT_LIMIT = 4096
