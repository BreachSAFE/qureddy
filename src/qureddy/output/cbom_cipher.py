# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Adapt shared symmetric-cipher classification to CycloneDX (#315).

The domain vocabulary lives in ``qureddy.core.ciphers``. This module preserves the
CycloneDX enum adapter used by TLS, legacy TLS, and SSH emitters.
"""

from __future__ import annotations

from cyclonedx.model.crypto import AlgorithmProperties, CryptoPrimitive

from qureddy.core.ciphers import cipher_classical_bits
from qureddy.core.ciphers import cipher_primitive as classify_cipher_primitive

__all__ = [
    "cipher_algorithm_properties",
    "cipher_classical_bits",
    "cipher_primitive",
    "mac_algorithm_properties",
]


def cipher_primitive(name: str) -> CryptoPrimitive:
    """CycloneDX primitive for a symmetric cipher name (all classical today)."""
    return CryptoPrimitive(classify_cipher_primitive(name))


def cipher_algorithm_properties(name: str) -> AlgorithmProperties:
    """Build the shared CycloneDX projection for a symmetric cipher."""
    return AlgorithmProperties(
        primitive=cipher_primitive(name),
        classical_security_level=cipher_classical_bits(name),
    )


def mac_algorithm_properties(_name: str) -> AlgorithmProperties:
    """Build the shared CycloneDX projection for a keyed hash."""
    return AlgorithmProperties(primitive=CryptoPrimitive.MAC)
