# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared symmetric-cipher classification for the CBOM (#315).

One place that maps a symmetric cipher name — a TLS cipher suite, a legacy TLS cipher, or an
SSH cipher — to its CycloneDX primitive and classical key strength, so the TLS, legacy, and
SSH emitters classify ciphers through identical logic instead of the per-emitter copies that
had already drifted (the legacy TLS copy matched `DES-CBC3` and uppercased; the SSH copy did
neither). Matching is case-insensitive substring, so it works across the three naming styles
(`TLS_AES_256_GCM_SHA384`, `AES256-GCM-SHA384`, `aes256-gcm@openssh.com`).
"""

from __future__ import annotations

from cyclonedx.model.crypto import CryptoPrimitive


def cipher_classical_bits(name: str) -> int | None:
    """Classical key strength (bits) of a symmetric cipher name, or None if unknown/broken.

    None for RC4, single-DES, NULL, and EXPORT ciphers: there is no honest positive strength
    to claim for them.
    """
    lowered = name.lower()
    if "chacha20" in lowered:
        return 256
    if "3des" in lowered or "des-cbc3" in lowered:
        return 112  # 3DES effective strength (NIST SP 800-57)
    for size in (256, 192, 128):
        if f"aes{size}" in lowered or f"aes-{size}" in lowered or f"aes_{size}" in lowered:
            return size
    return None


def cipher_primitive(name: str) -> CryptoPrimitive:
    """CycloneDX primitive for a symmetric cipher name (all classical today)."""
    lowered = name.lower()
    if "gcm" in lowered or "chacha20-poly1305" in lowered or "ccm" in lowered:
        return CryptoPrimitive.AE  # authenticated encryption
    if "rc4" in lowered or "arcfour" in lowered:
        return CryptoPrimitive("stream-cipher")
    return CryptoPrimitive("block-cipher")  # CBC, CTR, 3DES, etc.
