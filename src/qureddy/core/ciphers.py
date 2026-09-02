# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-neutral cipher classification shared by collectors and outputs."""

from __future__ import annotations

WEAK_CIPHER_MARKERS: tuple[str, ...] = (
    "3DES",
    "DES",
    "RC4",
    "RC2",
    "NULL",
    "EXPORT",
    "MD5",
    "ADH",
    "AECDH",
)


def _aes_classical_bits(lowered: str) -> int | None:
    """Return AES key strength for an already-lowercased cipher name."""
    for size in (256, 192, 128):
        if (
            f"aes{size}" in lowered
            or f"aes-{size}" in lowered
            or f"aes_{size}" in lowered
            or ("aes" in lowered and lowered.endswith(f"_{size}"))
        ):
            return size
    return None


def cipher_classical_bits(name: str) -> int | None:
    """Return the classical key strength of a symmetric cipher when established."""
    lowered = name.lower()
    if "chacha20" in lowered:
        return 256
    if "3des" in lowered or "des-cbc3" in lowered:
        return 112
    return _aes_classical_bits(lowered)


def cipher_primitive(name: str) -> str:
    """Return the protocol-neutral primitive vocabulary for a symmetric cipher."""
    lowered = name.lower()
    if "gcm" in lowered or "chacha20-poly1305" in lowered or "ccm" in lowered:
        return "ae"
    if "rc4" in lowered or "arcfour" in lowered:
        return "stream-cipher"
    return "block-cipher"


def has_weak_cipher(accepted_ciphers: tuple[str, ...]) -> bool:
    """Return whether any accepted cipher matches a known-weak marker."""
    return any(
        marker in cipher.upper() for cipher in accepted_ciphers for marker in WEAK_CIPHER_MARKERS
    )
