# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-neutral weak-cipher classification shared by collectors and outputs."""

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


def has_weak_cipher(accepted_ciphers: tuple[str, ...]) -> bool:
    """Return whether any accepted cipher matches a known-weak marker."""
    return any(
        marker in cipher.upper() for cipher in accepted_ciphers for marker in WEAK_CIPHER_MARKERS
    )
