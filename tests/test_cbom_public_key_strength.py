# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""RSA classical-strength citations must match their source (#531).

The public-key emitter attributed its strength table to "NIST SP 800-57 Part 1
Rev.5, Table 2", but Table 2 defines no 4096-bit (or 1024-bit) row. The 152 value
for RSA-4096 was an interpolation emitted under a citation that does not contain
it. The comment's own contract says off-table sizes yield no claimed strength, so
an off-table size must return ``None``.
"""

from __future__ import annotations

from qureddy.output.cbom_public_key import classify_public_key


def _strength(algorithm: str, bits: int) -> int | None:
    asset = classify_public_key(algorithm, bits)
    assert asset is not None
    return asset.properties.classical_security_level


def test_rsa_4096_is_off_table_no_claimed_strength() -> None:
    # 4096 is NOT a NIST SP 800-57 Table 2 row -> no claimed strength (was 152).
    assert _strength("rsaEncryption", 4096) is None


def test_rsa_1024_is_off_table_no_claimed_strength() -> None:
    # 1024 is likewise off Table 2 (its rows start at 2048).
    assert _strength("rsaEncryption", 1024) is None


def test_standard_table2_rsa_sizes_unchanged() -> None:
    assert _strength("rsaEncryption", 2048) == 112
    assert _strength("rsaEncryption", 3072) == 128
    assert _strength("rsaEncryption", 7680) == 192
    assert _strength("rsaEncryption", 15360) == 256
