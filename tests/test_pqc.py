# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Known-answer tests for the shared structural PQC classifier (#330)."""

from __future__ import annotations

import pytest

from qureddy.core import pqc


@pytest.mark.parametrize(
    ("name", "is_kem", "hybrid", "pure"),
    [
        # TLS standardized hybrids — the false-negative set (only X25519MLKEM768 matched before).
        ("X25519MLKEM768", True, True, False),
        ("SecP256r1MLKEM768", True, True, False),
        ("SecP384r1MLKEM1024", True, True, False),
        ("X25519Kyber768", True, True, False),
        # SSH hybrids.
        ("mlkem768x25519-sha256", True, True, False),
        ("sntrup761x25519-sha512", True, True, False),
        ("mlkem768nistp256-sha256", True, True, False),
        # Pure PQ (no classical half) — future ML-KEM-only groups.
        ("mlkem768", True, False, True),
        ("ML-KEM-1024", True, False, True),
        # Classical — not PQ at all.
        ("X25519", False, False, False),
        ("secp256r1", False, False, False),
        ("ecdh-sha2-nistp256", False, False, False),
        ("diffie-hellman-group14-sha256", False, False, False),
    ],
)
def test_structural_classification(name: str, is_kem: bool, hybrid: bool, pure: bool) -> None:
    assert pqc.is_pq_kem(name) is is_kem
    assert pqc.is_hybrid_pq(name) is hybrid
    assert pqc.is_pure_pq(name) is pure
    # hybrid and pure are mutually exclusive; both imply is_pq_kem.
    assert not (hybrid and pure)


@pytest.mark.parametrize(
    ("name", "canonical", "level"),
    [
        ("X25519MLKEM768", "ML-KEM-768", 3),
        ("SecP384r1MLKEM1024", "ML-KEM-1024", 5),
        ("mlkem512", "ML-KEM-512", 1),
        ("X25519Kyber768", "Kyber-768", 3),
        ("sntrup761x25519-sha512", "sntrup761", 2),
    ],
)
def test_kem_category(name: str, canonical: str, level: int) -> None:
    assert pqc.pq_kem_category(name) == (canonical, level)


def test_classical_has_no_category() -> None:
    assert pqc.pq_kem_category("X25519") is None
    assert pqc.pq_kem_category("ecdh-sha2-nistp256") is None
