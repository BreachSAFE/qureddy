# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared structural PQC classification (#330) — one source for TLS + SSH + future callers.

Structural (case-insensitive substring), not an allowlist, so a new ML-KEM/Kyber group
spelling classifies without a code change — this is what the TLS path was missing (it matched
only the literal ``X25519MLKEM768``, a false negative on every other standardized PQ hybrid).
A "hybrid" group carries a PQ KEM plus a classical half; a "pure PQ" group is the KEM alone.
"""

from __future__ import annotations

_PQ_KEM_TOKENS = ("mlkem", "ml-kem", "sntrup", "kyber")

# (token, canonical name, NIST post-quantum category). Longer/more-specific tokens first so
# "kyber-1024" is not shadowed by "kyber". ML-KEM categories per FIPS 203 (512/768/1024 =
# cat 1/3/5); Kyber round-3 shares them; sntrup761 is a documented conservative estimate (2).
_PQ_KEM_CATEGORY: tuple[tuple[str, str, int], ...] = (
    ("mlkem1024", "ML-KEM-1024", 5),
    ("ml-kem-1024", "ML-KEM-1024", 5),
    ("mlkem768", "ML-KEM-768", 3),
    ("ml-kem-768", "ML-KEM-768", 3),
    ("mlkem512", "ML-KEM-512", 1),
    ("ml-kem-512", "ML-KEM-512", 1),
    ("kyber-1024", "Kyber-1024", 5),
    ("kyber1024", "Kyber-1024", 5),
    ("kyber-768", "Kyber-768", 3),
    ("kyber768", "Kyber-768", 3),
    ("kyber-512", "Kyber-512", 1),
    ("kyber512", "Kyber-512", 1),
    ("sntrup761", "sntrup761", 2),
)

# Classical "half" markers, so a hybrid (PQ + classical) is told apart from a pure-PQ group.
_CLASSICAL_HALF = (
    "x25519",
    "x448",
    "secp256",
    "secp384",
    "secp521",
    "nistp256",
    "nistp384",
    "nistp521",
    "curve25519",
    "prime256v1",
    "ecdh",
)


def is_pq_kem(name: str) -> bool:
    """True if the group/KEX name carries any post-quantum KEM."""
    lowered = name.lower()
    return any(token in lowered for token in _PQ_KEM_TOKENS)


def pq_kem_category(name: str) -> tuple[str, int] | None:
    """Return ``(canonical KEM name, NIST category)`` for a PQ group, or None if not PQ."""
    lowered = name.lower()
    for token, canonical, level in _PQ_KEM_CATEGORY:
        if token in lowered:
            return canonical, level
    return None


def has_classical_half(name: str) -> bool:
    """True if the name carries a classical (ECDH/X25519/NIST-curve) component."""
    lowered = name.lower()
    return any(token in lowered for token in _CLASSICAL_HALF)


def is_hybrid_pq(name: str) -> bool:
    """PQ KEM combined with a classical half (X25519MLKEM768, SecP256r1MLKEM768, ...)."""
    return is_pq_kem(name) and has_classical_half(name)


def is_pure_pq(name: str) -> bool:
    """PQ KEM with no classical half (a future ML-KEM-only group)."""
    return is_pq_kem(name) and not has_classical_half(name)
