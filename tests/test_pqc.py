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


# --- #532 regression: anchored matching ------------------------------------------------
#
# Plain substring containment classified any name merely holding a token, so a
# server-chosen SSH KEX name read as post-quantum. SSH KEXINIT name-lists are
# arbitrary strings supplied by the peer, so this input is attacker-controlled.


@pytest.mark.parametrize(
    "name",
    [
        "xkyber999x25519-sha256",  # token glued behind a letter
        "notmlkem-fake@example.com",  # token inside a longer word
        "my-sntrup-lookalike@evil.test",  # token as a component, no parameter set
        "kyberdyne-systems@skynet.test",  # vendor name that merely starts with a token
    ],
)
def test_fabricated_name_is_not_post_quantum(name: str) -> None:
    """A name that only contains a KEM token carries no KEM (#532)."""
    assert pqc.is_pq_kem(name) is False
    assert pqc.is_hybrid_pq(name) is False
    assert pqc.is_pure_pq(name) is False
    assert pqc.pq_kem_category(name) is None


@pytest.mark.parametrize(
    "name",
    [
        "mlkem768-noecdh-sha256",  # "ecdh" behind a letter
        "pure-mlkem1024-notx25519",  # "x25519" behind a letter
    ],
)
def test_negated_classical_token_is_not_a_classical_half(name: str) -> None:
    """A classical token inside a longer word is not a classical half (#532)."""
    assert pqc.has_classical_half(name) is False
    assert pqc.is_pq_kem(name) is True
    assert pqc.is_pure_pq(name) is True


@pytest.mark.parametrize("name", ["X25519MLKEM768", "SecP256r1MLKEM768"])
def test_kem_token_may_follow_a_parameter_digit(name: str) -> None:
    """Guard for the anchor itself (#532).

    These are the two IANA TLS group names where the KEM token follows a digit. A
    left boundary of ``(?<![a-z0-9])`` rejects them, which is a false negative on the
    flagship hybrids and worse than the bug being fixed. Two drafts of the fix failed
    exactly here.
    """
    assert pqc.is_pq_kem(name) is True
    assert pqc.is_hybrid_pq(name) is True


def test_unreleased_parameter_set_still_classifies() -> None:
    """Structural matching must survive a new parameter set (#330).

    An allowlist of known parameter sets would reject this and reintroduce the
    false negative #330 fixed.
    """
    assert pqc.is_pq_kem("mlkem2048x25519-sha512") is True
    assert pqc.is_hybrid_pq("mlkem2048x25519-sha512") is True
    # No category is claimed for a parameter set we do not know.
    assert pqc.pq_kem_category("mlkem2048x25519-sha512") is None


def test_category_token_is_not_a_prefix_of_a_longer_number() -> None:
    """``kyber512`` must not match inside ``kyber5120`` (#532)."""
    assert pqc.pq_kem_category("kyber5120x25519") is None
    assert pqc.pq_kem_category("mlkem7680x25519") is None


def test_tokens_are_matched_literally_not_as_patterns() -> None:
    """Token tuples read as plain strings and must not act as regex metacharacters (#532)."""
    assert pqc.is_pq_kem("mlxkem768x25519") is False
    assert pqc.has_classical_half("xX25519") is False
