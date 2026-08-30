# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Name-component boundary tests for the structural PQC classifier (#532).

The classifier matched PQ/classical tokens by raw substring containment, so a
name that merely *contains* a token (``notmlkem-fake``, ``noecdh``) was
misclassified. On the SSH path the KEXINIT names are server-chosen, i.e.
attacker-controlled, so a fabricated name could be classified post-quantum.

These cases are the FIXED column of the issue's before/after table: real IANA
names keep classifying (regression guards for #330), and fabricated look-alikes
no longer match.
"""

from __future__ import annotations

import pytest

from qureddy.core import pqc

# (name, is_pq_kem, has_classical_half, is_hybrid_pq, is_pure_pq) — FIXED column.
_CASES = [
    # Real names — must keep classifying (regression guards).
    ("x25519mlkem768", True, True, True, False),
    ("secp256r1mlkem768", True, True, True, False),
    ("mlkem768x25519-sha256", True, True, True, False),
    ("sntrup761x25519-sha512@openssh.com", True, True, True, False),
    ("x25519-kyber-512r3-sha256-d00@amazon.com", True, True, True, False),
    ("mlkem1024nistp384-sha384", True, True, True, False),
    ("mlkem2048x25519-sha512", True, True, True, False),  # future size, guards #330
    ("curve25519-sha256", False, True, False, False),
    ("ecdh-sha2-nistp256", False, True, False, False),
    # Fabricated / look-alike names — must NOT classify as PQ (the bug).
    ("xkyber999x25519-sha256", False, True, False, False),  # kyber embedded after a letter
    ("notmlkem-fake@example.com", False, False, False, False),
    ("my-sntrup-lookalike@evil.test", False, False, False, False),
    ("kyberdyne-systems@skynet.test", False, False, False, False),
    ("mlkem768-noecdh-sha256", True, False, False, True),  # "noecdh" is not a classical half
    ("pure-mlkem1024-notx25519", True, False, False, True),  # "notx25519" is not classical
]


@pytest.mark.parametrize(("name", "is_kem", "classical_half", "hybrid", "pure"), _CASES)
def test_name_component_boundary(
    name: str, is_kem: bool, classical_half: bool, hybrid: bool, pure: bool
) -> None:
    assert pqc.is_pq_kem(name) is is_kem, "is_pq_kem"
    assert pqc.has_classical_half(name) is classical_half, "has_classical_half"
    assert pqc.is_hybrid_pq(name) is hybrid, "is_hybrid_pq"
    assert pqc.is_pure_pq(name) is pure, "is_pure_pq"
    assert not (hybrid and pure)


def test_category_not_shadowed_by_substring() -> None:
    """A fabricated name must not resolve to a KEM category either."""
    assert pqc.pq_kem_category("notmlkem-fake@example.com") is None
    assert pqc.pq_kem_category("kyberdyne-systems@skynet.test") is None
    # real names still resolve
    assert pqc.pq_kem_category("x25519mlkem768") == ("ML-KEM-768", 3)
