# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Compatibility imports for the moved core SSH algorithm taxonomy."""

from __future__ import annotations

from qureddy.core.ssh_algorithms import (
    KexClass,
    classify_kex,
    classify_offered_algorithm,
    is_classical_kex,
    is_pq_hybrid_kex,
    pq_hybrid_kex,
    terrapin_susceptible_modes,
    weak_cipher_note,
    weak_host_key_note,
    weak_host_keys,
    weak_kex,
    weak_kex_reasons,
    weak_mac_note,
)

__all__ = [
    "KexClass",
    "classify_kex",
    "classify_offered_algorithm",
    "is_classical_kex",
    "is_pq_hybrid_kex",
    "pq_hybrid_kex",
    "terrapin_susceptible_modes",
    "weak_cipher_note",
    "weak_host_key_note",
    "weak_host_keys",
    "weak_kex",
    "weak_kex_reasons",
    "weak_mac_note",
]
