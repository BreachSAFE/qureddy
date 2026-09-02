# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Own protocol-neutral algorithm classification for output projections."""

from __future__ import annotations

import re
from typing import NamedTuple

from qureddy.core import pqc
from qureddy.core.signatures import classify_pqc_signature

_CLASSICAL_KEX_CURVES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![a-z0-9])x25519(?![a-z0-9])"), "curve25519"),
    (re.compile(r"(?<![a-z0-9])curve25519(?![a-z0-9])"), "curve25519"),
    (re.compile(r"(?<![a-z0-9])nistp256(?![a-z0-9])"), "P-256"),
    (re.compile(r"(?<![a-z0-9])nistp384(?![a-z0-9])"), "P-384"),
    (re.compile(r"(?<![a-z0-9])nistp521(?![a-z0-9])"), "P-521"),
)
_CLASSICAL_SIGNATURE_MARKERS = ("ecdsa", "rsa", "ed25519", "ed448", "dsa", "dss")


class AlgorithmProfile(NamedTuple):
    """Describe output-neutral key-exchange classification facts."""

    primitive: str
    nist_quantum_security_level: int | None
    parameter_set_identifier: str | None = None
    curve: str | None = None


def classify_key_exchange(name: str) -> AlgorithmProfile | None:
    """Classify a TLS or SSH key-exchange identifier conservatively."""
    lowered = name.lower()
    if pqc.is_pq_kem(name):
        parameters = pqc.pq_kem_category(name)
        parameter_set, level = parameters if parameters is not None else (None, None)
        return AlgorithmProfile("kem", level, parameter_set_identifier=parameter_set)
    for pattern, curve in _CLASSICAL_KEX_CURVES:
        if pattern.search(lowered):
            return AlgorithmProfile("key-agree", 0, curve=curve)
    if lowered.startswith("diffie-hellman"):
        return AlgorithmProfile("key-agree", 0)
    if lowered.startswith("rsa"):
        return AlgorithmProfile("pke", 0)
    return None


def classify_signature_algorithm(name: str) -> AlgorithmProfile | None:
    """Classify a certificate or host-key signature identifier conservatively."""
    classified = classify_pqc_signature(name)
    if classified is not None:
        parameter_set, level = classified
        return AlgorithmProfile("signature", level, parameter_set_identifier=parameter_set.upper())
    if any(marker in name.lower() for marker in _CLASSICAL_SIGNATURE_MARKERS):
        return AlgorithmProfile("signature", 0)
    return None
