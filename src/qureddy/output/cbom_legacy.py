# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Legacy TLS cipher crypto-asset emission for the CBOM (#303).

The legacy sweep (legacy_probe.py) records the ciphers a target accepts on TLS 1.0/1.1/1.2.
Those used to live only as free text in an evidence notes blob; this module emits each as a
first-class ``cryptographic-asset`` component so the CBOM inventories the weak/legacy cipher
surface for compliance consumers. Classification is a fact of the cipher name (primitive +
classical strength + known-weak marker); the verdict property is algorithm-intrinsic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cyclonedx.model import Property
from cyclonedx.model.crypto import AlgorithmProperties

from qureddy.core.ciphers import has_weak_cipher
from qureddy.output.cbom_assets import (
    add_algorithm_assets,
    select_by_evidence_type,
    verdict_pairs,
)
from qureddy.output.cbom_cipher import cipher_classical_bits, cipher_primitive

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import ScanResult

LEGACY_CIPHER_EVIDENCE_TYPE = "tls.legacy.cipher"


def _legacy_cipher_properties(name: str) -> AlgorithmProperties:
    """AlgorithmProperties for a legacy TLS cipher: classical strength, never a quantum level.

    Classification is shared with the TLS 1.3 and SSH cipher emitters (#315).
    """
    return AlgorithmProperties(
        primitive=cipher_primitive(name),
        classical_security_level=cipher_classical_bits(name),
    )


def _legacy_cipher_verdict(name: str) -> list[Property]:
    """Algorithm-intrinsic verdict properties for a legacy cipher.

    classically_weak for a known-weak marker; otherwise quantum_vulnerable (classical crypto
    has no post-quantum confidentiality).
    """
    pairs = (
        verdict_pairs("classically_weak", "high")
        if has_weak_cipher((name,))
        else verdict_pairs("quantum_vulnerable", "low")
    )
    return [Property(name=prop_name, value=value) for prop_name, value in pairs]


def add_legacy_cipher_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit one crypto-asset component per accepted legacy TLS cipher (#303)."""
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_by_evidence_type(LEGACY_CIPHER_EVIDENCE_TYPE),
        algorithm_properties=_legacy_cipher_properties,
        extra_properties=_legacy_cipher_verdict,
    )
