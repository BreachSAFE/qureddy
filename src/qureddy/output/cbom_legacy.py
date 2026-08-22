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
from cyclonedx.model.crypto import AlgorithmProperties, CryptoPrimitive

from qureddy.output.cbom_assets import add_algorithm_assets
from qureddy.scanners.tls.legacy_probe import has_weak_cipher

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import ScanResult

LEGACY_CIPHER_EVIDENCE_TYPE = "tls.legacy.cipher"


def _legacy_cipher_bits(name: str) -> int | None:
    """Classical key strength (bits) for a TLS cipher-suite name, or None if unknown/broken."""
    upper = name.upper()
    if "CHACHA20" in upper:
        return 256
    if "3DES" in upper or "DES-CBC3" in upper:
        return 112  # 3DES effective strength (NIST SP 800-57)
    for size in (256, 192, 128):
        if f"AES{size}" in upper or f"AES-{size}" in upper or f"AES_{size}" in upper:
            return size
    # RC4 / single-DES / NULL / EXPORT: no honest positive strength to claim.
    return None


def _legacy_cipher_primitive(name: str) -> CryptoPrimitive:
    """CycloneDX primitive for a TLS cipher (all classical today)."""
    upper = name.upper()
    if "GCM" in upper or "CHACHA20-POLY1305" in upper or "CCM" in upper:
        return CryptoPrimitive("ae")  # authenticated encryption
    if "RC4" in upper:
        return CryptoPrimitive("stream-cipher")
    return CryptoPrimitive("block-cipher")  # CBC, 3DES, etc.


def _legacy_cipher_properties(name: str) -> AlgorithmProperties:
    """AlgorithmProperties for a legacy TLS cipher: classical strength, never a quantum level."""
    return AlgorithmProperties(
        primitive=_legacy_cipher_primitive(name),
        classical_security_level=_legacy_cipher_bits(name),
    )


def _legacy_cipher_verdict(name: str) -> list[Property]:
    """Algorithm-intrinsic verdict properties for a legacy cipher.

    classically_weak for a known-weak marker; otherwise quantum_vulnerable (classical crypto
    has no post-quantum confidentiality).
    """
    if has_weak_cipher((name,)):
        return [
            Property(name="qureddy:readiness", value="classically_weak"),
            Property(name="qureddy:severity", value="high"),
        ]
    return [
        Property(name="qureddy:readiness", value="quantum_vulnerable"),
        Property(name="qureddy:severity", value="low"),
    ]


def add_legacy_cipher_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit one crypto-asset component per accepted legacy TLS cipher (#303)."""
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=lambda e: (
            e.negotiated_group if e.evidence_type == LEGACY_CIPHER_EVIDENCE_TYPE else None
        ),
        algorithm_properties=_legacy_cipher_properties,
        extra_properties=_legacy_cipher_verdict,
    )
