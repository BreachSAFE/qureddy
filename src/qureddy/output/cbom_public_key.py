# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared endpoint public-key classification and CBOM emission (#313).

An endpoint's authentication public key — a TLS certificate's subject key today, an SSH host
key next (#291), a CA/chain key later — is the quantum-relevant asymmetric key: it is what a
harvest-now-decrypt-later adversary attacks. This module classifies such a key (algorithm
family + size -> primitive, classical strength, quantum verdict) and emits it as one CycloneDX
cryptographic-asset ALGORITHM component, protocol-agnostic so every scanner feeds the same
structure instead of reimplementing it. The parse source stays per-scanner; the classification
and emission are shared here.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING, NamedTuple

from cyclonedx.model import Property
from cyclonedx.model.crypto import AlgorithmProperties, CryptoPrimitive

from qureddy.output.cbom_assets import add_algorithm_component
from qureddy.scanners.tls.cert_sig import classify_pqc_signature

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.bom_ref import BomRef

# NIST SP 800-57 Part 1 Rev.5, Table 2: classical security strength (bits) by asymmetric
# key size. Only the standard sizes are listed; an off-table size yields no claimed strength.
_RSA_CLASSICAL_STRENGTH: MappingProxyType[int, int] = MappingProxyType(
    {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}
)
_EC_CLASSICAL_STRENGTH: MappingProxyType[int, int] = MappingProxyType(
    {255: 128, 256: 128, 384: 192, 448: 224, 521: 256}
)

# openssl "Public Key Algorithm:" names (and the SSH host-key identifiers #291 will pass)
# mapped to a family label. RSA is public-key encryption; EC/EdDSA/DSA leaf keys authenticate
# (sign) the handshake, so they carry the SIGNATURE primitive.
_PUBLIC_KEY_FAMILY: MappingProxyType[str, str] = MappingProxyType(
    {
        "rsaencryption": "RSA",
        "rsassa-pss": "RSA",
        "rsa-pss": "RSA",
        "id-ecpublickey": "EC",
        "ecpublickey": "EC",
        "id-ed25519": "Ed25519",
        "ed25519": "Ed25519",
        "id-ed448": "Ed448",
        "ed448": "Ed448",
        "dsaencryption": "DSA",
        "dsa": "DSA",
    }
)
# NIST SP 800-131A: RSA below 2048 bits is disallowed (classically weak), not merely
# quantum-vulnerable like a still-adequate classical key.
_RSA_MIN_ACCEPTABLE_BITS = 2048


class PublicKeyAsset(NamedTuple):
    """A classified endpoint public key ready to emit as one crypto-asset component."""

    name: str
    properties: AlgorithmProperties
    readiness: str
    severity: str


def classify_public_key(algorithm: str | None, bits: int | None) -> PublicKeyAsset | None:
    """Classify an endpoint public key by algorithm name + size, or None if unclassifiable.

    Protocol-agnostic: the caller supplies the algorithm name and size in bits from whatever
    it parsed (x509 text, SSH host key). A PQ signature key (ML-DSA / SLH-DSA) carries its
    NIST category and is quantum_safe; a classical asymmetric key (RSA / EC / EdDSA / DSA) has
    no post-quantum resistance (quantum_vulnerable), or classically_weak when undersized. An
    unrecognized algorithm returns None rather than fabricating a classification.
    """
    if not algorithm:
        return None
    classified = classify_pqc_signature(algorithm)
    if classified is not None:
        parameter_set, level = classified
        properties = AlgorithmProperties(
            primitive=CryptoPrimitive.SIGNATURE,
            parameter_set_identifier=parameter_set.upper(),
            nist_quantum_security_level=level,
        )
        return PublicKeyAsset(parameter_set.upper(), properties, "quantum_safe", "low")
    family = _PUBLIC_KEY_FAMILY.get(algorithm.lower())
    if family is None:
        return None
    if family == "RSA":
        primitive = CryptoPrimitive.PKE
        strength = _RSA_CLASSICAL_STRENGTH.get(bits) if bits else None
        weak = bits is not None and bits < _RSA_MIN_ACCEPTABLE_BITS
    else:
        primitive = CryptoPrimitive.SIGNATURE
        strength = _EC_CLASSICAL_STRENGTH.get(bits) if bits else None
        weak = False
    name = f"{family}-{bits}" if bits else family
    properties = AlgorithmProperties(
        primitive=primitive,
        classical_security_level=strength,
        nist_quantum_security_level=0,
    )
    readiness = "classically_weak" if weak else "quantum_vulnerable"
    severity = "high" if weak else "low"
    return PublicKeyAsset(name, properties, readiness, severity)


def add_public_key_component(
    bom: Bom,
    algorithm: str | None,
    bits: int | None,
    provides_edges: dict[str, list[str]],
) -> BomRef | None:
    """Emit one crypto-asset component for an endpoint public key; return its ref or None.

    None when the key cannot be classified, so a caller (e.g. the certificate emitter) simply
    leaves its reference unset rather than pointing at a fabricated component.
    """
    asset = classify_public_key(algorithm, bits)
    if asset is None:
        return None
    return add_algorithm_component(
        bom,
        name=asset.name,
        ref=f"crypto/algorithm/{asset.name.lower()}",
        algorithm_properties=asset.properties,
        provides_edges=provides_edges,
        properties=[
            Property(name="qureddy:readiness", value=asset.readiness),
            Property(name="qureddy:severity", value=asset.severity),
        ],
    )
