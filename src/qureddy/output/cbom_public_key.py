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
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoPrimitive,
    CryptoProperties,
    RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialState,
    RelatedCryptoMaterialType,
)

from qureddy.core.signatures import classify_pqc_signature
from qureddy.output.cbom_assets import add_algorithm_component, add_provides_edge, algorithm_ref

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

# NIST SP 800-57 Part 1 Rev.5, Table 2: classical security strength (bits) by asymmetric
# key size. Only the standard sizes are listed; an off-table size yields no claimed strength.
_RSA_CLASSICAL_STRENGTH: MappingProxyType[int, int] = MappingProxyType(
    {1024: 80, 2048: 112, 3072: 128, 7680: 192, 15360: 256}
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


def classify_public_key(
    algorithm: str | None, bits: int | None, curve: str | None = None
) -> PublicKeyAsset | None:
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
    return _classify_classical_public_key(algorithm, bits, curve)


def _classify_classical_public_key(
    algorithm: str, bits: int | None, curve: str | None = None
) -> PublicKeyAsset | None:
    """Classify a classical asymmetric key (RSA / EC / EdDSA / DSA), or None if unrecognized."""
    family = _PUBLIC_KEY_FAMILY.get(algorithm.lower())
    if family is None:
        return None
    primitive, strength, weak = _classical_properties(family, bits)
    name = f"{family}-{curve or bits}" if (curve or bits) else family
    properties = AlgorithmProperties(
        primitive=primitive,
        parameter_set_identifier=curve,
        classical_security_level=strength,
        # CycloneDX defines level 0 as “none of the NIST categories are met”.
        # This is a valid no-category sentinel, not a fabricated NIST category.
        nist_quantum_security_level=0,
    )
    readiness = "classically_weak" if weak else "quantum_vulnerable"
    severity = "high" if weak else "low"
    return PublicKeyAsset(name, properties, readiness, severity)


def _classical_properties(
    family: str, bits: int | None
) -> tuple[CryptoPrimitive, int | None, bool]:
    """Return the primitive, classical strength, and classical weakness for a family."""
    if family == "RSA":
        return (
            CryptoPrimitive.PKE,
            _RSA_CLASSICAL_STRENGTH.get(bits) if bits else None,
            bits is not None and bits < _RSA_MIN_ACCEPTABLE_BITS,
        )
    return CryptoPrimitive.SIGNATURE, _EC_CLASSICAL_STRENGTH.get(bits) if bits else None, False


def add_public_key_material(
    bom: Bom,
    *,
    ref: str,
    name: str,
    algorithm_ref: str,
    provides_edges: dict[str, list[str]],
    size: int | None = None,
    value: str | None = None,
    key_format: str | None = None,
) -> None:
    """Emit one observed public key as `related-crypto-material`.

    CycloneDX 1.7 names this exactly: `relatedCryptoMaterialProperties.type`
    carries `public-key`, "the non-confidential key of a key pair used in
    asymmetric cryptography". An `algorithm` asset describes what the key is
    made of; this describes the key itself, so a scanner that reads key bytes
    emits both and they point at each other through `algorithm_ref`.

    `value` stays optional and the caller decides. A TLS ephemeral key is
    session material and is recorded by size alone. A chain account's key is
    already published on a public ledger, so withholding it would hide evidence
    the scan exists to surface. A private key or any secret never reaches here.

    Idempotent by bom-ref, matching `add_algorithm_component`.
    """
    if any(component.bom_ref.value == ref for component in bom.components):
        return
    bom.components.add(
        Component(
            name=name,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=ref,
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
                related_crypto_material_properties=RelatedCryptoMaterialProperties(
                    type=RelatedCryptoMaterialType.PUBLIC_KEY,
                    state=RelatedCryptoMaterialState.ACTIVE,
                    algorithm_ref=BomRef(value=algorithm_ref),
                    size=size,
                    value=value,
                    format=key_format,
                ),
            ),
        )
    )
    add_provides_edge(provides_edges, ref)


def add_public_key_component(
    bom: Bom,
    algorithm: str | None,
    bits: int | None,
    provides_edges: dict[str, list[str]],
    curve: str | None = None,
) -> BomRef | None:
    """Emit one crypto-asset component for an endpoint public key; return its ref or None.

    None when the key cannot be classified, so a caller (e.g. the certificate emitter) simply
    leaves its reference unset rather than pointing at a fabricated component.
    """
    asset = classify_public_key(algorithm, bits, curve)
    if asset is None:
        return None
    return add_algorithm_component(
        bom,
        name=asset.name,
        ref=algorithm_ref(asset.name),
        algorithm_properties=asset.properties,
        provides_edges=provides_edges,
        properties=[
            Property(name="qureddy:readiness", value=asset.readiness),
            Property(name="qureddy:severity", value=asset.severity),
        ],
    )
