# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CycloneDX assets observed during a live TLS handshake."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cyclonedx.model import Property
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    CryptoAssetType,
    CryptoProperties,
    RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialState,
    RelatedCryptoMaterialType,
)

from qureddy.output.cbom_assets import (
    POSITIVE_OBSERVATIONS,
    add_algorithm_component,
    add_provides_edge,
    algorithm_ref,
)
from qureddy.output.cbom_components import signature_algorithm_properties

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import Evidence, ScanResult

_SIGNATURE_ROLE = "tls.handshake.certificate_verify"


def add_tls_handshake_components(
    bom: Bom,
    result: ScanResult,
    algorithm_refs: dict[str, str],
    provides_edges: dict[str, list[str]],
) -> None:
    """Emit live CertificateVerify and ephemeral-key assets."""
    for evidence in _positive_tls_negotiations(result):
        _add_handshake_signature(bom, evidence, provides_edges)
        _add_ephemeral_key(bom, evidence, algorithm_refs, provides_edges)


def _positive_tls_negotiations(result: ScanResult) -> list[Evidence]:
    """Return deterministic positive TLS negotiation evidence."""
    return sorted(
        (
            evidence
            for evidence in result.evidence
            if evidence.protocol == "tls"
            and evidence.evidence_type == "tls.negotiation"
            and evidence.observation_type in POSITIVE_OBSERVATIONS
        ),
        key=lambda evidence: evidence.id,
    )


def _add_handshake_signature(
    bom: Bom, evidence: Evidence, provides_edges: dict[str, list[str]]
) -> None:
    """Emit the signature used by the live TLS CertificateVerify message."""
    if evidence.handshake_signature is None:
        return
    properties = [
        Property(name="qureddy:observation", value=evidence.observation_type.value),
        Property(name="qureddy:signature.role", value=_SIGNATURE_ROLE),
    ]
    if evidence.handshake_hash is not None:
        properties.append(Property(name="qureddy:signature.hash", value=evidence.handshake_hash))
    add_algorithm_component(
        bom,
        name=evidence.handshake_signature,
        ref=algorithm_ref(evidence.handshake_signature),
        algorithm_properties=signature_algorithm_properties(evidence.handshake_signature),
        provides_edges=provides_edges,
        properties=properties,
    )


def _add_ephemeral_key(
    bom: Bom,
    evidence: Evidence,
    algorithm_refs: dict[str, str],
    provides_edges: dict[str, list[str]],
) -> None:
    """Emit observed ephemeral public-key material without the key value."""
    group = evidence.negotiated_group
    if group is None or evidence.key_bits is None or group not in algorithm_refs:
        return
    ref = f"crypto/related-material/tls-ephemeral-{group.lower()}"
    if any(component.bom_ref.value == ref for component in bom.components):
        return
    bom.components.add(
        Component(
            name=f"TLS ephemeral public key ({group})",
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=ref,
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.RELATED_CRYPTO_MATERIAL,
                related_crypto_material_properties=RelatedCryptoMaterialProperties(
                    type=RelatedCryptoMaterialType.PUBLIC_KEY,
                    state=RelatedCryptoMaterialState.ACTIVE,
                    algorithm_ref=BomRef(value=algorithm_refs[group]),
                    size=evidence.key_bits,
                ),
            ),
        )
    )
    add_provides_edge(provides_edges, ref)
