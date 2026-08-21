# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""SSH-specific CycloneDX crypto-asset emission for the CBOM (#143).

Split out of ``cbom_components`` to keep that module under the file-size ceiling.
SSH host keys are signature algorithms, not KEX groups, so ``add_algorithm_components``
deliberately skips ``ssh.hostkey`` evidence and this module emits it instead — the
rendered CBOM is unchanged in intent, only reorganized.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cyclonedx.model import Property
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import CryptoAssetType, CryptoProperties

from qureddy.output.cbom_components import (
    ENDPOINT_REF,
    OBSERVATION_RANK,
    POSITIVE_OBSERVATIONS,
    signature_algorithm_properties,
)

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import ObservationType, ScanResult


def add_ssh_host_key_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit each observed SSH host-key algorithm as a signature crypto asset (#143).

    The SSH scanner records every offered host-key algorithm as ``ssh.hostkey``
    evidence. ``add_algorithm_components`` skips those (host keys are signature
    algorithms, not KEX groups), so without this the CBOM dropped host keys entirely
    — the most security-relevant SSH signal was observed yet absent from the
    inventory. Each host key is classified with the shared signature classifier,
    honestly: every SSH host-key family is classical today (nistQuantumSecurityLevel
    0). Each carries the strongest observation seen, mirroring the KEX/cipher assets.
    """
    host_keys: dict[str, ObservationType] = {}
    for evidence in result.evidence:
        if (
            evidence.evidence_type == "ssh.hostkey"
            and evidence.observation_type in POSITIVE_OBSERVATIONS
            and evidence.negotiated_group
        ):
            seen = host_keys.get(evidence.negotiated_group)
            if seen is None or OBSERVATION_RANK[evidence.observation_type] > OBSERVATION_RANK[seen]:
                host_keys[evidence.negotiated_group] = evidence.observation_type
    for host_key in sorted(host_keys):
        ref = f"crypto/algorithm/{host_key.lower()}"
        bom.components.add(
            Component(
                name=host_key,
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                bom_ref=ref,
                crypto_properties=CryptoProperties(
                    asset_type=CryptoAssetType.ALGORITHM,
                    algorithm_properties=signature_algorithm_properties(host_key),
                ),
                properties=[Property(name="qureddy:observation", value=host_keys[host_key].value)],
            )
        )
        provides_edges.setdefault(ENDPOINT_REF, []).append(ref)
