# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""IKE-specific selection for the shared CycloneDX crypto-asset emitter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.output.cbom_assets import add_algorithm_assets, select_algorithm_by_evidence_type
from qureddy.output.cbom_cipher import cipher_algorithm_properties, mac_algorithm_properties
from qureddy.output.cbom_components import key_exchange_algorithm_properties

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import ScanResult


def add_ike_transport_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Inventory each reported encryption, PRF, and integrity identifier."""
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_algorithm_by_evidence_type("ike.cipher"),
        algorithm_properties=cipher_algorithm_properties,
    )
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_algorithm_by_evidence_type("ike.prf", "ike.integrity"),
        algorithm_properties=mac_algorithm_properties,
    )
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_algorithm_by_evidence_type("ike.dh_group"),
        algorithm_properties=key_exchange_algorithm_properties,
    )
