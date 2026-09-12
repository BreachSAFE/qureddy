# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Wallet crypto-asset components for the CycloneDX emitter.

Mirrors `cbom_ssh.py`: a per-protocol module that selects its own evidence and
hands it to the shared `add_algorithm_assets` loop. The wallet scanner records
the signing algorithm as `wallet.signature` evidence, which
`add_algorithm_components` skips because a wallet key is a signature algorithm
and not a TLS key-exchange group.

Every Bitcoin and Ethereum account signs on secp256k1, so the shared signature
classifier carries it at CycloneDX level 0: none of the NIST categories are met,
since Shor solves the elliptic curve discrete logarithm outright.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.vocabulary import WALLET_SIGNATURE_EVIDENCE
from qureddy.output.cbom_assets import add_algorithm_assets, select_by_evidence_type
from qureddy.output.cbom_components import signature_algorithm_properties

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import ScanResult


def add_wallet_signature_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit the account's signing algorithm as a signature crypto asset."""
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_by_evidence_type(WALLET_SIGNATURE_EVIDENCE),
        algorithm_properties=signature_algorithm_properties,
    )
