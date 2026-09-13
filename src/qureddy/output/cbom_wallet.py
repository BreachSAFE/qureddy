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
from qureddy.output.cbom_assets import add_algorithm_assets, algorithm_ref, select_by_evidence_type
from qureddy.output.cbom_components import signature_algorithm_properties
from qureddy.output.cbom_public_key import add_public_key_component, add_public_key_material

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import Evidence, ScanResult

#: Evidence type carrying one public key the chain lane read from a spend.
_PUBKEY_EVIDENCE = "pubkey"
#: What the scanner recovers is an EC point on this curve, so the shared
#: classifier is called with the x509 algorithm name every other caller uses.
_EC_ALGORITHM = "id-ecPublicKey"
_CURVE = "secp256k1"
_KEY_SIZE_BITS = 256


def _recovered_keys(result: ScanResult) -> list[Evidence]:
    """Evidence carrying key bytes this scanner read.

    C2: only a key this scanner read counts. An Ethereum exposure conclusion is
    INFERRED from account state and reads no key material, so it emits nothing
    here.
    """
    return [
        item
        for item in result.evidence
        if item.evidence_type == _PUBKEY_EVIDENCE and item.public_key
    ]


def add_wallet_signature_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit the account's signing algorithm, and its published key when read."""
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_by_evidence_type(WALLET_SIGNATURE_EVIDENCE),
        algorithm_properties=signature_algorithm_properties,
    )
    keys = _recovered_keys(result)
    if not keys:
        return
    # The key's algorithm, through the shared emitter a TLS certificate's subject
    # key and an SSH host key go through. The curve is passed because size alone
    # does not identify one: P-256 and secp256k1 are both 256-bit, and without it
    # the account key and an EC indexer certificate share a single component.
    add_public_key_component(bom, _EC_ALGORITHM, _KEY_SIZE_BITS, provides_edges, curve=_CURVE)
    # The keys themselves, through the shared emitter TLS ephemeral keys use.
    # CycloneDX calls this related-crypto-material of type public-key.
    for item in keys:
        key = item.public_key or ""
        add_public_key_material(
            bom,
            ref=f"crypto/related-material/wallet-pubkey-{key[:16]}",
            name=f"Account public key ({_CURVE})",
            algorithm_ref=algorithm_ref(f"EC-{_CURVE}"),
            provides_edges=provides_edges,
            size=_KEY_SIZE_BITS,
            value=key,
            key_format=item.public_key_format,
        )
