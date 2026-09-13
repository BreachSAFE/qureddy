# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the wallet CBOM and the shared emitters it reuses.

CycloneDX 1.7 names two different things and this scanner produces both: an
`algorithm` asset describing what a key is made of, and a
`related-crypto-material` asset of type `public-key` describing the key itself,
"the non-confidential key of a key pair used in asymmetric cryptography".
Before this, a wallet scan emitted the first and dropped the second, so the
indexer certificate's RSA key reached the inventory and the account key the scan
exists to find did not.
"""

from __future__ import annotations

import io
import json

from qureddy.core.models import (
    Asset,
    Evidence,
    ObservationType,
    ScanResult,
    ScanTarget,
)
from qureddy.core.vocabulary import WALLET_SIGNATURE_EVIDENCE
from qureddy.output.cbom import render_cbom
from qureddy.output.cbom_public_key import classify_public_key
from tests._cbom_fixtures import _build_result, _render

_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
_MATERIAL = "related-crypto-material"


def _wallet_result(*, with_key: bool) -> ScanResult:
    """A minimal wallet scan, optionally carrying one key the lane read."""
    base = _build_result()
    target = ScanTarget(
        original_input="bc1qexample",
        host="mempool.space",
        port=443,
        sni=None,
        scheme="btc",
        subject="bc1qexample",
        locator="btc://mempool.space:443",
    )
    asset = Asset(
        id="asset-w",
        asset_type="btc.account",
        locator=target.locator,
        display_name="mempool.space:443",
    )
    evidence = [
        Evidence(
            id="ev-alg",
            asset_id=asset.id,
            evidence_type=WALLET_SIGNATURE_EVIDENCE,
            observation_type=ObservationType.OBSERVED,
            source="offline",
            algorithm="ECDSA-secp256k1",
            negotiated_group="ECDSA-secp256k1",
            primitive="signature",
            nist_quantum_security_level=0,
            protocol="btc",
        )
    ]
    if with_key:
        evidence.append(
            Evidence(
                id="ev-key",
                asset_id=asset.id,
                evidence_type="pubkey",
                observation_type=ObservationType.OBSERVED,
                source="chain",
                algorithm="ECDSA-secp256k1",
                primitive="signature",
                nist_quantum_security_level=0,
                protocol="btc",
                public_key=_KEY,
                public_key_format="SEC1-compressed",
            )
        )
    return base.model_copy(
        update={
            "target": target,
            "assets": (asset,),
            "evidence": tuple(evidence),
            "findings": (),
        }
    )


def _components(result: ScanResult) -> dict[str, dict]:
    buf = io.StringIO()
    render_cbom(result, buf)
    document = json.loads(buf.getvalue())
    return {component["name"]: component for component in document["components"]}


def _material(result: ScanResult) -> list[dict]:
    return [
        component
        for component in _components(result).values()
        if component.get("cryptoProperties", {}).get("assetType") == _MATERIAL
    ]


def test_a_read_key_becomes_related_crypto_material() -> None:
    """The schema's own word for a key is related-crypto-material, not algorithm."""
    material = _material(_wallet_result(with_key=True))

    assert len(material) == 1
    properties = material[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert properties["type"] == "public-key"
    assert properties["state"] == "active"
    assert properties["size"] == 256
    assert properties["format"] == "SEC1-compressed"


def test_the_key_value_travels_because_it_is_already_public() -> None:
    """A key on a public ledger is evidence; withholding it hides what was read."""
    material = _material(_wallet_result(with_key=True))
    properties = material[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]

    assert properties["value"] == _KEY


def test_the_key_points_at_its_own_algorithm_and_not_the_indexer_curve() -> None:
    """P-256 and secp256k1 are both 256-bit, so the ref has to carry the curve."""
    result = _wallet_result(with_key=True)
    material = _material(result)
    properties = material[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]

    assert properties["algorithmRef"] == "crypto/algorithm/ec-secp256k1"
    assert "EC-secp256k1" in _components(result)


def test_a_scan_that_read_no_key_emits_no_key_material() -> None:
    """C2: an inferred exposure reads no key material, so it emits none.

    This is the genesis P2PK case and the whole Ethereum lane: the key exists
    and this scanner did not read it.
    """
    assert _material(_wallet_result(with_key=False)) == []


def test_the_curve_disambiguates_two_256_bit_ec_keys() -> None:
    """Without it both classify to EC-256 and share one bom-ref."""
    p256 = classify_public_key("id-ecPublicKey", 256)
    secp = classify_public_key("id-ecPublicKey", 256, "secp256k1")

    assert p256 is not None
    assert secp is not None
    assert p256.name == "EC-256"
    assert secp.name == "EC-secp256k1"
    assert p256.name != secp.name
    assert secp.properties.parameter_set_identifier == "secp256k1"


def test_omitting_the_curve_leaves_every_existing_caller_unchanged() -> None:
    """The parameter is optional so TLS and SSH keep the name they emitted."""
    for algorithm, bits, expected in (
        ("rsaEncryption", 2048, "RSA-2048"),
        ("id-ecPublicKey", 384, "EC-384"),
        ("ed25519", None, "Ed25519"),
    ):
        asset = classify_public_key(algorithm, bits)
        assert asset is not None
        assert asset.name == expected
        assert asset.properties.parameter_set_identifier is None


def test_a_tls_scan_emits_no_wallet_material() -> None:
    """The wallet emitter runs on every scan; it must select nothing here."""
    document = _render(_build_result())
    material = [
        component
        for component in document["components"]
        if component.get("cryptoProperties", {}).get("assetType") == _MATERIAL
    ]

    assert all("Account public key" not in component["name"] for component in material)
