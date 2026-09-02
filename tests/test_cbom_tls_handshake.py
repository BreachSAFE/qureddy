# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""JSON and CBOM parity tests for live TLS handshake details."""

from __future__ import annotations

import pytest

from qureddy.core.errors import CbomError
from qureddy.core.models import Evidence, ObservationType, ScanResult
from qureddy.output.cbom_semantics import validate_cbom_semantics
from tests._cbom_fixtures import _build_result, _render
from tests.conformance.harness import official_errors, semantic_errors


def _result_with_handshake_details() -> ScanResult:
    result = _build_result()
    evidence = Evidence(
        id="ev-live-auth",
        asset_id="asset-1",
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519",
        handshake_signature="rsa_pss_rsae_sha256",
        handshake_hash="SHA256",
        key_bits=253,
    )
    return result.model_copy(update={"evidence": (evidence,)})


def test_json_evidence_exposes_live_handshake_details() -> None:
    result = _result_with_handshake_details()
    evidence = result.model_dump(mode="json")["evidence"][0]

    assert evidence["handshake_signature"] == "rsa_pss_rsae_sha256"
    assert evidence["handshake_hash"] == "SHA256"
    assert evidence["key_bits"] == 253


def test_cbom_emits_live_certificate_verify_signature() -> None:
    payload = _render(_result_with_handshake_details())
    component = next(
        item for item in payload["components"] if item["name"] == "rsa_pss_rsae_sha256"
    )
    properties = {item["name"]: item["value"] for item in component["properties"]}

    assert component["cryptoProperties"]["algorithmProperties"]["primitive"] == "signature"
    assert properties["qureddy:signature.role"] == "tls.handshake.certificate_verify"
    assert properties["qureddy:signature.hash"] == "SHA256"


def test_cbom_emits_ephemeral_public_key_material() -> None:
    payload = _render(_result_with_handshake_details())
    component = next(
        item
        for item in payload["components"]
        if item["cryptoProperties"]["assetType"] == "related-crypto-material"
    )
    material = component["cryptoProperties"]["relatedCryptoMaterialProperties"]

    assert material["type"] == "public-key"
    assert material["algorithmRef"] == "crypto/algorithm/x25519"
    assert material["size"] == 253
    assert material["state"] == "active"


def test_handshake_cbom_passes_official_and_semantic_validation() -> None:
    payload = _render(_result_with_handshake_details())

    assert not official_errors(payload)
    assert not semantic_errors(payload)


def test_runtime_guard_rejects_dangling_ephemeral_algorithm_reference() -> None:
    payload = _render(_result_with_handshake_details())
    material = next(
        item
        for item in payload["components"]
        if item["cryptoProperties"]["assetType"] == "related-crypto-material"
    )
    material["cryptoProperties"]["relatedCryptoMaterialProperties"]["algorithmRef"] = (
        "crypto/algorithm/missing"
    )

    with pytest.raises(CbomError, match="dangling references"):
        validate_cbom_semantics(payload)
