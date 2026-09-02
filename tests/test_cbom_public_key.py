# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for endpoint public-key CBOM classification."""

from __future__ import annotations

import pytest

from qureddy.core.certificate import CertificateObservation
from qureddy.core.models import Evidence, ObservationType
from qureddy.output.cbom_public_key import classify_public_key
from tests._cbom_fixtures import _build_result, _render


@pytest.mark.parametrize(
    ("bits", "strength"),
    [(1024, 80), (2048, 112), (3072, 128), (7680, 192), (15360, 256)],
)
def test_rsa_nist_table2_strengths_are_preserved(bits: int, strength: int) -> None:
    """Every explicit RSA row from NIST SP 800-57 Table 2 remains mapped."""
    asset = classify_public_key("rsaEncryption", bits)

    assert asset is not None
    assert asset.properties.classical_security_level == strength


def test_rsa_4096_cbom_omits_interpolated_classical_strength() -> None:
    """Issue #531: do not attribute an off-table RSA-4096 value to NIST."""
    certificate = CertificateObservation(
        subject="CN=example.com",
        issuer="CN=Example CA",
        not_before="Jul 17 07:18:11 2026 GMT",
        not_after="Jul 17 07:18:11 2027 GMT",
        serial="0123456789ABCDEF",
        signature_algorithm="sha256WithRSAEncryption",
        public_key_summary="Public-Key: (4096 bit)",
        public_key_algorithm="rsaEncryption",
        public_key_bits=4096,
        is_self_signed=False,
        is_post_quantum_signature=False,
    )
    evidence = Evidence(
        id="ev-cert-rsa4096",
        asset_id="asset-1",
        evidence_type="tls.cert.signature",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.tls.cert_sig",
        certificate_record=certificate,
    )
    base = _build_result()
    payload = _render(base.model_copy(update={"evidence": (*base.evidence, evidence)}))
    component = next(item for item in payload["components"] if item["name"] == "RSA-4096")
    properties = component["cryptoProperties"]["algorithmProperties"]

    assert "classicalSecurityLevel" not in properties
    assert properties["nistQuantumSecurityLevel"] == 0
