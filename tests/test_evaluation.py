# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the protocol-neutral CISO evaluator."""

from __future__ import annotations

from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    HndlExposure,
    HygieneStatus,
    ObservationType,
    PqcSupport,
    ProbeRole,
    Readiness,
    Severity,
)
from qureddy.scanners.common.evaluation import PostureFacts, build_evaluation
from qureddy.scanners.common.posture import build_interpretation


def test_hybrid_evaluation_reports_observed_fallback() -> None:
    result = build_evaluation(
        PostureFacts(
            protocol="tls",
            support=PqcSupport.HYBRID_OBSERVED,
            hndl_exposure=HndlExposure.PROTECTED_DEFEASIBLE,
            hygiene_status=HygieneStatus.ACTION_NEEDED,
            negotiated_algorithm="X25519MLKEM768",
            classical_alternative="X25519",
            certificate_chain_signature="ecdsa_secp256r1_sha256",
        )
    )
    assert result.summary.startswith("TLS hybrid post-quantum protection")
    assert any("X25519MLKEM768" in fact for fact in result.observed_facts)
    assert any("Classical alternative accepted: X25519" in fact for fact in result.observed_facts)


def test_weak_hygiene_requires_hardening_and_names_algorithm() -> None:
    result = build_evaluation(
        PostureFacts(
            protocol="ssh",
            support=PqcSupport.HYBRID_OBSERVED,
            hndl_exposure=HndlExposure.PROTECTED,
            hygiene_status=HygieneStatus.WEAK,
            negotiated_algorithm="sntrup761x25519-sha512",
            weak_algorithms=("ssh-rsa",),
        )
    )
    assert result.hardening == "Protocol hardening is required"
    assert "SSH weak algorithm offered: ssh-rsa" in result.observed_facts


def test_evaluator_is_protocol_neutral() -> None:
    for protocol in ("ssh", "certificate", "sftp", "ike"):
        result = build_evaluation(
            PostureFacts(
                protocol=protocol,
                support=PqcSupport.HYBRID_OBSERVED,
                hndl_exposure=HndlExposure.PROTECTED,
                hygiene_status=HygieneStatus.OK,
                negotiated_algorithm="hybrid-test-algorithm",
            )
        )
        assert result.summary.startswith(f"{protocol.upper()} hybrid")
        assert "TLS" not in result.summary


def test_unknown_evaluation_does_not_fabricate_observations() -> None:
    result = build_evaluation(
        PostureFacts(
            protocol="tls",
            support=PqcSupport.UNKNOWN,
            hndl_exposure=HndlExposure.UNKNOWN,
            hygiene_status=HygieneStatus.UNKNOWN,
        )
    )
    assert result.summary == "TLS post-quantum protection could not be confirmed."
    assert result.hardening == "Hardening posture could not be assessed"
    assert result.observed_facts == ()


def test_classical_fact_requires_classical_control_probe_role() -> None:
    asset = Asset(
        id="asset-1",
        asset_type="tls.endpoint",
        locator="tls://example.com:443",
        display_name="example.com:443",
    )
    hybrid = Evidence(
        id="ev-hybrid",
        asset_id=asset.id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="test",
        negotiated_group="X25519MLKEM768",
        probe_role=ProbeRole.HYBRID_READINESS,
    )
    finding = Finding(
        id="finding-hybrid",
        asset_id=asset.id,
        evidence_ids=(hybrid.id,),
        rule_id="tls.hybrid.negotiated_pq",
        finding_type="tls.kex.hybrid",
        title="hybrid",
        description="hybrid",
        severity=Severity.INFO,
        readiness=Readiness.TRANSITIONAL_HYBRID,
        confidence=Confidence.HIGH,
        negotiated_group="X25519MLKEM768",
    )
    interpretation = build_interpretation([finding], [hybrid], None, protocol="tls")
    assert interpretation.display.evaluation.observed_facts == ("TLS negotiated X25519MLKEM768",)
