# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for structured posture interpretation."""

from __future__ import annotations

import pytest

from qureddy.core.models import (
    AxisStatus,
    Confidence,
    Evidence,
    FailureCategory,
    Finding,
    HndlExposure,
    HygieneStatus,
    ObservationType,
    PqcSupport,
    Readiness,
    Severity,
)
from qureddy.scanners.common.posture import build_interpretation


def _finding(
    rule_id: str,
    finding_type: str,
    readiness: Readiness,
    *,
    protocol: str = "tls",
) -> Finding:
    return Finding(
        id=rule_id,
        asset_id="asset-1",
        evidence_ids=("ev-1",),
        rule_id=rule_id,
        finding_type=finding_type,
        title=rule_id,
        description=rule_id,
        severity=Severity.INFO,
        readiness=readiness,
        confidence=Confidence.HIGH,
        protocol=protocol,
    )


def _ssh_evidence(evidence_type: str = "ssh.hostkey") -> Evidence:
    return Evidence(
        id="ev-ssh-1",
        asset_id="asset-1",
        evidence_type=evidence_type,
        observation_type=ObservationType.OFFERED,
        source="test",
        protocol="ssh",
    )


def test_failed_hybrid_probe_does_not_claim_classical_only() -> None:
    interpretation = build_interpretation(
        [
            _finding("tls.hybrid.probe_failed", "tls.kex.hybrid_probe", Readiness.UNKNOWN),
            _finding(
                "tls.classical.negotiated_x25519",
                "tls.kex.classical",
                Readiness.QUANTUM_VULNERABLE,
            ),
        ],
        [],
        None,
    )

    assert interpretation.effective is Readiness.QUANTUM_VULNERABLE
    assert interpretation.axes.pqc_support is PqcSupport.UNKNOWN
    assert interpretation.axes.key_exchange.value == "unknown"
    assert "hybrid_probe_failed" in interpretation.reason_codes


def test_rejected_classical_control_does_not_claim_classical_negotiated() -> None:
    interpretation = build_interpretation(
        [
            _finding(
                "tls.hybrid.negotiated_pq",
                "tls.kex.hybrid",
                Readiness.TRANSITIONAL_HYBRID,
            ),
            _finding(
                "tls.classical.control_rejected",
                "tls.kex.classical_control_rejected",
                Readiness.NOT_APPLICABLE,
            ),
        ],
        [],
        None,
    )

    assert interpretation.axes.pqc_support is PqcSupport.HYBRID_OBSERVED
    assert interpretation.axes.key_exchange is AxisStatus.HYBRID
    assert "classical_kex_negotiated" not in interpretation.reason_codes


def test_failed_target_is_not_testable_even_with_partial_findings() -> None:
    interpretation = build_interpretation(
        [
            _finding(
                "tls.classical.negotiated_x25519", "tls.kex.classical", Readiness.QUANTUM_VULNERABLE
            )
        ],
        [],
        FailureCategory.TARGET_CONNECT_FAILED,
    )

    assert interpretation.axes.pqc_support is PqcSupport.NOT_TESTABLE
    assert interpretation.axes.key_exchange.value == "not_testable"
    assert interpretation.axes.authentication.value == "not_testable"


def test_handshake_failure_without_hygiene_evidence_is_unknown() -> None:
    interpretation = build_interpretation(
        [
            _finding(
                "tls.hybrid.probe_failed",
                "tls.kex.probe_failed",
                Readiness.UNKNOWN,
            ),
            _finding(
                "tls.classical.control_rejected",
                "tls.kex.classical_control_rejected",
                Readiness.NOT_APPLICABLE,
            ),
        ],
        [],
        FailureCategory.TLS_HANDSHAKE_FAILED,
    )

    assert interpretation.hygiene_status is HygieneStatus.UNKNOWN
    assert interpretation.axes.protocol_hygiene is AxisStatus.UNKNOWN
    assert interpretation.display.current_hygiene == "Security hygiene could not be assessed"


def test_observed_legacy_hygiene_wins_over_handshake_failure() -> None:
    interpretation = build_interpretation(
        [
            _finding(
                "tls.hybrid.probe_failed",
                "tls.kex.probe_failed",
                Readiness.UNKNOWN,
            ),
            _finding(
                "tls.legacy.protocol_offered",
                "tls.legacy.protocol_offered",
                Readiness.CLASSICALLY_WEAK,
            ),
        ],
        [],
        FailureCategory.TLS_HANDSHAKE_FAILED,
    )

    assert interpretation.hygiene_status is HygieneStatus.ACTION_NEEDED
    assert interpretation.axes.protocol_hygiene is AxisStatus.ACTION_NEEDED
    assert interpretation.display.current_hygiene == "Protocol hardening is required"


def test_interpretation_covers_positive_and_classical_paths() -> None:
    hybrid_legacy = build_interpretation(
        [
            _finding("tls.hybrid.negotiated_pq", "tls.kex.hybrid", Readiness.TRANSITIONAL_HYBRID),
            _finding(
                "tls.legacy.protocol_offered",
                "tls.legacy.protocol_offered",
                Readiness.CLASSICALLY_WEAK,
            ),
            _finding(
                "tls.cert.signature", "tls.cert.classical_signature", Readiness.QUANTUM_VULNERABLE
            ),
        ],
        [],
        None,
    )
    assert hybrid_legacy.axes.key_exchange is AxisStatus.HYBRID
    assert "deprecated_protocol_observed" in hybrid_legacy.reason_codes
    assert "legacy protocol" in hybrid_legacy.headline
    assert hybrid_legacy.hndl_exposure is HndlExposure.PROTECTED
    assert hybrid_legacy.hygiene_status is HygieneStatus.ACTION_NEEDED
    assert hybrid_legacy.display.overall_status == "Hybrid PQC protection with hardening required"
    assert (
        "Protected against harvest-now/decrypt-later" in hybrid_legacy.display.future_quantum_risk
    )

    pure = build_interpretation(
        [_finding("tls.pq.negotiated_pure", "tls.kex.pure_pq", Readiness.QUANTUM_SAFE)], [], None
    )
    assert pure.headline.startswith("Pure post-quantum")
    assert pure.hndl_exposure is HndlExposure.PROTECTED
    assert pure.hygiene_status is HygieneStatus.OK
    assert pure.display.overall_status == "Post-quantum protection observed"


@pytest.mark.parametrize(
    ("finding_type", "readiness"),
    [
        ("ike.kex.classical", Readiness.QUANTUM_VULNERABLE),
        ("ike.kex.hybrid", Readiness.TRANSITIONAL_HYBRID),
        ("ike.kex.pure_pq", Readiness.QUANTUM_SAFE),
    ],
)
def test_ike_key_establishment_never_sets_global_hndl_posture(
    finding_type: str,
    readiness: Readiness,
) -> None:
    interpretation = build_interpretation(
        [_finding(finding_type, finding_type, readiness)],
        [],
        None,
        protocol="ike",
    )

    assert interpretation.hndl_exposure is HndlExposure.UNKNOWN


@pytest.mark.parametrize(
    (
        "explicit_protocol",
        "evidence_protocol",
        "finding_protocol",
        "finding_type",
        "readiness",
    ),
    [
        ("IKE", None, "tls", "ike.kex.hybrid", Readiness.TRANSITIONAL_HYBRID),
        (None, "ike", "tls", "ike.kex.classical", Readiness.QUANTUM_VULNERABLE),
        (None, None, "iKe", "ike.kex.hybrid", Readiness.TRANSITIONAL_HYBRID),
    ],
)
def test_ike_global_hndl_guard_uses_normalized_resolved_protocol(
    explicit_protocol: str | None,
    evidence_protocol: str | None,
    finding_protocol: str,
    finding_type: str,
    readiness: Readiness,
) -> None:
    evidence = (
        [
            Evidence(
                id="ev-ike-1",
                asset_id="asset-1",
                evidence_type="ike.proposal.selected",
                observation_type=ObservationType.OBSERVED,
                source="test",
                protocol=evidence_protocol,
            )
        ]
        if evidence_protocol is not None
        else []
    )
    interpretation = build_interpretation(
        [
            _finding(
                finding_type,
                finding_type,
                readiness,
                protocol=finding_protocol,
            )
        ],
        evidence,
        None,
        protocol=explicit_protocol,
    )

    assert interpretation.hndl_exposure is HndlExposure.UNKNOWN
    assert interpretation.display.future_quantum_risk == "Exposure is unknown"
    assert interpretation.display.evaluation.hndl_risk == "Exposure could not be determined"


def test_classical_only_is_at_risk_and_action_needed() -> None:
    interpretation = build_interpretation(
        [
            _finding(
                "tls.classical.negotiated_x25519",
                "tls.kex.classical",
                Readiness.QUANTUM_VULNERABLE,
            )
        ],
        [],
        None,
    )

    assert interpretation.hndl_exposure is HndlExposure.AT_RISK
    assert interpretation.hygiene_status is HygieneStatus.ACTION_NEEDED
    assert interpretation.display.overall_status == "Classical-only protection observed"

    classical = build_interpretation(
        [
            _finding(
                "tls.classical.negotiated_x25519", "tls.kex.classical", Readiness.QUANTUM_VULNERABLE
            )
        ],
        [],
        None,
    )
    assert classical.headline.startswith("Only classical")

    unknown = build_interpretation([], [], None)
    assert unknown.headline == "PQC posture is unknown."


def test_current_classical_protocol_is_not_deprecated_protocol_exposure() -> None:
    """TLS 1.2 classical KEX must not trigger legacy-protocol hygiene advice."""
    interpretation = build_interpretation(
        [
            _finding(
                "tls.classical.negotiated_x25519",
                "tls.kex.classical",
                Readiness.QUANTUM_VULNERABLE,
            ),
            _finding(
                "tls.classical.protocol_offered",
                "tls.kex.classical_protocol",
                Readiness.QUANTUM_VULNERABLE,
            ),
        ],
        [],
        None,
    )

    assert interpretation.axes.downgrade_resistance is AxisStatus.ACTION_NEEDED
    assert interpretation.axes.protocol_hygiene is AxisStatus.ACCEPTABLE
    assert "deprecated_protocol_observed" not in interpretation.reason_codes


def test_ssh_weak_posture_is_reflected_in_all_relevant_axes() -> None:
    """SSH findings must not produce a positive headline over a weak verdict."""
    interpretation = build_interpretation(
        [
            _finding("ssh.kex.hybrid_offered", "ssh.kex.hybrid", Readiness.TRANSITIONAL_HYBRID),
            _finding("ssh.hostkey.weak", "ssh.hostkey.weak", Readiness.CLASSICALLY_WEAK),
            _finding("ssh.transport.weak", "ssh.transport.weak", Readiness.CLASSICALLY_WEAK),
            _finding("ssh.terrapin.posture", "ssh.terrapin.posture", Readiness.NOT_APPLICABLE),
        ],
        [_ssh_evidence()],
        None,
    )

    assert interpretation.effective is Readiness.CLASSICALLY_WEAK
    assert interpretation.axes.authentication is AxisStatus.CLASSICAL
    assert interpretation.axes.downgrade_resistance is AxisStatus.ACTION_NEEDED
    assert interpretation.axes.protocol_hygiene is AxisStatus.ACTION_NEEDED
    assert interpretation.headline.startswith("Classically weak")


def test_ssh_hostkey_evidence_marks_classical_authentication_without_weak_finding() -> None:
    """A strong SSH host-key offer is still classical authentication."""
    interpretation = build_interpretation([], [_ssh_evidence()], None)

    assert interpretation.axes.authentication is AxisStatus.CLASSICAL
