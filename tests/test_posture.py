# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for structured posture interpretation."""

from __future__ import annotations

from qureddy.core.models import (
    AxisStatus,
    Confidence,
    FailureCategory,
    Finding,
    PqcSupport,
    Readiness,
    Severity,
)
from qureddy.scanners.common.posture import build_interpretation


def _finding(rule_id: str, finding_type: str, readiness: Readiness) -> Finding:
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

    pure = build_interpretation(
        [_finding("tls.pq.negotiated_pure", "tls.kex.pq", Readiness.QUANTUM_SAFE)], [], None
    )
    assert pure.headline.startswith("Pure post-quantum")

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
