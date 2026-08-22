# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the current readiness policy rules."""

from __future__ import annotations

from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    FailureCategory,
    ObservationType,
    ProbeRole,
    Readiness,
    Severity,
)
from qureddy.core.policy import classify_evidence


def _asset() -> Asset:
    return Asset(
        id="asset-1",
        asset_type="tls.endpoint",
        locator="tls://example.com:443",
        display_name="example.com:443",
    )


def _evidence(**overrides: object) -> Evidence:
    base = {
        "id": "ev-1",
        "asset_id": "asset-1",
        "evidence_type": "tls.negotiation",
        "observation_type": ObservationType.NEGOTIATED,
        "source": "openssl",
        "protocol_version": "TLSv1.3",
    }
    base.update(overrides)
    return Evidence(**base)  # type: ignore[arg-type]


class TestHybridNegotiatedRule:
    def test_negotiated_x25519mlkem768_produces_transitional_hybrid(self) -> None:
        ev = _evidence(negotiated_group="X25519MLKEM768")
        findings = classify_evidence(_asset(), [ev])
        assert len(findings) == 1
        assert findings[0].rule_id == "tls.hybrid.negotiated_pq"  # #330: structural rule id
        assert findings[0].severity is Severity.INFO
        assert findings[0].readiness is Readiness.TRANSITIONAL_HYBRID
        assert findings[0].confidence is Confidence.HIGH

    def test_offered_only_hybrid_does_not_fire_hybrid_rule(self) -> None:
        ev = _evidence(
            negotiated_group="X25519MLKEM768",
            observation_type=ObservationType.OFFERED,
        )
        findings = classify_evidence(_asset(), [ev])
        assert findings == []


class TestClassicalRule:
    def test_negotiated_x25519_produces_quantum_vulnerable(self) -> None:
        ev = _evidence(negotiated_group="X25519")
        findings = classify_evidence(_asset(), [ev])
        assert len(findings) == 1
        assert findings[0].rule_id == "tls.classical.negotiated_x25519"
        assert findings[0].severity is Severity.LOW
        assert findings[0].readiness is Readiness.QUANTUM_VULNERABLE


class TestNotTestableRule:
    def test_local_openssl_missing_yields_unknown_high(self) -> None:
        ev = _evidence(
            observation_type=ObservationType.NOT_TESTABLE,
            failure_category=FailureCategory.LOCAL_OPENSSL_MISSING,
        )
        findings = classify_evidence(_asset(), [ev])
        assert len(findings) == 1
        assert findings[0].rule_id == "tls.hybrid.not_testable"
        assert findings[0].readiness is Readiness.UNKNOWN
        assert findings[0].confidence is Confidence.HIGH

    def test_local_openssl_too_old_yields_unknown(self) -> None:
        ev = _evidence(
            observation_type=ObservationType.NOT_TESTABLE,
            failure_category=FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        )
        findings = classify_evidence(_asset(), [ev])
        assert findings[0].rule_id == "tls.hybrid.not_testable"

    def test_local_openssl_lacks_group_yields_unknown(self) -> None:
        ev = _evidence(
            observation_type=ObservationType.NOT_TESTABLE,
            failure_category=FailureCategory.LOCAL_OPENSSL_LACKS_GROUP,
        )
        findings = classify_evidence(_asset(), [ev])
        assert findings[0].rule_id == "tls.hybrid.not_testable"


class TestProbeFailedRule:
    def test_target_connect_failed_yields_unknown_medium(self) -> None:
        ev = _evidence(
            observation_type=ObservationType.OBSERVED,
            failure_category=FailureCategory.TARGET_CONNECT_FAILED,
            probe_role=ProbeRole.HYBRID_READINESS,
        )
        findings = classify_evidence(_asset(), [ev])
        assert len(findings) == 1
        assert findings[0].rule_id == "tls.hybrid.probe_failed"
        assert findings[0].readiness is Readiness.UNKNOWN
        assert findings[0].confidence is Confidence.MEDIUM

    def test_tls_handshake_failed_yields_probe_failed(self) -> None:
        ev = _evidence(
            observation_type=ObservationType.OBSERVED,
            failure_category=FailureCategory.TLS_HANDSHAKE_FAILED,
            probe_role=ProbeRole.HYBRID_READINESS,
        )
        findings = classify_evidence(_asset(), [ev])
        assert findings[0].rule_id == "tls.hybrid.probe_failed"

    def test_classical_control_failure_does_not_fire_hybrid_probe_failed_rule(self) -> None:
        """Issue #232: a classical-control probe failure must not attribute
        to the hybrid probe — a hybrid-only server is expected to reject
        pure classical fallback, so this is not evidence hybrid failed.
        """
        ev = _evidence(
            observation_type=ObservationType.OBSERVED,
            failure_category=FailureCategory.TLS_HANDSHAKE_FAILED,
            probe_role=ProbeRole.CLASSICAL_CONTROL,
        )
        findings = classify_evidence(_asset(), [ev])
        assert len(findings) == 1
        assert findings[0].rule_id == "tls.classical.control_rejected"
        assert findings[0].readiness is Readiness.NOT_APPLICABLE


class TestNonMatchingEvidence:
    def test_unrecognized_group_does_not_fire_any_rule(self) -> None:
        ev = _evidence(negotiated_group="secp256r1")
        assert classify_evidence(_asset(), [ev]) == []


class TestUnexpectedGroupRule:
    """Issue #235: UNEXPECTED_GROUP evidence must not be silently dropped."""

    def test_unexpected_group_evidence_produces_a_finding_not_silently_dropped(self) -> None:
        ev = _evidence(
            observation_type=ObservationType.OBSERVED,
            negotiated_group="X25519",
            failure_category=FailureCategory.UNEXPECTED_GROUP,
            probe_role=ProbeRole.HYBRID_READINESS,
        )
        findings = classify_evidence(_asset(), [ev])
        assert len(findings) == 1
        assert findings[0].rule_id == "tls.hybrid.downgraded_to_classical"
        assert findings[0].readiness is Readiness.QUANTUM_VULNERABLE
        assert findings[0].confidence is Confidence.MEDIUM

    def test_classical_only_server_with_non_x25519_group_reports_quantum_vulnerable_not_unknown(
        self,
    ) -> None:
        """A server negotiating a non-X25519 classical group (P-256 etc.) must
        still resolve to a quantum_vulnerable finding, not silently drop to
        the generic UNKNOWN probe_failed rule with no readiness signal.
        """
        ev = _evidence(
            observation_type=ObservationType.OBSERVED,
            negotiated_group="ECDH",
            failure_category=FailureCategory.UNEXPECTED_GROUP,
            probe_role=ProbeRole.HYBRID_READINESS,
        )
        findings = classify_evidence(_asset(), [ev])
        assert len(findings) == 1
        assert findings[0].readiness is Readiness.QUANTUM_VULNERABLE
