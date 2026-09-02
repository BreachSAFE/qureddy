# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Scan-level readiness and severity rollup precedence.

Split out of tests/test_scanner.py (issue #298) to keep each test module
under the 400-line ceiling. Covers `_scan_readiness` and `highest_severity`,
the two functions that collapse per-finding values to one scan-level verdict.
"""

from __future__ import annotations

from qureddy.core.models import (
    Confidence,
    Evidence,
    Finding,
    ObservationType,
    Readiness,
    ScanTarget,
    Severity,
)
from qureddy.scanners.tls._summary import build_summary, highest_severity
from qureddy.scanners.tls.scanner import _scan_readiness


class TestScanReadinessRollupPrecedence:
    """`_scan_readiness` rolls multiple findings to one scan-level value.

    Conclusively observed PQ support takes precedence in this PQ-readiness field.
    Without negotiated or observed evidence, present-day classical weakness keeps
    precedence so an offered-only capability cannot overstate endpoint posture.
    """

    @staticmethod
    def _finding(
        readiness: Readiness,
        suffix: str = "",
        *,
        evidence_id: str | None = None,
        rule_id: str | None = None,
        finding_type: str = "test",
    ) -> Finding:
        return Finding(
            id=f"f-{readiness.value}{suffix}",
            asset_id="asset-1",
            evidence_ids=(evidence_id or f"ev-{readiness.value}{suffix}",),
            rule_id=rule_id or f"test.{readiness.value}",
            finding_type=finding_type,
            title="t",
            description="d",
            severity=Severity.INFO,
            readiness=readiness,
            confidence=Confidence.HIGH,
        )

    def test_unproven_hybrid_does_not_override_classical_weakness(self) -> None:
        """Require conclusive evidence before a PQ finding changes the rollup."""
        findings = [
            self._finding(Readiness.TRANSITIONAL_HYBRID),
            self._finding(Readiness.CLASSICALLY_WEAK),
        ]
        assert _scan_readiness(findings) is Readiness.CLASSICALLY_WEAK

    def test_negotiated_hybrid_outranks_classical_hygiene(self) -> None:
        """Keep observed PQ support in the scan verdict when legacy TLS is offered."""
        hybrid = self._finding(
            Readiness.TRANSITIONAL_HYBRID,
            evidence_id="ev-hybrid",
            rule_id="tls.hybrid.negotiated_pq",
            finding_type="tls.kex.hybrid",
        )
        legacy = self._finding(
            Readiness.CLASSICALLY_WEAK,
            evidence_id="ev-legacy",
            rule_id="tls.legacy.protocol_offered",
            finding_type="tls.legacy.protocol_offered",
        )
        evidence = [
            Evidence(
                id="ev-hybrid",
                asset_id="asset-1",
                evidence_type="tls.negotiation",
                observation_type=ObservationType.NEGOTIATED,
                source="test",
                protocol="tls",
            ),
            Evidence(
                id="ev-legacy",
                asset_id="asset-1",
                evidence_type="tls.legacy.protocol",
                observation_type=ObservationType.OFFERED,
                source="test",
                protocol="tls",
            ),
        ]
        target = ScanTarget(
            original_input="example.test",
            host="example.test",
            port=443,
            sni=None,
            locator="tls://example.test:443",
        )

        summary = build_summary(target, [hybrid, legacy], evidence)

        assert summary.readiness is Readiness.TRANSITIONAL_HYBRID
        assert summary.interpretation is not None
        assert summary.interpretation.effective is Readiness.TRANSITIONAL_HYBRID

    def test_classically_weak_trumps_quantum_vulnerable(self) -> None:

        findings = [
            self._finding(Readiness.QUANTUM_VULNERABLE),
            self._finding(Readiness.CLASSICALLY_WEAK),
        ]
        assert _scan_readiness(findings) is Readiness.CLASSICALLY_WEAK

    def test_transitional_hybrid_trumps_quantum_vulnerable(self) -> None:
        """A target that negotiates hybrid AND has the classical control
        probe firing should report transitional_hybrid — the classical
        rule firing on the control probe is by design and shouldn't
        downgrade the verdict.
        """

        findings = [
            self._finding(Readiness.QUANTUM_VULNERABLE),
            self._finding(Readiness.TRANSITIONAL_HYBRID),
        ]
        assert _scan_readiness(findings) is Readiness.TRANSITIONAL_HYBRID

    def test_quantum_vulnerable_trumps_unknown(self) -> None:

        findings = [
            self._finding(Readiness.UNKNOWN),
            self._finding(Readiness.QUANTUM_VULNERABLE),
        ]
        assert _scan_readiness(findings) is Readiness.QUANTUM_VULNERABLE

    def test_empty_findings_is_unknown(self) -> None:

        assert _scan_readiness([]) is Readiness.UNKNOWN


class TestHighestSeverity:
    """`highest_severity` rolls per-finding severities to one scan-level value.

    Lifted from the pre-archive test suite. Specifically covers
    the all-info path that was previously untested — when every finding
    is `INFO`, the rollup must surface `INFO`, not fall through or
    return None.
    """

    @staticmethod
    def _finding(severity: Severity) -> Finding:
        return Finding(
            id=f"f-{severity.value}",
            asset_id="asset-1",
            evidence_ids=("ev-1",),
            rule_id=f"test.{severity.value}",
            finding_type="test",
            title="t",
            description="d",
            severity=severity,
            readiness=Readiness.UNKNOWN,
            confidence=Confidence.HIGH,
        )

    def test_all_info_findings_yields_info(self) -> None:
        findings = [self._finding(Severity.INFO), self._finding(Severity.INFO)]
        assert highest_severity(findings) is Severity.INFO

    def test_low_outranks_info(self) -> None:
        findings = [self._finding(Severity.INFO), self._finding(Severity.LOW)]
        assert highest_severity(findings) is Severity.LOW

    def test_critical_outranks_low(self) -> None:
        findings = [self._finding(Severity.LOW), self._finding(Severity.CRITICAL)]
        assert highest_severity(findings) is Severity.CRITICAL

    def test_empty_findings_is_none(self) -> None:
        assert highest_severity([]) is None
