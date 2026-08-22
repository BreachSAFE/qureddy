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
    Finding,
    Readiness,
    Severity,
)
from qureddy.scanners.tls._summary import highest_severity
from qureddy.scanners.tls.scanner import _scan_readiness


class TestScanReadinessRollupPrecedence:
    """`_scan_readiness` rolls multiple findings to one scan-level value.

    Precedence (highest first):
      CLASSICALLY_WEAK > TRANSITIONAL_HYBRID > QUANTUM_VULNERABLE >
      UNKNOWN > QUANTUM_SAFE > NOT_APPLICABLE

    Reviewer-flagged latent issue: CLASSICALLY_WEAK was unreachable in
    The current policy emits this finding when certificate evidence supports it,
    but the rollup branch was previously falling through to a
    nondeterministic `next(iter(...))`. These tests pin the precedence
    so certificate findings cannot be silently downgraded by
    a coexisting hybrid finding.
    """

    @staticmethod
    def _finding(readiness: Readiness, suffix: str = "") -> Finding:
        return Finding(
            id=f"f-{readiness.value}{suffix}",
            asset_id="asset-1",
            evidence_ids=(f"ev-{readiness.value}{suffix}",),
            rule_id=f"test.{readiness.value}",
            finding_type="test",
            title="t",
            description="d",
            severity=Severity.INFO,
            readiness=readiness,
            confidence=Confidence.HIGH,
        )

    def test_classically_weak_trumps_transitional_hybrid(self) -> None:

        findings = [
            self._finding(Readiness.TRANSITIONAL_HYBRID),
            self._finding(Readiness.CLASSICALLY_WEAK),
        ]
        assert _scan_readiness(findings) is Readiness.CLASSICALLY_WEAK

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
