# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for TLSScanner orchestration that don't require live network."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import qureddy.scanners.tls.scanner as scanner_module
from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    FailureCategory,
    Finding,
    ObservationType,
    OpenSSLDependency,
    ProbeCommand,
    ProbeResult,
    ProbeRole,
    Readiness,
    ScanMetadata,
    ScanResult,
    ScanTarget,
    Severity,
)
from qureddy.core.policy import classify_evidence
from qureddy.scanners.tls._evidence import build_asset, evidence_from_probe
from qureddy.scanners.tls._summary import highest_severity
from qureddy.scanners.tls.cert_probe import CertificateInfo
from qureddy.scanners.tls.openssl_probe import HYBRID_GROUP
from qureddy.scanners.tls.scanner import TLSScanner, _build_summary, _scan_readiness


class TestTLSScannerOrchestration:
    """Hermetic coverage of the full-scan orchestration branches."""

    @staticmethod
    def _target() -> ScanTarget:
        return ScanTarget(
            original_input="example.invalid",
            host="example.invalid",
            port=443,
            sni="example.invalid",
            locator="tls://example.invalid:443",
        )

    def test_reachable_target_collects_legacy_and_certificate_evidence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scanner = TLSScanner(openssl_path="/fixture/openssl")
        dependency = OpenSSLDependency(
            path="/fixture/openssl",
            version="3.6.3",
            supports_tls13_groups=True,
            supports_x25519mlkem768=True,
        )
        monkeypatch.setattr(
            scanner, "_check_capability", lambda _timeout: (dependency.path, dependency)
        )
        monkeypatch.setattr(scanner, "_collect_evidence", lambda **_kwargs: ([], 0))
        monkeypatch.setattr(scanner, "_collect_legacy_evidence", lambda **_kwargs: ([], []))

        def collect_cert(**kwargs: object) -> tuple[Evidence, None]:
            asset = kwargs["asset"]
            assert isinstance(asset, Asset)
            return (
                Evidence(
                    id="ev-cert",
                    asset_id=asset.id,
                    evidence_type="tls.cert.signature",
                    observation_type=ObservationType.NOT_TESTABLE,
                    source="fixture",
                ),
                None,
            )

        monkeypatch.setattr(scanner, "_collect_cert_evidence", collect_cert)
        result = scanner.scan(self._target(), timeout_seconds=1)
        assert result.scan.status == "completed"
        assert result.scan.total_attempts == 1
        assert result.evidence[0].id == "ev-cert"

    def test_unreachable_target_skips_supplemental_probes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scanner = TLSScanner(openssl_path="/fixture/openssl")
        dependency = OpenSSLDependency(
            path="/fixture/openssl",
            version="3.6.3",
            supports_tls13_groups=True,
            supports_x25519mlkem768=True,
        )
        target = self._target()
        asset = build_asset(target)
        failure = Evidence(
            id="ev-connect",
            asset_id=asset.id,
            evidence_type="tls.probe.failure",
            observation_type=ObservationType.OBSERVED,
            source="fixture",
            failure_category=FailureCategory.TARGET_CONNECT_FAILED,
        )
        monkeypatch.setattr(
            scanner, "_check_capability", lambda _timeout: (dependency.path, dependency)
        )
        monkeypatch.setattr(scanner, "_collect_evidence", lambda **_kwargs: ([failure], 1))

        def unexpected(**_kwargs: object) -> None:
            pytest.fail("supplemental probe ran for unreachable target")

        monkeypatch.setattr(scanner, "_collect_legacy_evidence", unexpected)
        monkeypatch.setattr(scanner, "_collect_cert_evidence", unexpected)
        result = scanner.scan(target, timeout_seconds=1)
        assert result.scan.status == "completed"
        assert result.scan.total_attempts == 1
        assert result.evidence[0].failure_category is FailureCategory.TARGET_CONNECT_FAILED

    def test_certificate_collection_covers_missing_and_observed_paths(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = self._target()
        asset = build_asset(target)
        monkeypatch.setattr(scanner_module, "fetch_certificate_pem", lambda *_args, **_kwargs: "")
        evidence, finding = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
        )
        assert finding is None
        assert evidence.observation_type is ObservationType.NOT_TESTABLE

        certificate = CertificateInfo(
            subject="CN=test",
            issuer="CN=issuer",
            not_before="before",
            not_after="after",
            serial="01",
            signature_algorithm="sha256WithRSAEncryption",
            public_key_summary="Public-Key: (2048 bit)",
            is_self_signed=False,
            is_post_quantum_signature=False,
        )
        monkeypatch.setattr(
            scanner_module, "fetch_certificate_pem", lambda *_args, **_kwargs: "fixture pem"
        )
        monkeypatch.setattr(
            scanner_module, "parse_certificate", lambda *_args, **_kwargs: certificate
        )
        evidence, finding = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
        )
        assert evidence.observation_type is ObservationType.OBSERVED
        assert finding is not None


class TestSummaryFailureCategoryPreservation:
    """The summary must surface the exact category, not collapse rules."""

    def _make_result_with_local_failure(
        self,
        category: FailureCategory,
    ) -> ScanResult:
        target = ScanTarget(
            original_input="example.com",
            host="example.com",
            port=443,
            sni="example.com",
            locator="tls://example.com:443",
        )
        asset = Asset(
            id="asset-1",
            asset_type="tls.endpoint",
            locator=target.locator,
            display_name="example.com:443",
        )
        ev = Evidence(
            id="ev-1",
            asset_id=asset.id,
            evidence_type="tls.capability",
            observation_type=ObservationType.NOT_TESTABLE,
            source="qureddy.openssl_probe",
            failure_category=category,
        )
        finding = Finding(
            id="f-1",
            asset_id=asset.id,
            evidence_ids=("ev-1",),
            rule_id="tls.hybrid.not_testable",
            finding_type="tls.kex.not_testable",
            title="not testable",
            description="d",
            severity=Severity.INFO,
            readiness=Readiness.UNKNOWN,
            confidence=Confidence.HIGH,
        )
        summary = _build_summary(target, [finding], [ev])
        return ScanResult(
            scan=ScanMetadata(
                scan_id="scan-1",
                started_at=datetime(2026, 4, 26, tzinfo=UTC),
                completed_at=datetime(2026, 4, 26, tzinfo=UTC),
                status="x",
            ),
            target=target,
            dependencies=(OpenSSLDependency(failure_category=category),),
            assets=(asset,),
            evidence=(ev,),
            findings=(finding,),
            summary=summary,
        )

    def test_local_openssl_too_old_preserved(self) -> None:
        result = self._make_result_with_local_failure(
            FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        )
        assert result.summary.failure_category is FailureCategory.LOCAL_OPENSSL_TOO_OLD

    def test_local_openssl_lacks_group_preserved(self) -> None:
        result = self._make_result_with_local_failure(
            FailureCategory.LOCAL_OPENSSL_LACKS_GROUP,
        )
        assert result.summary.failure_category is FailureCategory.LOCAL_OPENSSL_LACKS_GROUP

    def test_local_openssl_missing_preserved(self) -> None:
        result = self._make_result_with_local_failure(
            FailureCategory.LOCAL_OPENSSL_MISSING,
        )
        assert result.summary.failure_category is FailureCategory.LOCAL_OPENSSL_MISSING

    def test_probe_failure_categories_preserved(self) -> None:
        """target_connect_failed and tls_handshake_failed are distinct."""
        target = ScanTarget(
            original_input="t",
            host="t",
            port=443,
            sni="t",
            locator="tls://t:443",
        )
        asset = Asset(
            id="a",
            asset_type="tls.endpoint",
            locator=target.locator,
            display_name="t:443",
        )

        for category in (
            FailureCategory.TARGET_CONNECT_FAILED,
            FailureCategory.TLS_HANDSHAKE_FAILED,
            FailureCategory.MIDDLEBOX_OR_MTU_FAILURE,
            FailureCategory.PARSE_NO_GROUP,
        ):
            ev = Evidence(
                id=f"ev-{category.value}",
                asset_id=asset.id,
                evidence_type="tls.probe.failure",
                observation_type=ObservationType.OBSERVED,
                source="openssl",
                probe_result=ProbeResult(
                    command=ProbeCommand(
                        executable="openssl",
                        args=(),
                        timeout_seconds=30,
                    ),
                    return_code=1,
                    stdout_sha256="0" * 64,
                    stderr_sha256="0" * 64,
                    duration_ms=1,
                ),
                failure_category=category,
            )
            finding = Finding(
                id=f"f-{category.value}",
                asset_id=asset.id,
                evidence_ids=(ev.id,),
                rule_id="tls.hybrid.probe_failed",
                finding_type="tls.kex.probe_failed",
                title="t",
                description="d",
                severity=Severity.INFO,
                readiness=Readiness.UNKNOWN,
                confidence=Confidence.MEDIUM,
            )
            summary = _build_summary(target, [finding], [ev])
            assert summary.failure_category is category, (
                f"expected {category} preserved, got {summary.failure_category}"
            )


class TestSummaryFailureCategorySupersededByRetrySuccess:
    """Issue #241: a later successful retry must clear an earlier failure category."""

    def test_hybrid_negotiated_after_earlier_failed_attempt_clears_failure_category(
        self,
    ) -> None:
        target = ScanTarget(
            original_input="flaky.example",
            host="flaky.example",
            port=443,
            sni=None,
            locator="tls://flaky.example:443",
        )
        asset = build_asset(target)

        attempt1 = ProbeResult(
            command=ProbeCommand(
                executable="openssl", args=("s_client", "-groups", HYBRID_GROUP), timeout_seconds=5
            ),
            return_code=1,
            stdout_sha256="0" * 64,
            stderr_sha256="0" * 64,
            duration_ms=1,
            attempt_number=1,
            failure_category=FailureCategory.TARGET_CONNECT_FAILED,
        )
        attempt2_stdout = (
            "Protocol version: TLSv1.3\n"
            "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
            "Negotiated TLS1.3 group: X25519MLKEM768\n"
        )
        attempt2 = ProbeResult(
            command=ProbeCommand(
                executable="openssl", args=("s_client", "-groups", HYBRID_GROUP), timeout_seconds=5
            ),
            return_code=0,
            stdout_sha256="0" * 64,
            stderr_sha256="0" * 64,
            parser_input=attempt2_stdout,
            duration_ms=1,
            attempt_number=2,
            failure_category=None,
        )

        ev1 = evidence_from_probe(
            asset=asset,
            probe=attempt1,
            expected_group=HYBRID_GROUP,
            probe_role=ProbeRole.HYBRID_READINESS,
        )
        ev2 = evidence_from_probe(
            asset=asset,
            probe=attempt2,
            expected_group=HYBRID_GROUP,
            probe_role=ProbeRole.HYBRID_READINESS,
        )
        evidence = [ev1, ev2]
        findings = classify_evidence(asset, evidence)
        summary = _build_summary(target, findings, evidence)

        assert summary.readiness is Readiness.TRANSITIONAL_HYBRID
        assert summary.failure_category is None


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
