# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Rich console output adapter."""

from __future__ import annotations

import io
import re
from datetime import UTC, datetime

import pytest

from qureddy._branding import HEADER
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
    Readiness,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from qureddy.output.console import render_rich

ANSI_ESCAPE = re.compile(r"\x1b\[")


def _build_result(
    *,
    failure_category: FailureCategory | None = None,
    classical_group: str | None = "X25519",
) -> ScanResult:
    """A ScanResult with hybrid + classical evidence and one finding each."""
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
        protocol_version="TLSv1.3",
    )
    hybrid_probe = ProbeResult(
        command=ProbeCommand(
            executable="/opt/homebrew/opt/openssl@3.5/bin/openssl",
            args=(
                "s_client",
                "-connect",
                "example.com:443",
                "-tls1_3",
                "-groups",
                "X25519MLKEM768",
            ),
            timeout_seconds=30,
        ),
        return_code=0,
        stdout_sha256="0" * 64,
        stderr_sha256="0" * 64,
        duration_ms=120,
    )
    classical_probe = ProbeResult(
        command=ProbeCommand(
            executable="/opt/homebrew/opt/openssl@3.5/bin/openssl",
            args=("s_client", "-connect", "example.com:443", "-tls1_3", "-groups", "X25519"),
            timeout_seconds=30,
        ),
        return_code=0,
        stdout_sha256="0" * 64,
        stderr_sha256="0" * 64,
        duration_ms=110,
    )
    hybrid_evidence = Evidence(
        id="ev-hybrid",
        asset_id=asset.id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519MLKEM768",
        probe_result=hybrid_probe,
    )
    classical_evidence = Evidence(
        id="ev-classical",
        asset_id=asset.id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group=classical_group,
        probe_result=classical_probe,
    )
    findings = (
        Finding(
            id="f-hybrid",
            asset_id=asset.id,
            evidence_ids=("ev-hybrid",),
            rule_id="tls.hybrid.negotiated_pq",
            finding_type="tls.kex.hybrid",
            title="Hybrid",
            description="d",
            severity=Severity.INFO,
            readiness=Readiness.TRANSITIONAL_HYBRID,
            confidence=Confidence.HIGH,
            protocol_version="TLSv1.3",
            negotiated_group="X25519MLKEM768",
        ),
        Finding(
            id="f-classical",
            asset_id=asset.id,
            evidence_ids=("ev-classical",),
            rule_id="tls.classical.negotiated_x25519",
            finding_type="tls.kex.classical",
            title="Classical control",
            description="d",
            severity=Severity.LOW,
            readiness=Readiness.QUANTUM_VULNERABLE,
            confidence=Confidence.HIGH,
            protocol_version="TLSv1.3",
            negotiated_group="X25519",
        ),
    )
    return ScanResult(
        scan=ScanMetadata(
            scan_id="scan-1",
            started_at=datetime(2026, 4, 26, tzinfo=UTC),
            completed_at=datetime(2026, 4, 26, tzinfo=UTC),
            status="completed",
            total_attempts=2,
        ),
        target=target,
        dependencies=(
            OpenSSLDependency(
                path="/opt/homebrew/opt/openssl@3.5/bin/openssl",
                version="3.5.7",
                supports_tls13_groups=True,
                supports_x25519mlkem768=True,
            ),
        ),
        assets=(asset,),
        evidence=(hybrid_evidence, classical_evidence),
        findings=findings,
        summary=ScanSummary(
            target=target.locator,
            finding_count=2,
            highest_severity=Severity.LOW,
            readiness=Readiness.TRANSITIONAL_HYBRID,
            failure_category=failure_category,
        ),
    )


def _render_to_string(result: ScanResult) -> str:
    buf = io.StringIO()
    render_rich(result, buf)
    return buf.getvalue()


class TestSummaryRows:
    """The four new summary rows are present and populated from evidence."""

    def test_protocol_row_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "protocol" in out
        assert "TLSv1.3" in out

    def test_cipher_suite_row_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "cipher_suite" in out
        assert "TLS_AES_256_GCM_SHA384" in out

    def test_hybrid_probe_row_shows_negotiated(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "hybrid_probe" in out
        assert "negotiated" in out
        assert "X25519MLKEM768" in out

    def test_classical_probe_row_shows_negotiated_x25519(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "classical_probe" in out
        assert "X25519" in out


class TestNoColorEnvVar:
    """NO_COLOR=any-value disables ANSI escapes."""

    def test_no_color_set_strips_ansi(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert ANSI_ESCAPE.search(out) is None, (
            "NO_COLOR=1 should disable ANSI color output entirely"
        )

    def test_no_color_empty_string_also_disables_color(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """https://no-color.org: any value, including the empty string, disables color."""
        monkeypatch.setenv("NO_COLOR", "")
        out = _render_to_string(_build_result())
        assert ANSI_ESCAPE.search(out) is None


class TestFindingsTableProtocolColumn:
    """The findings table includes the new Protocol column."""

    def test_protocol_column_header_present(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "Protocol" in out

    def test_protocol_value_rendered_per_finding(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        # Two findings both have protocol_version=TLSv1.3.
        assert out.count("TLSv1.3") >= 2


class TestExistingContractStillHolds:
    """The pre-existing contract (target locator + schema version visible)
    must still hold after the redesign."""

    def test_target_locator_in_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        expected_locator = "tls://" + "example.com:443"
        assert expected_locator in out

    def test_mixed_posture_uses_two_axis_headline(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        result = _build_result()
        legacy = result.findings[1].model_copy(
            update={
                "finding_type": "tls.legacy.protocol_offered",
                "rule_id": "tls.legacy.protocol_offered",
                "protocol_version": "TLSv1.1",
            },
        )
        result = result.model_copy(
            update={
                "findings": (result.findings[0], legacy),
                "summary": result.summary.model_copy(
                    update={
                        "finding_count": 2,
                        "readiness": Readiness.CLASSICALLY_WEAK,
                    },
                ),
            },
        )
        out = _render_to_string(result)
        assert "PQ posture:" in out
        assert "ACCEPTABLE" in out
        assert "Protocol hygiene:" in out
        assert "ACTION NEEDED" in out
        assert "FAIL — weak legacy fallback" not in out

    def test_rule_id_is_not_ellipsized(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "tls.hybrid.negotiated_pq" in out

    def test_findings_are_sorted_by_severity(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        result = _build_result()
        out = _render_to_string(result)
        assert out.index("tls.classical.negotiated_x25519") < out.index(
            "tls.hybrid.negotiated_pq",
        )

    def test_schema_version_in_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "qureddy.scan.v1" in out

    def test_header_in_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The canonical HEADER constant appears in output.

        Pins via the imported `HEADER` (not a hardcoded literal) so a
        version bump propagates without test churn. Pre-extraction
        hardcoding `\"QuReddy 0.1.0 by BreachSAFE\"` was the
        version-drift bug the branding extraction fixed.
        """
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert HEADER in out

    def test_footer_contains_identity_and_run_provenance(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "Run details" in out
        assert "scan_id" in out
        assert "scanner" in out
        assert "tls" in out
        assert "0.0s" in out


class TestFailureCategoryRow:
    """When summary.failure_category is set, it appears in red."""

    def test_failure_category_row_present_when_set(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        result = _build_result(failure_category=FailureCategory.TLS_HANDSHAKE_FAILED)
        out = _render_to_string(result)
        assert "failure_category" in out
        assert "tls_handshake_failed" in out


class TestDependenciesTable:
    """Capability column shows yes/no, not booleans."""

    def test_supported_capability_renders_yes(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        # The capability column header is X25519MLKEM768; the cell value is yes.
        # Verify the cell rendered as "yes" (color stripped under NO_COLOR).
        assert " yes " in out or out.endswith("yes\n") or "│ yes " in out

    def test_capability_column_has_explicit_label(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        out = _render_to_string(_build_result())
        assert "openssl_hybrid_support" in out
