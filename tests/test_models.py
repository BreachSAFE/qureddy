# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for the locked Pydantic model surface in qureddy.core.models."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

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


def _make_target() -> ScanTarget:
    return ScanTarget(
        original_input="example.com",
        host="example.com",
        port=443,
        sni="example.com",
        locator="tls://example.com:443",
    )


def _make_asset() -> Asset:
    return Asset(
        id="asset-1",
        asset_type="tls.endpoint",
        locator="tls://example.com:443",
        display_name="example.com:443",
        protocol_version="TLSv1.3",
    )


def _make_evidence() -> Evidence:
    return Evidence(
        id="ev-1",
        asset_id="asset-1",
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="openssl",
        negotiated_group="X25519",
    )


def _make_finding() -> Finding:
    return Finding(
        id="f-1",
        asset_id="asset-1",
        evidence_ids=("ev-1",),
        rule_id="tls.classical.negotiated_x25519",
        finding_type="tls.kex",
        title="Classical X25519",
        description="Server negotiated classical X25519.",
        severity=Severity.LOW,
        readiness=Readiness.QUANTUM_VULNERABLE,
        confidence=Confidence.HIGH,
    )


def _make_scan_metadata() -> ScanMetadata:
    started = datetime(2026, 4, 26, 17, 0, 0, tzinfo=UTC)
    completed = datetime(2026, 4, 26, 17, 0, 5, tzinfo=UTC)
    return ScanMetadata(
        scan_id="scan-1",
        started_at=started,
        completed_at=completed,
        status="completed",
    )


def _make_scan_result() -> ScanResult:
    return ScanResult(
        scan=_make_scan_metadata(),
        target=_make_target(),
        dependencies=(),
        assets=(_make_asset(),),
        evidence=(_make_evidence(),),
        findings=(_make_finding(),),
        summary=ScanSummary(
            target="tls://example.com:443",
            finding_count=1,
            highest_severity=Severity.LOW,
            readiness=Readiness.QUANTUM_VULNERABLE,
        ),
    )


class TestScanResultSerialization:
    """JSON output is the public schema contract."""

    def test_top_level_keys_appear_in_locked_order(self) -> None:
        payload = _make_scan_result().model_dump(mode="json")
        expected = [
            "schema_version",
            "scan",
            "target",
            "dependencies",
            "assets",
            "evidence",
            "findings",
            "summary",
        ]
        assert list(payload.keys()) == expected

    def test_round_trips_through_json(self) -> None:
        result = _make_scan_result()
        payload = result.model_dump(mode="json")
        as_text = json.dumps(payload)
        reloaded = ScanResult.model_validate(json.loads(as_text))
        assert reloaded == result

    def test_schema_version_is_v1(self) -> None:
        assert _make_scan_result().schema_version == "qureddy.scan.v1"


class TestEnumSerialization:
    """Enums must serialize as their lowercase string values."""

    def test_severity_serializes_lowercase(self) -> None:
        f = _make_finding()
        assert f.model_dump(mode="json")["severity"] == "low"

    def test_observation_type_serializes_lowercase(self) -> None:
        e = _make_evidence()
        assert e.model_dump(mode="json")["observation_type"] == "negotiated"

    def test_failure_category_serializes_lowercase(self) -> None:
        dep = OpenSSLDependency(
            failure_category=FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        )
        assert dep.model_dump(mode="json")["failure_category"] == "local_openssl_too_old"

    def test_probe_result_parser_input_is_not_serialized(self) -> None:
        probe = ProbeResult(
            command=ProbeCommand(executable="openssl", args=("s_client",), timeout_seconds=30),
            return_code=0,
            stdout_sha256="stdout",
            stderr_sha256="stderr",
            parser_input="full parser-only output",
            duration_ms=1,
        )
        assert "parser_input" not in probe.model_dump(mode="json")


class TestModelImmutability:
    """All non-ScanMetadata models are frozen; mutation must raise."""

    def test_scan_target_is_frozen(self) -> None:
        target = _make_target()
        with pytest.raises(ValidationError):
            target.host = "other.example"  # type: ignore[misc]

    def test_evidence_is_frozen(self) -> None:
        ev = _make_evidence()
        with pytest.raises(ValidationError):
            ev.confidence = Confidence.LOW  # type: ignore[misc]

    def test_finding_is_frozen(self) -> None:
        f = _make_finding()
        with pytest.raises(ValidationError):
            f.severity = Severity.HIGH  # type: ignore[misc]

    def test_scan_metadata_is_frozen(self) -> None:
        meta = _make_scan_metadata()
        with pytest.raises(ValidationError):
            meta.status = "failed"  # type: ignore[misc]

    def test_extra_fields_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanTarget(
                original_input="example.com",
                host="example.com",
                port=443,
                sni="example.com",
                locator="tls://example.com:443",
                bogus="field",  # type: ignore[call-arg]
            )


class TestNistQuantumSecurityLevel:
    """ge=0, le=5 validation per spec."""

    def test_zero_is_accepted(self) -> None:
        Asset(
            id="a",
            asset_type="tls.endpoint",
            locator="tls://e:443",
            display_name="e:443",
            nist_quantum_security_level=0,
        )

    def test_five_is_accepted(self) -> None:
        Asset(
            id="a",
            asset_type="tls.endpoint",
            locator="tls://e:443",
            display_name="e:443",
            nist_quantum_security_level=5,
        )

    def test_negative_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Asset(
                id="a",
                asset_type="tls.endpoint",
                locator="tls://e:443",
                display_name="e:443",
                nist_quantum_security_level=-1,
            )

    def test_six_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Asset(
                id="a",
                asset_type="tls.endpoint",
                locator="tls://e:443",
                display_name="e:443",
                nist_quantum_security_level=6,
            )


class TestEvidenceObservationTypeRequired:
    """Evidence cannot be constructed without observation_type."""

    def test_missing_observation_type_raises(self) -> None:
        with pytest.raises(ValidationError):
            Evidence(  # type: ignore[call-arg]
                id="ev",
                asset_id="a",
                evidence_type="tls.negotiation",
                source="openssl",
            )


class TestFindingEvidenceIdsRequired:
    """Finding requires at least one evidence_id."""

    def test_empty_evidence_ids_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                id="f",
                asset_id="a",
                evidence_ids=(),
                rule_id="r",
                finding_type="t",
                title="T",
                description="D",
                severity=Severity.LOW,
                readiness=Readiness.QUANTUM_VULNERABLE,
                confidence=Confidence.HIGH,
            )


class TestProbeResultDefaults:
    """ProbeResult.attempt_number defaults to 1."""

    def test_attempt_number_default(self) -> None:
        cmd = ProbeCommand(
            executable="openssl",
            args=("s_client", "-connect", "example.com:443"),
            timeout_seconds=30,
        )
        r = ProbeResult(
            command=cmd,
            return_code=0,
            stdout_sha256="0" * 64,
            stderr_sha256="0" * 64,
            duration_ms=10,
        )
        assert r.attempt_number == 1
