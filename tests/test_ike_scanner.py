# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Hermetic orchestration tests for the IKE scanner."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from qureddy.core.contracts import (
    CollectionFailure,
    CollectionFailureKind,
    ScanSource,
    SourceKind,
)
from qureddy.core.models import (
    Confidence,
    Evidence,
    ExternalToolDependency,
    FailureCategory,
    ObservationType,
)
from qureddy.core.targets import parse_ike_target
from qureddy.scanners.ike.adapter import IkeScanAdapter
from qureddy.scanners.ike.scanner import (
    IKEScanner,
    _collection_failure_category,
    _probe_plan,
    _scan_source,
    _scan_status,
    _summary_failure,
    scan_ike,
)
from qureddy.scanners.ike.types import IKEMode


def _tool(tmp_path: Path, output: str = "") -> str:
    path = tmp_path / "ike-scan-scanner-fixture"
    path.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then echo \'ike-scan 1.9.5\'; exit 0; fi\n'
        f"printf '%s\\n' '{output}'\n"
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def _evidence(
    evidence_type: str,
    observation: ObservationType,
    category: FailureCategory | None = None,
) -> Evidence:
    return Evidence(
        id=f"ev-{evidence_type}",
        asset_id="asset-1",
        evidence_type=evidence_type,
        observation_type=observation,
        source="fixture",
        protocol="ike",
        confidence=Confidence.LOW,
        failure_category=category,
    )


def test_scanner_and_collector_run_real_adapter(tmp_path: Path) -> None:
    output = "Handshake returned (1 transforms) Encr=AES KeyLength=256 Group=14:modp2048"
    scanner = IKEScanner(IkeScanAdapter(_tool(tmp_path, output)))
    target = parse_ike_target("127.0.0.1")

    result = scanner.scan(target, timeout_seconds=1)
    collected = scanner.collect(
        ScanSource(kind=SourceKind.ENDPOINT, protocol="ike", locator=target.locator),
        timeout_seconds=1,
    )

    assert result.scan.status == "completed"
    assert result.scan.total_attempts == 3
    assert result.assets[0].asset_type == "ike.endpoint"
    assert collected.scan_result is not None
    assert collected.evidence
    assert collected.provenance is not None


def test_collector_ignores_unsupported_source() -> None:
    collected = IKEScanner().collect(
        ScanSource(kind=SourceKind.STATIC_INVENTORY, protocol="ike", locator="inventory"),
        timeout_seconds=1,
    )
    assert collected.failure is None
    assert not collected.evidence


def test_missing_tool_and_silent_tool_have_stable_status(tmp_path: Path) -> None:
    target = parse_ike_target("127.0.0.1")
    missing = IKEScanner(IkeScanAdapter("definitely-missing-ike-scan")).scan(
        target, timeout_seconds=1
    )
    silent = scan_ike(target, timeout_seconds=1, binary_name=_tool(tmp_path))
    assert missing.scan.status == FailureCategory.LOCAL_IKE_SCAN_MISSING.value
    assert silent.scan.status == "no_response"


def test_nat_t_plan_deduplicates_responding_modes(tmp_path: Path) -> None:
    output = "Handshake returned (1 transforms) Encr=AES Group=14:modp2048"
    target = parse_ike_target("127.0.0.1")
    result = IKEScanner(IkeScanAdapter(_tool(tmp_path, output)), nat_t=True).scan(
        target, timeout_seconds=1
    )
    assert result.scan.total_attempts == 3
    assert all("transport=nat_t" in record.notes for record in result.evidence)


def test_probe_plans_and_sources_cover_transport_shapes() -> None:
    direct = parse_ike_target("vpn.example")
    natt = parse_ike_target("vpn.example:4500")
    ipv6 = parse_ike_target("[2001:db8::1]")

    assert len(_probe_plan(direct, nat_t=False)) == 3
    assert len(_probe_plan(direct, nat_t=True)) == 6
    assert len(_probe_plan(natt, nat_t=True)) == 3
    source = _scan_source(ipv6, asset_id="asset-1", mode=IKEMode.IKEV2, port=500, nat_t=False)
    assert source.locator == "ike://[2001:db8::1]:500"
    assert source.metadata["mode"] == "ikev2"


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (CollectionFailureKind.TIMEOUT, FailureCategory.IKE_PROBE_TIMEOUT),
        (CollectionFailureKind.MALFORMED, FailureCategory.IKE_OUTPUT_LIMIT),
        (CollectionFailureKind.UNAVAILABLE, FailureCategory.LOCAL_IKE_SCAN_MISSING),
        (CollectionFailureKind.EXECUTION, FailureCategory.LOCAL_IKE_SCAN_BROKEN),
        (CollectionFailureKind.UNSUPPORTED, FailureCategory.IKE_OUTPUT_MALFORMED),
    ],
)
def test_collection_failure_mapping(kind: CollectionFailureKind, expected: FailureCategory) -> None:
    failure = CollectionFailure(kind=kind, message="fixture")
    assert _collection_failure_category(failure) is expected


def test_summary_failure_and_status_precedence() -> None:
    observed = _evidence("ike.mode.responded", ObservationType.OBSERVED)
    silent = _evidence(
        "ike.mode.no_response", ObservationType.NOT_TESTABLE, FailureCategory.IKE_PROBE_TIMEOUT
    )
    notify = _evidence("ike.notify", ObservationType.OBSERVED)
    clean_dependency = ExternalToolDependency(name="ike-scan")
    missing_dependency = ExternalToolDependency(
        name="ike-scan", failure_category=FailureCategory.LOCAL_IKE_SCAN_MISSING
    )

    assert (
        _summary_failure(
            [observed], [FailureCategory.IKE_PROBE_TIMEOUT], dependency=clean_dependency
        )
        is None
    )
    assert _summary_failure([], [], dependency=clean_dependency) is None
    assert (
        _summary_failure([], [], dependency=missing_dependency)
        is FailureCategory.LOCAL_IKE_SCAN_MISSING
    )
    assert (
        _summary_failure([silent], [FailureCategory.IKE_PROBE_TIMEOUT], dependency=clean_dependency)
        is FailureCategory.IKE_PROBE_TIMEOUT
    )
    assert _collection_failure_category(None) is None
    assert _scan_status([], FailureCategory.IKE_PROBE_TIMEOUT) == "ike_probe_timeout"
    assert _scan_status([notify], None) == "rejected"
    assert _scan_status([observed], None) == "completed"
    assert _scan_status([silent], None) == "no_response"
