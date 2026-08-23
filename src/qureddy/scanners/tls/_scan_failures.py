# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Structured TLS failure results and unreachable-target classification."""

from __future__ import annotations

from datetime import UTC, datetime

from qureddy.core.ids import new_id
from qureddy.core.models import (
    Evidence,
    FailureCategory,
    ObservationType,
    OpenSSLDependency,
    ScanResult,
    ScanTarget,
)
from qureddy.core.policy import classify_evidence
from qureddy.scanners.common.metadata import build_scan_metadata
from qureddy.scanners.tls._evidence import build_asset
from qureddy.scanners.tls._summary import build_summary

_UNREACHABLE_FAILURE_CATEGORIES = frozenset({FailureCategory.TARGET_CONNECT_FAILED})


def build_capability_failure_result(
    target: ScanTarget,
    dependency: OpenSSLDependency,
) -> ScanResult:
    """Build a structured result for the local-capability exit-3 path."""
    failure_category = dependency.failure_category or FailureCategory.LOCAL_OPENSSL_MISSING
    return _build_failure_result(
        target,
        failure_category,
        source="qureddy.openssl_probe",
        evidence_type="tls.capability",
        note="local OpenSSL is unusable for X25519MLKEM768 hybrid probing",
        dependencies=(dependency,),
    )


def build_scan_failure_result(
    target: ScanTarget,
    failure_category: FailureCategory,
    *,
    note: str,
) -> ScanResult:
    """Build a structured TLS result for a typed target-scan exception."""
    return _build_failure_result(
        target,
        failure_category,
        source="qureddy.scanners.tls.scanner",
        evidence_type="tls.scan",
        note=note,
        dependencies=(),
    )


def _build_failure_result(
    target: ScanTarget,
    failure_category: FailureCategory,
    *,
    source: str,
    evidence_type: str,
    note: str,
    dependencies: tuple[OpenSSLDependency, ...],
) -> ScanResult:
    started = datetime.now(UTC)
    asset = build_asset(target)
    evidence = Evidence(
        id=new_id("ev"),
        asset_id=asset.id,
        evidence_type=evidence_type,
        observation_type=ObservationType.NOT_TESTABLE,
        source=source,
        failure_category=failure_category,
        notes=(note,),
    )
    findings = classify_evidence(asset, [evidence])
    summary = build_summary(target, list(findings), [evidence]).model_copy(
        update={"failure_category": failure_category}
    )
    return ScanResult(
        scan=build_scan_metadata(
            scan_id=new_id("scan"),
            started_at=started,
            scanner_name="tls",
            status=failure_category.value,
            total_attempts=0,
        ),
        target=target,
        dependencies=dependencies,
        assets=(asset,),
        evidence=(evidence,),
        findings=tuple(findings),
        summary=summary,
    )


def target_appears_unreachable(evidence: list[Evidence]) -> bool:
    """Return whether every primary probe failed before connecting."""
    if not evidence:
        return False
    return all(item.failure_category in _UNREACHABLE_FAILURE_CATEGORIES for item in evidence)
