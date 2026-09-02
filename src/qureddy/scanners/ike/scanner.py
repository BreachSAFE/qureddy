# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""IKE orchestration from ToolAdapter results to the canonical ScanResult."""

from __future__ import annotations

from datetime import UTC, datetime

from qureddy.core.contracts import (
    Capability,
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    ScanSource,
    SourceKind,
)
from qureddy.core.ids import new_id
from qureddy.core.models import (
    Evidence,
    ExternalToolDependency,
    FailureCategory,
    ObservationType,
    ScanResult,
    ScanTarget,
)
from qureddy.core.targets import parse_ike_target
from qureddy.scanners.common.assets import build_endpoint_asset
from qureddy.scanners.common.metadata import build_scan_metadata
from qureddy.scanners.common.posture import build_scan_summary
from qureddy.scanners.ike.adapter import IkeScanAdapter
from qureddy.scanners.ike.classify import classify_ike
from qureddy.scanners.ike.types import IKEMode

_MODES = (IKEMode.IKEV1_MAIN, IKEMode.IKEV1_AGGRESSIVE, IKEMode.IKEV2)
_NAT_T_PORT = 4500


class IKEScanner:
    """Collect lower-trust IKE observations through one external-tool adapter."""

    scanner_name = "ike"
    collector_name = "ike-scan"
    collector_version = "1"
    capabilities = frozenset({Capability.IKE_ENDPOINT})

    def __init__(self, adapter: IkeScanAdapter | None = None, *, nat_t: bool = False) -> None:
        """Configure the tool adapter and optional NAT-T pass."""
        self._adapter = adapter or IkeScanAdapter()
        self._nat_t = nat_t

    def collect(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Collect a complete endpoint result through the canonical collector seam."""
        if source.kind is not SourceKind.ENDPOINT or source.protocol != "ike":
            return CollectionResult(
                collector=self.collector_name,
                collector_version=self.collector_version,
                failure=None,
            )
        result = self.scan(parse_ike_target(source.locator), timeout_seconds=timeout_seconds)
        return CollectionResult(
            collector=self.collector_name,
            collector_version=self.collector_version,
            evidence=result.evidence,
            findings=result.findings,
            provenance=result.scan.provenance,
            scan_result=result,
        )

    def scan(self, subject: ScanTarget, *, timeout_seconds: int) -> ScanResult:
        """Scan one IKE endpoint and assemble the shared result contract."""
        started = datetime.now(UTC)
        asset = build_endpoint_asset(subject, asset_type="ike.endpoint", protocol="ike")
        evidence, categories, attempts = self._collect(
            subject, asset_id=asset.id, timeout_seconds=timeout_seconds
        )
        findings = classify_ike(asset, evidence)
        failure = _summary_failure(evidence, categories, dependency=self._adapter.dependency())
        status = _scan_status(evidence, failure)
        return ScanResult(
            scan=build_scan_metadata(
                scan_id=new_id("scan"),
                started_at=started,
                scanner_name=self.scanner_name,
                status=status,
                total_attempts=attempts,
            ),
            target=subject,
            dependencies=(self._adapter.dependency(),),
            assets=(asset,),
            evidence=tuple(evidence),
            findings=tuple(findings),
            summary=build_scan_summary(subject, findings, evidence, failure, protocol="ike"),
        )

    def _collect(
        self, target: ScanTarget, *, asset_id: str, timeout_seconds: int
    ) -> tuple[list[Evidence], list[FailureCategory], int]:
        evidence: list[Evidence] = []
        categories: list[FailureCategory] = []
        plan = _probe_plan(target, nat_t=self._nat_t)
        responding_modes: set[IKEMode] = set()
        attempts = 0
        for mode, port, nat_t in plan:
            if not nat_t and mode in responding_modes:
                continue
            source = _scan_source(target, asset_id=asset_id, mode=mode, port=port, nat_t=nat_t)
            collected = self._adapter.run(source, timeout_seconds=timeout_seconds)
            attempts += 1
            evidence.extend(collected.evidence)
            if any(
                record.observation_type is ObservationType.OBSERVED for record in collected.evidence
            ):
                responding_modes.add(mode)
            categories.extend(
                record.failure_category
                for record in collected.evidence
                if record.failure_category is not None
            )
            collection_category = _collection_failure_category(collected.failure)
            if collection_category is not None:
                categories.append(collection_category)
        return evidence, categories, attempts


def _probe_plan(target: ScanTarget, *, nat_t: bool) -> tuple[tuple[IKEMode, int, bool], ...]:
    standard = tuple((mode, target.port, False) for mode in _MODES)
    if not nat_t:
        return standard
    natt = tuple((mode, _NAT_T_PORT, True) for mode in _MODES)
    if target.port == _NAT_T_PORT:
        return natt
    return tuple(
        probe
        for mode in _MODES
        for probe in ((mode, _NAT_T_PORT, True), (mode, target.port, False))
    )


def _scan_source(
    target: ScanTarget, *, asset_id: str, mode: IKEMode, port: int, nat_t: bool
) -> ScanSource:
    rendered = f"[{target.host}]" if ":" in target.host else target.host
    return ScanSource(
        kind=SourceKind.ENDPOINT,
        locator=f"ike://{rendered}:{port}",
        protocol="ike",
        metadata={"asset_id": asset_id, "mode": mode.value, "nat_t": str(nat_t).lower()},
    )


def _summary_failure(
    evidence: list[Evidence],
    categories: list[FailureCategory],
    *,
    dependency: ExternalToolDependency,
) -> FailureCategory | None:
    if dependency.failure_category is not None:
        return dependency.failure_category
    if any(record.observation_type is ObservationType.OBSERVED for record in evidence):
        return None
    return categories[0] if categories else None


def _collection_failure_category(failure: CollectionFailure | None) -> FailureCategory | None:
    """Map adapter failures onto the stable public failure vocabulary."""
    if failure is None:
        return None
    return {
        CollectionFailureKind.TIMEOUT: FailureCategory.IKE_PROBE_TIMEOUT,
        CollectionFailureKind.MALFORMED: FailureCategory.IKE_OUTPUT_LIMIT,
        CollectionFailureKind.UNAVAILABLE: FailureCategory.LOCAL_IKE_SCAN_MISSING,
        CollectionFailureKind.EXECUTION: FailureCategory.LOCAL_IKE_SCAN_BROKEN,
    }.get(failure.kind, FailureCategory.IKE_OUTPUT_MALFORMED)


def _scan_status(evidence: list[Evidence], failure: FailureCategory | None) -> str:
    if failure is not None:
        return failure.value
    modes = [record for record in evidence if record.evidence_type.startswith("ike.mode.")]
    if any(record.evidence_type == "ike.notify" for record in evidence):
        return "rejected"
    if any(record.observation_type is ObservationType.OBSERVED for record in modes):
        return "completed"
    return "no_response"


def scan_ike(
    target: ScanTarget,
    *,
    timeout_seconds: int = 8,
    nat_t: bool = False,
    binary_name: str = "ike-scan",
    source_port: int = 0,
) -> ScanResult:
    """Convenience entry point for one IKE endpoint scan."""
    adapter = IkeScanAdapter(binary_name, source_port=source_port)
    return IKEScanner(adapter, nat_t=nat_t).scan(target, timeout_seconds=timeout_seconds)
