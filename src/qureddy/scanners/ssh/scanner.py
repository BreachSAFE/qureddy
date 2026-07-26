# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""SSH scanner orchestrator: probe -> classify -> ScanResult (reuses core models)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    FailureCategory,
    Finding,
    ObservationType,
    Readiness,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from qureddy.scanners.ssh import classify
from qureddy.scanners.ssh.probe import read_kexinit_offer

if TYPE_CHECKING:
    from qureddy.core.errors import SSHProbeError

_DEFAULT_SSH_PORT = 22
# readiness rollup precedence (mirrors _summary.py)
_PRECEDENCE = (
    Readiness.CLASSICALLY_WEAK,
    Readiness.TRANSITIONAL_HYBRID,
    Readiness.QUANTUM_VULNERABLE,
    Readiness.UNKNOWN,
)
_SEV_ORDER = ("info", "low", "medium", "high", "critical")


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _build_ssh_asset(target: ScanTarget) -> Asset:
    """Build the single ssh.endpoint asset every SSH ScanResult carries."""
    return Asset(
        id=_uid("asset"),
        asset_type="ssh.endpoint",
        locator=target.locator,
        display_name=f"{target.host}:{target.port}",
        protocol="ssh",
    )


def build_ssh_failure_result(
    target: ScanTarget,
    error: SSHProbeError,
    *,
    cleaned_error: str,
) -> ScanResult:
    """Build a structured result for an SSH probe failure."""
    started = datetime.now(UTC)
    failure_category = (
        FailureCategory.TARGET_CONNECT_FAILED
        if isinstance(error.__cause__, OSError | TimeoutError)
        else FailureCategory.PARSE_AMBIGUOUS
    )
    asset = _build_ssh_asset(target)
    evidence = Evidence(
        id=_uid("ev"),
        asset_id=asset.id,
        evidence_type="ssh.kex",
        observation_type=ObservationType.NOT_TESTABLE,
        source="qureddy.scanners.ssh.probe",
        protocol="ssh",
        failure_category=failure_category,
        notes=(cleaned_error,),
    )
    return ScanResult(
        scan=ScanMetadata(
            scan_id=_uid("scan"),
            started_at=started,
            completed_at=datetime.now(UTC),
            scanner_name="ssh",
            status=failure_category.value,
            total_attempts=1,
        ),
        target=target,
        dependencies=(),
        assets=(asset,),
        evidence=(evidence,),
        findings=(),
        summary=ScanSummary(
            target=target.locator,
            finding_count=0,
            highest_severity=None,
            readiness=Readiness.UNKNOWN,
            failure_category=failure_category,
        ),
    )


def scan_ssh(target: ScanTarget, *, timeout_seconds: int = 8) -> ScanResult:
    """Scan an SSH endpoint for post-quantum readiness. Raises SSHProbeError on probe failure."""
    started = datetime.now(UTC)
    offer = read_kexinit_offer(target.host, target.port, timeout_seconds=timeout_seconds)

    asset = _build_ssh_asset(target)

    evidence: list[Evidence] = []
    findings: list[Finding] = []

    # axis 1 — key exchange
    pq = classify.pq_hybrid_kex(offer.kex_algorithms)
    if pq:
        ev = Evidence(
            id=_uid("ev"),
            asset_id=asset.id,
            evidence_type="ssh.kex",
            observation_type=ObservationType.OFFERED,
            source="qureddy.scanners.ssh.probe",
            protocol="ssh",
            negotiated_group=pq[0],
            notes=(f"PQ hybrid KEX offered: {', '.join(pq)}",),
        )
        evidence.append(ev)
        findings.append(
            Finding(
                id=_uid("finding"),
                asset_id=asset.id,
                evidence_ids=(ev.id,),
                rule_id="ssh.kex.hybrid_offered",
                finding_type="ssh.kex.hybrid",
                title=f"SSH offers post-quantum hybrid key exchange ({pq[0]})",
                description="Server offers a PQ hybrid KEX group; protects against harvest-now-decrypt-later.",
                severity=Severity.INFO,
                readiness=Readiness.TRANSITIONAL_HYBRID,
                confidence=Confidence.HIGH,
                algorithm=pq[0],
                # negotiated_group is what output/cbom.py reads to emit a
                # cryptographic-asset component; without it the SSH KEX
                # (e.g. sntrup761x25519-sha512) was absent from --format cbom.
                negotiated_group=pq[0],
                protocol="ssh",
            )
        )
    else:
        ev = Evidence(
            id=_uid("ev"),
            asset_id=asset.id,
            evidence_type="ssh.kex",
            observation_type=ObservationType.OFFERED,
            source="qureddy.scanners.ssh.probe",
            protocol="ssh",
            notes=("no PQ hybrid KEX offered",),
        )
        evidence.append(ev)
        findings.append(
            Finding(
                id=_uid("finding"),
                asset_id=asset.id,
                evidence_ids=(ev.id,),
                rule_id="ssh.kex.classical_only",
                finding_type="ssh.kex.classical",
                title="SSH offers classical key exchange only",
                description="No PQ hybrid KEX offered; exposed to harvest-now-decrypt-later.",
                severity=Severity.LOW,
                readiness=Readiness.QUANTUM_VULNERABLE,
                confidence=Confidence.HIGH,
                protocol="ssh",
            )
        )

    # axis 2 — host-key signature (weak DSA?)
    weak = classify.weak_host_keys(offer.host_key_algorithms)
    if weak:
        ev2 = Evidence(
            id=_uid("ev"),
            asset_id=asset.id,
            evidence_type="ssh.hostkey",
            observation_type=ObservationType.OFFERED,
            source="qureddy.scanners.ssh.probe",
            protocol="ssh",
            notes=(f"weak host-key algorithm offered: {', '.join(weak)}",),
        )
        evidence.append(ev2)
        findings.append(
            Finding(
                id=_uid("finding"),
                asset_id=asset.id,
                evidence_ids=(ev2.id,),
                rule_id="ssh.hostkey.weak",
                finding_type="ssh.hostkey.weak",
                title=f"Weak SSH host-key algorithm offered ({', '.join(weak)})",
                description="DSA host keys are deprecated and cryptographically weak.",
                severity=Severity.MEDIUM,
                readiness=Readiness.CLASSICALLY_WEAK,
                confidence=Confidence.HIGH,
                protocol="ssh",
            )
        )

    rset = {f.readiness for f in findings}
    readiness = next((r for r in _PRECEDENCE if r in rset), Readiness.UNKNOWN)
    highest = max((f.severity for f in findings), key=lambda s: _SEV_ORDER.index(s.value))
    completed = datetime.now(UTC)

    return ScanResult(
        scan=ScanMetadata(
            scan_id=_uid("scan"),
            started_at=started,
            completed_at=completed,
            scanner_name="ssh",
            status="completed",
            total_attempts=1,
        ),
        target=target,
        dependencies=(),
        assets=(asset,),
        evidence=tuple(evidence),
        findings=tuple(findings),
        summary=ScanSummary(
            target=target.locator,
            finding_count=len(findings),
            highest_severity=highest,
            readiness=readiness,
            failure_category=None,
        ),
    )
