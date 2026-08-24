# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""SSH scanner orchestrator: probe -> classify -> ScanResult (reuses core models)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qureddy.core.contracts import Scanner
from qureddy.core.ids import new_id
from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    FailureCategory,
    Finding,
    ObservationType,
    Readiness,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from qureddy.scanners.common.assets import build_endpoint_asset
from qureddy.scanners.common.metadata import build_scan_metadata
from qureddy.scanners.common.posture import build_interpretation
from qureddy.scanners.common.rollup import highest_severity, scan_readiness
from qureddy.scanners.ssh import classify
from qureddy.scanners.ssh._identity import server_identity_observations
from qureddy.scanners.ssh._observations import (
    ssh_offered_evidence,
    ssh_weak_finding,
    terrapin_observation,
    weak_kex_observation,
)
from qureddy.scanners.ssh.probe import read_kexinit_offer

if TYPE_CHECKING:
    from qureddy.core.errors import SSHProbeError

_DEFAULT_SSH_PORT = 22


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
    asset = build_endpoint_asset(target, asset_type="ssh.endpoint", protocol="ssh")
    evidence = Evidence(
        id=new_id("ev"),
        asset_id=asset.id,
        evidence_type="ssh.kex",
        observation_type=ObservationType.NOT_TESTABLE,
        source="qureddy.scanners.ssh.probe",
        protocol="ssh",
        failure_category=failure_category,
        notes=(cleaned_error,),
    )
    return ScanResult(
        scan=build_scan_metadata(
            scan_id=new_id("scan"),
            started_at=started,
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
            interpretation=build_interpretation([], [evidence], failure_category, protocol="ssh"),
        ),
    )


def _kex_group_evidence(asset: Asset, group: str, *, is_pq: bool) -> Evidence:
    """One OFFERED evidence record for a single offered KEX group.

    Every offered KEX group becomes evidence (not only the PQ hybrid) so the CBOM
    inventories the full offer the way the TLS path emits every observed group and
    the SSH host-key path emits every host key (#242). ``negotiated_group`` carries
    the group name so the shared CBOM emitter attaches it.
    """
    kind = "PQ hybrid KEX offered" if is_pq else "classical KEX offered"
    return ssh_offered_evidence(
        asset, evidence_type="ssh.kex", name=group, notes=(f"{kind}: {group}",)
    )


def _hybrid_kex_finding(
    asset: Asset, pq: tuple[str, ...], evidence_ids: tuple[str, ...]
) -> Finding:
    """Verdict finding when a PQ-hybrid KEX is offered."""
    return Finding(
        id=new_id("finding"),
        asset_id=asset.id,
        evidence_ids=evidence_ids,
        rule_id="ssh.kex.hybrid_offered",
        finding_type="ssh.kex.hybrid",
        title=f"SSH offers post-quantum hybrid key exchange ({pq[0]})",
        description="Server offers a PQ hybrid KEX group; protects against harvest-now-decrypt-later.",
        severity=Severity.INFO,
        readiness=Readiness.TRANSITIONAL_HYBRID,
        confidence=Confidence.HIGH,
        algorithm=pq[0],
        negotiated_group=pq[0],
        protocol="ssh",
    )


def _classical_kex_finding(asset: Asset, evidence_ids: tuple[str, ...]) -> Finding:
    """Verdict finding when no PQ-hybrid KEX is offered."""
    return Finding(
        id=new_id("finding"),
        asset_id=asset.id,
        evidence_ids=evidence_ids,
        rule_id="ssh.kex.classical_only",
        finding_type="ssh.kex.classical",
        title="SSH offers classical key exchange only",
        description="No PQ hybrid KEX offered; exposed to harvest-now-decrypt-later.",
        severity=Severity.LOW,
        readiness=Readiness.QUANTUM_VULNERABLE,
        confidence=Confidence.HIGH,
        protocol="ssh",
    )


def _no_kex_evidence(asset: Asset) -> Evidence:
    """Anchor evidence for a server that offers no KEX name-list at all.

    Carries no ``negotiated_group`` so it is not emitted as a component; it only
    gives the classical-only verdict a valid evidence reference in the degenerate
    empty-offer case (a Finding must cite at least one evidence id).
    """
    return ssh_offered_evidence(asset, evidence_type="ssh.kex", notes=("no KEX groups offered",))


def _kex_observations(asset: Asset, algorithms: tuple[str, ...]) -> tuple[list[Evidence], Finding]:
    """Emit one evidence per unique offered KEX group plus the readiness verdict.

    The verdict is unchanged: a PQ hybrid anywhere in the offer wins (#247's widened
    classifier decides membership); otherwise classical-only. The inventory is the
    full offer, deduped with offer order preserved.
    """
    pq_names = frozenset(classify.pq_hybrid_kex(algorithms))
    evidence_by_group: dict[str, Evidence] = {}
    for group in algorithms:
        if group not in evidence_by_group:
            evidence_by_group[group] = _kex_group_evidence(asset, group, is_pq=group in pq_names)
    if pq_names:
        pq = tuple(g for g in evidence_by_group if g in pq_names)
        finding = _hybrid_kex_finding(asset, pq, tuple(evidence_by_group[g].id for g in pq))
        return list(evidence_by_group.values()), finding
    evidence = list(evidence_by_group.values()) or [_no_kex_evidence(asset)]
    return evidence, _classical_kex_finding(asset, tuple(e.id for e in evidence))


def _host_key_evidence(asset: Asset, algorithm: str) -> tuple[Evidence, bool]:
    """One OFFERED evidence record for a single host-key algorithm.

    Every offered host-key algorithm becomes evidence (not only the weak ones) so
    the CBOM can emit the full observed host-key inventory the way the TLS path
    emits its algorithms. The boolean flags whether this algorithm is weak.
    """
    note = classify.weak_host_key_note(algorithm)
    notes = (f"{algorithm}: {note}",) if note else (f"host-key algorithm offered: {algorithm}",)
    evidence = ssh_offered_evidence(asset, evidence_type="ssh.hostkey", name=algorithm, notes=notes)
    return evidence, note is not None


def _host_key_observations(
    asset: Asset, algorithms: tuple[str, ...]
) -> tuple[list[Evidence], Finding | None]:
    """Evidence for every offered host key, plus a weak finding if any are weak."""
    evidence: list[Evidence] = []
    weak_ids: list[str] = []
    for algorithm in algorithms:
        record, is_weak = _host_key_evidence(asset, algorithm)
        evidence.append(record)
        if is_weak:
            weak_ids.append(record.id)
    if not weak_ids:
        return evidence, None
    weak = classify.weak_host_keys(algorithms)
    finding = ssh_weak_finding(
        asset,
        rule_id="ssh.hostkey.weak",
        finding_type="ssh.hostkey.weak",
        title=f"Weak SSH host-key algorithm offered ({', '.join(weak)})",
        description=(
            "Deprecated or SHA-1 host-key algorithms offered. DSA keys are fixed at "
            "1024-bit; ssh-rsa signs with SHA-1 (RFC 8332). Both are disabled by "
            "default in modern OpenSSH."
        ),
        evidence_ids=tuple(weak_ids),
    )
    return evidence, finding


def _cipher_mac_observations(
    asset: Asset, ciphers: tuple[str, ...], macs: tuple[str, ...]
) -> tuple[list[Evidence], Finding | None]:
    """Evidence for every offered cipher and MAC, plus a weak finding if any are weak (#243).

    Mirrors ``_host_key_observations``: each offered transport algorithm becomes OFFERED
    evidence carrying its own name in ``negotiated_group`` so the CBOM emits the full
    inventory (previously ciphers/MACs were never collected past the host-key name-list).
    """
    evidence: list[Evidence] = []
    weak_ids: list[str] = []
    weak_names: list[str] = []
    items = (
        *(("ssh.cipher", "cipher", name, classify.weak_cipher_note(name)) for name in ciphers),
        *(("ssh.mac", "MAC", name, classify.weak_mac_note(name)) for name in macs),
    )
    for evidence_type, label, name, note in items:
        notes = (f"{name}: {note}",) if note else (f"{label} offered: {name}",)
        record = ssh_offered_evidence(asset, evidence_type=evidence_type, name=name, notes=notes)
        evidence.append(record)
        if note is not None:
            weak_ids.append(record.id)
            weak_names.append(name)
    if not weak_ids:
        return evidence, None
    finding = ssh_weak_finding(
        asset,
        rule_id="ssh.transport.weak",
        finding_type="ssh.transport.weak",
        title=f"Weak SSH cipher or MAC offered ({', '.join(weak_names)})",
        description=(
            "Deprecated transport algorithms offered. RC4/arcfour and HMAC-MD5 are "
            "broken; 3DES-CBC uses a 64-bit block (SWEET32); HMAC-SHA1 and CBC ciphers "
            "are deprecated in modern OpenSSH."
        ),
        evidence_ids=tuple(weak_ids),
    )
    return evidence, finding


def _build_ssh_success_result(
    target: ScanTarget,
    asset: Asset,
    evidence: list[Evidence],
    findings: list[Finding],
    started: datetime,
) -> ScanResult:
    """Build the completed SSH result and deterministic rollup."""
    # Shared, complete, None-safe rollup (#248) — was a forked 4-tier copy + bare max().
    readiness = scan_readiness(findings)
    highest = highest_severity(findings)
    completed = datetime.now(UTC)

    return ScanResult(
        scan=build_scan_metadata(
            scan_id=new_id("scan"),
            started_at=started,
            scanner_name="ssh",
            status="completed",
            total_attempts=1,
            completed_at=completed,
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
            interpretation=build_interpretation(findings, evidence, None, protocol="ssh"),
        ),
    )


def _scan_ssh(target: ScanTarget, *, timeout_seconds: int = 8) -> ScanResult:
    """Scan an SSH endpoint for post-quantum readiness. Raises SSHProbeError on probe failure."""
    started = datetime.now(UTC)
    offer = read_kexinit_offer(target.host, target.port, timeout_seconds=timeout_seconds)
    asset = build_endpoint_asset(target, asset_type="ssh.endpoint", protocol="ssh")
    kex_evidence, kex_finding = _kex_observations(asset, offer.kex_algorithms)
    evidence, findings = kex_evidence.copy(), [kex_finding]
    evidence.extend(server_identity_observations(asset, offer.server_identity))
    weak_kex_result = weak_kex_observation(asset, offer.kex_algorithms)
    if weak_kex_result is not None:
        weak_kex_evidence, weak_kex_finding = weak_kex_result
        evidence.append(weak_kex_evidence)
        findings.append(weak_kex_finding)
    host_key_evidence, weak_host_key_finding = _host_key_observations(
        asset, offer.host_key_algorithms
    )
    evidence.extend(host_key_evidence)
    if weak_host_key_finding is not None:
        findings.append(weak_host_key_finding)
    cipher_mac_evidence, weak_transport_finding = _cipher_mac_observations(
        asset, offer.ciphers, offer.macs
    )
    evidence.extend(cipher_mac_evidence)
    if weak_transport_finding is not None:
        findings.append(weak_transport_finding)
    terrapin_evidence, terrapin_finding = terrapin_observation(
        asset,
        strict_kex=offer.strict_kex,
        ciphers=offer.ciphers,
        macs=offer.macs,
    )
    evidence.append(terrapin_evidence)
    findings.append(terrapin_finding)
    return _build_ssh_success_result(target, asset, evidence, findings, started)


class SSHScanner(Scanner[ScanTarget]):
    """Contract adapter for the existing SSH function-based scanner."""

    scanner_name = "ssh"

    def scan(self, target: ScanTarget, *, timeout_seconds: int = 8) -> ScanResult:
        """Collect SSH evidence through the existing function implementation."""
        return _scan_ssh(target, timeout_seconds=timeout_seconds)


def scan_ssh(target: ScanTarget, *, timeout_seconds: int = 8) -> ScanResult:
    """Backward-compatible function entry point for SSH scans."""
    return SSHScanner().scan(target, timeout_seconds=timeout_seconds)
