# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""SSH observation and finding builders used by the scanner orchestrator."""

from __future__ import annotations

from qureddy.core.ids import new_id
from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    ObservationType,
    Readiness,
    Severity,
)
from qureddy.scanners.ssh import classify


def ssh_offered_evidence(
    asset: Asset,
    *,
    evidence_type: str,
    notes: tuple[str, ...],
    name: str | None = None,
) -> Evidence:
    """Build one OFFERED SSH evidence record from the KEXINIT probe."""
    return Evidence(
        id=new_id("ev"),
        asset_id=asset.id,
        evidence_type=evidence_type,
        observation_type=ObservationType.OFFERED,
        source="qureddy.scanners.ssh.probe",
        protocol="ssh",
        protocol_version="2.0",
        negotiated_group=name,
        notes=notes,
    )


def ssh_weak_finding(
    asset: Asset,
    *,
    rule_id: str,
    finding_type: str,
    title: str,
    description: str,
    evidence_ids: tuple[str, ...],
) -> Finding:
    """Build the shared shape for weak SSH algorithm findings."""
    return Finding(
        id=new_id("finding"),
        asset_id=asset.id,
        evidence_ids=evidence_ids,
        rule_id=rule_id,
        finding_type=finding_type,
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        readiness=Readiness.CLASSICALLY_WEAK,
        confidence=Confidence.HIGH,
        protocol="ssh",
    )


def weak_kex_observation(
    asset: Asset, algorithms: tuple[str, ...]
) -> tuple[Evidence, Finding] | None:
    """Build the weak-KEX result pair, if a deprecated exchange is offered."""
    weak = classify.weak_kex(algorithms)
    if not weak:
        return None
    evidence = ssh_offered_evidence(
        asset,
        evidence_type="ssh.kex.weak",
        notes=classify.weak_kex_reasons(algorithms),
    )
    finding = ssh_weak_finding(
        asset,
        rule_id="ssh.kex.weak",
        finding_type="ssh.kex.weak",
        title=f"Weak SSH key-exchange algorithm offered ({', '.join(weak)})",
        description=(
            "Deprecated key-exchange algorithms offered. Small (1024-bit) MODP groups "
            "and SHA-1 key-exchange hashes are disabled by default in modern OpenSSH."
        ),
        evidence_ids=(evidence.id,),
    )
    return evidence, finding


def terrapin_observation(
    asset: Asset,
    *,
    strict_kex: bool,
    ciphers: tuple[str, ...],
    macs: tuple[str, ...],
) -> tuple[Evidence, Finding]:
    """Report observable Terrapin posture without claiming exploitability."""
    strict = "present" if strict_kex else "absent"
    susceptible_modes = classify.terrapin_susceptible_modes(ciphers, macs)
    modes_text = ", ".join(susceptible_modes) or "none"
    evidence = ssh_offered_evidence(
        asset,
        evidence_type="ssh.terrapin",
        notes=(
            f"strict KEX marker: {strict}",
            f"Terrapin-susceptible offered modes: {modes_text}",
        ),
    )
    finding = Finding(
        id=new_id("finding"),
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        rule_id="ssh.terrapin.posture",
        finding_type="ssh.terrapin.posture",
        title="SSH Terrapin posture observed",
        description=(
            f"Strict KEX is {strict}; Terrapin-susceptible offered modes are recorded "
            f"as evidence ({modes_text}). This is an "
            "offered-capability fact, not a negotiated-exploitability verdict."
        ),
        severity=Severity.INFO,
        readiness=Readiness.NOT_APPLICABLE,
        confidence=Confidence.HIGH,
        protocol="ssh",
    )
    return evidence, finding
