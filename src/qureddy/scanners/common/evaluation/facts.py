# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Normalized facts passed from protocol adapters to the evaluator."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from qureddy.core.models import (
    Evidence,
    Finding,
    HndlExposure,
    HygieneStatus,
    PqcSupport,
    ProbeRole,
)


class PostureFacts(BaseModel):
    """Protocol adapter output; the evaluator never parses raw evidence."""

    model_config = ConfigDict(frozen=True)

    protocol: str
    support: PqcSupport
    hndl_exposure: HndlExposure
    hygiene_status: HygieneStatus
    negotiated_algorithm: str | None = None
    classical_alternative: str | None = None
    certificate_chain_signature: str | None = None
    weak_algorithms: tuple[str, ...] = ()


def normalize_facts(
    findings: list[Finding],
    evidence: list[Evidence],
    *,
    protocol: str,
    support: PqcSupport,
    hndl_exposure: HndlExposure,
    hygiene_status: HygieneStatus,
) -> PostureFacts:
    """Normalize adapter observations before handing them to the evaluator."""
    return PostureFacts(
        protocol=protocol,
        support=support,
        hndl_exposure=hndl_exposure,
        hygiene_status=hygiene_status,
        negotiated_algorithm=_negotiated_algorithm(findings, evidence),
        classical_alternative=_classical_alternative(findings, evidence),
        certificate_chain_signature=_certificate_signature(findings),
        weak_algorithms=_weak_algorithms(findings, evidence),
    )


def _first(values: tuple[str | None, ...]) -> str | None:
    return next((value for value in values if value), None)


def _negotiated_algorithm(findings: list[Finding], evidence: list[Evidence]) -> str | None:
    return _first(
        (
            *(ev.negotiated_group for ev in evidence),
            *(finding.negotiated_group for finding in findings),
            *(finding.algorithm for finding in findings),
        )
    )


def _classical_alternative(findings: list[Finding], evidence: list[Evidence]) -> str | None:
    return _first(
        (
            *(
                ev.negotiated_group
                for ev in evidence
                if ev.probe_role is ProbeRole.CLASSICAL_CONTROL
            ),
            *(
                finding.negotiated_group
                for finding in findings
                if "classical.negotiated" in finding.rule_id
            ),
            *(
                finding.algorithm
                for finding in findings
                if "classical.negotiated" in finding.rule_id
            ),
        )
    )


def _certificate_signature(findings: list[Finding]) -> str | None:
    return next(
        (
            finding.algorithm
            for finding in findings
            if finding.finding_type == "tls.cert.classical_signature" and finding.algorithm
        ),
        None,
    )


def _weak_algorithms(findings: list[Finding], evidence: list[Evidence]) -> tuple[str, ...]:
    """Return algorithm names attached to explicit weak-algorithm findings."""
    weak_evidence_ids = {
        evidence_id
        for finding in findings
        if ".weak" in finding.finding_type or ".weak" in finding.rule_id
        for evidence_id in finding.evidence_ids
    }
    return tuple(
        dict.fromkeys(
            item.negotiated_group
            for item in evidence
            if item.id in weak_evidence_ids and item.negotiated_group
        )
    )
