# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Normalized facts passed from protocol adapters to the evaluator."""

from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class PostureSignals:
    """Neutral policy signals derived once from protocol-specific records."""

    hybrid: bool
    pure_pq: bool
    classical_kex: bool
    hybrid_failed: bool
    downgrade_action_needed: bool
    authentication_classical: bool
    authentication_pq: bool
    classical_certificate: bool
    legacy_protocol: bool
    weak_algorithm: bool
    protocol_action_needed: bool
    hygiene_weak: bool


def derive_signals(findings: list[Finding], evidence: list[Evidence]) -> PostureSignals:
    """Translate protocol finding IDs into stable evaluator signals."""
    types = {finding.finding_type for finding in findings}
    rules = {finding.rule_id for finding in findings}
    evidence_types = {item.evidence_type for item in evidence}
    hybrid, classical_kex, hybrid_failed = _kex_signals(findings, types, rules)
    authentication_classical, authentication_pq, classical_certificate = _authentication_signals(
        types, evidence_types
    )
    legacy_protocol = _has_suffix(types, "legacy.protocol_offered")
    weak_algorithm = any(
        _has_suffix(types, suffix) for suffix in ("kex.weak", "hostkey.weak", "transport.weak")
    )
    return PostureSignals(
        hybrid=hybrid,
        pure_pq=any(finding.readiness.value == "quantum_safe" for finding in findings),
        classical_kex=classical_kex,
        hybrid_failed=hybrid_failed,
        downgrade_action_needed=legacy_protocol
        or _has_suffix(rules, "classical.protocol_offered")
        or weak_algorithm,
        authentication_classical=authentication_classical,
        authentication_pq=authentication_pq,
        classical_certificate=classical_certificate,
        legacy_protocol=legacy_protocol,
        weak_algorithm=weak_algorithm,
        protocol_action_needed=legacy_protocol
        or any(_has_suffix(types, suffix) for suffix in ("transport.weak", "terrapin.posture")),
        hygiene_weak=weak_algorithm,
    )


def _kex_signals(
    findings: list[Finding], types: set[str], rules: set[str]
) -> tuple[bool, bool, bool]:
    return (
        any(
            finding.readiness.value == "transitional_hybrid"
            and (
                _has_suffix({finding.finding_type}, "kex.hybrid")
                or _has_suffix({finding.rule_id}, "kex.hybrid")
            )
            for finding in findings
        ),
        _has_suffix(types, "kex.classical")
        or _has_suffix(rules, "classical.negotiated_x25519")
        or _has_suffix(rules, "kex.classical_only"),
        _has_suffix(rules, "hybrid.probe_failed"),
    )


def _authentication_signals(types: set[str], evidence_types: set[str]) -> tuple[bool, bool, bool]:
    return (
        bool(
            _has_suffix(types, "cert.classical_signature")
            or _has_suffix(evidence_types, "hostkey")
            or _has_suffix(types, "hostkey.weak")
        ),
        _has_suffix(types, "cert.pq_signature"),
        _has_suffix(types, "cert.classical_signature"),
    )


def _has_suffix(values: set[str], suffix: str) -> bool:
    """Match a semantic finding suffix without coupling to a protocol prefix."""
    return any(value == suffix or value.endswith(f".{suffix}") for value in values)


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
            if _has_suffix({finding.finding_type}, "cert.classical_signature") and finding.algorithm
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
