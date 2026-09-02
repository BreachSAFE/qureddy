# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Normalized facts passed from protocol adapters to the evaluator."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict

from qureddy.core.models import (
    Evidence,
    Finding,
    HndlExposure,
    HygieneStatus,
    PqcSupport,
    ProbeRole,
    Readiness,
)
from qureddy.core.signals import SemanticSignal


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
    semantic: frozenset[SemanticSignal]


def derive_signals(findings: list[Finding], evidence: list[Evidence]) -> PostureSignals:
    """Translate protocol finding IDs into stable evaluator signals."""
    types = {finding.finding_type for finding in findings}
    rules = {finding.rule_id for finding in findings}
    evidence_types = {item.evidence_type for item in evidence}
    semantic = _semantic_signals(findings, types, rules, evidence_types)
    hybrid = SemanticSignal.HYBRID_PQC in semantic
    classical_kex = SemanticSignal.CLASSICAL_KEX in semantic
    hybrid_failed = SemanticSignal.HYBRID_PROBE_FAILED in semantic
    legacy_protocol = SemanticSignal.LEGACY_PROTOCOL in semantic
    weak_algorithm = SemanticSignal.WEAK_ALGORITHM in semantic
    return PostureSignals(
        hybrid=hybrid,
        pure_pq=SemanticSignal.PURE_PQC in semantic,
        classical_kex=classical_kex,
        hybrid_failed=hybrid_failed,
        downgrade_action_needed=SemanticSignal.DOWNGRADE_ACTION_NEEDED in semantic,
        authentication_classical=SemanticSignal.AUTHENTICATION_CLASSICAL in semantic,
        authentication_pq=SemanticSignal.AUTHENTICATION_PQ in semantic,
        classical_certificate=SemanticSignal.CLASSICAL_CERTIFICATE in semantic,
        legacy_protocol=legacy_protocol,
        weak_algorithm=weak_algorithm,
        protocol_action_needed=SemanticSignal.PROTOCOL_ACTION_NEEDED in semantic,
        hygiene_weak=weak_algorithm,
        semantic=frozenset(semantic),
    )


def _semantic_signals(
    findings: list[Finding],
    types: set[str],
    rules: set[str],
    evidence_types: set[str],
) -> set[SemanticSignal]:
    """Map legacy protocol identifiers to the stable signal taxonomy once."""
    signals = {
        signal
        for signal, predicate in _SIGNAL_PREDICATES
        if predicate(findings, types, rules, evidence_types)
    }
    if SemanticSignal.WEAK_ALGORITHM in signals:
        signals.update({SemanticSignal.WEAK_ALGORITHM, SemanticSignal.DOWNGRADE_ACTION_NEEDED})
    if SemanticSignal.WEAK_ALGORITHM in signals:
        signals.add(SemanticSignal.HYGIENE_WEAK)
    return signals


SignalPredicate = Callable[[list[Finding], set[str], set[str], set[str]], bool]


def _hybrid_signal(findings: list[Finding], *_: set[str]) -> bool:
    """Return whether a transitional hybrid finding was observed."""
    return _finding_pair_signal(
        findings,
        finding_type_suffix="kex.hybrid",
        readiness=Readiness.TRANSITIONAL_HYBRID,
    )


def _pure_pq_signal(findings: list[Finding], *_: set[str]) -> bool:
    """Return whether a pure post-quantum finding was observed."""
    return _finding_pair_signal(
        findings,
        finding_type_suffix="kex.pure_pq",
        readiness=Readiness.QUANTUM_SAFE,
    )


def _classical_kex_signal(findings: list[Finding], *_: set[str]) -> bool:
    """Return whether a classical key-exchange path was observed."""
    return _finding_pair_signal(
        findings,
        finding_type_suffix="kex.classical",
        readiness=Readiness.QUANTUM_VULNERABLE,
    )


def _finding_pair_signal(
    findings: list[Finding],
    *,
    finding_type_suffix: str,
    readiness: Readiness,
) -> bool:
    """Require the canonical finding-type and readiness pair for a KEX signal."""
    return any(
        finding.readiness is readiness and _has_suffix({finding.finding_type}, finding_type_suffix)
        for finding in findings
    )


def _rule_signal(suffix: str) -> SignalPredicate:
    """Build a predicate for a rule suffix."""
    return lambda _findings, _types, rules, _evidence: _has_suffix(rules, suffix)


def _type_signal(suffix: str) -> SignalPredicate:
    """Build a predicate for a finding-type suffix."""
    return lambda _findings, types, _rules, _evidence: _has_suffix(types, suffix)


def _weak_signal(_: list[Finding], types: set[str], _rules: set[str], __: set[str]) -> bool:
    """Return whether an explicit weak algorithm finding was observed."""
    return any(
        _has_suffix(types, suffix) for suffix in ("kex.weak", "hostkey.weak", "transport.weak")
    )


def _authentication_classical_signal(
    _: list[Finding], types: set[str], _rules: set[str], evidence_types: set[str]
) -> bool:
    """Return whether classical authentication evidence was observed."""
    return any(
        (
            _has_suffix(types, "cert.classical_signature"),
            _has_suffix(evidence_types, "hostkey"),
            _has_suffix(types, "hostkey.weak"),
        )
    )


_SIGNAL_PREDICATES: tuple[tuple[SemanticSignal, SignalPredicate], ...] = (
    (SemanticSignal.HYBRID_PQC, _hybrid_signal),
    (SemanticSignal.PURE_PQC, _pure_pq_signal),
    (SemanticSignal.CLASSICAL_KEX, _classical_kex_signal),
    (SemanticSignal.HYBRID_PROBE_FAILED, _rule_signal("hybrid.probe_failed")),
    (SemanticSignal.LEGACY_PROTOCOL, _type_signal("legacy.protocol_offered")),
    (SemanticSignal.DOWNGRADE_ACTION_NEEDED, _rule_signal("classical.protocol_offered")),
    (SemanticSignal.WEAK_ALGORITHM, _weak_signal),
    (
        SemanticSignal.PROTOCOL_ACTION_NEEDED,
        lambda _f, types, _r, _e: any(
            (_has_suffix(types, "transport.weak"), _has_suffix(types, "terrapin.posture"))
        ),
    ),
    (SemanticSignal.AUTHENTICATION_CLASSICAL, _authentication_classical_signal),
    (SemanticSignal.AUTHENTICATION_PQ, _type_signal("cert.pq_signature")),
    (SemanticSignal.CLASSICAL_CERTIFICATE, _type_signal("cert.classical_signature")),
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
                if (
                    "classical.negotiated" in finding.rule_id
                    or _has_suffix({finding.rule_id}, "kex.classical_alternative")
                )
            ),
            *(
                finding.algorithm
                for finding in findings
                if (
                    "classical.negotiated" in finding.rule_id
                    or _has_suffix({finding.rule_id}, "kex.classical_alternative")
                )
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
    names = (
        item.negotiated_group or item.algorithm for item in evidence if item.id in weak_evidence_ids
    )
    return tuple(dict.fromkeys(name for name in names if name is not None))
