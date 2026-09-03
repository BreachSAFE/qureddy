# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Scan-level readiness + severity rollup — ONE source of truth (#248).

Folds a scanner's per-finding records into a single scan verdict. Both the TLS and
SSH scanners call these; previously SSH kept its own copy that omitted two readiness
tiers (QUANTUM_SAFE, NOT_APPLICABLE) so a future pure-PQ SSH KEX would silently roll
up to UNKNOWN, and used a bare ``max`` that raised on an empty finding set.
"""

from __future__ import annotations

from qureddy.core.models import Evidence, Finding, ObservationType, Readiness, Severity

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Default readiness precedence, highest first. CLASSICALLY_WEAK stays above an offered-only
# PQ capability because broken classical crypto is exploitable today and SSH currently observes
# name-lists rather than a completed negotiation. A PQ finding backed by negotiated or observed
# evidence is handled first by ``scan_readiness`` so a working PQ path remains the PQ-readiness
# verdict while the independent hygiene axis carries present-day weakness.
READINESS_PRECEDENCE: tuple[Readiness, ...] = (
    Readiness.CLASSICALLY_WEAK,
    Readiness.TRANSITIONAL_HYBRID,
    Readiness.QUANTUM_SAFE,
    Readiness.QUANTUM_VULNERABLE,
    Readiness.UNKNOWN,
    Readiness.NOT_APPLICABLE,
)

_POSITIVE_READINESS: tuple[Readiness, ...] = (
    Readiness.TRANSITIONAL_HYBRID,
    Readiness.QUANTUM_SAFE,
)
_POSITIVE_OBSERVATIONS: frozenset[ObservationType] = frozenset(
    {ObservationType.NEGOTIATED, ObservationType.OBSERVED}
)


def highest_severity(findings: list[Finding]) -> Severity | None:
    """Return the most-severe ``Severity`` across ``findings``, or None when empty."""
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_ORDER[s])


def _conclusive_evidence_ids(evidence: list[Evidence] | None) -> frozenset[str]:
    """Return evidence identifiers that prove an observed protocol result."""
    if not evidence:
        return frozenset()
    return frozenset(
        item.id for item in evidence if item.observation_type in _POSITIVE_OBSERVATIONS
    )


def _first_matching_tier(
    readinesses: set[Readiness], precedence: tuple[Readiness, ...]
) -> Readiness | None:
    """Return the first readiness present in the ordered precedence tuple."""
    for tier in precedence:
        if tier in readinesses:
            return tier
    return None


def scan_readiness(findings: list[Finding], evidence: list[Evidence] | None = None) -> Readiness:
    """Roll up findings, preserving PQ support backed by conclusive evidence."""
    if not findings:
        return Readiness.UNKNOWN
    conclusive_evidence_ids = _conclusive_evidence_ids(evidence)
    conclusive_readinesses = {
        finding.readiness
        for finding in findings
        if conclusive_evidence_ids.intersection(finding.evidence_ids)
    }
    conclusive_readiness = _first_matching_tier(conclusive_readinesses, _POSITIVE_READINESS)
    if conclusive_readiness is not None:
        return conclusive_readiness
    readinesses = {f.readiness for f in findings}
    return _first_matching_tier(readinesses, READINESS_PRECEDENCE) or Readiness.UNKNOWN
