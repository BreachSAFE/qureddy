# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Scan-level readiness + severity rollup — ONE source of truth (#248).

Folds a scanner's per-finding records into a single scan verdict. Both the TLS and
SSH scanners call these; previously SSH kept its own copy that omitted two readiness
tiers (QUANTUM_SAFE, NOT_APPLICABLE) so a future pure-PQ SSH KEX would silently roll
up to UNKNOWN, and used a bare ``max`` that raised on an empty finding set.
"""

from __future__ import annotations

from qureddy.core.models import Finding, Readiness, Severity

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Readiness rollup precedence, highest first. CLASSICALLY_WEAK trumps everything
# because broken classical crypto is exploitable today regardless of PQ posture;
# TRANSITIONAL_HYBRID outranks QUANTUM_VULNERABLE because a firing hybrid rule means
# PQ negotiation works (the classical control fires by design on every scan and must
# not downgrade the verdict). The full tier set is listed so no verdict silently
# degrades to UNKNOWN.
READINESS_PRECEDENCE: tuple[Readiness, ...] = (
    Readiness.CLASSICALLY_WEAK,
    Readiness.TRANSITIONAL_HYBRID,
    Readiness.QUANTUM_VULNERABLE,
    Readiness.UNKNOWN,
    Readiness.QUANTUM_SAFE,
    Readiness.NOT_APPLICABLE,
)


def highest_severity(findings: list[Finding]) -> Severity | None:
    """Return the most-severe ``Severity`` across ``findings``, or None when empty."""
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: SEVERITY_ORDER[s])


def scan_readiness(findings: list[Finding]) -> Readiness:
    """Roll up per-finding readiness to one scan verdict (precedence highest first)."""
    if not findings:
        return Readiness.UNKNOWN
    readinesses = {f.readiness for f in findings}
    for tier in READINESS_PRECEDENCE:
        if tier in readinesses:
            return tier
    return Readiness.UNKNOWN
