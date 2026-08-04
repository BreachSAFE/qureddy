# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scan-level summary rollup helpers.

Pure functions that fold a list of `Finding` and `Evidence` records into
a `ScanSummary`. Extracted from `scanner.py` to keep that file under the
400-line hard ceiling.
"""

from __future__ import annotations

from qureddy.core.models import (
    LOCAL_CAPABILITY_CATEGORIES,
    Evidence,
    FailureCategory,
    Finding,
    Readiness,
    ScanSummary,
    ScanTarget,
    Severity,
)

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Readiness rollup precedence. CLASSICALLY_WEAK trumps everything because
# broken classical crypto is exploitable today regardless of PQ posture.
# TRANSITIONAL_HYBRID over QUANTUM_VULNERABLE because the hybrid rule
# firing means PQ negotiation works; the classical control fires by
# design on every scan and shouldn't downgrade the verdict.
_READINESS_PRECEDENCE: tuple[Readiness, ...] = (
    Readiness.CLASSICALLY_WEAK,
    Readiness.TRANSITIONAL_HYBRID,
    Readiness.QUANTUM_VULNERABLE,
    Readiness.UNKNOWN,
    Readiness.QUANTUM_SAFE,
    Readiness.NOT_APPLICABLE,
)


def build_summary(
    target: ScanTarget,
    findings: list[Finding],
    evidence: list[Evidence],
) -> ScanSummary:
    """Build the top-level `ScanSummary` from the scan's findings + evidence."""
    return ScanSummary(
        target=target.locator,
        finding_count=len(findings),
        highest_severity=highest_severity(findings),
        readiness=scan_readiness(findings),
        failure_category=summary_failure_category(findings, evidence),
    )


def highest_severity(findings: list[Finding]) -> Severity | None:
    """Return the most-severe `Severity` across `findings`, or None when empty."""
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: _SEVERITY_ORDER[s])


def scan_readiness(findings: list[Finding]) -> Readiness:
    """Roll up the per-finding readinesses to a single scan-level value.

    Precedence (highest first):
      CLASSICALLY_WEAK > TRANSITIONAL_HYBRID > QUANTUM_VULNERABLE >
      UNKNOWN > QUANTUM_SAFE > NOT_APPLICABLE
    """
    if not findings:
        return Readiness.UNKNOWN
    readinesses = {f.readiness for f in findings}
    for tier in _READINESS_PRECEDENCE:
        if tier in readinesses:
            return tier
    return Readiness.UNKNOWN


# Issue #241: retry attempts accumulate rather than replace, so an earlier
# failed attempt's Finding survives in the list alongside a later attempt's
# success. A failure category must not outlive proof that the probe it
# describes eventually succeeded.
_SUCCESS_RULE_IDS: frozenset[str] = frozenset(
    {
        "tls.hybrid.negotiated_x25519mlkem768",
        "tls.classical.negotiated_x25519",
    }
)


def summary_failure_category(
    findings: list[Finding],
    evidence: list[Evidence],
) -> FailureCategory | None:
    """Surface the exact `FailureCategory` from supporting evidence.

    Local-capability failures take precedence over target-side probe
    failures so consumers can distinguish "your openssl is broken" from
    "the server isn't reachable". Within each tier, the first matching
    evidence record wins.

    A successful negotiation finding (e.g. from a later retry attempt)
    supersedes an earlier attempt's failure category — see #241.
    """
    evidence_by_id = {e.id: e for e in evidence}
    local_match = _first_matching_category(
        findings,
        evidence_by_id,
        "tls.hybrid.not_testable",
        allowed=LOCAL_CAPABILITY_CATEGORIES,
    )
    if local_match is not None:
        return local_match
    if any(f.rule_id in _SUCCESS_RULE_IDS for f in findings):
        return None
    return _first_matching_category(
        findings,
        evidence_by_id,
        "tls.hybrid.probe_failed",
        allowed=None,
    )


def _first_matching_category(
    findings: list[Finding],
    evidence_by_id: dict[str, Evidence],
    rule_id: str,
    *,
    allowed: frozenset[FailureCategory] | None,
) -> FailureCategory | None:
    """Find the first finding for `rule_id` and return its evidence's category."""
    for finding in findings:
        if finding.rule_id != rule_id:
            continue
        for ev_id in finding.evidence_ids:
            ev = evidence_by_id.get(ev_id)
            if ev is None or ev.failure_category is None:
                continue
            if allowed is None or ev.failure_category in allowed:
                return ev.failure_category
    return None
