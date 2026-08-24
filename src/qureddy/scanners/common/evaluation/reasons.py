# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Stable reason-code derivation shared by protocol adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from qureddy.core.models import FailureCategory, Finding


def _presence_sets(findings: list[Finding]) -> tuple[set[str], set[str]]:
    """Return finding-type and rule-id sets used to derive reason codes."""
    types = {finding.finding_type for finding in findings}
    rule_ids = {finding.rule_id for finding in findings}
    return types, rule_ids


def _candidates(
    findings: list[Finding], types: set[str], rule_ids: set[str]
) -> tuple[tuple[bool, str], ...]:
    """Pair each candidate reason code with its observed presence."""
    hybrid = any(
        finding.readiness.value == "transitional_hybrid"
        and "kex.hybrid" in (finding.finding_type + finding.rule_id)
        for finding in findings
    )
    pure_pq = any(finding.readiness.value == "quantum_safe" for finding in findings)
    classical = bool(
        {"tls.kex.classical", "ssh.kex.classical"} & types
        or {"tls.classical.negotiated_x25519", "ssh.kex.classical_only"} & rule_ids
    )
    hybrid_failed = "tls.hybrid.probe_failed" in rule_ids
    return (
        (hybrid, "hybrid_pqc_observed"),
        (pure_pq, "pure_pq_observed"),
        (hybrid_failed, "hybrid_probe_failed"),
        (classical, "classical_kex_negotiated"),
        ("tls.cert.classical_signature" in types, "classical_certificate_signature"),
        ("tls.legacy.protocol_offered" in types, "deprecated_protocol_observed"),
        (
            bool({"ssh.kex.weak", "ssh.hostkey.weak", "ssh.transport.weak"} & types),
            "weak_classical_algorithm_observed",
        ),
    )


def reason_codes(
    findings: list[Finding], failure_category: FailureCategory | None
) -> tuple[str, ...]:
    """Return deterministic machine-readable reasons for the posture result."""
    types, rule_ids = _presence_sets(findings)
    codes = [code for present, code in _candidates(findings, types, rule_ids) if present]
    if failure_category is not None:
        codes.append(failure_category.value)
    return tuple(dict.fromkeys(codes))
