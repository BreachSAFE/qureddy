# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-agnostic posture interpretation from scanner evidence."""

from __future__ import annotations

from qureddy.core.models import (
    AxisStatus,
    Evidence,
    FailureCategory,
    Finding,
    PostureAxes,
    PqcSupport,
    Readiness,
    ScanInterpretation,
)
from qureddy.scanners.common.rollup import scan_readiness

POLICY_ID = "qureddy-readiness"
POLICY_VERSION = "1"


def _ciso_text(
    axes: PostureAxes,
    reasons: tuple[str, ...],
) -> tuple[str, str]:
    """Create deterministic headline/action text from structured reasons."""
    if "weak_classical_algorithm_observed" in reasons:
        return (
            "Classically weak algorithm exposure was observed.",
            "Remove weak algorithms and re-scan the endpoint.",
        )
    if "hybrid_pqc_observed" in reasons and "deprecated_protocol_observed" in reasons:
        return (
            "Hybrid PQC is available, but legacy protocol exposure remains.",
            "Disable TLS 1.0/1.1 and remove classical fallback where compatible.",
        )
    if "hybrid_probe_failed" in reasons:
        return (
            "PQC support could not be confirmed; classical key exchange was observed.",
            "Verify the target TLS terminator supports the requested hybrid group and re-scan.",
        )
    return {
        PqcSupport.PURE_PQ_OBSERVED: (
            "Pure post-quantum key exchange was observed.",
            "Continue monitoring negotiated posture.",
        ),
        PqcSupport.HYBRID_OBSERVED: (
            "Hybrid post-quantum key exchange was observed.",
            "Continue monitoring negotiated posture.",
        ),
        PqcSupport.NOT_TESTABLE: (
            "PQC posture could not be tested.",
            "Resolve the scan failure and re-run the assessment.",
        ),
        PqcSupport.CLASSICAL_ONLY_OBSERVED: (
            "Only classical key exchange was observed.",
            "Enable a supported hybrid group and re-run the assessment.",
        ),
    }.get(
        axes.pqc_support,
        ("PQC posture is unknown.", "Resolve probe limitations and re-run the assessment."),
    )


def _is_not_testable(failure_category: FailureCategory | None) -> bool:
    return failure_category in {
        FailureCategory.TARGET_CONNECT_FAILED,
        FailureCategory.TARGET_SCAN_FAILED,
        FailureCategory.LOCAL_OPENSSL_MISSING,
        FailureCategory.LOCAL_OPENSSL_BROKEN,
        FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        FailureCategory.LOCAL_OPENSSL_VERSION_MISMATCH,
        FailureCategory.LOCAL_OPENSSL_LACKS_GROUP,
    }


def _signals(findings: list[Finding]) -> tuple[set[str], set[str], bool, bool, bool, bool]:
    types = {f.finding_type for f in findings}
    rules = {f.rule_id for f in findings}
    hybrid = any(
        f.readiness is Readiness.TRANSITIONAL_HYBRID
        and "kex.hybrid" in (f.finding_type + f.rule_id)
        for f in findings
    )
    pure_pq = any(f.readiness is Readiness.QUANTUM_SAFE for f in findings)
    classical = bool(
        {"tls.kex.classical", "ssh.kex.classical"} & types
        or {"tls.classical.negotiated_x25519", "ssh.kex.classical_only"} & rules
    )
    hybrid_failed = "tls.hybrid.probe_failed" in rules
    return types, rules, hybrid, pure_pq, classical, hybrid_failed


def _pqc_axis(
    *, classical: bool, hybrid: bool, pure_pq: bool, hybrid_failed: bool, not_testable: bool
) -> tuple[PqcSupport, AxisStatus]:
    if not_testable:
        return PqcSupport.NOT_TESTABLE, AxisStatus.NOT_TESTABLE
    if hybrid:
        return PqcSupport.HYBRID_OBSERVED, AxisStatus.HYBRID
    if pure_pq:
        return PqcSupport.PURE_PQ_OBSERVED, AxisStatus.PURE_PQ
    if classical and not hybrid_failed:
        return PqcSupport.CLASSICAL_ONLY_OBSERVED, AxisStatus.CLASSICAL
    return PqcSupport.UNKNOWN, AxisStatus.UNKNOWN


def _downgrade_axis(
    types: set[str],
    rules: set[str],
    *,
    classical: bool,
    hybrid: bool,
    pure_pq: bool,
    not_testable: bool,
) -> AxisStatus:
    return (
        AxisStatus.NOT_TESTABLE
        if not_testable
        else AxisStatus.ACTION_NEEDED
        if (
            "tls.legacy.protocol_offered" in types
            or "tls.classical.protocol_offered" in rules
            or bool({"ssh.kex.weak", "ssh.hostkey.weak", "ssh.transport.weak"} & types)
        )
        else AxisStatus.ACCEPTABLE
        if classical or hybrid or pure_pq
        else AxisStatus.UNKNOWN
    )


def _authentication_axis(
    types: set[str], evidence_types: set[str], *, not_testable: bool
) -> AxisStatus:
    return (
        AxisStatus.NOT_TESTABLE
        if not_testable
        else AxisStatus.CLASSICAL
        if (
            "tls.cert.classical_signature" in types
            or "ssh.hostkey" in evidence_types
            or "ssh.hostkey.weak" in types
        )
        else AxisStatus.PURE_PQ
        if "tls.cert.pq_signature" in types
        else AxisStatus.NOT_APPLICABLE
    )


def _protocol_axis(types: set[str], *, has_findings: bool, not_testable: bool) -> AxisStatus:
    return (
        AxisStatus.NOT_TESTABLE
        if not_testable
        else AxisStatus.ACTION_NEEDED
        if (
            "tls.legacy.protocol_offered" in types
            or "ssh.transport.weak" in types
            or "ssh.terrapin.posture" in types
        )
        else AxisStatus.ACCEPTABLE
        if has_findings
        else AxisStatus.UNKNOWN
    )


def _build_axes(
    findings: list[Finding],
    evidence: list[Evidence],
    failure_category: FailureCategory | None,
) -> PostureAxes:
    types, rules, hybrid, pure_pq, classical, hybrid_failed = _signals(findings)
    evidence_types = {ev.evidence_type for ev in evidence}
    not_testable = _is_not_testable(failure_category)

    pqc_support, key_exchange = _pqc_axis(
        classical=classical,
        hybrid=hybrid,
        pure_pq=pure_pq,
        hybrid_failed=hybrid_failed,
        not_testable=not_testable,
    )

    downgrade = _downgrade_axis(
        types,
        rules,
        classical=classical,
        hybrid=hybrid,
        pure_pq=pure_pq,
        not_testable=not_testable,
    )
    authentication = _authentication_axis(types, evidence_types, not_testable=not_testable)
    protocol_hygiene = _protocol_axis(types, has_findings=bool(findings), not_testable=not_testable)
    return PostureAxes(
        pqc_support=pqc_support,
        key_exchange=key_exchange,
        downgrade_resistance=downgrade,
        authentication=authentication,
        protocol_hygiene=protocol_hygiene,
    )


def _reason_codes(
    findings: list[Finding], failure_category: FailureCategory | None
) -> tuple[str, ...]:
    types, _rules, hybrid, pure_pq, classical, hybrid_failed = _signals(findings)
    candidates = (
        (hybrid, "hybrid_pqc_observed"),
        (pure_pq, "pure_pq_observed"),
        (hybrid_failed, "hybrid_probe_failed"),
        (classical, "classical_kex_negotiated"),
        ("tls.cert.classical_signature" in types, "classical_certificate_signature"),
        (
            "tls.legacy.protocol_offered" in types,
            "deprecated_protocol_observed",
        ),
        (
            bool({"ssh.kex.weak", "ssh.hostkey.weak", "ssh.transport.weak"} & types),
            "weak_classical_algorithm_observed",
        ),
    )
    codes = [code for present, code in candidates if present]
    if failure_category is not None:
        codes.append(failure_category.value)
    return tuple(dict.fromkeys(codes))


def build_interpretation(
    findings: list[Finding],
    evidence: list[Evidence],
    failure_category: FailureCategory | None,
) -> ScanInterpretation:
    """Build stable posture axes and provenance from observed findings."""
    axes = _build_axes(findings, evidence, failure_category)
    reason_codes = _reason_codes(findings, failure_category)
    headline, recommended_action = _ciso_text(axes, reason_codes)
    return ScanInterpretation(
        effective=scan_readiness(findings),
        headline=headline,
        recommended_action=recommended_action,
        axes=axes,
        reason_codes=reason_codes,
        evidence_refs=tuple(ev.id for ev in evidence),
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
    )
