# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-agnostic posture interpretation from scanner evidence."""

from __future__ import annotations

from qureddy.core.evaluation import InterpretationDisplay, PostureEvaluation
from qureddy.core.models import (
    AxisStatus,
    Evidence,
    FailureCategory,
    Finding,
    HndlExposure,
    HygieneStatus,
    PostureAxes,
    PqcSupport,
    ScanInterpretation,
)
from qureddy.scanners.common.evaluation import (
    PostureSignals,
    derive_signals,
    evaluate_posture,
)
from qureddy.scanners.common.evaluation import reason_codes as build_reason_codes
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


def _resolve_protocol(
    findings: list[Finding], evidence: list[Evidence], protocol: str | None
) -> str:
    """Resolve and normalize the protocol before deriving any posture."""
    resolved = (
        protocol
        or next(
            (item.protocol for item in evidence if item.protocol),
            None,
        )
        or next(
            (item.protocol for item in findings if item.protocol),
            "unknown",
        )
    )
    return resolved.casefold()


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


def _downgrade_axis(signals: PostureSignals, *, not_testable: bool) -> AxisStatus:
    return (
        AxisStatus.NOT_TESTABLE
        if not_testable
        else AxisStatus.ACTION_NEEDED
        if signals.downgrade_action_needed
        else AxisStatus.ACCEPTABLE
        if signals.classical_kex or signals.hybrid or signals.pure_pq
        else AxisStatus.UNKNOWN
    )


def _authentication_axis(signals: PostureSignals, *, not_testable: bool) -> AxisStatus:
    return (
        AxisStatus.NOT_TESTABLE
        if not_testable
        else AxisStatus.CLASSICAL
        if signals.authentication_classical
        else AxisStatus.PURE_PQ
        if signals.authentication_pq
        else AxisStatus.NOT_APPLICABLE
    )


def _protocol_axis(
    signals: PostureSignals, *, has_findings: bool, not_testable: bool
) -> AxisStatus:
    return (
        AxisStatus.NOT_TESTABLE
        if not_testable
        else AxisStatus.ACTION_NEEDED
        if signals.protocol_action_needed
        else AxisStatus.ACCEPTABLE
        if has_findings
        else AxisStatus.UNKNOWN
    )


def _hndl_exposure(
    *,
    protocol: str,
    classical: bool,
    hybrid: bool,
    pure_pq: bool,
    not_testable: bool,
) -> HndlExposure:
    """Classify future-quantum exposure without ranking present-day hygiene."""
    if protocol == "ike":
        return HndlExposure.UNKNOWN
    if not_testable:
        return HndlExposure.UNKNOWN
    if hybrid:
        return HndlExposure.PROTECTED_DEFEASIBLE if classical else HndlExposure.PROTECTED
    if pure_pq:
        return HndlExposure.PROTECTED
    if classical:
        return HndlExposure.AT_RISK
    return HndlExposure.UNKNOWN


def _hygiene_status(
    signals: PostureSignals, *, not_testable: bool, has_findings: bool
) -> HygieneStatus:
    """Classify present-day hygiene independently of HNDL exposure."""
    if not_testable:
        return HygieneStatus.UNKNOWN
    if signals.hygiene_weak:
        return HygieneStatus.WEAK
    if (
        signals.classical_kex
        or signals.authentication_classical
        or signals.downgrade_action_needed
        or signals.protocol_action_needed
    ):
        return HygieneStatus.ACTION_NEEDED
    return HygieneStatus.OK if has_findings else HygieneStatus.UNKNOWN


def _overall_status(
    support: PqcSupport,
    hygiene_status: HygieneStatus,
) -> str:
    if support is PqcSupport.PURE_PQ_OBSERVED:
        return "Post-quantum protection observed"
    if support is PqcSupport.HYBRID_OBSERVED:
        return (
            "Hybrid PQC protection observed"
            if hygiene_status is HygieneStatus.OK
            else "Hybrid PQC protection with hardening required"
        )
    if support is PqcSupport.CLASSICAL_ONLY_OBSERVED:
        return "Classical-only protection observed"
    return "PQC protection could not be confirmed"


def _display(
    axes: PostureAxes,
    *,
    hndl_exposure: HndlExposure,
    hygiene_status: HygieneStatus,
    not_testable: bool,
    evaluation: PostureEvaluation,
) -> InterpretationDisplay:
    """Translate stable machine statuses into concise CISO-facing language."""
    if not_testable:
        return InterpretationDisplay(
            overall_status="Unable to assess",
            quantum_protection="PQC capability could not be tested",
            future_quantum_risk="Exposure is unknown",
            current_hygiene="Security hygiene could not be assessed",
            evaluation=evaluation,
        )

    quantum_protection = {
        PqcSupport.PURE_PQ_OBSERVED: "Pure post-quantum key exchange observed",
        PqcSupport.HYBRID_OBSERVED: "Hybrid PQC key exchange observed",
        PqcSupport.CLASSICAL_ONLY_OBSERVED: "Only classical key exchange observed",
        PqcSupport.UNKNOWN: "No PQC key exchange was confirmed",
        PqcSupport.NOT_TESTABLE: "PQC capability could not be tested",
    }[axes.pqc_support]
    future_quantum_risk = {
        HndlExposure.PROTECTED: "Protected against harvest-now/decrypt-later exposure",
        HndlExposure.PROTECTED_DEFEASIBLE: (
            "Protected today, but a classical downgrade path remains"
        ),
        HndlExposure.AT_RISK: "At risk of harvest-now/decrypt-later exposure",
        HndlExposure.UNKNOWN: "Exposure is unknown",
    }[hndl_exposure]
    current_hygiene = {
        HygieneStatus.OK: "No immediate protocol hardening issue identified",
        HygieneStatus.ACTION_NEEDED: "Protocol hardening is required",
        HygieneStatus.WEAK: "Weak cryptography requires remediation",
        HygieneStatus.UNKNOWN: "Security hygiene could not be assessed",
    }[hygiene_status]
    return InterpretationDisplay(
        overall_status=_overall_status(axes.pqc_support, hygiene_status),
        quantum_protection=quantum_protection,
        future_quantum_risk=future_quantum_risk,
        current_hygiene=current_hygiene,
        evaluation=evaluation,
    )


def _build_axes(
    findings: list[Finding],
    evidence: list[Evidence],
    failure_category: FailureCategory | None,
) -> PostureAxes:
    signals = derive_signals(findings, evidence)
    not_testable = _is_not_testable(failure_category)

    pqc_support, key_exchange = _pqc_axis(
        classical=signals.classical_kex,
        hybrid=signals.hybrid,
        pure_pq=signals.pure_pq,
        hybrid_failed=signals.hybrid_failed,
        not_testable=not_testable,
    )

    downgrade = _downgrade_axis(signals, not_testable=not_testable)
    authentication = _authentication_axis(signals, not_testable=not_testable)
    protocol_hygiene = _protocol_axis(
        signals, has_findings=bool(findings), not_testable=not_testable
    )
    return PostureAxes(
        pqc_support=pqc_support,
        key_exchange=key_exchange,
        downgrade_resistance=downgrade,
        authentication=authentication,
        protocol_hygiene=protocol_hygiene,
    )


def build_interpretation(
    findings: list[Finding],
    evidence: list[Evidence],
    failure_category: FailureCategory | None,
    protocol: str | None = None,
) -> ScanInterpretation:
    """Build stable posture axes and provenance from observed findings."""
    resolved_protocol = _resolve_protocol(findings, evidence, protocol)
    axes = _build_axes(findings, evidence, failure_category)
    reason_codes = build_reason_codes(findings, failure_category)
    signals = derive_signals(findings, evidence)
    not_testable = _is_not_testable(failure_category)
    headline, recommended_action = _ciso_text(axes, reason_codes)
    hndl_exposure = _hndl_exposure(
        protocol=resolved_protocol,
        classical=signals.classical_kex,
        hybrid=signals.hybrid,
        pure_pq=signals.pure_pq,
        not_testable=not_testable,
    )
    hygiene_status = _hygiene_status(
        signals, not_testable=not_testable, has_findings=bool(findings)
    )
    evaluation = evaluate_posture(
        findings,
        evidence,
        protocol=resolved_protocol,
        support=axes.pqc_support,
        hndl_exposure=hndl_exposure,
        hygiene_status=hygiene_status,
    )
    return ScanInterpretation(
        effective=scan_readiness(findings, evidence),
        headline=headline,
        recommended_action=recommended_action,
        display=_display(
            axes,
            hndl_exposure=hndl_exposure,
            hygiene_status=hygiene_status,
            not_testable=not_testable,
            evaluation=evaluation,
        ),
        hndl_exposure=hndl_exposure,
        hygiene_status=hygiene_status,
        axes=axes,
        reason_codes=reason_codes,
        evidence_refs=tuple(ev.id for ev in evidence),
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
    )
