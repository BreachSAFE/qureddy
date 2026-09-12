# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-agnostic posture interpretation from scanner evidence.

    evidence and findings
           │
           ├─ peer facts observed → posture axes and explanatory text
           └─ local/target failure → NOT_TESTABLE / UNKNOWN text
                                      (never a fabricated peer verdict)

This module owns the cross-protocol interpretation boundary. Probe-specific
collectors own acquisition, and renderers only project this result.
"""

from __future__ import annotations

from qureddy.core.models import (
    AxisStatus,
    Evidence,
    FailureCategory,
    Finding,
    HndlExposure,
    HygieneStatus,
    ObservationType,
    PostureAxes,
    PqcSupport,
    ScanInterpretation,
    ScanSummary,
    ScanTarget,
)
from qureddy.scanners.common.evaluation import (
    PostureSignals,
    derive_signals,
    evaluate_posture,
)
from qureddy.scanners.common.evaluation import reason_codes as build_reason_codes
from qureddy.scanners.common.evaluation.display import build_display
from qureddy.scanners.common.rollup import (
    highest_severity,
    scan_nist_quantum_security_levels,
    scan_readiness,
)
from qureddy.scanners.common.signature_posture import (
    protocol_hndl_exposure,
    signature_only_pqc_axis,
)

POLICY_ID = "qureddy-readiness"
POLICY_VERSION = "1"


def _ciso_text(
    axes: PostureAxes,
    reasons: tuple[str, ...],
    has_positive_evidence: bool,
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
    if (
        "hybrid_probe_failed" in reasons
        and has_positive_evidence
        and axes.pqc_support
        not in {
            PqcSupport.HYBRID_OBSERVED,
            PqcSupport.PURE_PQ_OBSERVED,
            PqcSupport.NOT_TESTABLE,
        }
    ):
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


def _has_positive_evidence(
    evidence: list[Evidence], failure_category: FailureCategory | None
) -> bool:
    """Allow peer-behaviour headlines only for successful, failure-free evidence."""
    return failure_category is None and any(
        item.failure_category is None
        and item.observation_type
        in {
            ObservationType.NEGOTIATED,
            ObservationType.OFFERED,
            ObservationType.OBSERVED,
        }
        for item in evidence
    )


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
    *,
    classical: bool,
    hybrid: bool,
    pure_pq: bool,
    hybrid_failed: bool,
    not_testable: bool,
    signature_only: tuple[PqcSupport, AxisStatus] | None = None,
) -> tuple[PqcSupport, AxisStatus]:
    if not_testable:
        return PqcSupport.NOT_TESTABLE, AxisStatus.NOT_TESTABLE
    if signature_only is not None:
        return signature_only
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


def _has_unresolved_probe_failure(signals: PostureSignals) -> bool:
    """Return whether failed coverage lacks any successful KEX observation."""
    return signals.hybrid_failed and not (
        signals.classical_kex or signals.hybrid or signals.pure_pq
    )


def _protocol_axis(
    signals: PostureSignals,
    *,
    has_findings: bool,
    not_testable: bool,
) -> AxisStatus:
    return (
        AxisStatus.NOT_TESTABLE
        if not_testable
        else AxisStatus.ACTION_NEEDED
        if signals.protocol_action_needed or signals.legacy_protocol
        else AxisStatus.UNKNOWN
        if _has_unresolved_probe_failure(signals)
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
    signature_classical: bool = False,
) -> HndlExposure:
    """Classify future-quantum exposure without ranking present-day hygiene."""
    by_protocol = protocol_hndl_exposure(
        protocol=protocol, not_testable=not_testable, signature_classical=signature_classical
    )
    if by_protocol is not None:
        return by_protocol
    if hybrid:
        return HndlExposure.PROTECTED_DEFEASIBLE if classical else HndlExposure.PROTECTED
    if pure_pq:
        return HndlExposure.PROTECTED_DEFEASIBLE if classical else HndlExposure.PROTECTED
    if classical:
        return HndlExposure.AT_RISK
    return HndlExposure.UNKNOWN


def _hygiene_status(
    signals: PostureSignals,
    *,
    not_testable: bool,
    has_findings: bool,
) -> HygieneStatus:
    """Classify present-day hygiene independently of HNDL exposure."""
    if not_testable:
        return HygieneStatus.UNKNOWN
    if signals.hygiene_weak:
        return HygieneStatus.WEAK
    if (
        signals.legacy_protocol
        or signals.classical_kex
        or signals.authentication_classical
        or signals.downgrade_action_needed
        or signals.protocol_action_needed
    ):
        return HygieneStatus.ACTION_NEEDED
    if _has_unresolved_probe_failure(signals):
        return HygieneStatus.UNKNOWN
    return HygieneStatus.OK if has_findings else HygieneStatus.UNKNOWN


def _build_axes(
    findings: list[Finding],
    evidence: list[Evidence],
    failure_category: FailureCategory | None,
    protocol: str,
) -> tuple[PostureAxes, PostureSignals, bool]:
    signals = derive_signals(findings, evidence)
    not_testable = _is_not_testable(failure_category)

    pqc_support, key_exchange = _pqc_axis(
        classical=signals.classical_kex,
        hybrid=signals.hybrid,
        pure_pq=signals.pure_pq,
        hybrid_failed=signals.hybrid_failed,
        not_testable=not_testable,
        signature_only=signature_only_pqc_axis(
            protocol=protocol, signature_classical=signals.authentication_classical
        ),
    )

    downgrade = _downgrade_axis(signals, not_testable=not_testable)
    authentication = _authentication_axis(signals, not_testable=not_testable)
    protocol_hygiene = _protocol_axis(
        signals,
        has_findings=bool(findings),
        not_testable=not_testable,
    )
    axes = PostureAxes(
        pqc_support=pqc_support,
        key_exchange=key_exchange,
        downgrade_resistance=downgrade,
        authentication=authentication,
        protocol_hygiene=protocol_hygiene,
    )
    return axes, signals, not_testable


def _statuses(
    signals: PostureSignals,
    *,
    protocol: str,
    not_testable: bool,
    has_findings: bool,
) -> tuple[HndlExposure, HygieneStatus]:
    """Compute the two independent status axes from one set of signals."""
    return (
        _hndl_exposure(
            protocol=protocol,
            classical=signals.classical_kex,
            hybrid=signals.hybrid,
            pure_pq=signals.pure_pq,
            not_testable=not_testable,
            signature_classical=signals.authentication_classical,
        ),
        _hygiene_status(signals, not_testable=not_testable, has_findings=has_findings),
    )


def build_interpretation(
    findings: list[Finding],
    evidence: list[Evidence],
    failure_category: FailureCategory | None,
    protocol: str | None = None,
) -> ScanInterpretation:
    """Build stable posture axes and provenance from observed findings."""
    resolved_protocol = _resolve_protocol(findings, evidence, protocol)
    axes, signals, not_testable = _build_axes(
        findings, evidence, failure_category, resolved_protocol
    )
    reason_codes = build_reason_codes(findings, failure_category)
    positive_evidence = _has_positive_evidence(evidence, failure_category)
    headline, recommended_action = _ciso_text(axes, reason_codes, positive_evidence)
    hndl_exposure, hygiene_status = _statuses(
        signals,
        protocol=resolved_protocol,
        not_testable=not_testable,
        has_findings=bool(findings),
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
        display=build_display(
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


def build_scan_summary(
    target: ScanTarget,
    findings: list[Finding],
    evidence: list[Evidence],
    failure_category: FailureCategory | None,
    *,
    protocol: str,
) -> ScanSummary:
    """Build the canonical scan summary from protocol-neutral records."""
    interpretation = build_interpretation(
        findings,
        evidence,
        failure_category,
        protocol=protocol,
    )
    nist_levels = scan_nist_quantum_security_levels(evidence)
    return ScanSummary(
        target=target.locator,
        finding_count=len(findings),
        highest_severity=highest_severity(findings),
        readiness=interpretation.effective,
        nist_quantum_security_levels=nist_levels,
        nist_quantum_security_level_max=max(nist_levels) if nist_levels is not None else None,
        failure_category=failure_category,
        interpretation=interpretation,
    )
