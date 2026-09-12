# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Wording for the posture axes `posture.py` computes.

Kept apart from the computation so a sentence change cannot alter a status, and
so `posture.py` stays inside the size policy. Every branch here reads a status
that is already decided; none of them decides one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.evaluation import InterpretationDisplay
from qureddy.core.models import HndlExposure, HygieneStatus, PqcSupport

if TYPE_CHECKING:  # pragma: no cover - typing only
    from qureddy.core.evaluation import PostureEvaluation
    from qureddy.core.models import PostureAxes


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


def build_display(
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
