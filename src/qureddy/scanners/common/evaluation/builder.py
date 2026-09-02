# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Build one evidence-backed CISO evaluation for every scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.evaluation import PostureEvaluation
from qureddy.core.models import HndlExposure, HygieneStatus, PqcSupport

if TYPE_CHECKING:
    from qureddy.scanners.common.evaluation.facts import PostureFacts


def _hndl_risk(exposure: HndlExposure) -> str:
    return {
        HndlExposure.AT_RISK: "At risk of harvest-now/decrypt-later exposure",
        HndlExposure.PROTECTED_DEFEASIBLE: (
            "Protected when hybrid protection is negotiated, but a classical downgrade path remains"
        ),
        HndlExposure.PROTECTED: "Protected against observed harvest-now/decrypt-later exposure",
    }.get(exposure, "Exposure could not be determined")


def _summary(facts: PostureFacts) -> str:
    protocol = facts.protocol.upper()
    if facts.support is PqcSupport.HYBRID_OBSERVED and facts.negotiated_algorithm:
        if facts.classical_alternative:
            return (
                f"{protocol} hybrid post-quantum protection is working, "
                "but classical downgrade remains possible."
            )
        return f"{protocol} hybrid post-quantum protection was observed."
    if facts.support is PqcSupport.PURE_PQ_OBSERVED:
        return f"{protocol} pure post-quantum protection was observed."
    if facts.support is PqcSupport.CLASSICAL_ONLY_OBSERVED:
        if facts.hndl_exposure is HndlExposure.UNKNOWN:
            scope = "IPsec" if protocol == "IKE" else protocol
            return (
                f"Only classical {protocol} key exchange was observed. "
                f"Overall {scope} HNDL exposure could not be determined."
            )
        return (
            f"Only classical {protocol} key exchange was observed. "
            "The endpoint remains exposed to harvest-now/decrypt-later risk."
        )
    return f"{protocol} post-quantum protection could not be confirmed."


def _protection(support: PqcSupport) -> str:
    return {
        PqcSupport.HYBRID_OBSERVED: "Hybrid post-quantum protection observed",
        PqcSupport.PURE_PQ_OBSERVED: "Pure post-quantum protection observed",
        PqcSupport.CLASSICAL_ONLY_OBSERVED: "Only classical protection observed",
    }.get(support, "Post-quantum protection could not be confirmed")


def _action(facts: PostureFacts) -> str:
    if facts.support is PqcSupport.HYBRID_OBSERVED:
        return "Restrict classical fallback where compatible and continue monitoring."
    if facts.support is PqcSupport.PURE_PQ_OBSERVED:
        return "Continue monitoring negotiated post-quantum protection."
    if facts.support is PqcSupport.CLASSICAL_ONLY_OBSERVED:
        return f"Enable hybrid post-quantum protection for {facts.protocol.upper()} and re-run."
    return "Resolve probe limitations and re-run the assessment."


def _hardening(status: HygieneStatus) -> str:
    if status in {HygieneStatus.ACTION_NEEDED, HygieneStatus.WEAK}:
        return "Protocol hardening is required"
    if status is HygieneStatus.UNKNOWN:
        return "Hardening posture could not be assessed"
    return "No immediate hardening issue identified"


def build_evaluation(facts: PostureFacts) -> PostureEvaluation:
    """Build CISO language from normalized protocol facts."""
    protocol = facts.protocol.upper()
    observed: list[str] = []
    if facts.negotiated_algorithm:
        observed.append(f"{protocol} negotiated {facts.negotiated_algorithm}")
    if facts.classical_alternative:
        observed.append(f"Classical alternative accepted: {facts.classical_alternative}")
    if facts.certificate_chain_signature:
        observed.append(
            f"Classical certificate-chain issuer signature: {facts.certificate_chain_signature}"
        )
    observed.extend(
        f"{protocol} weak algorithm offered: {algorithm}" for algorithm in facts.weak_algorithms
    )
    return PostureEvaluation(
        summary=_summary(facts),
        hndl_risk=_hndl_risk(facts.hndl_exposure),
        protection=_protection(facts.support),
        hardening=_hardening(facts.hygiene_status),
        recommended_action=_action(facts),
        observed_facts=tuple(observed),
    )
