# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Build one evidence-backed CISO evaluation for every scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.evaluation import PostureEvaluation
from qureddy.core.models import HndlExposure, HygieneStatus, PqcSupport
from qureddy.core.vocabulary import SIGNATURE_ONLY_PROTOCOLS

if TYPE_CHECKING:
    from qureddy.scanners.common.evaluation.facts import PostureFacts


def _hndl_risk(facts: PostureFacts) -> str:
    if facts.account_without_key:
        return "No key is held at this address, so it carries no harvest exposure"
    return {
        HndlExposure.AT_RISK: "At risk of harvest-now/decrypt-later exposure",
        HndlExposure.PROTECTED_DEFEASIBLE: (
            "Protected by observed post-quantum key exchange, "
            "but a classical downgrade path remains"
        ),
        HndlExposure.PROTECTED: "Protected against observed harvest-now/decrypt-later exposure",
    }.get(facts.hndl_exposure, "Exposure could not be determined")


def _summary(facts: PostureFacts) -> str:
    protocol = facts.protocol.upper()
    if facts.account_without_key:
        return _no_key_summary(facts)
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
        return _classical_summary(facts, protocol)
    return f"{protocol} post-quantum protection could not be confirmed."


def _no_key_summary(facts: PostureFacts) -> str:
    """A contract account holds no externally owned key, so it has none to expose."""
    return (
        f"This {facts.protocol.upper()} address holds no key of its own. Its owner and "
        "upgrade keys are held elsewhere and were not examined."
    )


def _classical_summary(facts: PostureFacts, protocol: str) -> str:
    """Word the classical-only case for the surface the protocol actually has."""
    if facts.protocol in SIGNATURE_ONLY_PROTOCOLS:
        # These protocols negotiate nothing, so "key exchange" would name a step
        # that never runs. The signing algorithm is the whole surface.
        algorithm = facts.negotiated_algorithm or "a classical algorithm"
        return (
            f"{protocol} accounts sign with {algorithm}, which meets no NIST post-quantum category."
        )
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


def _protection(facts: PostureFacts) -> str:
    if facts.account_without_key:
        return "No key material is held at this address"
    return {
        PqcSupport.HYBRID_OBSERVED: "Hybrid post-quantum protection observed",
        PqcSupport.PURE_PQ_OBSERVED: "Pure post-quantum protection observed",
        PqcSupport.CLASSICAL_ONLY_OBSERVED: "Only classical protection observed",
    }.get(facts.support, "Post-quantum protection could not be confirmed")


def _action(facts: PostureFacts) -> str:
    if facts.account_without_key:
        return "Assess the owner and upgrade keys, which are held off this address."
    if facts.support is PqcSupport.HYBRID_OBSERVED:
        return "Restrict classical fallback where compatible and continue monitoring."
    if facts.support is PqcSupport.PURE_PQ_OBSERVED:
        return "Continue monitoring negotiated post-quantum protection."
    if facts.support is PqcSupport.CLASSICAL_ONLY_OBSERVED:
        if facts.protocol in SIGNATURE_ONLY_PROTOCOLS:
            # No configuration on this side changes a chain's signing algorithm.
            return "Track the published key, since exposure begins at publication."
        return f"Enable hybrid post-quantum protection for {facts.protocol.upper()} and re-run."
    return "Resolve probe limitations and re-run the assessment."


def _hardening(facts: PostureFacts) -> str:
    """Present-day hygiene, or an empty string where the axis does not apply.

    A chain account has no protocol to harden. Its present-day question is
    whether a signing defect makes the key derivable today, which the defect
    findings answer, so "Protocol hardening is required" named a control that
    does not exist and a reader who knows the chain can see that.
    """
    if facts.protocol in SIGNATURE_ONLY_PROTOCOLS:
        return ""
    status = facts.hygiene_status
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
        hndl_risk=_hndl_risk(facts),
        protection=_protection(facts),
        hardening=_hardening(facts),
        recommended_action=_action(facts),
        observed_facts=tuple(observed),
    )
