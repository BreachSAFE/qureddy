# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CycloneDX metadata for the structured posture interpretation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cyclonedx.model import Property

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import ScanInterpretation


def add_interpretation_properties(bom: Bom, interpretation: ScanInterpretation) -> None:
    """Mirror the CISO evaluation and machine axes into CBOM properties."""
    axes = interpretation.axes
    pairs = (
        ("qureddy:scan.effective_readiness", interpretation.effective.value),
        ("qureddy:scan.headline", interpretation.headline),
        ("qureddy:scan.recommended_action", interpretation.recommended_action),
        ("qureddy:scan.display.overall_status", interpretation.display.overall_status),
        ("qureddy:scan.display.quantum_protection", interpretation.display.quantum_protection),
        ("qureddy:scan.display.future_quantum_risk", interpretation.display.future_quantum_risk),
        ("qureddy:scan.display.current_hygiene", interpretation.display.current_hygiene),
        ("qureddy:scan.display.evaluation", interpretation.display.evaluation.summary),
        ("qureddy:scan.display.evaluation.hndl_risk", interpretation.display.evaluation.hndl_risk),
        (
            "qureddy:scan.display.evaluation.protection",
            interpretation.display.evaluation.protection,
        ),
        ("qureddy:scan.display.evaluation.hardening", interpretation.display.evaluation.hardening),
        (
            "qureddy:scan.display.evaluation.recommended_action",
            interpretation.display.evaluation.recommended_action,
        ),
        ("qureddy:scan.hndl_exposure", interpretation.hndl_exposure.value),
        ("qureddy:scan.hygiene_status", interpretation.hygiene_status.value),
        ("qureddy:scan.pqc_support", axes.pqc_support.value),
        ("qureddy:scan.axis.key_exchange", axes.key_exchange.value),
        ("qureddy:scan.axis.downgrade_resistance", axes.downgrade_resistance.value),
        ("qureddy:scan.axis.authentication", axes.authentication.value),
        ("qureddy:scan.axis.protocol_hygiene", axes.protocol_hygiene.value),
        ("qureddy:scan.policy_id", interpretation.policy_id),
        ("qureddy:scan.policy_version", interpretation.policy_version),
    )
    for name, value in pairs:
        bom.metadata.properties.add(Property(name=name, value=value))
    if interpretation.reason_codes:
        bom.metadata.properties.add(
            Property(name="qureddy:scan.reason_codes", value=",".join(interpretation.reason_codes))
        )
    if interpretation.display.evaluation.observed_facts:
        bom.metadata.properties.add(
            Property(
                name="qureddy:scan.display.evaluation.observed_facts",
                value=" | ".join(interpretation.display.evaluation.observed_facts),
            )
        )
