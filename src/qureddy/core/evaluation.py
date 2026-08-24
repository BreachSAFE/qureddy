# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CISO evaluation models kept separate from the broad domain model module."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class PostureEvaluation(BaseModel):
    """Evidence-backed, protocol-neutral CISO evaluation."""

    model_config = _FROZEN

    summary: str
    hndl_risk: str
    protection: str
    hardening: str
    recommended_action: str
    observed_facts: tuple[str, ...] = Field(default_factory=tuple)


def _default_posture_evaluation() -> PostureEvaluation:
    """Keep deserialization of pre-0.2.58 interpretation JSON additive."""
    return PostureEvaluation(
        summary="Posture evaluation unavailable",
        hndl_risk="Exposure is unknown",
        protection="Post-quantum protection could not be confirmed",
        hardening="Security hygiene could not be assessed",
        recommended_action="Resolve probe limitations and re-run the assessment.",
    )


class InterpretationDisplay(BaseModel):
    """CISO-facing interpretation text derived from stable status axes."""

    model_config = _FROZEN

    overall_status: str
    quantum_protection: str
    future_quantum_risk: str
    current_hygiene: str
    evaluation: PostureEvaluation = Field(default_factory=_default_posture_evaluation)
