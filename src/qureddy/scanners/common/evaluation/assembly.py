# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Assemble normalized facts into the canonical evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.scanners.common.evaluation.builder import build_evaluation
from qureddy.scanners.common.evaluation.facts import normalize_facts

if TYPE_CHECKING:
    from qureddy.core.evaluation import PostureEvaluation
    from qureddy.core.models import Evidence, Finding, HndlExposure, HygieneStatus, PqcSupport


def evaluate_posture(
    findings: list[Finding],
    evidence: list[Evidence],
    *,
    protocol: str,
    support: PqcSupport,
    hndl_exposure: HndlExposure,
    hygiene_status: HygieneStatus,
) -> PostureEvaluation:
    """Build one evaluation from adapter records and stable posture axes."""
    return build_evaluation(
        normalize_facts(
            findings,
            evidence,
            protocol=protocol,
            support=support,
            hndl_exposure=hndl_exposure,
            hygiene_status=hygiene_status,
        )
    )
