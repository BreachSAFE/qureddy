# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Stable reason-code derivation shared by protocol adapters."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.scanners.common.evaluation.facts import derive_signals

if TYPE_CHECKING:
    from qureddy.core.models import FailureCategory, Finding


def reason_codes(
    findings: list[Finding], failure_category: FailureCategory | None
) -> tuple[str, ...]:
    """Return deterministic machine-readable reasons for the posture result."""
    signals = derive_signals(findings, [])
    candidates = (
        (signals.hybrid, "hybrid_pqc_observed"),
        (signals.pure_pq, "pure_pq_observed"),
        (
            signals.hybrid_failed and not any((signals.hybrid, signals.pure_pq)),
            "hybrid_probe_failed",
        ),
        (signals.classical_kex, "classical_kex_negotiated"),
        (signals.classical_certificate, "classical_certificate_signature"),
        (signals.legacy_protocol, "deprecated_protocol_observed"),
        (signals.weak_algorithm, "weak_classical_algorithm_observed"),
    )
    codes = [code for present, code in candidates if present]
    if failure_category is not None:
        codes.append(failure_category.value)
    return tuple(dict.fromkeys(codes))
