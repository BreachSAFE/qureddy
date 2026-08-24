# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-neutral posture evaluation."""

from __future__ import annotations

from qureddy.scanners.common.evaluation.assembly import evaluate_posture
from qureddy.scanners.common.evaluation.builder import build_evaluation
from qureddy.scanners.common.evaluation.facts import PostureFacts, normalize_facts
from qureddy.scanners.common.evaluation.reasons import reason_codes

__all__ = [
    "PostureFacts",
    "build_evaluation",
    "evaluate_posture",
    "normalize_facts",
    "reason_codes",
]
