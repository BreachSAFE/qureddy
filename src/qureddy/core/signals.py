# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Versioned, protocol-neutral posture signals."""

from __future__ import annotations

from enum import StrEnum

SEMANTIC_SIGNAL_VERSION = "1"


class SemanticSignal(StrEnum):
    """Stable facts used by protocol-neutral posture evaluation."""

    HYBRID_PQC = "kex.hybrid_pqc"
    PURE_PQC = "kex.pure_pqc"
    CLASSICAL_KEX = "kex.classical"
    HYBRID_PROBE_FAILED = "kex.hybrid_probe_failed"
    DOWNGRADE_ACTION_NEEDED = "downgrade.action_needed"
    AUTHENTICATION_CLASSICAL = "authentication.classical"
    AUTHENTICATION_PQ = "authentication.pq"
    CLASSICAL_CERTIFICATE = "certificate.signature.classical"
    LEGACY_PROTOCOL = "protocol.legacy"
    WEAK_ALGORITHM = "algorithm.weak"
    PROTOCOL_ACTION_NEEDED = "protocol.action_needed"
    HYGIENE_WEAK = "hygiene.weak"


def unknown_signal_is_gap(signal: str) -> bool:
    """Return whether an unrecognized signal must be an evaluation gap."""
    return signal not in {member.value for member in SemanticSignal}
