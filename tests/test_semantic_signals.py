# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the versioned protocol-neutral signal taxonomy."""

from __future__ import annotations

import pytest

from qureddy.core.models import Confidence, Finding, Readiness, Severity
from qureddy.core.signals import (
    SEMANTIC_SIGNAL_VERSION,
    SemanticSignal,
    unknown_signal_is_gap,
)
from qureddy.scanners.common.evaluation.facts import derive_signals


def _finding(rule_id: str, finding_type: str, readiness: Readiness) -> Finding:
    return Finding(
        id="finding-1",
        asset_id="asset-1",
        evidence_ids=("evidence-1",),
        rule_id=rule_id,
        finding_type=finding_type,
        title="test",
        description="test",
        severity=Severity.INFO,
        readiness=readiness,
        confidence=Confidence.HIGH,
    )


def test_signal_taxonomy_is_versioned_and_unknowns_are_gaps() -> None:
    assert SEMANTIC_SIGNAL_VERSION == "1"
    assert SemanticSignal.HYBRID_PQC.value == "kex.hybrid_pqc"
    assert not unknown_signal_is_gap(SemanticSignal.CLASSICAL_KEX.value)
    assert unknown_signal_is_gap("future.unreviewed_signal")


def test_legacy_tls_and_ssh_ids_map_to_same_neutral_signals() -> None:
    tls = derive_signals(
        [
            _finding(
                "tls.classical.negotiated_x25519", "tls.kex.classical", Readiness.QUANTUM_VULNERABLE
            )
        ],
        [],
    )
    ssh = derive_signals(
        [
            _finding(
                "ssh.kex.classical_alternative", "ssh.kex.classical", Readiness.QUANTUM_VULNERABLE
            )
        ],
        [],
    )
    assert tls.semantic == ssh.semantic == frozenset({SemanticSignal.CLASSICAL_KEX})


@pytest.mark.parametrize(
    ("rule_id", "finding_type", "readiness", "expected"),
    [
        (
            "tls.hybrid.negotiated_pq",
            "tls.kex.hybrid",
            Readiness.TRANSITIONAL_HYBRID,
            {SemanticSignal.HYBRID_PQC},
        ),
        (
            "ssh.kex.hybrid_offered",
            "ssh.kex.hybrid",
            Readiness.TRANSITIONAL_HYBRID,
            {SemanticSignal.HYBRID_PQC},
        ),
        (
            "tls.classical.negotiated_x25519",
            "tls.kex.classical",
            Readiness.QUANTUM_VULNERABLE,
            {SemanticSignal.CLASSICAL_KEX},
        ),
        (
            "ssh.kex.classical_alternative",
            "ssh.kex.classical",
            Readiness.QUANTUM_VULNERABLE,
            {SemanticSignal.CLASSICAL_KEX},
        ),
        (
            "tls.pq.negotiated_pure",
            "tls.kex.pure_pq",
            Readiness.QUANTUM_SAFE,
            {SemanticSignal.PURE_PQC},
        ),
        (
            "ssh.hostkey.weak",
            "ssh.hostkey.weak",
            Readiness.CLASSICALLY_WEAK,
            {
                SemanticSignal.AUTHENTICATION_CLASSICAL,
                SemanticSignal.WEAK_ALGORITHM,
                SemanticSignal.HYGIENE_WEAK,
                SemanticSignal.DOWNGRADE_ACTION_NEEDED,
            },
        ),
        (
            "ssh.transport.weak",
            "ssh.transport.weak",
            Readiness.CLASSICALLY_WEAK,
            {
                SemanticSignal.WEAK_ALGORITHM,
                SemanticSignal.HYGIENE_WEAK,
                SemanticSignal.DOWNGRADE_ACTION_NEEDED,
                SemanticSignal.PROTOCOL_ACTION_NEEDED,
            },
        ),
        (
            "ssh.terrapin.posture",
            "ssh.terrapin.posture",
            Readiness.NOT_APPLICABLE,
            {SemanticSignal.PROTOCOL_ACTION_NEEDED},
        ),
        (
            "tls.cert.signature_algorithm",
            "tls.cert.classical_signature",
            Readiness.NOT_APPLICABLE,
            {SemanticSignal.AUTHENTICATION_CLASSICAL, SemanticSignal.CLASSICAL_CERTIFICATE},
        ),
        (
            "tls.cert.signature_algorithm",
            "tls.cert.pq_signature",
            Readiness.NOT_APPLICABLE,
            {SemanticSignal.AUTHENTICATION_PQ},
        ),
        (
            "tls.legacy.protocol_offered",
            "tls.legacy.protocol_offered",
            Readiness.QUANTUM_VULNERABLE,
            {SemanticSignal.LEGACY_PROTOCOL},
        ),
        (
            "tls.classical.protocol_offered",
            "tls.kex.classical_protocol",
            Readiness.QUANTUM_VULNERABLE,
            {SemanticSignal.DOWNGRADE_ACTION_NEEDED},
        ),
        (
            "tls.hybrid.probe_failed",
            "tls.kex.probe_failed",
            Readiness.UNKNOWN,
            {SemanticSignal.HYBRID_PROBE_FAILED},
        ),
    ],
)
def test_all_current_protocol_findings_map_to_typed_signals(
    rule_id: str,
    finding_type: str,
    readiness: Readiness,
    expected: set[SemanticSignal],
) -> None:
    signals = derive_signals([_finding(rule_id, finding_type, readiness)], [])
    assert signals.semantic == frozenset(expected)


@pytest.mark.parametrize(
    ("rule_id", "finding_type", "readiness"),
    [
        ("ike.proposal.selected", "ike.proposal.selected", Readiness.QUANTUM_SAFE),
        ("ike.kex.pure_pq", "ike.kex.pure_pq", Readiness.UNKNOWN),
        ("ike.kex.classical", "ike.kex.classical", Readiness.QUANTUM_SAFE),
        ("ike.kex.hybrid", "ike.proposal.selected", Readiness.TRANSITIONAL_HYBRID),
    ],
)
def test_kex_signals_require_canonical_finding_type_and_readiness_pair(
    rule_id: str,
    finding_type: str,
    readiness: Readiness,
) -> None:
    signals = derive_signals([_finding(rule_id, finding_type, readiness)], [])

    assert not signals.semantic
