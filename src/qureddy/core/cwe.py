# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Conservative CWE classifications for actionable QuReddy findings.

The scanner observes protocol configuration; it does not prove exploitation.
Only findings whose rule expresses a documented cryptographic weakness are
classified. Informational observations and unknown probe outcomes stay
unclassified instead of receiving a speculative CWE.

    rule_id ──▶ immutable CWE mapping ──▶ Finding.cwe_ids
                                      ├─▶ JSON / JSONL
                                      ├─▶ Rich
                                      └─▶ CBOM annotation text
"""

from __future__ import annotations

from types import MappingProxyType

_CWE_BY_RULE_ID = MappingProxyType(
    {
        # Broken or obsolete cryptographic algorithms/protocols.
        "tls.transport.weak": ("CWE-327",),
        "tls.legacy.protocol_offered": ("CWE-327",),
        "tls.cert.weak_signature_algorithm": ("CWE-327",),
        "ssh.kex.weak": ("CWE-327",),
        "ssh.hostkey.weak": ("CWE-327",),
        "ssh.transport.weak": ("CWE-327",),
        "ike.transport.prohibited": ("CWE-327",),
        "ike.transport.legacy_3des": ("CWE-327",),
        "ike.transport.weak": ("CWE-327",),
        # A measured choice of a weaker negotiated alternative.
        "tls.hybrid.downgraded_to_classical": ("CWE-757",),
        "ssh.kex.classical_alternative": ("CWE-757",),
        # Explicitly inadequate finite-field/DH strength.
        "ike.dh.weak": ("CWE-326",),
    }
)


def cwe_ids_for_rule(rule_id: str) -> tuple[str, ...]:
    """Return authoritative CWE IDs for a rule, or empty for no mapping."""
    return _CWE_BY_RULE_ID.get(rule_id, ())
