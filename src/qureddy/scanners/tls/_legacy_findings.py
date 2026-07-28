# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Evidence/Finding builders for legacy_probe.py's protocol/cipher results.

Deliberately bypasses `core/policy.py`'s `classify_evidence` rule engine
rather than extending it: `RuleCondition` only supports equality
matching (`NEGOTIATED_GROUP`/`OBSERVATION_TYPE`/`FAILURE_CATEGORY`), and
"does this accepted-cipher list contain a weak marker" needs substring
matching the model doesn't support. Extending `RuleCondition` for one
new evidence shape is a bigger, riskier change than a small dedicated
builder — kept separate on purpose (issue #192).
"""

from __future__ import annotations

import uuid

from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    ObservationType,
    Readiness,
    Severity,
)
from qureddy.scanners.tls.legacy_probe import LegacyProtocolResult, has_weak_cipher

# Named once here (the module that owns this finding_type value) so
# console.py's lookup imports it instead of re-typing the literal
# string in a second place — same pattern as _cert_findings.py's
# FINDING_TYPE_PQ_SIGNATURE/FINDING_TYPE_CLASSICAL_SIGNATURE.
FINDING_TYPE_LEGACY_PROTOCOL_OFFERED = "tls.legacy.protocol_offered"
FINDING_TYPE_CLASSICAL_PROTOCOL = "tls.kex.classical_protocol"


def evidence_from_legacy_result(asset: Asset, result: LegacyProtocolResult) -> Evidence:
    """One Evidence record per legacy-protocol sweep, offered or not.

    Generated regardless of outcome (unlike the Finding below) so a
    scan's evidence list is a complete audit trail: "we checked TLS 1.0
    and confirmed it is not offered" is itself a real, positive signal,
    not noise to discard.

    Issue #246: that claim is only true when the sweep actually
    completed. `result.probe_incomplete` means a subprocess timeout cut
    it short with zero ciphers accepted — "not offered" would be a false
    negative in that case, not a real observation. Recorded as
    NOT_TESTABLE instead. A timeout *after* some ciphers were already
    accepted still reports OFFERED — those acceptances are real,
    positive observations regardless of whether the sweep finished.
    """
    if result.probe_incomplete and not result.accepted_ciphers:
        return Evidence(
            id=f"ev-{uuid.uuid4().hex[:12]}",
            asset_id=asset.id,
            evidence_type="tls.legacy.protocol",
            observation_type=ObservationType.NOT_TESTABLE,
            source="qureddy.scanners.tls.legacy_probe",
            protocol_version=result.protocol_version,
            notes=("probe did not complete (timeout) — protocol support undetermined",),
        )
    notes: tuple[str, ...] = (
        (f"accepted ciphers: {', '.join(result.accepted_ciphers)}",)
        if result.accepted_ciphers
        else ("not offered",)
    )
    if result.probe_incomplete:
        notes = (*notes, "sweep incomplete — timed out before checking remaining candidates")
    # A completed sweep with zero accepted ciphers is a confirmed "not offered", not an
    # OFFERED observation; tagging it OFFERED made the CBOM's positive-observation filter
    # claim the endpoint *provides* TLS 1.0/1.1 for essentially every modern target (#137).
    observation_type = ObservationType.OFFERED if result.offered else ObservationType.NOT_OFFERED
    return Evidence(
        id=f"ev-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id,
        evidence_type="tls.legacy.protocol",
        observation_type=observation_type,
        source="qureddy.scanners.tls.legacy_probe",
        protocol_version=result.protocol_version,
        notes=notes,
    )


_DEPRECATED_PROTOCOLS = frozenset({"TLSv1", "TLSv1.1"})


def finding_from_legacy_result(
    asset: Asset, evidence: Evidence, result: LegacyProtocolResult
) -> Finding | None:
    """A Finding when the protocol is deprecated, weak, or purely classical.

    TLS 1.0/1.1 are themselves deprecated (PCI-DSS/NIST SP 800-52) —
    always a finding when offered, regardless of cipher.

    TLS 1.2 is *not* deprecated (NIST SP 800-52 Rev. 2 still allows it
    as the floor) and coexists with TLS 1.3 on most real servers by
    design (confirmed live: breachsafe.ai, this project's own target,
    offers TLS 1.2 alongside a clean PQC-hybrid TLS 1.3 config) — a
    naive "any legacy protocol = classically_weak" rule made that
    ordinary, common case look identical to a genuinely deprecated
    TLS 1.0 server, both in severity and in readiness rollup.

    Issue #240: a TLS-1.2-only server with no deprecated protocol and no
    weak cipher is not "classically broken" (correct for a generic
    vulnerability scanner) but IS quantum_vulnerable for a PQ-readiness
    scanner: ECDHE/RSA key establishment provides no PQ confidentiality
    regardless of whether it's broken by today's classical attacks.
    `_summary.py`'s readiness precedence already ranks TRANSITIONAL_HYBRID
    above QUANTUM_VULNERABLE, so this finding is correctly superseded
    when a hybrid TLS 1.3 finding is also present — it only becomes the
    scan's verdict when TLS 1.2 is the only protocol actually offered.

    Severity: HIGH when the accepted-cipher list contains a known-weak
    marker (see legacy_probe.WEAK_CIPHER_MARKERS and its documented gap
    for RC4/3DES/DES on the required OpenSSL 3.5 LTS+ build), MEDIUM
    otherwise. The classical-protocol-only case is LOW: it is expected,
    common behavior, not a defect being flagged.
    """
    if not result.offered:
        return None
    weak = has_weak_cipher(result.accepted_ciphers)
    deprecated_protocol = result.protocol_version in _DEPRECATED_PROTOCOLS
    cipher_list = ", ".join(result.accepted_ciphers)
    if not deprecated_protocol and not weak:
        return Finding(
            id=f"finding-{uuid.uuid4().hex[:12]}",
            asset_id=asset.id,
            evidence_ids=(evidence.id,),
            rule_id="tls.classical.protocol_offered",
            finding_type=FINDING_TYPE_CLASSICAL_PROTOCOL,
            title=f"{result.protocol_version} offers classical key establishment",
            description=(
                f"{result.protocol_version} negotiated classical cipher suites "
                f"({cipher_list}); this provides no post-quantum confidentiality."
            ),
            severity=Severity.LOW,
            readiness=Readiness.QUANTUM_VULNERABLE,
            confidence=Confidence.HIGH,
            protocol_version=result.protocol_version,
        )
    severity = Severity.HIGH if weak else Severity.MEDIUM
    reason = (
        f"{result.protocol_version} is deprecated per PCI-DSS/NIST SP 800-52"
        if deprecated_protocol
        else f"{result.protocol_version} accepts a known-weak cipher"
    )
    return Finding(
        id=f"finding-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        rule_id="tls.legacy.protocol_offered",
        finding_type=FINDING_TYPE_LEGACY_PROTOCOL_OFFERED,
        title=f"{result.protocol_version} offered" + (" with a known-weak cipher" if weak else ""),
        description=f"{reason}. Accepted ciphers: {cipher_list}.",
        severity=severity,
        readiness=Readiness.CLASSICALLY_WEAK,
        confidence=Confidence.HIGH,
        protocol_version=result.protocol_version,
    )
