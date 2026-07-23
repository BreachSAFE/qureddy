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


def evidence_from_legacy_result(asset: Asset, result: LegacyProtocolResult) -> Evidence:
    """One Evidence record per legacy-protocol sweep, offered or not.

    Generated regardless of outcome (unlike the Finding below) so a
    scan's evidence list is a complete audit trail: "we checked TLS 1.0
    and confirmed it is not offered" is itself a real, positive signal,
    not noise to discard.
    """
    notes = (
        (f"accepted ciphers: {', '.join(result.accepted_ciphers)}",)
        if result.accepted_ciphers
        else ("not offered",)
    )
    return Evidence(
        id=f"ev-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id,
        evidence_type="tls.legacy.protocol",
        observation_type=ObservationType.OFFERED,
        source="qureddy.scanners.tls.legacy_probe",
        protocol_version=result.protocol_version,
        notes=notes,
    )


_DEPRECATED_PROTOCOLS = frozenset({"TLSv1", "TLSv1.1"})


def finding_from_legacy_result(
    asset: Asset, evidence: Evidence, result: LegacyProtocolResult
) -> Finding | None:
    """A Finding when the protocol is deprecated, or a weak cipher was found.

    TLS 1.0/1.1 are themselves deprecated (PCI-DSS/NIST SP 800-52) —
    always a finding when offered, regardless of cipher.

    TLS 1.2 is *not* deprecated (NIST SP 800-52 Rev. 2 still allows it
    as the floor) and coexists with TLS 1.3 on most real servers by
    design (confirmed live: breachsafe.ai, this project's own target,
    offers TLS 1.2 alongside a clean PQC-hybrid TLS 1.3 config) — a
    naive "any legacy protocol = classically_weak" rule made that
    ordinary, common case look identical to a genuinely deprecated
    TLS 1.0 server, both in severity and in readiness rollup. TLS 1.2
    alone (no weak cipher) returns None here — "should TLS 1.2 be
    flagged when TLS 1.3 is also available" is issue #171's scope
    (downgrade detection), not this one's.

    Severity: HIGH when the accepted-cipher list contains a known-weak
    marker (see legacy_probe.WEAK_CIPHER_MARKERS and its documented gap
    for RC4/3DES/DES on the required OpenSSL 3.5+ build), MEDIUM
    otherwise.
    """
    if not result.offered:
        return None
    weak = has_weak_cipher(result.accepted_ciphers)
    deprecated_protocol = result.protocol_version in _DEPRECATED_PROTOCOLS
    if not deprecated_protocol and not weak:
        return None
    severity = Severity.HIGH if weak else Severity.MEDIUM
    cipher_list = ", ".join(result.accepted_ciphers)
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
        finding_type="tls.legacy.protocol_offered",
        title=f"{result.protocol_version} offered" + (" with a known-weak cipher" if weak else ""),
        description=f"{reason}. Accepted ciphers: {cipher_list}.",
        severity=severity,
        readiness=Readiness.CLASSICALLY_WEAK,
        confidence=Confidence.HIGH,
        protocol_version=result.protocol_version,
    )
