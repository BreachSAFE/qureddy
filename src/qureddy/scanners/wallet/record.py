# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The evidence and finding accumulator every wallet recorder writes through.

One place builds an `Evidence` and its `Finding` together, so a recorder names
a lane and a source expression (C1) and cannot emit one without the other.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.ids import new_id
from qureddy.core.models import Evidence, Finding
from qureddy.core.vocabulary import Confidence, ObservationType, Readiness, Severity

if TYPE_CHECKING:  # pragma: no cover - typing only
    from qureddy.core.models import Asset

#: secp256k1 meets no NIST post-quantum category, so Shor recovers the key outright.
NIST_LEVEL_SECP256K1 = 0
CURVE = "secp256k1"
PRIMITIVE = "signature"
KEY_SIZE_BITS = 256
NOT_TESTED = "not tested"


def _note(lane: str, source: str) -> tuple[str, ...]:
    """C1: the lane that produced a value and the expression it came from."""
    return (f"lane={lane}", f"source={source}")


class Builder:
    """Accumulates evidence and findings for one scan, keeping ids consistent."""

    def __init__(self, asset: Asset, protocol: str) -> None:
        """Bind the accumulator to one asset and the protocol its findings carry."""
        self.asset = asset
        self.protocol = protocol
        self.evidence: list[Evidence] = []
        self.findings: list[Finding] = []

    def record(
        self,
        name: str,
        value: str,
        *,
        lane: str,
        source: str,
        observation: ObservationType,
        evidence_type: str | None = None,
        negotiated_group: str | None = None,
        public_key: str | None = None,
        public_key_format: str | None = None,
        severity: Severity = Severity.INFO,
        readiness: Readiness = Readiness.NOT_APPLICABLE,
        confidence: Confidence = Confidence.HIGH,
        description: str = "",
    ) -> None:
        """Add one observation and the finding that reports it."""
        item = Evidence(
            id=new_id("evidence"),
            asset_id=self.asset.id,
            evidence_type=evidence_type or name,
            observation_type=observation,
            negotiated_group=negotiated_group,
            public_key=public_key,
            public_key_format=public_key_format,
            source=lane,
            protocol=self.protocol,
            algorithm=f"ECDSA-{CURVE}",
            primitive=PRIMITIVE,
            nist_quantum_security_level=NIST_LEVEL_SECP256K1,
            confidence=confidence,
            notes=_note(lane, source),
        )
        self.evidence.append(item)
        self.findings.append(
            self._finding(
                item.id,
                name,
                value,
                lane=lane,
                source=source,
                severity=severity,
                readiness=readiness,
                confidence=confidence,
                description=description,
            )
        )

    def _finding(
        self,
        evidence_id: str,
        name: str,
        value: str,
        *,
        lane: str,
        source: str,
        severity: Severity,
        readiness: Readiness,
        confidence: Confidence,
        description: str,
    ) -> Finding:
        """The finding that reports one observation, C1 source line included."""
        return Finding(
            id=new_id("finding"),
            asset_id=self.asset.id,
            evidence_ids=(evidence_id,),
            rule_id=f"wallet.{name}",
            finding_type=name,
            title=f"{name}: {value}",
            description=description or f"{value}. Read by the {lane} lane from {source}.",
            severity=severity,
            readiness=readiness,
            confidence=confidence,
            protocol=self.protocol,
            algorithm=f"ECDSA-{CURVE}",
            primitive=PRIMITIVE,
            nist_quantum_security_level=NIST_LEVEL_SECP256K1,
        )

    def not_tested(self, name: str, reason: str, *, lane: str) -> None:
        """C3: record what a lane did not measure, in place of a default."""
        self.record(
            name,
            NOT_TESTED,
            lane=lane,
            source=reason,
            observation=ObservationType.NOT_TESTABLE,
            confidence=Confidence.LOW,
            description=f"{NOT_TESTED}. {reason}",
        )
