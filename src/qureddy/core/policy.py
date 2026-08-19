# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Current hardcoded readiness policy. Seven rules, no YAML loading."""

from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel

from qureddy.core.models import (
    FROZEN,
    LOCAL_CAPABILITY_CATEGORIES,
    Asset,
    Confidence,
    Evidence,
    FailureCategory,
    Finding,
    ObservationType,
    ProbeRole,
    Readiness,
    Severity,
)


class RuleField(str, Enum):
    """Which Evidence attribute a RuleCondition reads."""

    NEGOTIATED_GROUP = "negotiated_group"
    OBSERVATION_TYPE = "observation_type"
    FAILURE_CATEGORY = "failure_category"
    PROBE_ROLE = "probe_role"


class RuleCondition(BaseModel):
    """A single condition the evidence must satisfy for a rule to fire."""

    model_config = FROZEN

    field: RuleField
    equals: str | None = None
    failure_category: FailureCategory | None = None
    observation_type: ObservationType | None = None
    failure_category_in: tuple[FailureCategory, ...] | None = None
    probe_role: ProbeRole | None = None


class PolicyRule(BaseModel):
    """An MVP policy rule. All conditions must match for the rule to fire."""

    model_config = FROZEN

    id: str
    finding_type: str
    title: str
    description: str
    severity: Severity
    readiness: Readiness
    confidence: Confidence
    conditions: tuple[RuleCondition, ...]


_LOCAL_NOT_TESTABLE = tuple(LOCAL_CAPABILITY_CATEGORIES)
_PROBE_FAILED = (
    FailureCategory.TARGET_CONNECT_FAILED,
    FailureCategory.TLS_HANDSHAKE_FAILED,
    FailureCategory.SNI_REQUIRED_OR_WRONG,
    FailureCategory.MIDDLEBOX_OR_MTU_FAILURE,
    FailureCategory.PARSE_NO_GROUP,
    FailureCategory.PARSE_AMBIGUOUS,
)

MVP_POLICY: tuple[PolicyRule, ...] = (
    PolicyRule(
        id="tls.hybrid.negotiated_x25519mlkem768",
        finding_type="tls.kex.hybrid",
        title="TLS 1.3 negotiated X25519MLKEM768",
        description=(
            "Server selected the hybrid post-quantum group X25519MLKEM768 for TLS 1.3 key exchange."
        ),
        severity=Severity.INFO,
        readiness=Readiness.TRANSITIONAL_HYBRID,
        confidence=Confidence.HIGH,
        conditions=(
            RuleCondition(field=RuleField.NEGOTIATED_GROUP, equals="X25519MLKEM768"),
            RuleCondition(
                field=RuleField.OBSERVATION_TYPE,
                observation_type=ObservationType.NEGOTIATED,
            ),
        ),
    ),
    PolicyRule(
        id="tls.hybrid.not_testable",
        finding_type="tls.kex.not_testable",
        title="Local OpenSSL cannot test X25519MLKEM768",
        description=(
            "Local OpenSSL is missing, too old, or lacks the X25519MLKEM768 "
            "group; the scanner cannot determine the target's hybrid posture."
        ),
        severity=Severity.INFO,
        readiness=Readiness.UNKNOWN,
        confidence=Confidence.HIGH,
        conditions=(
            RuleCondition(
                field=RuleField.FAILURE_CATEGORY,
                failure_category_in=_LOCAL_NOT_TESTABLE,
            ),
        ),
    ),
    PolicyRule(
        id="tls.hybrid.probe_failed",
        finding_type="tls.kex.probe_failed",
        title="TLS probe failed",
        description=("The TLS probe did not produce parseable evidence of the negotiated group."),
        severity=Severity.INFO,
        readiness=Readiness.UNKNOWN,
        confidence=Confidence.MEDIUM,
        conditions=(
            # Issue #232: scoped to the hybrid-readiness probe specifically.
            # Without this, a classical control probe's failure (which is
            # not evidence the hybrid probe failed — a hybrid-only server
            # is *expected* to reject pure classical) fired this exact
            # rule, turning a correct transitional_hybrid scan into a
            # reported "probe failed" / exit 2. Live-verified with the pinned
            # OpenSSL 3.5.7 LTS client: a hybrid-only server (accepts
            # X25519MLKEM768, rejects X25519) negotiated hybrid cleanly while its classical
            # control failed with TLS_HANDSHAKE_FAILED — that failure must
            # not attribute to the hybrid probe.
            RuleCondition(field=RuleField.PROBE_ROLE, probe_role=ProbeRole.HYBRID_READINESS),
            RuleCondition(
                field=RuleField.FAILURE_CATEGORY,
                failure_category_in=_PROBE_FAILED,
            ),
        ),
    ),
    PolicyRule(
        id="tls.hybrid.downgraded_to_classical",
        finding_type="tls.kex.unexpected_group",
        title="Server rejected requested TLS 1.3 group and negotiated a different one",
        description=(
            "The probe requested a specific TLS 1.3 group but the server "
            "negotiated a different group instead, indicating the requested "
            "group (often the PQC hybrid candidate) is unsupported."
        ),
        severity=Severity.LOW,
        readiness=Readiness.QUANTUM_VULNERABLE,
        confidence=Confidence.MEDIUM,
        conditions=(
            # Issue #232 follow-through on #235's own documented caveat:
            # scoped to the hybrid probe so a classical-control probe that
            # (rarely, but possibly) reports UNEXPECTED_GROUP is not read
            # as "the PQC candidate is unsupported" — that claim only
            # makes sense for the probe that was actually requesting it.
            RuleCondition(field=RuleField.PROBE_ROLE, probe_role=ProbeRole.HYBRID_READINESS),
            RuleCondition(
                field=RuleField.FAILURE_CATEGORY,
                failure_category=FailureCategory.UNEXPECTED_GROUP,
            ),
        ),
    ),
    PolicyRule(
        id="tls.classical.negotiated_x25519",
        finding_type="tls.kex.classical",
        title="Classical X25519 available on TLS 1.3 control probe",
        description=(
            "The forced classical control probe negotiated X25519. This "
            "demonstrates the server still accepts pure classical key "
            "exchange when offered, which provides no protection against "
            "harvest-now-decrypt-later. A separate hybrid finding may "
            "also be present if the server prefers X25519MLKEM768 when "
            "both groups are offered."
        ),
        severity=Severity.LOW,
        readiness=Readiness.QUANTUM_VULNERABLE,
        confidence=Confidence.HIGH,
        conditions=(
            RuleCondition(field=RuleField.NEGOTIATED_GROUP, equals="X25519"),
            RuleCondition(
                field=RuleField.OBSERVATION_TYPE,
                observation_type=ObservationType.NEGOTIATED,
            ),
        ),
    ),
    PolicyRule(
        id="tls.classical.control_rejected",
        finding_type="tls.kex.classical_control_rejected",
        title="Classical control probe rejected — no pure-classical fallback accepted",
        description=(
            "The forced classical-only control probe did not negotiate. When "
            "the hybrid probe succeeded, this is a positive hardening signal: "
            "the server offers no pure-classical downgrade path. Readiness is "
            "deliberately NOT_APPLICABLE — it never overrides the hybrid or "
            "legacy-protocol axes, which are the actual readiness signal; this "
            "finding only records that the control probe itself was rejected "
            "(issue #232 — this was previously misattributed to "
            "tls.hybrid.probe_failed, incorrectly turning a successful hybrid "
            "scan into a reported failure)."
        ),
        severity=Severity.INFO,
        readiness=Readiness.NOT_APPLICABLE,
        confidence=Confidence.HIGH,
        conditions=(
            RuleCondition(field=RuleField.PROBE_ROLE, probe_role=ProbeRole.CLASSICAL_CONTROL),
            RuleCondition(
                field=RuleField.FAILURE_CATEGORY,
                failure_category_in=_PROBE_FAILED,
            ),
        ),
    ),
)


def classify_evidence(asset: Asset, evidence: list[Evidence]) -> list[Finding]:
    """Classify a list of Evidence into Finding objects.

    A rule fires once per matching Evidence. Each finding lists the
    matching evidence_ids; min_length=1 is enforced by the model.
    """
    findings: list[Finding] = []
    for ev in evidence:
        for rule in MVP_POLICY:
            if _rule_matches(rule, ev):
                findings.append(_build_finding(asset, rule, ev))
                break
    return findings


def _rule_matches(rule: PolicyRule, evidence: Evidence) -> bool:
    return all(_condition_matches(c, evidence) for c in rule.conditions)


def _condition_matches(condition: RuleCondition, evidence: Evidence) -> bool:
    if condition.field is RuleField.NEGOTIATED_GROUP:
        return evidence.negotiated_group == condition.equals
    if condition.field is RuleField.OBSERVATION_TYPE:
        return evidence.observation_type is condition.observation_type
    if condition.field is RuleField.FAILURE_CATEGORY:
        if condition.failure_category is not None:
            return evidence.failure_category is condition.failure_category
        if condition.failure_category_in is not None:
            return evidence.failure_category in condition.failure_category_in
    if condition.field is RuleField.PROBE_ROLE:
        return evidence.probe_role is condition.probe_role
    return False


def _build_finding(asset: Asset, rule: PolicyRule, evidence: Evidence) -> Finding:
    return Finding(
        id=f"finding-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        rule_id=rule.id,
        finding_type=rule.finding_type,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        readiness=rule.readiness,
        confidence=rule.confidence,
        protocol_version=evidence.protocol_version,
        negotiated_group=evidence.negotiated_group,
    )
