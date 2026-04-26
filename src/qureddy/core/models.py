# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Domain models for QuReddy.

Locked by .claude/skills/mvp-implement/SKILL.md. Field set is fixed for
MVP 0.1; do not add or remove fields without updating the skill first.

ANTIPATTERN ACCEPTED: speculative generality, because CycloneDX field
names will land at MVP 0.3 and JSON schema stability matters for early
adopters. Mirrored verbatim from the skill's "Model notes" section.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

FROZEN = ConfigDict(frozen=True, extra="forbid")


class ObservationType(str, Enum):
    NEGOTIATED = "negotiated"
    OFFERED = "offered"
    OBSERVED = "observed"
    INFERRED = "inferred"
    NOT_TESTABLE = "not_testable"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Readiness(str, Enum):
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    CLASSICALLY_WEAK = "classically_weak"
    TRANSITIONAL_HYBRID = "transitional_hybrid"
    QUANTUM_SAFE = "quantum_safe"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FailureCategory(str, Enum):
    LOCAL_OPENSSL_MISSING = "local_openssl_missing"
    LOCAL_OPENSSL_TOO_OLD = "local_openssl_too_old"
    LOCAL_OPENSSL_LACKS_GROUP = "local_openssl_lacks_group"
    TARGET_CONNECT_FAILED = "target_connect_failed"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    SNI_REQUIRED_OR_WRONG = "sni_required_or_wrong"
    MIDDLEBOX_OR_MTU_FAILURE = "middlebox_or_mtu_failure"
    PARSE_NO_GROUP = "parse_no_group"
    PARSE_AMBIGUOUS = "parse_ambiguous"
    UNEXPECTED_GROUP = "unexpected_group"


class OutputFormat(str, Enum):
    RICH = "rich"
    JSON = "json"


class ScanTarget(BaseModel):
    """A normalized scan target."""

    model_config = FROZEN

    original_input: str
    host: str
    port: int
    sni: str | None
    scheme: str = "tls"
    locator: str


class OpenSSLDependency(BaseModel):
    """Local OpenSSL dependency metadata captured during capability check."""

    model_config = FROZEN

    name: str = "openssl"
    path: str | None = None
    version: str | None = None
    supports_tls13_groups: bool = False
    supports_x25519mlkem768: bool = False
    failure_category: FailureCategory | None = None


class ProbeCommand(BaseModel):
    """Subprocess command issued for a single probe."""

    model_config = FROZEN

    executable: str
    args: tuple[str, ...]
    timeout_seconds: int
    redacted: bool = False


class ProbeResult(BaseModel):
    """Outcome of a single OpenSSL invocation."""

    model_config = FROZEN

    command: ProbeCommand
    return_code: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    duration_ms: int
    attempt_number: int = 1
    failure_category: FailureCategory | None = None


class Asset(BaseModel):
    """A scanned crypto asset (e.g., a TLS endpoint)."""

    model_config = FROZEN

    id: str
    asset_type: str
    locator: str
    display_name: str
    protocol: str = "tls"
    protocol_version: str | None = None
    algorithm: str | None = None
    primitive: str | None = None
    parameter_set_identifier: str | None = None
    key_size: int | None = None
    negotiated_group: str | None = None
    bom_ref: str | None = None
    oid: str | None = None
    nist_quantum_security_level: int | None = Field(default=None, ge=0, le=5)


class Evidence(BaseModel):
    """Observation supporting a finding."""

    model_config = FROZEN

    id: str
    asset_id: str
    evidence_type: str
    observation_type: ObservationType
    source: str
    protocol: str = "tls"
    protocol_version: str | None = None
    cipher_suite: str | None = None
    negotiated_group: str | None = None
    probe_result: ProbeResult | None = None
    failure_category: FailureCategory | None = None
    confidence: Confidence = Confidence.HIGH
    notes: tuple[str, ...] = Field(default_factory=tuple)


class Finding(BaseModel):
    """Classification produced by policy evaluation."""

    model_config = FROZEN

    id: str
    asset_id: str
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    rule_id: str
    finding_type: str
    title: str
    description: str
    severity: Severity
    readiness: Readiness
    confidence: Confidence
    algorithm: str | None = None
    primitive: str | None = None
    parameter_set_identifier: str | None = None
    key_size: int | None = None
    protocol: str = "tls"
    protocol_version: str | None = None
    negotiated_group: str | None = None
    bom_ref: str | None = None
    oid: str | None = None
    nist_quantum_security_level: int | None = Field(default=None, ge=0, le=5)


class ScanMetadata(BaseModel):
    """Run-level metadata. Built once at end-of-scan."""

    model_config = FROZEN

    scan_id: str
    started_at: datetime
    completed_at: datetime
    scanner_name: str = "tls"
    scanner_version: str = "0.1.0"
    status: str
    total_attempts: int = 1


class ScanSummary(BaseModel):
    """Top-line summary of a scan result."""

    model_config = FROZEN

    target: str
    finding_count: int
    highest_severity: Severity | None = None
    readiness: Readiness
    failure_category: FailureCategory | None = None


class ScanResult(BaseModel):
    """Top-level scan output. Field order is the JSON schema contract."""

    model_config = FROZEN

    schema_version: str = "qureddy.scan.v1"
    scan: ScanMetadata
    target: ScanTarget
    dependencies: tuple[OpenSSLDependency, ...]
    assets: tuple[Asset, ...]
    evidence: tuple[Evidence, ...]
    findings: tuple[Finding, ...]
    summary: ScanSummary
