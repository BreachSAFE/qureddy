# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Domain models for QuReddy.

The field set is part of the 0.2 JSON compatibility contract; changes require
an accompanying schema and compatibility review.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from qureddy import __version__ as _version
from qureddy.core.certificate import CertificateObservation  # noqa: TC001

FROZEN = ConfigDict(frozen=True, extra="forbid")

MIN_PORT = 1
MAX_PORT = 65535

# Canonical hostname grammar for the platform, kept here because models.py is
# the lower module of the pair: targets.py imports ScanTarget from this module,
# so the reverse import would be circular. targets.py imports HOSTNAME_PATTERN
# from here instead of re-declaring it, so there is exactly one copy (#315).
# Callers use `.fullmatch` (not `.match`): the trailing `$` also matches just
# before a final "\n", so `.match` would accept "example.com\n" and let a
# control char / newline reach OpenSSL argv; `.fullmatch` rejects it (#369).
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
)

# The transport schemes a ScanTarget may carry — TLS scans and SSH scans.
# Constrained so a caller (or deserialized JSON) cannot supply an arbitrary
# scheme that would flow into the locator and downstream tooling (#369).
SUPPORTED_SCHEMES = frozenset({"tls", "ssh"})


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class ObservationType(str, Enum):
    """How a piece of evidence was obtained.

    `negotiated` and `offered` come from observed TLS handshakes;
    `observed` from passive probe output; `inferred` from policy
    rules without direct measurement; `not_offered` when a completed
    probe confirmed the protocol is absent; `not_testable` when the
    local capability check prevented probing the target.
    """

    NEGOTIATED = "negotiated"
    OFFERED = "offered"
    OBSERVED = "observed"
    INFERRED = "inferred"
    NOT_OFFERED = "not_offered"
    NOT_TESTABLE = "not_testable"


class Severity(str, Enum):
    """Severity of a finding.

    `info` for routine readiness signals (e.g. transitional_hybrid
    negotiated). `critical`/`high`/`medium`/`low` reserved for active
    risk findings. CycloneDX-aligned vocabulary for forward CBOM compat.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Readiness(str, Enum):
    """Quantum-safe readiness verdict for a scanned asset.

    `quantum_safe` reserved for future pure-PQ deployments;
    `transitional_hybrid` is the current best-practice posture
    (hybrid PQ + classical key exchange); `quantum_vulnerable` for
    classical-only; `classically_weak` for broken primitives;
    `unknown`/`not_applicable` for failed probes or scope misfit.
    """

    QUANTUM_VULNERABLE = "quantum_vulnerable"
    CLASSICALLY_WEAK = "classically_weak"
    TRANSITIONAL_HYBRID = "transitional_hybrid"
    QUANTUM_SAFE = "quantum_safe"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class Confidence(str, Enum):
    """Confidence level for a finding's evidence chain."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProbeRole(str, Enum):
    """Which purpose a TLS 1.3 key-exchange probe served — issue #232.

    Distinguishes "this evidence is testing whether PQ hybrid negotiation
    works" from "this evidence is a diagnostic control testing whether the
    server still accepts pure classical fallback". A failure in the second
    role is not evidence that the first role failed — confirmed live: a
    real hybrid-only server (accepts X25519MLKEM768, rejects pure X25519)
    correctly negotiates hybrid while its classical control is rejected by
    design, and that rejection was previously misattributed to
    `tls.hybrid.probe_failed`.
    """

    HYBRID_READINESS = "hybrid_readiness"
    CLASSICAL_CONTROL = "classical_control"
    # #337: a supplementary per-group coverage probe (SecP256r1MLKEM768, SecP384r1MLKEM1024).
    # A negotiated hybrid still fires the positive readiness rule (structural, role-agnostic),
    # but a rejection/failure does NOT fire the primary probe's rejected/failed rules — so
    # forcing extra groups adds coverage without spurious quantum_vulnerable findings.
    HYBRID_COVERAGE = "hybrid_coverage"


class FailureCategory(str, Enum):
    """Typed reason a scan or probe did not produce a clean finding.

    Local-prefixed categories indicate problems with the operator's
    environment (exit 3); target/TLS/parse categories indicate
    problems with the target or its responses (exit 2). Drives both
    the exit-code surface and the `--retry-on` allowlist.
    """

    LOCAL_OPENSSL_MISSING = "local_openssl_missing"
    LOCAL_OPENSSL_BROKEN = "local_openssl_broken"
    LOCAL_OPENSSL_VERSION_UNREADABLE = "local_openssl_version_unreadable"
    LOCAL_OPENSSL_IS_LIBRESSL = "local_openssl_is_libressl"
    LOCAL_OPENSSL_TOO_OLD = "local_openssl_too_old"
    LOCAL_OPENSSL_VERSION_MISMATCH = "local_openssl_version_mismatch"
    LOCAL_OPENSSL_LACKS_GROUP = "local_openssl_lacks_group"
    TARGET_SCAN_FAILED = "target_scan_failed"
    TARGET_CONNECT_FAILED = "target_connect_failed"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    SNI_REQUIRED_OR_WRONG = "sni_required_or_wrong"
    MIDDLEBOX_OR_MTU_FAILURE = "middlebox_or_mtu_failure"
    PARSE_NO_GROUP = "parse_no_group"
    PARSE_AMBIGUOUS = "parse_ambiguous"
    UNEXPECTED_GROUP = "unexpected_group"


# The "operator's environment is the problem" categories, defined once
# so policy.py, _summary.py, and _styles.py import the same set instead of
# each hand-typing an identical copy — confirmed live: adding
# LOCAL_OPENSSL_IS_LIBRESSL required editing all three copies in the same
# commit, with nothing enforcing they stay in sync.
LOCAL_CAPABILITY_CATEGORIES: frozenset[FailureCategory] = frozenset(
    {
        FailureCategory.LOCAL_OPENSSL_MISSING,
        FailureCategory.LOCAL_OPENSSL_BROKEN,
        FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE,
        FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL,
        FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        FailureCategory.LOCAL_OPENSSL_VERSION_MISMATCH,
        FailureCategory.LOCAL_OPENSSL_LACKS_GROUP,
    }
)


class OutputFormat(str, Enum):
    """CLI `--format` choices: terminal-rendered `rich` or machine-readable `json`."""

    RICH = "rich"
    JSON = "json"
    CBOM = "cbom"
    """CycloneDX 1.7 CBOM export — see qureddy.output.cbom."""


class ScanTarget(BaseModel):
    """A normalized scan target.

    Issue #236: enforces its own invariants at the construction boundary
    so a caller building this model directly (or deserializing external
    JSON via `model_validate`) cannot supply a `locator` that names a
    different endpoint than `host`/`port`/`sni` — the scanner would
    connect to the latter but attribute evidence to the former.
    """

    model_config = FROZEN

    original_input: str
    host: str
    port: int = Field(ge=MIN_PORT, le=MAX_PORT)
    sni: str | None
    scheme: str = "tls"
    locator: str

    @field_validator("host")
    @classmethod
    def _host_must_be_valid(cls, value: str) -> str:
        if not value or not value.strip():
            msg = "host cannot be empty"
            raise ValueError(msg)
        if "[" in value or "]" in value:
            # scanners/tls/_net.py::build_connect_target brackets IPv6
            # hosts itself and assumes `host` is stored unbracketed
            # (confirmed live: a pre-bracketed host produces a
            # double-bracketed, malformed `-connect` argv). Reject at
            # the source instead of letting that corruption happen
            # downstream in a different module.
            msg = f"host must not contain brackets, store IPv6 unbracketed: {value!r}"
            raise ValueError(msg)
        if not _is_ip_literal(value) and not HOSTNAME_PATTERN.fullmatch(value):
            msg = f"host is not a valid hostname or IP: {value!r}"
            raise ValueError(msg)
        return value

    @field_validator("sni")
    @classmethod
    def _sni_must_be_valid(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.strip():
            msg = "sni cannot be empty or whitespace-only"
            raise ValueError(msg)
        if not HOSTNAME_PATTERN.fullmatch(value):
            # SNI is passed verbatim as OpenSSL's `-servername`; a leading dash,
            # newline, control char, ANSI escape, or space is argv injection or
            # a non-hostname that has no business on the wire (RFC 6066, #369/#145).
            msg = f"sni is not a valid hostname: {value!r}"
            raise ValueError(msg)
        return value

    @field_validator("scheme")
    @classmethod
    def _scheme_must_be_supported(cls, value: str) -> str:
        if value not in SUPPORTED_SCHEMES:
            msg = f"scheme must be one of {sorted(SUPPORTED_SCHEMES)}: {value!r}"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _locator_matches_endpoint(self) -> ScanTarget:
        rendered_host = f"[{self.host}]" if ":" in self.host else self.host
        expected = f"{self.scheme}://{rendered_host}:{self.port}"
        if self.locator != expected:
            msg = f"locator {self.locator!r} does not match host/port/scheme {expected!r}"
            raise ValueError(msg)
        return self


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
    parser_input: str = Field(default="", exclude=True, repr=False)
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
    """Observation supporting a finding.

    Issue #232: `probe_role`/`expected_group` are new, optional (default
    None) fields — added to `qureddy.scan.v1` with explicit maintainer
    authorization, not silently. They let policy distinguish a hybrid
    readiness probe's failure from a classical control probe's failure,
    which are not the same fact.
    """

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
    probe_role: ProbeRole | None = None
    expected_group: str | None = None
    probe_result: ProbeResult | None = None
    failure_category: FailureCategory | None = None
    confidence: Confidence = Confidence.HIGH
    notes: tuple[str, ...] = Field(default_factory=tuple)
    certificate: CertificateObservation | None = Field(default=None, exclude=True, repr=False)


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
    scanner_version: str = _version
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
