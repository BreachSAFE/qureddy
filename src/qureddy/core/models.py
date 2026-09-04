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

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from qureddy import __version__ as _version
from qureddy.core.certificate import CertificateDetails, CertificateObservation  # noqa: TC001
from qureddy.core.evaluation import InterpretationDisplay, PostureEvaluation  # noqa: F401, TC001
from qureddy.core.vocabulary import (
    LOCAL_CAPABILITY_CATEGORIES as LOCAL_CAPABILITY_CATEGORIES,  # noqa: PLC0414
)
from qureddy.core.vocabulary import AxisStatus as AxisStatus  # noqa: PLC0414
from qureddy.core.vocabulary import Confidence as Confidence  # noqa: PLC0414
from qureddy.core.vocabulary import FailureCategory as FailureCategory  # noqa: PLC0414
from qureddy.core.vocabulary import HndlExposure as HndlExposure  # noqa: PLC0414
from qureddy.core.vocabulary import HygieneStatus as HygieneStatus  # noqa: PLC0414
from qureddy.core.vocabulary import ObservationType as ObservationType  # noqa: PLC0414
from qureddy.core.vocabulary import OutputFormat as OutputFormat  # noqa: PLC0414
from qureddy.core.vocabulary import PqcSupport as PqcSupport  # noqa: PLC0414
from qureddy.core.vocabulary import ProbeRole as ProbeRole  # noqa: PLC0414
from qureddy.core.vocabulary import Readiness as Readiness  # noqa: PLC0414
from qureddy.core.vocabulary import Severity as Severity  # noqa: PLC0414

FROZEN = ConfigDict(frozen=True, extra="forbid")

MIN_PORT = 1
MAX_PORT = 65535

# Canonical hostname grammar lives here because targets.py imports ScanTarget
# from this module; the reverse import would be circular. targets.py imports
# HOSTNAME_PATTERN from here, so there is exactly one copy (#315).
# Callers use `.fullmatch` (not `.match`): the trailing `$` also matches just
# before a final "\n", so `.match` would accept "example.com\n" and let a
# control char / newline reach OpenSSL argv; `.fullmatch` rejects it (#369).
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$",
)

# Constrain schemes so deserialized input cannot reach downstream tooling (#369).
SUPPORTED_SCHEMES = frozenset({"tls", "ssh", "ike"})


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class PostureAxes(BaseModel):
    """Independent posture dimensions derived from observed evidence."""

    model_config = FROZEN

    pqc_support: PqcSupport
    key_exchange: AxisStatus
    downgrade_resistance: AxisStatus
    authentication: AxisStatus
    protocol_hygiene: AxisStatus


class ScanInterpretation(BaseModel):
    """Explain the readiness rollup without changing the legacy verdict."""

    model_config = FROZEN

    effective: Readiness
    headline: str
    recommended_action: str
    display: InterpretationDisplay
    hndl_exposure: HndlExposure
    hygiene_status: HygieneStatus
    axes: PostureAxes
    reason_codes: tuple[str, ...] = Field(default_factory=tuple)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple)
    policy_id: str
    policy_version: str


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


class ExternalToolDependency(BaseModel):
    """Executable-backed scanner dependency captured as result provenance."""

    model_config = FROZEN

    name: str
    path: str | None = None
    version: str | None = None
    failure_category: FailureCategory | None = None


RuntimeDependency = OpenSSLDependency | ExternalToolDependency


class ProbeCommand(BaseModel):
    """Subprocess command issued for a single probe."""

    model_config = FROZEN

    executable: str
    args: tuple[str, ...]
    timeout_seconds: int
    redacted: bool = False


class ProbeResult(BaseModel):
    """Outcome of a single local probe invocation."""

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
    """Observation supporting a finding, including optional typed protocol details."""

    model_config = FROZEN

    id: str
    asset_id: str
    evidence_type: str
    observation_type: ObservationType
    source: str
    protocol: str = "tls"
    protocol_version: str | None = None
    cipher_suite: str | None = None
    algorithm: str | None = None
    primitive: str | None = None
    parameter_set_identifier: str | None = None
    nist_quantum_security_level: int | None = Field(default=None, ge=0, le=5)
    negotiated_group: str | None = None
    handshake_signature: str | None = None
    handshake_hash: str | None = None
    key_bits: int | None = Field(default=None, ge=1)
    server_software: str | None = None
    server_version: str | None = None
    probe_role: ProbeRole | None = None
    expected_group: str | None = None
    ike_group_id: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        exclude_if=lambda value: value is None,
    )
    probe_result: ProbeResult | None = None
    failure_category: FailureCategory | None = None
    confidence: Confidence = Confidence.HIGH
    notes: tuple[str, ...] = Field(default_factory=tuple)
    certificate_record: CertificateObservation | None = Field(
        default=None, exclude=True, repr=False
    )
    # Raw leaf PEM is retained only in-memory so --output-dir can write the
    # exact certificate fetched by the probe. It is excluded from every result
    # serialization and never enters logs, JSONL, or CBOM.
    certificate_pem: str | None = Field(default=None, exclude=True, repr=False)

    @computed_field(exclude_if=lambda value: value is None)  # type: ignore[prop-decorator]
    @property
    def certificate(self) -> CertificateDetails | None:
        """Return the stable public projection of an internal certificate observation."""
        observed = self.certificate_record
        return observed.public_details() if observed is not None else None


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


class ScanProvenance(BaseModel):
    """Advisory build identity; absent context remains explicitly null."""

    model_config = FROZEN

    distribution: str
    source_revision: str | None = None
    source_dirty: bool | None = None
    container_digest: str | None = None


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
    provenance: ScanProvenance | None = Field(default=None, exclude_if=lambda value: value is None)


class ScanSummary(BaseModel):
    """Top-line summary of a scan result."""

    model_config = FROZEN

    target: str
    finding_count: int
    highest_severity: Severity | None = None
    readiness: Readiness
    failure_category: FailureCategory | None = None
    interpretation: ScanInterpretation | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


class ScanResult(BaseModel):
    """Top-level scan output. Field order is the JSON schema contract."""

    model_config = FROZEN

    schema_version: str = "qureddy.scan.v1"
    scan: ScanMetadata
    target: ScanTarget
    dependencies: tuple[RuntimeDependency, ...]
    assets: tuple[Asset, ...]
    evidence: tuple[Evidence, ...]
    findings: tuple[Finding, ...]
    summary: ScanSummary
