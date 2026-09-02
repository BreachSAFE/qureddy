# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Typed seams shared by protocol-specific scanners.

The contract deliberately stops at ``ScanResult``. Serialization and OSCAL
projection remain downstream concerns. Outputs consume canonical core models
and neutral semantic facts; they must not import protocol-private scanner
modules. A future scanner may reuse this result boundary, but a general scanner
registry selection now lives in `registry.py`; execution, timeout, and retry remain
separate concerns.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from qureddy.core.models import Evidence, Finding, ScanProvenance, ScanResult, ScanTarget

SubjectT_contra = TypeVar("SubjectT_contra", contravariant=True)


class SourceKind(StrEnum):
    """First-class source types accepted by the future registry."""

    ENDPOINT = "endpoint"
    SSH_PUBLIC_KEY = "ssh_public_key"
    SSH_CONFIG = "ssh_config"
    CERTIFICATE = "certificate"
    STATIC_INVENTORY = "static_inventory"


class ToolPolicy(StrEnum):
    """Explicit acquisition policy; AUTO selects by registered capability."""

    AUTO = "auto"
    NATIVE = "native"
    OPENSSL = "openssl"
    SSH_AUDIT = "ssh-audit"


class Capability(StrEnum):
    """Capabilities used by registry selection, not output rendering."""

    TLS_ENDPOINT = "tls.endpoint"
    SSH_ENDPOINT = "ssh.endpoint"
    SSH_PUBLIC_KEY = "ssh.public_key"
    SSH_CONFIG = "ssh.config"
    X509_CERTIFICATE = "x509.certificate"


class CollectionFailureKind(StrEnum):
    """Typed, non-fatal collector outcomes."""

    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    MALFORMED = "malformed"
    PERMISSION_DENIED = "permission_denied"
    UNSUPPORTED = "unsupported"
    EXECUTION = "execution"


class ScanSource(BaseModel):
    """Validated source descriptor passed to a collector."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: SourceKind
    locator: str = Field(min_length=1, max_length=4096)
    protocol: str | None = Field(default=None, max_length=32)
    metadata: Mapping[str, str] = Field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CollectionFailure:
    """Failure metadata that cannot be mistaken for a successful scan."""

    kind: CollectionFailureKind
    message: str
    retryable: bool = False


@dataclass(frozen=True, slots=True)
class CollectionResult:
    """Normalized collector output consumed by the future orchestrator."""

    collector: str
    collector_version: str
    evidence: tuple[Evidence, ...] = ()
    findings: tuple[Finding, ...] = ()
    provenance: ScanProvenance | None = None
    failure: CollectionFailure | None = None
    scan_result: ScanResult | None = None


class ToolAdapter(Protocol):
    """External-tool boundary; adapters never decide posture."""

    tool_id: str
    version: str
    capabilities: frozenset[Capability]

    def available(self) -> bool:
        """Return whether the configured executable/provider is usable."""

    def run(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Run the tool and normalize output or a typed failure."""


class Collector(Protocol):
    """Source/protocol boundary; may wrap one or more ToolAdapters."""

    collector_name: str
    collector_version: str
    capabilities: frozenset[Capability]

    def collect(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Collect canonical evidence for one source."""


@runtime_checkable
class Scanner(Protocol[SubjectT_contra]):
    """A protocol-specific collector with one canonical result boundary."""

    scanner_name: str

    def scan(self, subject: SubjectT_contra, *, timeout_seconds: int) -> ScanResult:
        """Collect protocol evidence and return the canonical scan result."""


@runtime_checkable
class ScanCollector(Collector, Protocol):
    """Collector that can return the canonical endpoint result for CLI execution."""

    scanner_name: str

    def scan(self, subject: ScanTarget, *, timeout_seconds: int) -> ScanResult:
        """Run the collector's native scan path."""
