# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Native collector adapters for the shipped TLS and SSH scanners."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.contracts import (
    Capability,
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    ScanSource,
    SourceKind,
)
from qureddy.core.errors import QureddyError
from qureddy.core.targets import parse_ssh_target, parse_target

if TYPE_CHECKING:
    from qureddy.core.contracts import Scanner
    from qureddy.core.models import ScanResult, ScanTarget


class _NativeEndpointCollector:
    """Shared adapter logic for a scanner-backed endpoint collector."""

    def __init__(
        self, scanner: Scanner[ScanTarget], *, protocol: str, capability: Capability
    ) -> None:
        self._scanner = scanner
        self._protocol = protocol
        self.scanner_name = protocol
        self.collector_name = f"native-{protocol}"
        self.collector_version = "1"
        self.capabilities = frozenset({capability})

    def scan(self, target: ScanTarget, *, timeout_seconds: int) -> ScanResult:
        """Run the existing scanner without changing its error contract."""
        return self._scanner.scan(target, timeout_seconds=timeout_seconds)

    def collect(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Collect one canonical result and normalize adapter failures."""
        if source.kind is not SourceKind.ENDPOINT or source.protocol != self._protocol:
            return CollectionResult(
                collector=self.collector_name,
                collector_version=self.collector_version,
                failure=CollectionFailure(
                    kind=CollectionFailureKind.UNSUPPORTED,
                    message=f"collector does not support {source.kind.value}/{source.protocol!r}",
                ),
            )
        try:
            target = (
                parse_ssh_target(source.locator)
                if self._protocol == "ssh"
                else parse_target(source.locator)
            )
            result = self.scan(target, timeout_seconds=timeout_seconds)
        except TimeoutError as exc:
            return CollectionResult(
                collector=self.collector_name,
                collector_version=self.collector_version,
                failure=CollectionFailure(
                    kind=CollectionFailureKind.TIMEOUT, message=str(exc), retryable=True
                ),
            )
        except (QureddyError, OSError, ValueError) as exc:
            return CollectionResult(
                collector=self.collector_name,
                collector_version=self.collector_version,
                failure=CollectionFailure(
                    kind=CollectionFailureKind.EXECUTION,
                    message=f"{type(exc).__name__}: {exc}",
                ),
            )
        return CollectionResult(
            collector=self.collector_name,
            collector_version=self.collector_version,
            evidence=result.evidence,
            findings=result.findings,
            provenance=result.scan.provenance,
            scan_result=result,
        )


class NativeTLSCollector(_NativeEndpointCollector):
    """Registry-visible adapter for the native TLS scanner."""

    def __init__(self, scanner: Scanner[ScanTarget]) -> None:
        """Wrap one configured TLS scanner."""
        super().__init__(scanner, protocol="tls", capability=Capability.TLS_ENDPOINT)


class NativeSSHCollector(_NativeEndpointCollector):
    """Registry-visible adapter for the native SSH scanner."""

    def __init__(self, scanner: Scanner[ScanTarget]) -> None:
        """Wrap one configured SSH scanner."""
        super().__init__(scanner, protocol="ssh", capability=Capability.SSH_ENDPOINT)
