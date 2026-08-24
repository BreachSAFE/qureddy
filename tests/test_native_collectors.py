# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for registry-selected native collectors."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING

from qureddy.collectors import NativeSSHCollector, NativeTLSCollector
from qureddy.core.contracts import CollectionFailureKind, ScanSource, SourceKind

if TYPE_CHECKING:
    from qureddy.core.models import ScanTarget


class FakeScanner:
    """Minimal scanner implementing the canonical scanner protocol."""

    def __init__(self) -> None:
        self.calls: list[tuple[ScanTarget, int]] = []

    def scan(self, target: ScanTarget, *, timeout_seconds: int) -> SimpleNamespace:
        self.calls.append((target, timeout_seconds))
        return SimpleNamespace(
            evidence=("evidence",),
            findings=("finding",),
            scan=SimpleNamespace(provenance="provenance"),
        )


def test_native_tls_collector_adapts_existing_scanner() -> None:
    scanner = FakeScanner()
    collector = NativeTLSCollector(scanner)

    result = collector.collect(
        ScanSource(kind=SourceKind.ENDPOINT, protocol="tls", locator="example.com:443"),
        timeout_seconds=12,
    )

    assert result.failure is None
    assert result.scan_result is not None
    assert result.evidence == ("evidence",)
    assert scanner.calls[0][0].locator == "tls://example.com:443"
    assert scanner.calls[0][1] == 12


def test_native_ssh_collector_rejects_wrong_source_without_scanning() -> None:
    scanner = FakeScanner()
    result = NativeSSHCollector(scanner).collect(
        ScanSource(kind=SourceKind.CERTIFICATE, locator="leaf.pem"),
        timeout_seconds=8,
    )

    assert result.scan_result is None
    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.UNSUPPORTED
    assert scanner.calls == []
