# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for deterministic collector selection without network execution."""

from __future__ import annotations

import pytest

from qureddy.core.contracts import (
    Capability,
    CollectionResult,
    ScanSource,
    SourceKind,
    ToolPolicy,
)
from qureddy.core.registry import CollectorRegistry, CollectorSelectionError


class FakeCollector:
    def __init__(self, name: str, *capabilities: Capability) -> None:
        self.collector_name = name
        self.collector_version = "test"
        self.capabilities = frozenset(capabilities)

    def collect(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        return CollectionResult(self.collector_name, self.collector_version)


def test_registry_selects_by_source_and_policy() -> None:
    registry = CollectorRegistry()
    registry.register(FakeCollector("native-tls", Capability.TLS_ENDPOINT))
    registry.register(FakeCollector("openssl", Capability.TLS_ENDPOINT))
    registry.register(FakeCollector("x509", Capability.X509_CERTIFICATE))

    tls = ScanSource(kind=SourceKind.ENDPOINT, protocol="tls", locator="example.com:443")
    cert = ScanSource(kind=SourceKind.CERTIFICATE, locator="leaf.pem")
    assert registry.select(tls).collector_name == "native-tls"
    assert registry.select(tls, tool_policy=ToolPolicy.OPENSSL).collector_name == "openssl"
    assert registry.select(cert).collector_name == "x509"


def test_registry_rejects_ambiguous_or_unsupported_selection() -> None:
    registry = CollectorRegistry()
    registry.register(FakeCollector("native-tls", Capability.TLS_ENDPOINT))
    with pytest.raises(CollectorSelectionError):
        registry.select(ScanSource(kind=SourceKind.ENDPOINT, locator="x"))
    with pytest.raises(CollectorSelectionError):
        registry.select(
            ScanSource(kind=SourceKind.ENDPOINT, protocol="ssh", locator="x"),
            tool_policy=ToolPolicy.SSH_AUDIT,
        )
