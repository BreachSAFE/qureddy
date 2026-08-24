# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for source-neutral collectors and tool adapters."""

from __future__ import annotations

from qureddy.core.contracts import (
    Capability,
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    ScanSource,
    SourceKind,
    ToolPolicy,
)


def test_source_and_tool_contract_are_protocol_neutral() -> None:
    source = ScanSource(kind=SourceKind.CERTIFICATE, locator="leaf.pem")
    assert source.kind is SourceKind.CERTIFICATE
    assert ToolPolicy.SSH_AUDIT.value == "ssh-audit"
    assert Capability.X509_CERTIFICATE.value == "x509.certificate"


def test_partial_failure_is_typed_and_not_success() -> None:
    result = CollectionResult(
        collector="ssh-audit",
        collector_version="3.0",
        failure=CollectionFailure(
            kind=CollectionFailureKind.UNAVAILABLE,
            message="binary not installed",
        ),
    )
    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.UNAVAILABLE
    assert result.evidence == ()
