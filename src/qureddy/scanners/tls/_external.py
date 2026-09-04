# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Optional external TLS evidence collection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.contracts import ScanSource, SourceKind
from qureddy.core.policy import classify_evidence

if TYPE_CHECKING:
    from qureddy.core.models import Asset, Evidence, ExternalToolDependency, Finding, ScanTarget
    from qureddy.scanners.external.tls_scan import TLSScanAdapter


def collect_tls_scan_evidence(
    adapter: TLSScanAdapter,
    target: ScanTarget,
    asset_id: str,
    timeout_seconds: int,
    starttls: str | None = None,
) -> list[Evidence]:
    """Run the optional adapter and return only canonical evidence records."""
    result = adapter.run(
        ScanSource(
            kind=SourceKind.ENDPOINT,
            protocol="tls",
            locator=target.locator,
            metadata={
                "asset_id": asset_id,
                **({"starttls": starttls} if starttls is not None else {}),
            },
        ),
        timeout_seconds=timeout_seconds,
    )
    return list(result.evidence)


def append_external_evidence(
    adapter: TLSScanAdapter,
    target: ScanTarget,
    asset: Asset,
    evidence: list[Evidence],
    findings: list[Finding],
    timeout_seconds: int,
    starttls: str | None,
) -> ExternalToolDependency | None:
    """Append optional evidence and return dependency metadata when available."""
    if not adapter.available():
        return None
    evidence.extend(collect_tls_scan_evidence(adapter, target, asset.id, timeout_seconds, starttls))
    findings[:] = classify_evidence(asset, evidence)
    return adapter.dependency()


def collect_and_classify_external(
    adapter: TLSScanAdapter,
    target: ScanTarget,
    asset: Asset,
    evidence: list[Evidence],
    findings: list[Finding],
    timeout_seconds: int,
    starttls: str | None,
) -> ExternalToolDependency | None:
    """Run the optional adapter only when installed and update shared findings."""
    return append_external_evidence(
        adapter, target, asset, evidence, findings, timeout_seconds, starttls
    )
