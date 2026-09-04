# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Optional legacy and certificate evidence phases for the TLS scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from qureddy.core.models import Asset, Evidence, Finding, ScanTarget
    from qureddy.scanners.tls.scanner import TLSScanner

from qureddy.scanners.tls._scan_failures import target_appears_unreachable


def collect_optional_axes(
    scanner: TLSScanner,
    target: ScanTarget,
    asset: Asset,
    openssl_path: str,
    timeout_seconds: int,
    evidence: list[Evidence],
    findings: list[Finding],
) -> int:
    """Collect legacy and certificate evidence unless the target is unreachable."""
    if target_appears_unreachable(evidence):
        return 0
    legacy_evidence, legacy_findings = scanner._collect_legacy_evidence(  # noqa: SLF001
        target=target,
        asset=asset,
        openssl_path=openssl_path,
        timeout_seconds=timeout_seconds,
        starttls=scanner.starttls,
    )
    evidence.extend(legacy_evidence)
    findings.extend(legacy_findings)
    cert_evidence, cert_finding = scanner._collect_cert_evidence(  # noqa: SLF001
        target=target,
        asset=asset,
        openssl_path=openssl_path,
        timeout_seconds=timeout_seconds,
        starttls=scanner.starttls,
    )
    evidence.append(cert_evidence)
    if cert_finding is not None:
        findings.append(cert_finding)
    return len(legacy_evidence) + 1
