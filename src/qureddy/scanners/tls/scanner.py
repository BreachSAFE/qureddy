# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""TLS scanner orchestrator.

Composes the capability check, probe runners, parser, policy, and
summary rollup. Evidence-record construction lives in `_evidence.py`;
summary rollup helpers live in `_summary.py`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog

from qureddy.core.errors import LocalOpenSSLMissing
from qureddy.core.ids import new_id
from qureddy.core.logging import get_logger
from qureddy.core.models import (
    Asset,
    Evidence,
    FailureCategory,
    Finding,
    OpenSSLDependency,
    ProbeResult,
    ProbeRole,
    ScanResult,
    ScanTarget,
)
from qureddy.core.policy import classify_evidence
from qureddy.core.retry import run_with_retries
from qureddy.core.status import STATUS_COMPLETED
from qureddy.scanners.common.metadata import build_scan_metadata
from qureddy.scanners.tls._cert_findings import (
    evidence_from_certificate,
    finding_from_certificate,
)
from qureddy.scanners.tls._evidence import build_asset, evidence_from_probe
from qureddy.scanners.tls._legacy_findings import (
    cipher_evidence_from_legacy_result,
    evidence_from_legacy_result,
    finding_from_legacy_result,
)
from qureddy.scanners.tls._scan_failures import (
    build_capability_failure_result,
    build_scan_failure_result,
    target_appears_unreachable,
)
from qureddy.scanners.tls._summary import (
    build_summary,
    scan_readiness,
    summary_failure_category,
)
from qureddy.scanners.tls.cert_probe import fetch_certificate_pem, parse_certificate
from qureddy.scanners.tls.legacy_probe import probe_all_legacy_protocols
from qureddy.scanners.tls.openssl_probe import (
    CLASSICAL_GROUP,
    DEFAULT_TIMEOUT_SECONDS,
    HYBRID_GROUPS,
    run_classical_probe,
    run_hybrid_probe,
)
from qureddy.scanners.tls.openssl_probe.capability import resolve_openssl_with_capability

# Re-exported for tests that pin the rollup behavior. Canonical impls
# live in `_summary.py`; the public test surface stays on this module
# for backward compat across the file split.
_build_summary = build_summary
_scan_readiness = scan_readiness
_summary_failure_category = summary_failure_category


@dataclass(frozen=True, slots=True)
class RetryConfig:
    """Retry knobs passed in by the CLI."""

    retries: int = 0
    retry_delay: float = 1.0
    retry_on: frozenset[FailureCategory] = frozenset()


def _collect_optional_axes(
    scanner: TLSScanner,
    target: ScanTarget,
    asset: Asset,
    openssl_path: str,
    timeout_seconds: int,
    evidence: list[Evidence],
    findings: list[Finding],
) -> int:
    """Collect legacy and certificate axes unless the target is unreachable."""
    if target_appears_unreachable(evidence):
        get_logger(__name__).info(
            "scan.legacy_and_cert_probes_skipped",
            reason="target_appears_unreachable",
        )
        return 0
    legacy_evidence, legacy_findings = scanner._collect_legacy_evidence(  # noqa: SLF001
        target=target,
        asset=asset,
        openssl_path=openssl_path,
        timeout_seconds=timeout_seconds,
    )
    evidence.extend(legacy_evidence)
    findings.extend(legacy_findings)
    cert_evidence, cert_finding = scanner._collect_cert_evidence(  # noqa: SLF001
        target=target,
        asset=asset,
        openssl_path=openssl_path,
        timeout_seconds=timeout_seconds,
    )
    evidence.append(cert_evidence)
    if cert_finding is not None:
        findings.append(cert_finding)
    return len(legacy_evidence) + 1


def _completed_scan_result(
    target: ScanTarget,
    asset: Asset,
    dependency: OpenSSLDependency,
    evidence: list[Evidence],
    findings: list[Finding],
    scan_id: str,
    started: datetime,
    total_attempts: int,
) -> ScanResult:
    """Roll up and build a completed TLS scan result."""
    completed = datetime.now(UTC)
    summary = build_summary(target, findings, evidence)
    get_logger(__name__).info(
        "scan.complete",
        duration_ms=int((completed - started).total_seconds() * 1000),
        finding_count=len(findings),
        readiness=summary.readiness.value,
    )
    status = summary.failure_category.value if summary.failure_category else STATUS_COMPLETED
    return ScanResult(
        scan=build_scan_metadata(
            scan_id=scan_id,
            started_at=started,
            scanner_name="tls",
            status=status,
            total_attempts=total_attempts,
            completed_at=completed,
        ),
        target=target,
        dependencies=(dependency,),
        assets=(asset,),
        evidence=tuple(evidence),
        findings=tuple(findings),
        summary=summary,
    )


def _run_tls_scan(
    scanner: TLSScanner,
    target: ScanTarget,
    timeout_seconds: int,
) -> ScanResult:
    """Run the TLS phases while keeping the public method a thin entrypoint."""
    started = datetime.now(UTC)
    scan_id = scanner._begin(target)  # noqa: SLF001
    openssl_path, dependency = scanner._check_capability(timeout_seconds)  # noqa: SLF001
    asset = build_asset(target)
    evidence, total_attempts = scanner._collect_evidence(  # noqa: SLF001
        target=target,
        asset=asset,
        openssl_path=openssl_path,
        timeout_seconds=timeout_seconds,
    )
    findings = classify_evidence(asset, evidence)
    total_attempts += _collect_optional_axes(
        scanner,
        target,
        asset,
        openssl_path,
        timeout_seconds,
        evidence,
        findings,
    )
    return _completed_scan_result(
        target,
        asset,
        dependency,
        evidence,
        findings,
        scan_id,
        started,
        total_attempts,
    )


class TLSScanner:
    """Orchestrate one TLS scan from capability check through classification."""

    def __init__(
        self,
        *,
        openssl_path: str | None = None,
        retry: RetryConfig | None = None,
    ) -> None:
        """Initialize the scanner with optional OpenSSL path + retry config.

        `openssl_path` is the override the CLI passes via `--openssl`; when
        None the probe module resolves via `QUREDDY_OPENSSL` env var then
        PATH. `retry` defaults to no retries; CLI passes its parsed
        `RetryConfig` for `--retry-on / --retries / --retry-delay`.
        """
        self._openssl_path_override = openssl_path
        self._retry = retry or RetryConfig()

    def scan(
        self,
        target: ScanTarget,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> ScanResult:
        """Run a full TLS scan against `target` and return a ScanResult."""
        return _run_tls_scan(self, target, timeout_seconds)

    @staticmethod
    def _begin(target: ScanTarget) -> str:
        # Bind scan_id and target into structlog contextvars so every log
        # call from any module reached during this scan carries the same
        # correlation tags. CLI tests verify these propagate.
        scan_id = new_id("scan")
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(scan_id=scan_id, target=target.locator)
        get_logger(__name__).info("scan.start", host=target.host, port=target.port)
        return scan_id

    def _check_capability(self, timeout_seconds: int) -> tuple[str, OpenSSLDependency]:
        return resolve_openssl_with_capability(
            self._openssl_path_override, timeout_seconds=timeout_seconds
        )

    def _collect_evidence(
        self,
        *,
        target: ScanTarget,
        asset: Asset,
        openssl_path: str,
        timeout_seconds: int,
    ) -> tuple[list[Evidence], int]:
        log = get_logger(__name__)
        evidence: list[Evidence] = []
        probe_count = 0
        # #337: force each standardized PQ hybrid group. The first (X25519MLKEM768) is the
        # primary readiness probe (drives the not-testable/rejected/failed rules); the rest are
        # supplementary coverage — a negotiated hybrid still fires the positive rule, but a
        # rejection does not spawn a spurious quantum_vulnerable finding.
        for index, group in enumerate(HYBRID_GROUPS):
            role = ProbeRole.HYBRID_READINESS if index == 0 else ProbeRole.HYBRID_COVERAGE
            log.info("probe.phase.start", phase="tls13_hybrid", group=group)
            results = self._probe_with_retries(
                run_hybrid_probe,
                target=target,
                openssl_path=openssl_path,
                timeout_seconds=timeout_seconds,
                group=group,
            )
            log.info("probe.phase.complete", phase="tls13_hybrid", group=group)
            probe_count += len(results)
            evidence.extend(
                evidence_from_probe(asset=asset, probe=r, expected_group=group, probe_role=role)
                for r in results
            )
        log.info("probe.phase.start", phase="tls13_classical")
        classical_results = self._probe_with_retries(
            run_classical_probe,
            target=target,
            openssl_path=openssl_path,
            timeout_seconds=timeout_seconds,
        )
        log.info("probe.phase.complete", phase="tls13_classical")
        probe_count += len(classical_results)
        evidence.extend(
            evidence_from_probe(
                asset=asset,
                probe=r,
                expected_group=CLASSICAL_GROUP,
                probe_role=ProbeRole.CLASSICAL_CONTROL,
            )
            for r in classical_results
        )
        return evidence, probe_count

    @staticmethod
    def _collect_legacy_evidence(
        *,
        target: ScanTarget,
        asset: Asset,
        openssl_path: str,
        timeout_seconds: int,
    ) -> tuple[list[Evidence], list[Finding]]:
        """Legacy TLS 1.0/1.1/1.2 protocol + cipher enumeration (issue #192).

        No retries: unlike the hybrid/classical probes (single handshake,
        worth retrying on a flaky connection), this is already a multi
        -handshake sweep per protocol — retrying the whole sweep on any
        transient failure would multiply an already-slower path.
        """
        log = get_logger(__name__)
        log.info("probe.phase.start", phase="legacy_tls1_tls11_tls12")
        results = probe_all_legacy_protocols(
            openssl_path,
            target.host,
            target.port,
            target.sni,
            timeout_seconds=timeout_seconds,
        )
        log.info("probe.phase.complete", phase="legacy_tls1_tls11_tls12")
        evidence = [evidence_from_legacy_result(asset, r) for r in results]
        findings = [
            f
            for ev, r in zip(evidence, results, strict=True)
            if (f := finding_from_legacy_result(asset, ev, r)) is not None
        ]
        # Per-cipher evidence is appended after the finding zip (which pairs 1:1 with the
        # protocol-level evidence above) so each accepted legacy cipher becomes a CBOM
        # component without disturbing that pairing (#303).
        for r in results:
            evidence.extend(cipher_evidence_from_legacy_result(asset, r))
        return evidence, findings

    @staticmethod
    def _collect_cert_evidence(
        *,
        target: ScanTarget,
        asset: Asset,
        openssl_path: str,
        timeout_seconds: int,
    ) -> tuple[Evidence, Finding | None]:
        """Certificate issuer-signature axis (issue #183): PQ vs classical signature.

        Issue #226: this is the certificate's issuer/chain-of-trust signature,
        not a claim about the live handshake's authentication signature —
        see cert_sig.py's docstring for why those are different operations.

        Independent of the key-exchange probes above — same pattern as
        cli.py's _fetch_cert_for_cbom, now also run for the live scan
        path, not just --format cbom. Swallows fetch/parse failures the
        same way: a missing certificate must not fail the whole scan,
        since the key-exchange axis is still a complete, valid result
        without it. LocalOpenSSLMissing is not swallowed — same openssl
        binary the rest of the scan already required, so if it's
        missing the capability check above would already have failed.
        """
        log = get_logger(__name__)
        log.info("probe.phase.start", phase="certificate")
        try:
            pem = fetch_certificate_pem(
                openssl_path, target.host, target.port, target.sni, timeout_seconds=timeout_seconds
            )
            certificate = (
                parse_certificate(openssl_path, pem, timeout_seconds=timeout_seconds)
                if pem
                else None
            )
        except (LocalOpenSSLMissing, ValueError):
            certificate = None
        evidence = evidence_from_certificate(asset, certificate)
        finding = finding_from_certificate(asset, evidence, certificate)
        log.info("probe.phase.complete", phase="certificate", observed=certificate is not None)
        return evidence, finding

    def _probe_with_retries(
        self,
        probe_fn: Callable[..., ProbeResult],
        *,
        target: ScanTarget,
        openssl_path: str,
        timeout_seconds: int,
        group: str | None = None,
    ) -> list[ProbeResult]:
        extra = {"group": group} if group is not None else {}
        return run_with_retries(
            lambda n: probe_fn(
                openssl_path,
                target.host,
                target.port,
                target.sni,
                timeout_seconds=timeout_seconds,
                attempt_number=n,
                **extra,
            ),
            retries=self._retry.retries,
            retry_delay=self._retry.retry_delay,
            retry_on=self._retry.retry_on,
        )


__all__ = [
    "RetryConfig",
    "TLSScanner",
    "build_capability_failure_result",
    "build_scan_failure_result",
]
