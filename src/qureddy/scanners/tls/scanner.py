# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""TLS scanner orchestrator.

Composes the capability check, probe runners, parser, policy, and
summary rollup. Evidence-record construction lives in `_evidence.py`;
summary rollup helpers live in `_summary.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog

from qureddy.core.logging import get_logger
from qureddy.core.models import (
    Asset,
    Evidence,
    FailureCategory,
    ObservationType,
    OpenSSLDependency,
    ProbeResult,
    ScanMetadata,
    ScanResult,
    ScanTarget,
)
from qureddy.core.policy import classify_evidence
from qureddy.core.retry import run_with_retries
from qureddy.core.status import STATUS_COMPLETED
from qureddy.scanners.tls._evidence import build_asset, evidence_from_probe
from qureddy.scanners.tls._summary import (
    build_summary,
    scan_readiness,
    summary_failure_category,
)
from qureddy.scanners.tls.openssl_probe import (
    CLASSICAL_GROUP,
    DEFAULT_TIMEOUT_SECONDS,
    HYBRID_GROUP,
    probe_capability,
    raise_if_unusable,
    resolve_openssl_path,
    run_classical_probe,
    run_hybrid_probe,
)

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


class TLSScanner:
    """Orchestrate one TLS scan from capability check through classification."""

    def __init__(
        self,
        *,
        openssl_path: str | None = None,
        retry: RetryConfig | None = None,
    ) -> None:
        self._openssl_path_override = openssl_path
        self._retry = retry or RetryConfig()

    def scan(
        self,
        target: ScanTarget,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> ScanResult:
        """Run a full TLS scan against `target` and return a ScanResult."""
        started = datetime.now(UTC)
        scan_id = self._begin(target)
        log = get_logger(__name__)
        openssl_path, dependency = self._check_capability(timeout_seconds)
        asset = build_asset(target)
        evidence, total_attempts = self._collect_evidence(
            target=target,
            asset=asset,
            openssl_path=openssl_path,
            timeout_seconds=timeout_seconds,
        )
        findings = classify_evidence(asset, evidence)
        completed = datetime.now(UTC)
        summary = build_summary(target, findings, evidence)
        log.info(
            "scan.complete",
            duration_ms=int((completed - started).total_seconds() * 1000),
            finding_count=len(findings),
            readiness=summary.readiness.value,
        )
        return ScanResult(
            scan=ScanMetadata(
                scan_id=scan_id,
                started_at=started,
                completed_at=completed,
                status=(
                    summary.failure_category.value if summary.failure_category else STATUS_COMPLETED
                ),
                total_attempts=total_attempts,
            ),
            target=target,
            dependencies=(dependency,),
            assets=(asset,),
            evidence=tuple(evidence),
            findings=tuple(findings),
            summary=summary,
        )

    @staticmethod
    def _begin(target: ScanTarget) -> str:
        # Bind scan_id and target into structlog contextvars so every log
        # call from any module reached during this scan carries the same
        # correlation tags. CLI tests verify these propagate.
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(scan_id=scan_id, target=target.locator)
        get_logger(__name__).info("scan.start", host=target.host, port=target.port)
        return scan_id

    def _check_capability(self, timeout_seconds: int) -> tuple[str, OpenSSLDependency]:
        openssl_path = resolve_openssl_path(self._openssl_path_override)
        dependency = probe_capability(openssl_path, timeout_seconds=timeout_seconds)
        raise_if_unusable(dependency)
        return openssl_path, dependency

    def _collect_evidence(
        self,
        *,
        target: ScanTarget,
        asset: Asset,
        openssl_path: str,
        timeout_seconds: int,
    ) -> tuple[list[Evidence], int]:
        hybrid_results = self._probe_with_retries(
            run_hybrid_probe,
            target=target,
            openssl_path=openssl_path,
            timeout_seconds=timeout_seconds,
        )
        classical_results = self._probe_with_retries(
            run_classical_probe,
            target=target,
            openssl_path=openssl_path,
            timeout_seconds=timeout_seconds,
        )
        evidence = [
            evidence_from_probe(asset=asset, probe=r, expected_group=HYBRID_GROUP)
            for r in hybrid_results
        ]
        evidence.extend(
            evidence_from_probe(asset=asset, probe=r, expected_group=CLASSICAL_GROUP)
            for r in classical_results
        )
        return evidence, len(hybrid_results) + len(classical_results)

    def _probe_with_retries(
        self,
        probe_fn: Callable[..., ProbeResult],
        *,
        target: ScanTarget,
        openssl_path: str,
        timeout_seconds: int,
    ) -> list[ProbeResult]:
        return run_with_retries(
            lambda n: probe_fn(
                openssl_path,
                target.host,
                target.port,
                target.sni,
                timeout_seconds=timeout_seconds,
                attempt_number=n,
            ),
            retries=self._retry.retries,
            retry_delay=self._retry.retry_delay,
            retry_on=self._retry.retry_on,
        )


def build_capability_failure_result(
    target: ScanTarget,
    dependency: OpenSSLDependency,
) -> ScanResult:
    """Build a `ScanResult` for the local-capability-failure exit-3 path."""
    started = datetime.now(UTC)
    asset = build_asset(target)
    failure_category = dependency.failure_category or FailureCategory.LOCAL_OPENSSL_MISSING
    evidence = Evidence(
        id=f"ev-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id,
        evidence_type="tls.capability",
        observation_type=ObservationType.NOT_TESTABLE,
        source="qureddy.openssl_probe",
        failure_category=failure_category,
        notes=("local OpenSSL is unusable for X25519MLKEM768 hybrid probing",),
    )
    findings = classify_evidence(asset, [evidence])
    return ScanResult(
        scan=ScanMetadata(
            scan_id=f"scan-{uuid.uuid4().hex[:12]}",
            started_at=started,
            completed_at=datetime.now(UTC),
            status=failure_category.value,
            total_attempts=0,
        ),
        target=target,
        dependencies=(dependency,),
        assets=(asset,),
        evidence=(evidence,),
        findings=tuple(findings),
        summary=build_summary(target, list(findings), [evidence]),
    )


__all__ = [
    "RetryConfig",
    "TLSScanner",
    "build_capability_failure_result",
]
