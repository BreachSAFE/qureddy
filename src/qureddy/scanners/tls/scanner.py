# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""TLS scanner orchestration and evidence collection.

This module owns the scan lifecycle; specialized modules own probe execution,
parsing, finding construction, and summary policy. The important boundary is
that probe results become typed evidence before policy classifies them:

    CLI target
        │
        ├── capability resolution ──▶ OpenSSL dependencies
        │
        ├── TLS 1.3 group probes ──▶ typed probe evidence
        │       │
        │       └── target_connect_failed ──▶ stop duplicate network probes
        │
        ├── classical / legacy / certificate probes
        │
        └── evidence ──▶ findings ──▶ summary ──▶ ScanResult

Evidence-record construction lives in `_evidence.py`; legacy and certificate
finding construction lives in their dedicated modules; summary rollup helpers
live in `_summary.py`. This module coordinates those seams without re-parsing
or re-implementing their domain rules.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog

from qureddy.core.contracts import Scanner
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
from qureddy.scanners.common.metadata import build_scan_metadata
from qureddy.scanners.tls._cert_findings import (
    evidence_from_certificate,
    findings_from_certificate,
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
    scan_status,
    summary_failure_category,
)
from qureddy.scanners.tls.cert_probe import fetch_certificate_pem, parse_certificate
from qureddy.scanners.tls.legacy_probe import probe_all_legacy_protocols
from qureddy.scanners.tls.openssl_probe import (
    CLASSICAL_GROUP,
    DEFAULT_TIMEOUT_SECONDS,
    HYBRID_GROUPS,
    PURE_PQ_GROUPS,
    run_classical_probe,
    run_group_probe,
)
from qureddy.scanners.tls.openssl_probe.capability import resolve_openssl_with_capability
from qureddy.scanners.tls.openssl_probe.resolver import resolve_legacy_openssl

if TYPE_CHECKING:
    from qureddy.scanners.tls.connection import StartTLSMode

_build_summary = build_summary
_scan_readiness = scan_readiness
_summary_failure_category = summary_failure_category

_GROUP_PROBE_PLAN: tuple[tuple[str, ProbeRole, str], ...] = (
    (HYBRID_GROUPS[0], ProbeRole.HYBRID_READINESS, "tls13_hybrid"),
    *((group, ProbeRole.HYBRID_COVERAGE, "tls13_hybrid") for group in HYBRID_GROUPS[1:]),
    *((group, ProbeRole.PURE_PQ_COVERAGE, "tls13_pure_pq") for group in PURE_PQ_GROUPS),
)


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
    legacy_openssl_path: str | None,
    timeout_seconds: int,
    evidence: list[Evidence],
    findings: list[Finding],
) -> int:
    """Collect legacy and certificate evidence after primary TLS probing.

    These axes are supplementary: they enrich a reached endpoint with legacy
    cipher and certificate facts but do not replace the primary TLS result.
    An explicit transport failure from the primary phase suppresses them,
    because a second lane cannot recover endpoint evidence from an unreachable
    port. The return value counts only the certificate plus native legacy
    evidence added to the attempt total; compatibility evidence is reported in
    the evidence stream but is intentionally not double-counted here.

    Data-flow invariant:

        primary evidence ──unreachable──▶ return 0
                              │
                              └──reached──▶ legacy + certificate evidence

    This function mutates the caller-owned ``evidence`` and ``findings``
    lists so every lane contributes to one final summary; it does not create a
    second status or policy path.
    """
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
        starttls=scanner.starttls,
        native_fallback=legacy_openssl_path is None,
    )
    evidence.extend(legacy_evidence)
    findings.extend(legacy_findings)
    if legacy_openssl_path is not None:
        compatibility_evidence, compatibility_findings = scanner._collect_legacy_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path=legacy_openssl_path,
            timeout_seconds=timeout_seconds,
            starttls=scanner.starttls,
            runtime="openssl-legacy",
            legacy_compat=True,
        )
        evidence.extend(compatibility_evidence)
        findings.extend(compatibility_findings)
    cert_evidence, cert_findings = scanner._collect_cert_evidence(  # noqa: SLF001
        target=target,
        asset=asset,
        openssl_path=openssl_path,
        timeout_seconds=timeout_seconds,
        starttls=scanner.starttls,
    )
    evidence.append(cert_evidence)
    findings.extend(cert_findings)
    return len(legacy_evidence) + 1


def _completed_scan_result(
    target: ScanTarget,
    asset: Asset,
    dependency: OpenSSLDependency,
    legacy_dependency: OpenSSLDependency,
    evidence: list[Evidence],
    findings: list[Finding],
    scan_id: str,
    started: datetime,
    total_attempts: int,
) -> ScanResult:
    """Assemble the canonical result after all permitted probes finish.

    Findings are already classified when this helper runs. It derives the
    summary and public scan status from the complete typed evidence set, then
    preserves both OpenSSL dependency records so consumers can distinguish the
    primary capability runtime from the optional legacy runtime.

    The status is derived once, here, after classification. Renderers and
    serializers must consume this ``ScanResult`` rather than infer a status
    from individual findings or subprocess text.
    """
    completed = datetime.now(UTC)
    summary = build_summary(target, findings, evidence)
    get_logger(__name__).info(
        "scan.complete",
        duration_ms=int((completed - started).total_seconds() * 1000),
        finding_count=len(findings),
        readiness=summary.readiness.value,
    )
    status = scan_status(summary.failure_category, evidence)
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
        dependencies=(dependency, legacy_dependency),
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
    """Execute the ordered TLS scan pipeline for one target.

    Capability resolution happens before any network probe. The primary group
    and classical probes establish reachability and negotiation evidence;
    policy classification follows; optional legacy and certificate lanes then
    enrich the same evidence list. Probe failures are represented as data by
    the lower layers and are converted into the final status by
    `_completed_scan_result`.

    Ordering is intentional: capability errors happen before network work;
    primary evidence is classified before optional axes; final assembly owns
    the single public status. Do not move policy classification into a probe
    runner or make certificate collection a prerequisite for a scan result.
    """
    started = datetime.now(UTC)
    scan_id = _begin_scan(target)
    openssl_path, dependency = scanner._check_capability(timeout_seconds)  # noqa: SLF001
    legacy_openssl_path, legacy_dependency = scanner._check_legacy_capability(  # noqa: SLF001
        timeout_seconds
    )
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
        legacy_openssl_path,
        timeout_seconds,
        evidence,
        findings,
    )
    return _completed_scan_result(
        target,
        asset,
        dependency,
        legacy_dependency,
        evidence,
        findings,
        scan_id,
        started,
        total_attempts,
    )


def _begin_scan(target: ScanTarget) -> str:
    """Create the scan identifier and bind target context to structured logs.

    The identifier is generated once per invocation and reused by metadata and
    structured log records. Clearing context first prevents a prior scan in a
    reused process from contaminating this target's diagnostics.
    """
    scan_id = new_id("scan")
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(scan_id=scan_id, target=target.locator)
    get_logger(__name__).info("scan.start", host=target.host, port=target.port)
    return scan_id


class TLSScanner(Scanner[ScanTarget]):
    """Orchestrate one TLS scan from capability check through classification.

    The scanner is deliberately a coordinator rather than a probe
    implementation. It selects the probe lanes, converts their results to
    evidence, and delegates classification and rollup to shared helpers.
    """

    scanner_name = "tls"

    def __init__(
        self,
        *,
        openssl_path: str | None = None,
        retry: RetryConfig | None = None,
        starttls: StartTLSMode | None = None,
    ) -> None:
        """Initialize the scanner with optional OpenSSL path + retry config.

        `openssl_path` is the override the CLI passes via `--openssl`; when
        None the probe module resolves via `QUREDDY_OPENSSL` env var then
        PATH. `retry` defaults to no retries; CLI passes its parsed
        `RetryConfig` for `--retry-on / --retries / --retry-delay`.
        """
        self._openssl_path_override = openssl_path
        self._retry = retry or RetryConfig()
        self._starttls = starttls

    @property
    def starttls(self) -> StartTLSMode | None:
        """Return the configured application-protocol upgrade mode."""
        return self._starttls

    def scan(
        self,
        target: ScanTarget,
        *,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> ScanResult:
        """Run a full TLS scan against the target."""
        return _run_tls_scan(self, target, timeout_seconds)

    def _check_capability(self, timeout_seconds: int) -> tuple[str, OpenSSLDependency]:
        """Resolve and validate the primary OpenSSL runtime for this scan.

        Resolution and capability validation remain in the resolver module so
        CLI overrides, environment overrides, PATH discovery, and feature
        checks have one owner. This method only passes the configured override
        through and returns the typed dependency record.
        """
        return resolve_openssl_with_capability(
            self._openssl_path_override, timeout_seconds=timeout_seconds
        )

    def _check_legacy_capability(
        self, timeout_seconds: int
    ) -> tuple[str | None, OpenSSLDependency]:
        """Resolve the optional legacy runtime without making it mandatory.

        A missing legacy binary is a capability limitation recorded in the
        dependency metadata; it must not prevent the primary OpenSSL lane from
        producing a result.

        The returned path is ``None`` when compatibility probing is unavailable.
        Callers use that value to select the native fallback and preserve the
        limitation in dependency metadata rather than silently claiming
        complete legacy coverage.
        """
        path, dependency = resolve_legacy_openssl(timeout_seconds=timeout_seconds)
        get_logger(__name__).info("legacy_openssl.resolved", path=path, version=dependency.version)
        return path, dependency

    def _collect_evidence(
        self,
        *,
        target: ScanTarget,
        asset: Asset,
        openssl_path: str,
        timeout_seconds: int,
    ) -> tuple[list[Evidence], int]:
        """Collect ordered TLS group and classical-control evidence.

        `_GROUP_PROBE_PLAN` starts with the readiness group, followed by
        coverage groups. A group-level peer rejection remains useful evidence
        and allows the sweep to continue. A completed group whose every result
        is `TARGET_CONNECT_FAILED` proves the transport is unreachable, so
        continuing would only multiply the same timeout and duplicate failure
        records; #998 stops at that boundary.

        The returned attempt count is the number of actual probe invocations,
        not the number of planned groups. That distinction is the regression
        contract for filtered ports: skipped work must not be reported as work
        that ran.
        """
        log = get_logger(__name__)
        evidence: list[Evidence] = []
        probe_count = 0
        for group, role, phase in _GROUP_PROBE_PLAN:
            log.info("probe.phase.start", phase=phase, group=group)
            results = self._probe_with_retries(
                run_group_probe,
                target=target,
                openssl_path=openssl_path,
                timeout_seconds=timeout_seconds,
                group=group,
                starttls=self.starttls,
            )
            log.info("probe.phase.complete", phase=phase, group=group)
            probe_count += len(results)
            evidence.extend(
                evidence_from_probe(asset=asset, probe=r, expected_group=group, probe_role=role)
                for r in results
            )
            # #998: a target we cannot reach cannot answer any later group either.
            # Every remaining probe would spend the full timeout to restate one
            # fact, so an unreachable port costs timeout x len(_GROUP_PROBE_PLAN).
            # Stop on the transport failure; a server that merely declines this
            # group reports a different category and does not stop the sweep.
            if results and all(
                r.failure_category is FailureCategory.TARGET_CONNECT_FAILED for r in results
            ):
                log.info("probe.sweep.abandoned", reason="target_connect_failed", group=group)
                return evidence, probe_count
        log.info("probe.phase.start", phase="tls13_classical")
        classical_results = self._probe_with_retries(
            run_classical_probe,
            target=target,
            openssl_path=openssl_path,
            timeout_seconds=timeout_seconds,
            starttls=self.starttls,
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
        starttls: StartTLSMode | None = None,
        runtime: str = "openssl",
        legacy_compat: bool = False,
        native_fallback: bool = False,
    ) -> tuple[list[Evidence], list[Finding]]:
        """Enumerate legacy protocols and ciphers without retrying the sweep.

        The legacy probe owns its protocol/cipher matrix and returns one typed
        result per attempted combination. This helper adapts those results to
        evidence and findings while preserving the runtime label (`openssl` or
        `openssl-legacy`) for downstream comparisons.
        """
        log = get_logger(__name__)
        log.info("probe.phase.start", phase="legacy_tls1_tls11_tls12")
        results = probe_all_legacy_protocols(
            openssl_path,
            target.host,
            target.port,
            target.sni,
            timeout_seconds=timeout_seconds,
            starttls=starttls,
            legacy_compat=legacy_compat,
            native_fallback=native_fallback,
        )
        log.info("probe.phase.complete", phase="legacy_tls1_tls11_tls12")
        evidence = [evidence_from_legacy_result(asset, r, runtime=runtime) for r in results]
        findings = [
            finding
            for ev, r in zip(evidence, results, strict=True)
            for finding in finding_from_legacy_result(asset, ev, r, runtime=runtime)
        ]
        for r in results:
            evidence.extend(cipher_evidence_from_legacy_result(asset, r, runtime=runtime))
        return evidence, findings

    @staticmethod
    def _collect_cert_evidence(
        *,
        target: ScanTarget,
        asset: Asset,
        openssl_path: str,
        timeout_seconds: int,
        starttls: StartTLSMode | None = None,
        now: datetime | None = None,
    ) -> tuple[Evidence, tuple[Finding, ...]]:
        """Collect certificate evidence without making it a scan prerequisite.

        Certificate retrieval and parsing are best-effort enrichment. Missing
        local OpenSSL capability, malformed certificate material, and an empty
        response produce certificate evidence without aborting the scan or
        hiding the primary TLS findings.
        """
        log = get_logger(__name__)
        log.info("probe.phase.start", phase="certificate")
        pem = ""
        try:
            pem = fetch_certificate_pem(
                openssl_path,
                target.host,
                target.port,
                target.sni,
                timeout_seconds=timeout_seconds,
                starttls=starttls,
            )
            certificate = (
                parse_certificate(openssl_path, pem, timeout_seconds=timeout_seconds)
                if pem
                else None
            )
        except (LocalOpenSSLMissing, ValueError):  # fmt: skip
            certificate = None
        evidence = evidence_from_certificate(asset, certificate).model_copy(
            update={"certificate_pem": pem or None}
        )
        findings = findings_from_certificate(asset, evidence, certificate, now=now)
        log.info("probe.phase.complete", phase="certificate", observed=certificate is not None)
        return evidence, findings

    def _probe_with_retries(
        self,
        probe_fn: Callable[..., ProbeResult],
        *,
        target: ScanTarget,
        openssl_path: str,
        timeout_seconds: int,
        group: str | None = None,
        starttls: StartTLSMode | None = None,
    ) -> list[ProbeResult]:
        """Run one probe lane through the configured retry policy.

        The callable receives the resolved executable, target coordinates,
        timeout, attempt number, optional group, and StartTLS mode. Retry
        decisions remain centralized in `run_with_retries`; this coordinator
        only supplies the lane-specific arguments and returns raw typed probe
        results for evidence conversion.

        A retry can produce several results for one lane. Callers must preserve
        that list: later summary logic needs the complete attempt history to
        distinguish a transient failure from a successful retry.
        """
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
                starttls=starttls,
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
