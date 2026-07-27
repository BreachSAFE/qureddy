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

from qureddy.core.errors import LocalOpenSSLMissing
from qureddy.core.logging import get_logger
from qureddy.core.models import (
    Asset,
    Evidence,
    FailureCategory,
    Finding,
    ObservationType,
    OpenSSLDependency,
    ProbeResult,
    ProbeRole,
    ScanMetadata,
    ScanResult,
    ScanTarget,
)
from qureddy.core.policy import classify_evidence
from qureddy.core.retry import run_with_retries
from qureddy.core.status import STATUS_COMPLETED
from qureddy.scanners.tls._cert_findings import (
    evidence_from_certificate,
    finding_from_certificate,
)
from qureddy.scanners.tls._evidence import build_asset, evidence_from_probe
from qureddy.scanners.tls._legacy_findings import (
    evidence_from_legacy_result,
    finding_from_legacy_result,
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
        if _target_appears_unreachable(evidence):
            # Issue #192/#183 follow-up: the legacy-protocol sweep (3
            # protocols) and cert fetch each open their own connection
            # with their own timeout_seconds budget. Against a target
            # that silently drops packets (not an immediate TCP
            # refuse), that's 4 more full timeout windows stacked onto
            # the 2 the hybrid/classical probes already spent — verified
            # live: 18s at --timeout 3 (6x), ~180s at the default 30s.
            # If the main probes already both failed to even complete a
            # handshake, more attempts against the same host with
            # different flags are extremely unlikely to succeed and
            # only multiply the wait.
            log.info("scan.legacy_and_cert_probes_skipped", reason="target_appears_unreachable")
        else:
            legacy_evidence, legacy_findings = self._collect_legacy_evidence(
                target=target,
                asset=asset,
                openssl_path=openssl_path,
                timeout_seconds=timeout_seconds,
            )
            evidence.extend(legacy_evidence)
            findings.extend(legacy_findings)
            total_attempts += len(legacy_evidence)
            cert_evidence, cert_finding = self._collect_cert_evidence(
                target=target,
                asset=asset,
                openssl_path=openssl_path,
                timeout_seconds=timeout_seconds,
            )
            evidence.append(cert_evidence)
            if cert_finding is not None:
                findings.append(cert_finding)
            total_attempts += 1
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
        log = get_logger(__name__)
        log.info("probe.phase.start", phase="tls13_hybrid")
        hybrid_results = self._probe_with_retries(
            run_hybrid_probe,
            target=target,
            openssl_path=openssl_path,
            timeout_seconds=timeout_seconds,
        )
        log.info("probe.phase.complete", phase="tls13_hybrid")
        log.info("probe.phase.start", phase="tls13_classical")
        classical_results = self._probe_with_retries(
            run_classical_probe,
            target=target,
            openssl_path=openssl_path,
            timeout_seconds=timeout_seconds,
        )
        log.info("probe.phase.complete", phase="tls13_classical")
        evidence = [
            evidence_from_probe(
                asset=asset,
                probe=r,
                expected_group=HYBRID_GROUP,
                probe_role=ProbeRole.HYBRID_READINESS,
            )
            for r in hybrid_results
        ]
        evidence.extend(
            evidence_from_probe(
                asset=asset,
                probe=r,
                expected_group=CLASSICAL_GROUP,
                probe_role=ProbeRole.CLASSICAL_CONTROL,
            )
            for r in classical_results
        )
        return evidence, len(hybrid_results) + len(classical_results)

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
    summary = build_summary(target, list(findings), [evidence]).model_copy(
        update={"failure_category": failure_category}
    )
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
        summary=summary,
    )


def build_scan_failure_result(
    target: ScanTarget,
    failure_category: FailureCategory,
    *,
    note: str,
) -> ScanResult:
    """Build a structured TLS result for a typed target-scan exception."""
    started = datetime.now(UTC)
    asset = build_asset(target)
    evidence = Evidence(
        id=f"ev-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id,
        evidence_type="tls.scan",
        observation_type=ObservationType.NOT_TESTABLE,
        source="qureddy.scanners.tls.scanner",
        failure_category=failure_category,
        notes=(note,),
    )
    findings = classify_evidence(asset, [evidence])
    summary = build_summary(target, list(findings), [evidence]).model_copy(
        update={"failure_category": failure_category}
    )
    return ScanResult(
        scan=ScanMetadata(
            scan_id=f"scan-{uuid.uuid4().hex[:12]}",
            started_at=started,
            completed_at=datetime.now(UTC),
            status=failure_category.value,
            total_attempts=0,
        ),
        target=target,
        dependencies=(),
        assets=(asset,),
        evidence=(evidence,),
        findings=tuple(findings),
        summary=summary,
    )


_UNREACHABLE_FAILURE_CATEGORIES = frozenset({FailureCategory.TARGET_CONNECT_FAILED})


def _target_appears_unreachable(evidence: list[Evidence]) -> bool:
    """True when every hybrid/classical probe attempt never even connected.

    Issue #216: TLS_HANDSHAKE_FAILED used to be in this set too, on the
    theory that it meant the target couldn't be talked to. Wrong —
    confirmed live against badssl.com: the *forced-group* TLS 1.3
    handshake fails with TLS_HANDSHAKE_FAILED both when a target is
    genuinely dead AND when it's alive, responding, and simply doesn't
    support that specific forced group — exactly the servers #192's
    legacy-protocol sweep exists to catch (badssl.com genuinely
    negotiates TLS 1.0/1.2 with different flags, confirmed independently
    with raw openssl). TARGET_CONNECT_FAILED is the only category that's
    unambiguous: the TCP connection itself never completed, so no
    OpenSSL flag combination would help. Requires ALL evidence records
    to match, not just one, so a single flaky attempt among successful
    retries doesn't trigger a skip.
    """
    if not evidence:
        return False
    return all(ev.failure_category in _UNREACHABLE_FAILURE_CATEGORIES for ev in evidence)


__all__ = [
    "RetryConfig",
    "TLSScanner",
    "build_capability_failure_result",
    "build_scan_failure_result",
]
