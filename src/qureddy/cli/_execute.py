# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Scan execution and failure-to-exit-code mapping for `scan tls`."""

from __future__ import annotations

from typing import TYPE_CHECKING

import typer

from qureddy.cli._errors import (
    EXIT_LOCAL_DEPENDENCY,
    EXIT_OK,
    EXIT_TARGET_FAILED,
    _echo_operator_diagnostic,
)
from qureddy.core.errors import (
    LocalOpenSSLBroken,
    LocalOpenSSLIsLibreSSL,
    LocalOpenSSLLacksGroup,
    LocalOpenSSLMissing,
    LocalOpenSSLTooOld,
    LocalOpenSSLVersionUnreadable,
    QureddyError,
)
from qureddy.core.logging import get_logger
from qureddy.core.models import FailureCategory, OpenSSLDependency
from qureddy.scanners.tls.scanner import (
    build_capability_failure_result,
    build_scan_failure_result,
)

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult, ScanTarget
    from qureddy.scanners.tls.scanner import TLSScanner


def _execute_scan(
    scanner: TLSScanner,
    scan_target: ScanTarget,
    timeout: int,
    *,
    machine_format: bool,
) -> tuple[ScanResult, int]:
    """Run the scan; map local-capability + scan failures to exit codes.

    Returns `(result, exit_code)`. Exit codes: 0 ok, 2 target failed,
    3 local dependency, 4 usage (handled upstream).
    """
    log = get_logger("qureddy.cli")
    try:
        result = scanner.scan(scan_target, timeout_seconds=timeout)
        exit_code = EXIT_OK
    except (
        LocalOpenSSLBroken,
        LocalOpenSSLMissing,
        LocalOpenSSLTooOld,
        LocalOpenSSLVersionUnreadable,
        LocalOpenSSLIsLibreSSL,
        LocalOpenSSLLacksGroup,
    ) as exc:
        log.warning("scan.local_dependency_unusable", error=str(exc))
        # Keep the actionable fix on stderr unless fd-level `2>&1` would
        # corrupt the single machine-readable document (issues #30/#274).
        _echo_operator_diagnostic(str(exc), machine_format=machine_format)
        # Consume the original result; re-probing creates a TOCTOU window.
        dependency = exc.dependency or OpenSSLDependency(
            failure_category=FailureCategory.LOCAL_OPENSSL_MISSING,
        )
        result = build_capability_failure_result(scan_target, dependency)
        exit_code = EXIT_LOCAL_DEPENDENCY
    except QureddyError as exc:
        if not machine_format:
            log.exception("scan.failed", error=str(exc))
        _echo_operator_diagnostic(f"scan failed: {exc}", machine_format=machine_format)
        if not machine_format:
            raise typer.Exit(code=EXIT_TARGET_FAILED) from None
        result = build_scan_failure_result(
            scan_target,
            FailureCategory.TARGET_SCAN_FAILED,
            note=str(exc),
        )
        exit_code = EXIT_TARGET_FAILED

    if exit_code == EXIT_OK and result.summary.failure_category is not None:
        exit_code = EXIT_TARGET_FAILED
    return result, exit_code
