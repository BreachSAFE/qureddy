# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Output-format dispatch for the `scan tls` command."""

from __future__ import annotations

import sys

from qureddy.core.errors import LocalOpenSSLMissing
from qureddy.core.models import OutputFormat, ScanResult
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from qureddy.scanners.tls.cert_probe import (
    CertificateInfo,
    fetch_certificate_pem,
    parse_certificate,
)


def _render(
    result: ScanResult, output_format: OutputFormat, verbose: int, timeout_seconds: int
) -> None:
    """Dispatch to the JSON, CBOM, or Rich renderer."""
    if output_format is OutputFormat.JSON:
        render_json(result, sys.stdout)
    elif output_format is OutputFormat.CBOM:
        render_cbom(result, sys.stdout, certificate=_fetch_cert_for_cbom(result, timeout_seconds))
    else:
        render_rich(result, sys.stdout, verbosity=verbose)


def _fetch_cert_for_cbom(result: ScanResult, timeout_seconds: int) -> CertificateInfo | None:
    """Best-effort certificate fetch for CBOM output.

    Uses the scan's already-resolved, accepted OpenSSL dependency and the
    caller's timeout (issue #225). A missing or malformed certificate is
    omitted because the CBOM remains valid without it. Multiple dependencies
    violate the MVP 0.1 single-scanner invariant and fail explicitly.
    """
    if not result.dependencies:
        return None
    if len(result.dependencies) != 1:
        msg = (
            f"expected exactly one OpenSSL dependency, got {len(result.dependencies)} "
            "— _fetch_cert_for_cbom's use of dependencies[0] assumes the MVP 0.1 "
            "single-scanner invariant"
        )
        raise AssertionError(msg)
    dependency = result.dependencies[0]
    if dependency.failure_category is not None or not dependency.path:
        # Issue #274: a rejected dependency still has a `path`, so a
        # path-only guard let the CBOM cert fetch shell out to the very
        # binary the capability check refused (real case: LibreSSL —
        # which also serializes DNs differently, silently forking the
        # CBOM's certificate data shape). A binary that failed the
        # capability check must not be used for anything.
        return None
    openssl_path = dependency.path
    try:
        pem = fetch_certificate_pem(
            openssl_path,
            result.target.host,
            result.target.port,
            result.target.sni,
            timeout_seconds=timeout_seconds,
        )
        return (
            parse_certificate(openssl_path, pem, timeout_seconds=timeout_seconds) if pem else None
        )
    except (LocalOpenSSLMissing, ValueError):
        return None
