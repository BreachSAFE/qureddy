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

    Issue #225: this redundant fetch (see docstring below) previously
    ignored the user's --timeout entirely, hardcoding cert_probe's
    30-second default regardless of what was requested. Now threads the
    same timeout_seconds the scan itself used. Eliminating the redundant
    fetch entirely (reusing the scan's own already-fetched certificate)
    is a separate, larger design change — tracked in #252, not done here.

    Reviewer-flagged bug: this call path did not exist, so cbom.py's
    certificate-component code was dead — render_cbom was always called
    with certificate=None.

    Uses the already-resolved OpenSSL path from the scan's own dependency
    check (`result.dependencies[0].path`) rather than re-resolving —
    avoids a second capability probe and stays consistent with whatever
    binary the scan itself used. Swallows fetch/parse failures: a missing
    certificate must not turn a successful TLS scan into a CBOM-export
    failure, since the CBOM is still valid (just certificate-less) without
    one.

    Raises AssertionError (not a bare `assert`, which `python -O` strips)
    if more than one dependency is present: every `TLSScanner` call site
    (`scanner.py` lines 125, 229) constructs `dependencies=(dependency,)`
    as a single-element tuple — this is a real MVP 0.1 invariant (one
    scanner, one OpenSSL dependency), not a coincidence. Enforcing it
    here means a future second-scanner change that breaks the invariant
    fails loudly at this call site instead of this function silently
    picking `[0]` and reporting the wrong binary's certificate.
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
