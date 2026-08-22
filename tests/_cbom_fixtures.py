# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared scan-result builders for the CBOM output tests.

Extracted from tests/test_cbom.py (issue #298) so the CycloneDX-contract and
CBOM-semantics test modules can each stay under the 400-line ceiling while
sharing one canonical fixture. Not a test module itself (no ``test_*``).
"""

from __future__ import annotations

import contextlib
import io
import json
import locale
from datetime import UTC, datetime

from qureddy.core.models import (
    Asset,
    Evidence,
    Finding,
    ObservationType,
    OpenSSLDependency,
    ProbeCommand,
    ProbeResult,
    Readiness,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from qureddy.output.cbom import render_cbom


def _build_result() -> ScanResult:
    target = ScanTarget(
        original_input="example.com",
        host="example.com",
        port=443,
        sni="example.com",
        locator="tls://example.com:443",
    )
    asset = Asset(
        id="asset-1",
        asset_type="tls.endpoint",
        locator=target.locator,
        display_name="example.com:443",
    )
    finding = Finding(
        id="finding-1",
        asset_id=asset.id,
        evidence_ids=("ev-1",),
        rule_id="tls.hybrid.negotiated_pq",
        finding_type="tls.kex.hybrid",
        title="TLS 1.3 negotiated X25519MLKEM768",
        description="test",
        severity=Severity.INFO,
        readiness=Readiness.TRANSITIONAL_HYBRID,
        confidence="high",  # type: ignore[arg-type]
        protocol_version="TLSv1.3",
        negotiated_group="X25519MLKEM768",
    )
    evidence = Evidence(
        id="ev-1",
        asset_id=asset.id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519MLKEM768",
    )
    dependency = OpenSSLDependency(
        path="/opt/homebrew/opt/openssl@3.5/bin/openssl",
        version="3.5.7",
        supports_tls13_groups=True,
        supports_x25519mlkem768=True,
    )
    return ScanResult(
        scan=ScanMetadata(
            scan_id="scan-test",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            status="completed",
        ),
        target=target,
        dependencies=(dependency,),
        assets=(asset,),
        evidence=(evidence,),
        findings=(finding,),
        summary=ScanSummary(
            target=target.locator,
            finding_count=1,
            highest_severity=Severity.INFO,
            readiness=Readiness.TRANSITIONAL_HYBRID,
        ),
    )


def _render(result: ScanResult) -> dict:
    buf = io.StringIO()
    render_cbom(result, buf)
    return json.loads(buf.getvalue())


# The openssl subcommand a real probe records; only the interpreter/prefix path
# differs from one host to the next. It carries the target and forced group,
# which are semantic and must survive canonicalization verbatim (#207).
_PROBE_ARGS: tuple[str, ...] = (
    "s_client",
    "-connect",
    "example.com:443",
    "-groups",
    "X25519MLKEM768",
    "-servername",
    "example.com",
)


def _build_result_with_probe(executable: str) -> ScanResult:
    """A scan whose sole evidence carries a ProbeResult run from ``executable``.

    Two hosts observing identical crypto differ only in where their openssl binary
    lives (e.g. /opt/homebrew/opt/openssl@3.5/bin/openssl vs /usr/bin/openssl). This
    lets a test vary that host-specific path while holding the observed crypto and
    the probe's semantic arguments fixed (#207).
    """
    result = _build_result()
    probe_evidence = Evidence(
        id="ev-1",
        asset_id=result.assets[0].id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519MLKEM768",
        probe_result=ProbeResult(
            command=ProbeCommand(
                executable=executable,
                args=_PROBE_ARGS,
                timeout_seconds=30,
            ),
            return_code=0,
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            duration_ms=42,
            attempt_number=1,
        ),
    )
    return result.model_copy(update={"evidence": (probe_evidence,)})


def _render_reproducible_bytes(result: ScanResult) -> str:
    buf = io.StringIO()
    render_cbom(result, buf, reproducible=True)
    return buf.getvalue()


def _emit_reproducible_cbom_bytes() -> str:
    """Render a fixed, probe-bearing scan in reproducible mode.

    Called both in-process and from a child interpreter (a distinct
    ``PYTHONHASHSEED``) so a test can prove the serialized bytes do not depend on
    set/dict iteration order across processes (#196).
    """
    result = _build_result_with_probe("/opt/homebrew/opt/openssl@3.5/bin/openssl")
    return _render_reproducible_bytes(result)


@contextlib.contextmanager
def _forced_non_english_lc_time() -> object:
    """Force a non-English LC_TIME if one is installed; restore it on exit (#116).

    Never skips: where no non-English locale is available on the runner, the
    body still asserts correct parsing under the default locale.
    """
    original = locale.setlocale(locale.LC_TIME)
    try:
        for candidate in ("de_DE.UTF-8", "de_DE.utf8", "fr_FR.UTF-8", "German_Germany.1252"):
            with contextlib.suppress(locale.Error):
                locale.setlocale(locale.LC_TIME, candidate)
                break
        yield
    finally:
        locale.setlocale(locale.LC_TIME, original)
