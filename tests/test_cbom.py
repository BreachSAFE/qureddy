# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for qureddy.output.cbom (rapid-prototype module).

Regression test for a real bug caught during manual verification (piping
output through Qurum): the scanned endpoint was built as a component
separate from `bom.metadata.component`, so Qurum's dependency traversal
(which starts from `metadata.component`'s own bom-ref) never found the
`dependsOn`/`provides` path to the OpenSSL library component, and every
crypto asset resolved as `crypto_library_name: UNKNOWN` despite a
structurally correct graph existing elsewhere in the BOM. Fixed by making
the endpoint component *be* metadata.component rather than a disconnected
second node. This test pins that shape so it can't regress silently.
"""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

from qureddy.core.models import (
    Asset,
    Evidence,
    Finding,
    ObservationType,
    OpenSSLDependency,
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
        rule_id="tls.hybrid.negotiated_x25519mlkem768",
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
        path="/opt/homebrew/opt/openssl@3/bin/openssl",
        version="3.6.3",
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


class TestLibraryLinkage:
    """The regression this file exists to pin."""

    def test_metadata_component_is_the_endpoint_not_a_separate_node(self) -> None:
        payload = _render(_build_result())
        metadata_ref = payload["metadata"]["component"]["bom-ref"]
        component_refs = {c["bom-ref"] for c in payload["components"]}
        assert metadata_ref in component_refs, (
            "metadata.component must be one of the real components (the endpoint), "
            "not a synthetic node absent from the components list"
        )

    def test_endpoint_depends_on_library_which_provides_crypto_assets(self) -> None:
        payload = _render(_build_result())
        metadata_ref = payload["metadata"]["component"]["bom-ref"]
        deps_by_ref = {d["ref"]: d for d in payload["dependencies"]}

        assert metadata_ref in deps_by_ref
        assert "crypto-library/openssl" in deps_by_ref[metadata_ref]["dependsOn"]

        library_dep = deps_by_ref["crypto-library/openssl"]
        assert "crypto/protocol/tls-tlsv1.3" in library_dep["provides"]
        assert "crypto/algorithm/x25519mlkem768" in library_dep["provides"]

    def test_real_cipher_suite_name_used_not_synthetic_placeholder(self) -> None:
        payload = _render(_build_result())
        protocol = next(c for c in payload["components"] if c["name"] == "TLSv1.3")
        cipher_suite_name = protocol["cryptoProperties"]["protocolProperties"]["cipherSuites"][0]["name"]
        assert cipher_suite_name == "TLS_AES_256_GCM_SHA384"
