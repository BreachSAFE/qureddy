# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Evidence builder tests for parser/probe integration."""

from __future__ import annotations

from qureddy.core.models import FailureCategory, ProbeRole, ScanTarget
from qureddy.scanners.tls._evidence import build_asset, evidence_from_probe
from qureddy.scanners.tls.openssl_probe import HYBRID_GROUP, run_hybrid_probe
from tests._fake_openssl import fake_openssl


def _target() -> ScanTarget:
    return ScanTarget(
        original_input="example.com",
        host="example.com",
        port=443,
        sni="example.com",
        locator="tls://example.com:443",
    )


def test_evidence_parser_uses_full_probe_output_not_excerpt() -> None:
    """A group line beyond EXCERPT_LIMIT must not become PARSE_NO_GROUP."""
    probe = run_hybrid_probe(
        fake_openssl("openssl_long_brief_output"),
        host="example.com",
        port=443,
        sni="example.com",
    )
    evidence = evidence_from_probe(
        asset=build_asset(_target()),
        probe=probe,
        expected_group=HYBRID_GROUP,
        probe_role=ProbeRole.HYBRID_READINESS,
    )

    assert probe.stdout_excerpt
    assert "Negotiated TLS1.3 group" not in probe.stdout_excerpt
    assert evidence.negotiated_group == HYBRID_GROUP
    assert evidence.failure_category is None


def test_evidence_parser_does_not_match_across_stream_boundary() -> None:
    """A line synthesized by stdout+stderr concatenation must not parse."""
    probe = run_hybrid_probe(
        fake_openssl("openssl_stream_boundary_phantom"),
        host="example.com",
        port=443,
        sni="example.com",
    )
    evidence = evidence_from_probe(
        asset=build_asset(_target()),
        probe=probe,
        expected_group=HYBRID_GROUP,
        probe_role=ProbeRole.HYBRID_READINESS,
    )

    assert evidence.negotiated_group is None
    assert evidence.failure_category is FailureCategory.PARSE_NO_GROUP
