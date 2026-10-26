# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for native TLS signature-algorithm capability probes."""

from __future__ import annotations

import hashlib

from qureddy.core.models import (
    Asset,
    FailureCategory,
    ObservationType,
    ProbeCommand,
    ProbeResult,
)
from qureddy.scanners.tls._evidence import evidence_from_signature_probe
from qureddy.scanners.tls.openssl_probe import signature as signature_probe


def _probe(
    *,
    return_code: int = 0,
    parser_input: str = "Protocol version: TLSv1.2",
    failure_category: FailureCategory | None = None,
) -> ProbeResult:
    empty_hash = hashlib.sha256(b"").hexdigest()
    return ProbeResult(
        command=ProbeCommand(
            executable="openssl",
            args=("s_client",),
            timeout_seconds=30,
        ),
        return_code=return_code,
        stdout_sha256=empty_hash,
        stderr_sha256=empty_hash,
        parser_input=parser_input,
        duration_ms=10,
        failure_category=failure_category,
    )


def _asset() -> Asset:
    return Asset(
        id="asset-1",
        asset_type="tls.endpoint",
        locator="tls://example.test:443",
        display_name="example.test:443",
    )


def test_modern_signature_probe_uses_tls12_compatibility_cipher(monkeypatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(
        signature_probe,
        "_run_probe",
        lambda args, **_: captured.append(args) or _probe(),
    )

    signature_probe.run_signature_algorithm_probe(
        "openssl",
        "example.test",
        443,
        "example.test",
        signature_algorithm="rsa_pkcs1_sha1",
    )

    assert captured[0][-5:] == [
        "-sigalgs",
        "rsa_pkcs1_sha1",
        "-brief",
        "-servername",
        "example.test",
    ]
    assert "DEFAULT:@SECLEVEL=0" in captured[0]


def test_legacy_signature_probe_does_not_use_modern_cipher_expression(monkeypatch) -> None:
    captured: list[list[str]] = []
    monkeypatch.setattr(
        signature_probe,
        "_run_probe",
        lambda args, **_: captured.append(args) or _probe(),
    )

    signature_probe.run_signature_algorithm_probe(
        "/opt/openssl-legacy/bin/openssl",
        "example.test",
        443,
        "example.test",
        signature_algorithm="RSA+SHA1",
        runtime="openssl-legacy",
    )

    assert "ALL" in captured[0]
    assert "DEFAULT:@SECLEVEL=0" not in captured[0]


def test_signature_success_is_offered_evidence() -> None:
    evidence = evidence_from_signature_probe(
        asset=_asset(),
        probe=_probe(),
        signature_algorithm="rsa_pkcs1_sha256",
        runtime="openssl",
    )

    assert evidence.evidence_type == "tls.signature_algorithm"
    assert evidence.observation_type is ObservationType.OFFERED
    assert evidence.algorithm == "rsa_pkcs1_sha256"
    assert evidence.runtime == "openssl"


def test_signature_peer_decline_is_not_offered_evidence() -> None:
    evidence = evidence_from_signature_probe(
        asset=_asset(),
        probe=_probe(
            return_code=1,
            parser_input="error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure",
            failure_category=FailureCategory.TLS_HANDSHAKE_FAILED,
        ),
        signature_algorithm="rsa_pkcs1_sha256",
        runtime="openssl",
    )

    assert evidence.observation_type is ObservationType.NOT_OFFERED
    assert evidence.failure_category is None


def test_signature_local_failure_is_not_testable() -> None:
    evidence = evidence_from_signature_probe(
        asset=_asset(),
        probe=_probe(
            return_code=1,
            parser_input="error: no suitable signature algorithm",
            failure_category=FailureCategory.LOCAL_OPENSSL_BROKEN,
        ),
        signature_algorithm="mldsa65",
        runtime="openssl",
    )

    assert evidence.observation_type is ObservationType.NOT_TESTABLE
    assert evidence.failure_category is FailureCategory.LOCAL_OPENSSL_BROKEN
