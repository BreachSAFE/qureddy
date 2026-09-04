# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Parser safety tests for the tls-scan external evidence boundary."""

from __future__ import annotations

import json

import pytest

from qureddy.scanners.external.tls_scan import parse_tls_scan


def test_parse_preserves_legacy_matrix_and_evidence_fields() -> None:
    raw = json.dumps(
        {
            "host": "legacy.example",
            "ip": "192.0.2.10",
            "port": 443,
            "tlsVersion": "TLSv1.2",
            "cipher": "AES128-SHA TLSv1 Kx=RSA Au=RSA Enc=AES(128) Mac=SHA1",
            "tempPublicKeyAlg": "ECDH prime256v1",
            "tempPublicKeySize": 256,
            "secureRenego": False,
            "compression": "NONE",
            "expansion": "NONE",
            "sessionLifetimeHint": 100800,
            "sessionReuse": True,
            "ocspStapled": False,
            "verifyOcspResult": False,
            "alpn": "h2",
            "tlsVersions": ["SSLv3", "TLSv1", "TLSv1_2"],
            "cipherSuite": {
                "supported": ["AES128-SHA", "DES-CBC3-SHA"],
                "notSupported": ["RC4-SHA"],
            },
            "certificateChain": [{"signatureAlg": "sha1WithRSAEncryption"}],
        }
    )

    observation = parse_tls_scan(raw)[0]

    assert observation.protocol_versions == ("SSLv3", "TLSv1", "TLSv1_2")
    assert observation.supported_ciphers == ("AES128-SHA", "DES-CBC3-SHA")
    assert observation.unsupported_ciphers == ("RC4-SHA",)
    assert observation.certificate_chain[0]["signatureAlg"] == "sha1WithRSAEncryption"
    assert observation.session_reuse is True


def test_parse_accepts_json_records_with_whitespace_between_them() -> None:
    raw = '{"host":"one"}\n  {"host":"two"}\n'
    assert [item.host for item in parse_tls_scan(raw)] == ["one", "two"]


def test_parse_rejects_non_object_record() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        parse_tls_scan("[]")


def test_parse_rejects_oversized_output() -> None:
    with pytest.raises(ValueError, match="bounded evidence"):
        parse_tls_scan("x" * (10 * 1024 * 1024 + 1))
