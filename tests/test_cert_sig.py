# SPDX-FileCopyrightText: 2026 Paul Volosen <paulvolosen@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for leaf-certificate signature-algorithm detection (issue #7)."""

from __future__ import annotations

from qureddy.scanners.tls.cert_sig import parse_certificate_signature

# Minimal slices of `openssl x509 -text` output — only the line the parser keys on.
ML_DSA_87_TEXT = """\
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: ML-DSA-87
        Issuer: CN=QuCert Demo Root
"""

ML_DSA_65_TEXT = "        Signature Algorithm: ML-DSA-65\n"

CLASSICAL_TEXT = "        Signature Algorithm: ecdsa-with-SHA256\n"

RSA_TEXT = "        Signature Algorithm: sha256WithRSAEncryption\n"

NO_SIG_TEXT = "Certificate:\n    Data:\n        Version: 3 (0x2)\n"


def test_detects_ml_dsa_87_level_5():
    r = parse_certificate_signature(ML_DSA_87_TEXT)
    assert r.is_post_quantum is True
    assert r.canonical_name == "ML-DSA-87"
    assert r.oid == "2.16.840.1.101.3.4.3.19"  # RFC 9881 §2
    assert r.nist_level == 5


def test_detects_ml_dsa_65_level_3():
    r = parse_certificate_signature(ML_DSA_65_TEXT)
    assert r.is_post_quantum is True
    assert r.canonical_name == "ML-DSA-65"
    assert r.oid == "2.16.840.1.101.3.4.3.18"
    assert r.nist_level == 3


def test_classical_ecdsa_is_not_post_quantum():
    r = parse_certificate_signature(CLASSICAL_TEXT)
    assert r.raw_algorithm == "ecdsa-with-SHA256"
    assert r.is_post_quantum is False
    assert r.canonical_name is None
    assert r.nist_level is None


def test_classical_rsa_is_not_post_quantum():
    r = parse_certificate_signature(RSA_TEXT)
    assert r.raw_algorithm == "sha256WithRSAEncryption"
    assert r.is_post_quantum is False


def test_missing_signature_line_is_undetermined():
    r = parse_certificate_signature(NO_SIG_TEXT)
    assert r.raw_algorithm is None
    assert r.is_post_quantum is False  # undetermined != quantum-safe (fail-closed)
