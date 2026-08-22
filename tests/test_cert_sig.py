# SPDX-FileCopyrightText: 2026 Paul Volosen <paulvolosen@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Tests for leaf-certificate signature-algorithm detection (issue #7)."""

from __future__ import annotations

import pytest

from qureddy.scanners.tls.cert_sig import parse_certificate_signature, pqc_signature_standard

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


# --- SLH-DSA (FIPS 205) regression, issue #201 --------------------------------
# Before the fix these certs were classified is_post_quantum=False (false
# negative): a real FIPS 205 hash-based signature reported as classical.

SLH_DSA_SHA2_128S_TEXT = """\
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: SLH-DSA-SHA2-128s
        Issuer: CN=BreachSAFE Demo Root
"""

SLH_DSA_SHAKE_256F_TEXT = "        Signature Algorithm: SLH-DSA-SHAKE-256f\n"


def test_detects_slh_dsa_sha2_128s_level_1():
    # #201: FIPS 205 category-1 root-CA signature must read as post-quantum.
    r = parse_certificate_signature(SLH_DSA_SHA2_128S_TEXT)
    assert r.is_post_quantum is True
    assert r.canonical_name == "SLH-DSA-SHA2-128s"
    assert r.oid == "2.16.840.1.101.3.4.3.20"  # FIPS 205 CSOR arc
    assert r.nist_level == 1


def test_detects_slh_dsa_shake_256f_level_5():
    r = parse_certificate_signature(SLH_DSA_SHAKE_256F_TEXT)
    assert r.is_post_quantum is True
    assert r.canonical_name == "SLH-DSA-SHAKE-256f"
    assert r.oid == "2.16.840.1.101.3.4.3.31"
    assert r.nist_level == 5


@pytest.mark.parametrize(
    ("name", "oid", "level"),
    [
        ("SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20", 1),
        ("SLH-DSA-SHA2-128f", "2.16.840.1.101.3.4.3.21", 1),
        ("SLH-DSA-SHA2-192s", "2.16.840.1.101.3.4.3.22", 3),
        ("SLH-DSA-SHA2-192f", "2.16.840.1.101.3.4.3.23", 3),
        ("SLH-DSA-SHA2-256s", "2.16.840.1.101.3.4.3.24", 5),
        ("SLH-DSA-SHA2-256f", "2.16.840.1.101.3.4.3.25", 5),
        ("SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.26", 1),
        ("SLH-DSA-SHAKE-128f", "2.16.840.1.101.3.4.3.27", 1),
        ("SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.28", 3),
        ("SLH-DSA-SHAKE-192f", "2.16.840.1.101.3.4.3.29", 3),
        ("SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.30", 5),
        ("SLH-DSA-SHAKE-256f", "2.16.840.1.101.3.4.3.31", 5),
    ],
)
def test_all_twelve_slh_dsa_parameter_sets_are_post_quantum(name, oid, level):
    r = parse_certificate_signature(f"        Signature Algorithm: {name}\n")
    assert r.is_post_quantum is True
    assert r.canonical_name == name
    assert r.oid == oid
    assert r.nist_level == level


def test_slh_dsa_lookup_is_case_insensitive():
    # OpenSSL prints the s/f suffix lower-case; a stray upper-case variant must
    # still classify as the same PQC algorithm rather than falling through.
    r = parse_certificate_signature("        Signature Algorithm: SLH-DSA-SHA2-128S\n")
    assert r.is_post_quantum is True
    assert r.nist_level == 1


def test_pqc_signature_standard_maps_family_to_fips_document():
    assert pqc_signature_standard("ML-DSA-87") == "FIPS 204"
    assert pqc_signature_standard("SLH-DSA-SHA2-128s") == "FIPS 205"


# --- #344 item 3: DN-injection resistance via line anchoring ------------------
# The readiness-driving signature axis must be safe by *design* (line-anchored
# regex), not by the accident that the genuine "Signature Algorithm:" line
# happens to be scanned first. A subject/issuer DN is attacker-controlled and is
# printed by `openssl x509 -text` on the Issuer:/Subject: line, which precedes
# the real signature block — so an unanchored `.search` would return an injected
# value first.

DN_INJECTED_SIG_TEXT = """\
Certificate:
    Data:
        Version: 3 (0x2)
        Issuer: CN = Signature Algorithm: ML-DSA-87
        Subject: CN = Signature Algorithm: ML-DSA-87
        Subject Public Key Info:
        Signature Algorithm: sha256WithRSAEncryption
"""


def test_dn_injected_signature_algorithm_is_rejected_by_anchoring():
    # The injected "Signature Algorithm: ML-DSA-87" strings live inside the
    # Issuer/Subject DN lines and appear *before* the genuine signature line.
    # The line-anchored regex ignores them and reports the real classical
    # signature; an unanchored parser would report ML-DSA-87 (a false PQ pass).
    r = parse_certificate_signature(DN_INJECTED_SIG_TEXT)
    assert r.raw_algorithm == "sha256WithRSAEncryption"
    assert r.is_post_quantum is False
    assert r.canonical_name is None
    assert r.nist_level is None
