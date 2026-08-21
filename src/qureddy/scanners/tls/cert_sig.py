# SPDX-FileCopyrightText: 2026 Paul Volosen <paulvolosen@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Detect the leaf certificate's issuer signature algorithm (PQC vs classical).

Issue #226 correction: this module reads the CA/issuer's signature *over the
certificate* (``openssl x509 -text``'s ``Signature Algorithm:`` line) — this is
NOT the same operation as the live TLS 1.3 handshake's server authentication.
That's a distinct signature (OpenSSL calls it ``Signature type:`` in
``s_client -brief`` output, over the leaf's own private key via
``CertificateVerify``) that can use a different algorithm than the issuer's
signature over the certificate. A previous revision of this docstring called
this module's output "the authentication axis" — wrong: do not treat what
this module reports as a claim about live-handshake authentication. It is a
statement about the certificate's chain-of-trust (issuer) signature only.
Confirmed live: a real ML-DSA-65-issued certificate with an ECDSA leaf key
negotiates a classical ECDSA `CertificateVerify` — this module correctly
reports "ML-DSA-65", which is true of the issuer signature and would be
false if read as "this connection authenticated with a PQ signature."

This module reads the leaf cert's ``Signature Algorithm`` (as printed by
``openssl x509 -text``) and classifies it as post-quantum — ML-DSA (FIPS 204 /
RFC 9881) or SLH-DSA (FIPS 205, the stateless hash-based SPHINCS+ family) — or
classical.

Consistent with the rest of the scanner, this parses OpenSSL text output rather than
adding a crypto dependency. Detection only — this does NOT validate trust or the chain.

Pulled in from `feat/7-cert-detect-clean` (issue #7) and wired into the live scan path
per issue #183 — previously existed but was never called by `scanner.py`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ``openssl x509 -text`` prints the cert's outer signature algorithm as a
# "Signature Algorithm:" line followed by the algorithm name (e.g. ML-DSA-87).
# It appears for both the TBS signature field and the outer signatureAlgorithm;
# we take the first match, which is the TBSCertificate.signature — identical
# value for a valid cert.
SIGNATURE_ALGORITHM = re.compile(
    r"^[^\S\r\n]*Signature Algorithm:[^\S\r\n]*(?P<alg>[A-Za-z0-9._-]+)[^\S\r\n]*$",
    re.MULTILINE,
)

# Shared PQC vocabulary with QuCert / QuCrypt — same names, OIDs, NIST levels.
# Keyed by the algorithm name OpenSSL prints (upper-cased for case-insensitive
# lookup); value = (canonical name, OID, NIST level).
#
# ML-DSA (FIPS 204 / RFC 9881 §2): lattice signatures, categories 2/3/5.
_ML_DSA = {
    "ML-DSA-44": ("ML-DSA-44", "2.16.840.1.101.3.4.3.17", 2),
    "ML-DSA-65": ("ML-DSA-65", "2.16.840.1.101.3.4.3.18", 3),
    "ML-DSA-87": ("ML-DSA-87", "2.16.840.1.101.3.4.3.19", 5),
}
# SLH-DSA (FIPS 205): the 12 stateless hash-based (SPHINCS+) parameter sets.
# OIDs 2.16.840.1.101.3.4.3.20 through .31 (NIST CSOR arc); NIST category is fixed
# by the hash-output size (128 -> category 1, 192 -> category 3, 256 -> category 5,
# FIPS 205 Table 2). The ``s`` (small) and ``f`` (fast) variants share a category.
_SLH_DSA = {
    "SLH-DSA-SHA2-128s": ("SLH-DSA-SHA2-128s", "2.16.840.1.101.3.4.3.20", 1),
    "SLH-DSA-SHA2-128f": ("SLH-DSA-SHA2-128f", "2.16.840.1.101.3.4.3.21", 1),
    "SLH-DSA-SHA2-192s": ("SLH-DSA-SHA2-192s", "2.16.840.1.101.3.4.3.22", 3),
    "SLH-DSA-SHA2-192f": ("SLH-DSA-SHA2-192f", "2.16.840.1.101.3.4.3.23", 3),
    "SLH-DSA-SHA2-256s": ("SLH-DSA-SHA2-256s", "2.16.840.1.101.3.4.3.24", 5),
    "SLH-DSA-SHA2-256f": ("SLH-DSA-SHA2-256f", "2.16.840.1.101.3.4.3.25", 5),
    "SLH-DSA-SHAKE-128s": ("SLH-DSA-SHAKE-128s", "2.16.840.1.101.3.4.3.26", 1),
    "SLH-DSA-SHAKE-128f": ("SLH-DSA-SHAKE-128f", "2.16.840.1.101.3.4.3.27", 1),
    "SLH-DSA-SHAKE-192s": ("SLH-DSA-SHAKE-192s", "2.16.840.1.101.3.4.3.28", 3),
    "SLH-DSA-SHAKE-192f": ("SLH-DSA-SHAKE-192f", "2.16.840.1.101.3.4.3.29", 3),
    "SLH-DSA-SHAKE-256s": ("SLH-DSA-SHAKE-256s", "2.16.840.1.101.3.4.3.30", 5),
    "SLH-DSA-SHAKE-256f": ("SLH-DSA-SHAKE-256f", "2.16.840.1.101.3.4.3.31", 5),
}
# One table for lookup, indexed by the upper-cased OpenSSL name so casing of the
# ``s``/``f`` suffix (OpenSSL prints them lower-case) does not cause a miss.
_PQC_SIGNATURES = {name.upper(): value for name, value in (*_ML_DSA.items(), *_SLH_DSA.items())}


@dataclass(frozen=True, slots=True)
class CertSignature:
    """The leaf certificate's signature algorithm and its post-quantum classification.

    Internal parser-to-scanner state (not the locked Pydantic Evidence/Asset shapes; the
    scanner converts this downstream).
    """

    raw_algorithm: str | None = None
    """The algorithm string OpenSSL printed (e.g. ``ML-DSA-87``, ``ecdsa-with-SHA256``)."""
    is_post_quantum: bool = False
    """True iff the signature algorithm is a recognized PQC (ML-DSA or SLH-DSA) algorithm."""
    canonical_name: str | None = None
    """Canonical name for a recognized PQC algorithm (e.g. ``ML-DSA-87``, ``SLH-DSA-SHA2-128s``); else None."""
    oid: str | None = None
    """OID for a recognized PQC algorithm (RFC 9881 / FIPS 205 CSOR arc); else None."""
    nist_level: int | None = None
    """NIST security category (1/2/3/5) for a recognized PQC algorithm; else None."""


def parse_certificate_signature(x509_text: str) -> CertSignature:
    """Parse ``openssl x509 -text`` output into a `CertSignature`.

    Args:
        x509_text: stdout from ``openssl x509 -noout -text`` (or ``s_client -showcerts``
            piped through it) for the server's leaf certificate.

    Returns:
        A `CertSignature`. If no signature algorithm line is found, all fields are None /
        False (the scanner treats that as "cert axis undetermined", not "quantum-safe").
    """
    match = SIGNATURE_ALGORITHM.search(x509_text)
    if match is None:
        return CertSignature()
    raw = match.group("alg")
    pqc = _PQC_SIGNATURES.get(raw.upper())
    if pqc is None:
        # Recognized format but a classical (or unknown) algorithm: report it, not PQC.
        return CertSignature(raw_algorithm=raw, is_post_quantum=False)
    name, oid, level = pqc
    return CertSignature(
        raw_algorithm=raw,
        is_post_quantum=True,
        canonical_name=name,
        oid=oid,
        nist_level=level,
    )


def classify_pqc_signature(algorithm: str) -> tuple[str, int] | None:
    """Return ``(canonical parameter-set name, NIST level)`` for a PQC signature name.

    The single source of truth for "is this signature algorithm post-quantum, and at
    what NIST category" — shared by the CBOM emitter so the CLI and CBOM paths cannot
    drift (#201). Returns None for a classical or unrecognized name.
    """
    pqc = _PQC_SIGNATURES.get(algorithm.upper())
    if pqc is None:
        return None
    canonical, _oid, level = pqc
    return canonical, level


def pqc_signature_standard(algorithm: str) -> str:
    """Return the NIST standard that specifies a PQC signature algorithm.

    ML-DSA is FIPS 204; SLH-DSA is FIPS 205. Used for accurate finding/verdict
    copy so an SLH-DSA cert is not mislabeled "FIPS 204" (#201). Assumes the caller
    already established the algorithm is post-quantum; defaults to FIPS 204 for any
    other name.
    """
    return "FIPS 205" if algorithm.upper().startswith("SLH-DSA") else "FIPS 204"
