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

from qureddy.core.signatures import (
    PQC_SIGNATURES,
    classify_pqc_signature,
    pqc_signature_standard,
)

__all__ = [
    "CertSignature",
    "classify_pqc_signature",
    "parse_certificate_signature",
    "pqc_signature_standard",
]

# ``openssl x509 -text`` prints the cert's outer signature algorithm as a
# "Signature Algorithm:" line followed by the algorithm name (e.g. ML-DSA-87).
# It appears for both the TBS signature field and the outer signatureAlgorithm;
# we take the first match, which is the TBSCertificate.signature — identical
# value for a valid cert.
SIGNATURE_ALGORITHM = re.compile(
    r"^[^\S\r\n]*Signature Algorithm:[^\S\r\n]*(?P<alg>[A-Za-z0-9._-]+)[^\S\r\n]*$",
    re.MULTILINE,
)


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
    pqc = PQC_SIGNATURES.get(raw.upper())
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
