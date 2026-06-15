# SPDX-FileCopyrightText: 2026 Paul Volosen <paulvolosen@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Detect the leaf certificate's signature algorithm (PQC vs classical).

QuReddy judges TLS on two independent axes:

  - confidentiality  -> the negotiated key-exchange group (parse.py)
  - authentication   -> the server CERTIFICATE's signature algorithm (this module)

A server can be post-quantum on one axis and not the other. This module closes the
certificate axis: it reads the leaf cert's ``Signature Algorithm`` (as printed by
``openssl x509 -text``) and classifies it as ML-DSA (post-quantum, FIPS 204 / RFC 9881)
or classical.

Consistent with the rest of the scanner, this parses OpenSSL text output rather than
adding a crypto dependency. Detection only — this does NOT validate trust or the chain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ``openssl x509 -text`` prints the cert's outer signature algorithm as e.g.
#   "    Signature Algorithm: ML-DSA-87"
# (it appears for both the TBS signature field and the outer signatureAlgorithm; we take
# the first match, which is the TBSCertificate.signature — identical value for a valid cert).
SIGNATURE_ALGORITHM = re.compile(
    r"^[^\S\r\n]*Signature Algorithm:[^\S\r\n]*(?P<alg>[A-Za-z0-9._-]+)[^\S\r\n]*$",
    re.MULTILINE,
)

# Shared PQC vocabulary with QuCert / QuCrypt — same names, OIDs (RFC 9881 §2), NIST levels.
# Keyed by the algorithm name OpenSSL prints; value = (canonical name, OID, NIST level).
_ML_DSA = {
    "ML-DSA-44": ("ML-DSA-44", "2.16.840.1.101.3.4.3.17", 2),
    "ML-DSA-65": ("ML-DSA-65", "2.16.840.1.101.3.4.3.18", 3),
    "ML-DSA-87": ("ML-DSA-87", "2.16.840.1.101.3.4.3.19", 5),
}


@dataclass(frozen=True, slots=True)
class CertSignature:
    """The leaf certificate's signature algorithm and its post-quantum classification.

    Internal parser-to-scanner state (not the locked Pydantic Evidence/Asset shapes; the
    scanner converts this downstream).
    """

    raw_algorithm: str | None = None
    """The algorithm string OpenSSL printed (e.g. ``ML-DSA-87``, ``ecdsa-with-SHA256``)."""
    is_post_quantum: bool = False
    """True iff the signature algorithm is a recognized PQC (ML-DSA) algorithm."""
    canonical_name: str | None = None
    """Canonical name for a recognized PQC algorithm (e.g. ``ML-DSA-87``); else None."""
    oid: str | None = None
    """RFC 9881 OID for a recognized PQC algorithm; else None."""
    nist_level: int | None = None
    """NIST security category (2/3/5) for a recognized PQC algorithm; else None."""


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
    pqc = _ML_DSA.get(raw)
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
