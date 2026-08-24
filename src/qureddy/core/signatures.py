# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Protocol-neutral post-quantum signature classification.

Certificate and CBOM adapters share this pure vocabulary. Protocol parsers
remain responsible for extracting the algorithm name; this module owns only
the classification table and standards mapping.
"""

from __future__ import annotations

from types import MappingProxyType

_ML_DSA = {
    "ML-DSA-44": ("ML-DSA-44", "2.16.840.1.101.3.4.3.17", 2),
    "ML-DSA-65": ("ML-DSA-65", "2.16.840.1.101.3.4.3.18", 3),
    "ML-DSA-87": ("ML-DSA-87", "2.16.840.1.101.3.4.3.19", 5),
}
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
PQC_SIGNATURES = MappingProxyType(
    {name.upper(): value for name, value in (*_ML_DSA.items(), *_SLH_DSA.items())}
)


def classify_pqc_signature(algorithm: str) -> tuple[str, int] | None:
    """Return the canonical PQ signature name and NIST level, if recognized."""
    pqc = PQC_SIGNATURES.get(algorithm.upper())
    return None if pqc is None else (pqc[0], pqc[2])


def pqc_signature_standard(algorithm: str) -> str:
    """Return the FIPS standard naming a PQ signature family."""
    return "FIPS 205" if algorithm.upper().startswith("SLH-DSA") else "FIPS 204"
