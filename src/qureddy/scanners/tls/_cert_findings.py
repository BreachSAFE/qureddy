# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Evidence/Finding builders for the certificate issuer-signature axis (issue #183).

Issue #226 correction: this is the certificate's *issuer* signature axis
(chain-of-trust), not a live-handshake authentication claim — see cert_sig.py's
docstring for why those are different operations that can use different
algorithms. This module closes the wiring gap: the detection logic
(cert_sig.py, issue #7) existed but nothing called it, so the scan never
reported this axis and output hardcoded a false "remain classical" assertion
regardless of what the cert actually used.

Readiness is deliberately Readiness.NOT_APPLICABLE for both outcomes
(NOT_APPLICABLE is the lowest-precedence tier in _summary.py's
scan_readiness rollup, so it can never override the key-exchange axis's
verdict) — formally combining both axes into a single verdict is
issue #166's "quantum_ready" tier, out of scope here. This only makes
the axis visible and honest, not blindly asserted.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from qureddy.core.certificate import CertificateObservation
from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    ObservationType,
    Readiness,
    Severity,
)

if TYPE_CHECKING:
    from qureddy.scanners.tls.cert_probe import CertificateInfo

# Named once here (the module that owns these finding_type values) so
# console.py's lookup can import them instead of re-typing the literal
# strings in a second place, where they could silently drift out of
# sync with a rename here.
FINDING_TYPE_PQ_SIGNATURE = "tls.cert.pq_signature"
FINDING_TYPE_CLASSICAL_SIGNATURE = "tls.cert.classical_signature"


def evidence_from_certificate(asset: Asset, certificate: CertificateInfo | None) -> Evidence:
    """One Evidence record for the cert axis — present even when the fetch failed.

    `certificate is None` means the independent cert probe didn't
    produce a usable PEM (timeout, connection refused, etc.) — still
    worth recording as "not inspected", per the issue's own guidance:
    never assert "classical" when the cert was never actually looked at.
    """
    if certificate is None:
        return Evidence(
            id=f"ev-{uuid.uuid4().hex[:12]}",
            asset_id=asset.id,
            evidence_type="tls.cert.signature",
            observation_type=ObservationType.NOT_TESTABLE,
            source="qureddy.scanners.tls.cert_probe",
            notes=("certificate not fetched or unparseable",),
        )
    return Evidence(
        id=f"ev-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id,
        evidence_type="tls.cert.signature",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.tls.cert_sig",
        notes=(f"signature algorithm: {certificate.signature_algorithm}",),
        certificate=CertificateObservation(
            subject=certificate.subject,
            issuer=certificate.issuer,
            not_before=certificate.not_before,
            not_after=certificate.not_after,
            serial=certificate.serial,
            signature_algorithm=certificate.signature_algorithm,
            public_key_summary=certificate.public_key_summary,
            is_self_signed=certificate.is_self_signed,
            is_post_quantum_signature=certificate.is_post_quantum_signature,
        ),
    )


def finding_from_certificate(
    asset: Asset, evidence: Evidence, certificate: CertificateInfo | None
) -> Finding | None:
    """A Finding reporting the cert axis, or None when the cert wasn't inspected.

    No Finding on a failed/missing fetch (evidence above already
    records that) — a finding implies a real observation to act on.
    """
    if certificate is None or certificate.signature_algorithm == "UNKNOWN":
        return None
    pq = certificate.is_post_quantum_signature
    return Finding(
        id=f"finding-{uuid.uuid4().hex[:12]}",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        rule_id="tls.cert.signature_algorithm",
        finding_type=FINDING_TYPE_PQ_SIGNATURE if pq else FINDING_TYPE_CLASSICAL_SIGNATURE,
        title=(
            f"Certificate issuer signature: {certificate.signature_algorithm}"
            + (" (post-quantum)" if pq else " (classical)")
        ),
        description=(
            f"Leaf certificate subject={certificate.subject!r} was issued using "
            f"{certificate.signature_algorithm} as the CA/issuer signature over "
            "the certificate. "
            + (
                "This is a NIST-standardized post-quantum signature algorithm (FIPS 204). "
                if pq
                else "This is a classical (non-post-quantum) signature algorithm. "
            )
            + "This describes the certificate's chain-of-trust signature only — "
            "it is NOT the live TLS handshake's authentication signature "
            "(CertificateVerify), which uses the leaf's own key and can use a "
            "different algorithm (issue #226)."
        ),
        severity=Severity.INFO,
        readiness=Readiness.NOT_APPLICABLE,
        confidence=Confidence.HIGH,
        algorithm=certificate.signature_algorithm,
        primitive="signature",
    )
