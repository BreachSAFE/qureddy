# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Internal typed certificate observation shared by scanners and renderers."""

from pydantic import BaseModel, ConfigDict

_FROZEN = ConfigDict(frozen=True, extra="forbid")


class CertificateObservation(BaseModel):
    """Certificate facts captured by the scan's single certificate probe.

    This typed observation lets alternate renderers reuse the exact
    bytes-derived result without performing another network fetch.
    """

    model_config = _FROZEN

    subject: str
    issuer: str
    not_before: str
    not_after: str
    serial: str
    signature_algorithm: str
    public_key_summary: str
    is_self_signed: bool | None
    is_post_quantum_signature: bool
    # #313: the certificate's own subject public key (algorithm name + size in bits),
    # parsed structurally from the x509 text. The leaf key is the quantum-relevant fact.
    # Optional so an older/partial observation (or a parse that found no key line) stays valid.
    public_key_algorithm: str | None = None
    public_key_bits: int | None = None
