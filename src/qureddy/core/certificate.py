# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Internal typed certificate observation shared by scanners and renderers."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict

_FROZEN = ConfigDict(frozen=True, extra="forbid")
# OpenSSL emits fixed English month abbreviations in its C-locale date format.
# An explicit map avoids the host-locale dependence of ``strptime("%b")``.
_OPENSSL_MONTHS = MappingProxyType(
    {
        month: index
        for index, month in enumerate(
            ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
            start=1,
        )
    }
)
# ``\s+`` accepts OpenSSL's space-padded single-digit days. The scanner only
# accepts the GMT and UTC labels that OpenSSL uses for certificate validity.
_OPENSSL_DATE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<year>\d{4})\s+(?P<tz>GMT|UTC)$"
)


def parse_openssl_date(text: str) -> datetime | None:
    """Parse a locale-independent ``openssl x509 -dates`` value."""
    match = _OPENSSL_DATE.match(text.strip()) if text else None
    month = _OPENSSL_MONTHS.get(match.group("mon")) if match else None
    if match is None or month is None:
        return None
    try:
        return datetime(
            int(match.group("year")),
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=UTC,
        )
    except ValueError:
        return None


class CertificateDetails(BaseModel):
    """Stable public certificate facts emitted by ``qureddy.scan.v1``."""

    model_config = _FROZEN

    subject: str
    issuer: str
    not_valid_before: str | None
    not_valid_after: str | None
    serial_number: str
    signature_algorithm: str
    public_key_algorithm: str | None = None
    public_key_bits: int | None = None
    is_self_signed: bool | None
    is_post_quantum_signature: bool


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

    def public_details(self) -> CertificateDetails:
        """Project the internal observation onto the stable JSON contract."""
        not_before = parse_openssl_date(self.not_before)
        not_after = parse_openssl_date(self.not_after)
        return CertificateDetails(
            subject=self.subject,
            issuer=self.issuer,
            not_valid_before=not_before.isoformat() if not_before is not None else None,
            not_valid_after=not_after.isoformat() if not_after is not None else None,
            serial_number=self.serial,
            signature_algorithm=self.signature_algorithm,
            public_key_algorithm=self.public_key_algorithm,
            public_key_bits=self.public_key_bits,
            is_self_signed=self.is_self_signed,
            is_post_quantum_signature=self.is_post_quantum_signature,
        )
