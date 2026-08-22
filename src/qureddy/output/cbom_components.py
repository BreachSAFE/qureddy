# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CycloneDX crypto-asset component builders for the CBOM.

The algorithm/cipher-suite/protocol/certificate cryptographic-asset
components QuReddy positively observed, plus their classification profiles.
Split out of ``cbom.py`` to keep that module under the file-size ceiling;
the rendered CBOM is unchanged (#171).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from types import MappingProxyType
from typing import TYPE_CHECKING, NamedTuple

from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesCipherSuite,
    ProtocolPropertiesType,
)

from qureddy.output.cbom_assets import (
    ENDPOINT_REF,
    POSITIVE_OBSERVATIONS,
    add_algorithm_assets,
)
from qureddy.scanners.tls.cert_sig import classify_pqc_signature

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.certificate import CertificateObservation
    from qureddy.core.models import Evidence, ScanResult

CERTIFICATE_REF = "crypto/certificate/leaf"
# Evidence types handled by dedicated emitters (SSH host keys/KEX/cipher/MAC in cbom_ssh;
# legacy TLS ciphers in cbom_legacy), skipped by the generic algorithm emitter so no bom-ref
# is emitted twice and each keeps its specialized classification.
_SPECIALIZED_EVIDENCE_TYPES = frozenset(
    {"ssh.hostkey", "ssh.kex", "ssh.kex.weak", "ssh.cipher", "ssh.mac", "tls.legacy.cipher"}
)


def add_algorithm_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> dict[str, str]:
    """Add one cryptographic asset per unique positively observed TLS group.

    SSH evidence gets its own SSH-specific classified components (host keys are
    signature primitives, #143; KEX groups need SSH KEX-name classification, #241/#242),
    so this shared TLS-oriented emitter skips SSH evidence types — nothing is emitted
    twice under the same bom-ref.
    """
    return add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=lambda e: (
            e.negotiated_group if e.evidence_type not in _SPECIALIZED_EVIDENCE_TYPES else None
        ),
        algorithm_properties=_algorithm_properties,
    )


# Classical security strength (bits) of the TLS 1.3 AEAD cipher suites qureddy observes.
# AES-256-GCM and ChaCha20-Poly1305 provide 256-bit symmetric strength; AES-128-GCM, 128.
_CIPHER_SUITE_BITS: MappingProxyType[str, int] = MappingProxyType(
    {
        "TLS_AES_128_GCM_SHA256": 128,
        "TLS_AES_256_GCM_SHA384": 256,
        "TLS_CHACHA20_POLY1305_SHA256": 256,
    }
)


def _cipher_suite_properties(suite: str) -> AlgorithmProperties | None:
    """AEAD algorithmProperties for a TLS 1.3 cipher suite, keyed by classical bits."""
    bits = _CIPHER_SUITE_BITS.get(suite)
    if bits is None:
        return None
    return AlgorithmProperties(primitive=CryptoPrimitive.AE, classical_security_level=bits)


def add_cipher_suite_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit the negotiated AEAD cipher suite as its own crypto asset (#150).

    JSON carries `evidence.cipher_suite`; the CBOM previously only nested it inside
    `protocolProperties.cipherSuites`, so a core symmetric asset of the connection had
    no standalone component. Each carries the strongest observation seen for it.
    """
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=lambda e: e.cipher_suite,
        algorithm_properties=_cipher_suite_properties,
    )


# Structured classification for the key-exchange groups qureddy positively observes, so a
# CBOM consumer doesn't have to string-match the component name (#146). Values verified:
# ML-KEM-768 is NIST security category 3 (FIPS 203); X25519 is classical (no PQ resistance,
# level 0). Only groups we can classify with confidence are listed; anything else keeps a
# minimal (empty) algorithmProperties rather than fabricating a primitive/level.
# CONFORMANCE: expanding this table (SSH groups, signature algorithms) and re-checking every
# nistQuantumSecurityLevel is a breachsafe-conformance follow-up before claiming full coverage.
class _AlgorithmSpec(NamedTuple):
    primitive: CryptoPrimitive
    nist_quantum_security_level: int
    crypto_functions: tuple[CryptoFunction, ...]
    parameter_set_identifier: str | None = None
    curve: str | None = None


_KEM_FUNCTIONS = (CryptoFunction.KEYGEN, CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE)
_ALGORITHM_PROFILE: MappingProxyType[str, _AlgorithmSpec] = MappingProxyType(
    {
        "X25519MLKEM768": _AlgorithmSpec(
            CryptoPrimitive.KEM, 3, _KEM_FUNCTIONS, parameter_set_identifier="ML-KEM-768"
        ),
        "X25519": _AlgorithmSpec(
            CryptoPrimitive.KEY_AGREE, 0, (CryptoFunction.KEYGEN,), curve="curve25519"
        ),
    }
)


def _algorithm_properties(group: str) -> AlgorithmProperties | None:
    """Return a fresh AlgorithmProperties for a known group, else None (#146).

    A fresh instance per call keeps CycloneDX's mutable model out of shared module state.
    """
    spec = _ALGORITHM_PROFILE.get(group)
    if spec is None:
        return None
    return AlgorithmProperties(
        primitive=spec.primitive,
        parameter_set_identifier=spec.parameter_set_identifier,
        curve=spec.curve,
        crypto_functions=list(spec.crypto_functions),
        nist_quantum_security_level=spec.nist_quantum_security_level,
    )


_SIGNATURE_FUNCTIONS = (CryptoFunction.SIGN, CryptoFunction.VERIFY)
# Substrings that identify a classical (non-PQ) signature algorithm, drawn from X.509
# signatureAlgorithm names and SSH host-key identifiers.
_CLASSICAL_SIGNATURE_MARKERS = ("ecdsa", "rsa", "ed25519", "ed448", "dsa", "dss")


def signature_algorithm_properties(name: str) -> AlgorithmProperties | None:
    """Classify a certificate or host-key signature algorithm (#177, #201).

    Every signature is the SIGNATURE primitive with sign/verify functions. ML-DSA
    (FIPS 204) and SLH-DSA (FIPS 205) each carry their NIST security category
    (from cert_sig's single classification table); a classical signature (ECDSA,
    RSA, EdDSA, DSA) has no post-quantum resistance (nistQuantumSecurityLevel 0).
    A name we can't classify keeps a minimal algorithmProperties rather than
    fabricating a level. The PQC check runs before the classical-marker scan
    because both ML-DSA and SLH-DSA names contain the classical substring ``dsa``.
    """
    classified = classify_pqc_signature(name)
    if classified is not None:
        parameter_set, level = classified
        return AlgorithmProperties(
            primitive=CryptoPrimitive.SIGNATURE,
            parameter_set_identifier=parameter_set.upper(),
            crypto_functions=list(_SIGNATURE_FUNCTIONS),
            nist_quantum_security_level=level,
        )
    if any(marker in name.lower() for marker in _CLASSICAL_SIGNATURE_MARKERS):
        return AlgorithmProperties(
            primitive=CryptoPrimitive.SIGNATURE,
            crypto_functions=list(_SIGNATURE_FUNCTIONS),
            nist_quantum_security_level=0,
        )
    return None


def add_protocol_components(
    bom: Bom,
    result: ScanResult,
    algorithm_refs: dict[str, str],
    provides_edges: dict[str, list[str]],
) -> None:
    """Add one protocol asset per unique observed protocol and version."""
    positive_evidence = _positive_protocol_evidence(result)
    protocol_versions = {
        (evidence.protocol, evidence.protocol_version)
        for evidence in positive_evidence
        if evidence.protocol_version is not None
    }
    for protocol, protocol_version in sorted(protocol_versions):
        matching = [
            evidence
            for evidence in positive_evidence
            if (evidence.protocol, evidence.protocol_version) == (protocol, protocol_version)
        ]
        ref = f"crypto/protocol/{protocol}-{protocol_version.lower()}"
        bom.components.add(
            _protocol_component(
                protocol,
                protocol_version,
                ref,
                _protocol_cipher_suites(matching, algorithm_refs),
            )
        )
        provides_edges.setdefault(ENDPOINT_REF, []).append(ref)


def _positive_protocol_evidence(result: ScanResult) -> list[Evidence]:
    """Return only positive observations that identify a protocol version."""
    return [
        evidence
        for evidence in result.evidence
        if evidence.observation_type in POSITIVE_OBSERVATIONS and evidence.protocol_version
    ]


def _protocol_cipher_suites(
    evidence: list[Evidence], algorithm_refs: dict[str, str]
) -> list[ProtocolPropertiesCipherSuite]:
    """Build deterministic cipher-suite entries for one protocol version."""
    suites = []
    for cipher_suite in sorted({item.cipher_suite for item in evidence if item.cipher_suite}):
        group_refs = sorted(
            {
                algorithm_refs[item.negotiated_group]
                for item in evidence
                if item.cipher_suite == cipher_suite and item.negotiated_group in algorithm_refs
            }
        )
        suites.append(
            ProtocolPropertiesCipherSuite(
                name=cipher_suite,
                algorithms=[BomRef(value=ref) for ref in group_refs] or None,
            )
        )
    return suites


def _protocol_component(
    protocol: str,
    protocol_version: str,
    ref: str,
    cipher_suites: list[ProtocolPropertiesCipherSuite],
) -> Component:
    """Build one CycloneDX protocol cryptographic asset."""
    protocol_type = {
        "tls": ProtocolPropertiesType.TLS,
        "ssh": ProtocolPropertiesType.SSH,
    }.get(protocol)
    return Component(
        name=protocol_version,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=ref,
        crypto_properties=CryptoProperties(
            asset_type=CryptoAssetType.PROTOCOL,
            protocol_properties=ProtocolProperties(
                type=protocol_type,
                version=_bare_protocol_version(protocol, protocol_version),
                cipher_suites=cipher_suites or None,
            ),
        ),
    )


def _bare_protocol_version(protocol: str, protocol_version: str) -> str:
    """Return the CycloneDX bare protocol version (`1.0`, `1.3`, `2.0`).

    TLS evidence stores `"TLSv1.3"`; CycloneDX 1.7 documents this field as a bare
    version, and the SSH path already emits `"2.0"`. Strip the `TLSv` prefix so a
    consumer keying on the version sees consistent values across TLS and SSH. The
    human-facing component `name`/`bom-ref` keep the fuller label (#140).
    """
    if protocol == "tls" and protocol_version.startswith("TLSv"):
        rest = protocol_version.removeprefix("TLSv")
        # "TLSv1" is TLS 1.0; give it an explicit minor so every value is "major.minor".
        return rest if "." in rest else f"{rest}.0"
    return protocol_version


# OpenSSL prints certificate dates in the C locale regardless of the host locale
# ("Jul 17 07:18:11 2026 GMT"), so the English month abbreviations are fixed. We map
# them ourselves instead of using strptime's `%b`, which is LC_TIME-dependent and
# silently fails on a non-English host (e.g. de_DE), dropping the cert dates (#116).
_OPENSSL_MONTHS = MappingProxyType(
    {
        month: index
        for index, month in enumerate(
            ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
            start=1,
        )
    }
)
# Day is `\d{1,2}` because OpenSSL space-pads single-digit days ("Jul  7 ..."), which
# `%d` also mishandles. Only GMT/UTC is accepted (OpenSSL always reports these in GMT).
_OPENSSL_DATE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<year>\d{4})\s+(?P<tz>GMT|UTC)$"
)


def _parse_openssl_date(text: str) -> datetime | None:
    """Parse `openssl x509 -dates` output (e.g. "Jul 17 07:18:11 2026 GMT").

    Returns None on anything unparseable rather than raising — a date
    the CBOM can't represent should degrade to "absent from this CBOM",
    not abort rendering the rest of a real, otherwise-valid certificate.
    Parsing is locale-independent (see ``_OPENSSL_MONTHS``); OpenSSL always
    reports GMT (== UTC), which is attached explicitly to satisfy the
    project's timezone-aware-datetime rule.
    """
    if not text:
        return None
    match = _OPENSSL_DATE.match(text.strip())
    if not match:
        return None
    month = _OPENSSL_MONTHS.get(match.group("mon"))
    if month is None:
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


def _add_signature_algorithm_component(
    bom: Bom, signature_algorithm: str, provides_edges: dict[str, list[str]]
) -> BomRef | None:
    """One cryptographic-asset component for the certificate's signature algorithm.

    Mirrors `add_algorithm_components`'s per-negotiated-group pattern —
    same reasoning: `signature_algorithm_ref` on `CertificateProperties`
    is typed `Optional[BomRef]`, a reference to a separate component, not
    a free-text string (confirmed via `inspect.signature`). Returns None
    for the "UNKNOWN" placeholder `cert_probe.py` emits when the `-text`
    output has no matching line, rather than emitting a fake component.
    """
    if signature_algorithm == "UNKNOWN":
        return None
    ref = f"crypto/algorithm/{signature_algorithm.lower()}"
    bom.components.add(
        Component(
            name=signature_algorithm,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=ref,
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.ALGORITHM,
                algorithm_properties=signature_algorithm_properties(signature_algorithm),
            ),
        )
    )
    provides_edges.setdefault(ENDPOINT_REF, []).append(ref)
    return BomRef(value=ref)


def add_certificate_component(
    bom: Bom, certificate: CertificateObservation, provides_edges: dict[str, list[str]]
) -> None:
    """One certificate component from a real fetched+parsed cert (cert_probe.py).

    `subject_public_key_ref` (pubkey) stays unset pending an OID/key-type
    lookup table (larger, separate work — issue #190) rather than a fake
    reference. The installed library model does not expose CycloneDX 1.7's
    native ``certificateProperties.serialNumber`` field, so the final-byte
    patch adds it after typed serialization.
    """
    ref = CERTIFICATE_REF
    sig_alg_ref = _add_signature_algorithm_component(
        bom, certificate.signature_algorithm, provides_edges
    )
    bom.components.add(
        Component(
            name=certificate.subject,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=ref,
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.CERTIFICATE,
                certificate_properties=CertificateProperties(
                    subject_name=certificate.subject,
                    issuer_name=certificate.issuer,
                    certificate_format="X.509",
                    not_valid_before=_parse_openssl_date(certificate.not_before),
                    not_valid_after=_parse_openssl_date(certificate.not_after),
                    signature_algorithm_ref=sig_alg_ref,
                ),
            ),
        )
    )
    provides_edges.setdefault(ENDPOINT_REF, []).append(ref)
