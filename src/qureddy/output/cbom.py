# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Render scan observations as a CycloneDX 1.7 CBOM.

The official CycloneDX model is the output contract. QuReddy and its local
OpenSSL runtime are collection-tool provenance under ``metadata.tools``;
neither is attributed to the remote endpoint. The endpoint is the stable
``metadata.component`` root and provides the cryptographic assets QuReddy
positively observed.

ANTIPATTERN ACCEPTED: raw-json-post-processing, because
`cyclonedx-python-lib`'s `Bom.register_dependency` has no `provides`
parameter (confirmed via `inspect.signature(Dependency.__init__)` — only
`ref`/`dependencies` exist) despite `provides` being valid CycloneDX 1.7,
and its `CertificateProperties` model does not yet expose 1.7's native
``serialNumber`` field. The final-byte patch is limited to those two
upstream API gaps; everything else is delegated to ``JsonV1Dot7``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import warnings
from datetime import UTC, datetime
from types import MappingProxyType
from typing import IO, TYPE_CHECKING, NamedTuple

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
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
from cyclonedx.model.tool import ToolRepository
from cyclonedx.output.json import JsonV1Dot7

from qureddy.core.models import ObservationType, ScanResult
from qureddy.output.cbom_semantics import validate_cbom_semantics

if TYPE_CHECKING:
    from qureddy.core.certificate import CertificateObservation
    from qureddy.core.models import Evidence, OpenSSLDependency

_ENDPOINT_REF = "endpoint"
_QUREDDY_TOOL_REF = "tool/qureddy"
_OPENSSL_TOOL_REF = "tool/openssl"
_CERTIFICATE_REF = "crypto/certificate/leaf"
_POSITIVE_OBSERVATIONS = frozenset(
    {ObservationType.NEGOTIATED, ObservationType.OFFERED, ObservationType.OBSERVED}
)


def render_cbom(
    result: ScanResult,
    stream: IO[str] | None = None,
    *,
    reproducible: bool = False,
) -> None:
    """Render typed scan observations as CycloneDX 1.7.

    Issue #239: `stream: IO[str] = sys.stdout` as a default is resolved
    once at function-definition time, not per call — same root cause as
    #237/#238. Resolve at call time instead.

    When ``reproducible`` is set, the per-run identity fields (the CycloneDX
    serialNumber and metadata.timestamp, plus the scan id and start/finish
    times) are omitted so the same scan is byte- and digest-reproducible for
    content addressing (#162). The observed crypto content is unchanged.
    """
    target_stream = stream if stream is not None else sys.stdout
    bom = Bom()
    if reproducible:
        # The Bom() constructor auto-generates a random serialNumber and an
        # emission timestamp; drop both (they are optional in CycloneDX) so the
        # output is content-addressable.
        # The library stub types these non-optional, but both are optional in
        # CycloneDX and are omitted from output when None (verified at runtime).
        bom.serial_number = None  # type: ignore[assignment]
        bom.metadata.timestamp = None  # type: ignore[assignment]
    provides_edges: dict[str, list[str]] = {}

    # WHY: adding this same object to bom.components makes the library's
    # BomRefDiscriminator visit it twice and replace "endpoint" with a random
    # ref. metadata.component already establishes the document root.
    endpoint = Component(
        name=f"{result.target.host}:{result.target.port}",
        type=ComponentType.APPLICATION,
        bom_ref=_ENDPOINT_REF,
    )
    bom.metadata.component = endpoint
    _add_tool_provenance(bom, result, reproducible=reproducible)
    _add_scan_status_properties(bom, result)
    _add_scan_target_metadata(bom, result, reproducible=reproducible)
    _add_evidence_provenance(bom, result, reproducible=reproducible)
    _add_finding_verdicts(bom, result)

    algorithm_refs = _add_algorithm_components(bom, result, provides_edges)
    _add_cipher_suite_components(bom, result, provides_edges)
    _add_protocol_components(bom, result, algorithm_refs, provides_edges)
    certificate = _captured_certificate(result)
    if certificate is not None:
        _add_certificate_component(bom, certificate, provides_edges)

    bom.register_dependency(endpoint)
    _write_with_library_gap_patches(
        bom,
        provides_edges,
        certificate.serial if certificate is not None else None,
        target_stream,
    )


def _captured_certificate(result: ScanResult) -> CertificateObservation | None:
    """Return the certificate already captured by the scan, never refetch it."""
    observations = [
        evidence.certificate
        for evidence in result.evidence
        if evidence.observation_type is ObservationType.OBSERVED
        and evidence.certificate is not None
    ]
    if len(observations) > 1:
        msg = f"expected at most one captured leaf certificate, got {len(observations)}"
        raise ValueError(msg)
    return observations[0] if observations else None


def _add_tool_provenance(bom: Bom, result: ScanResult, *, reproducible: bool = False) -> None:
    """Record QuReddy and local OpenSSL as collection tools."""
    tools = [
        Component(
            name="qureddy",
            type=ComponentType.APPLICATION,
            bom_ref=_QUREDDY_TOOL_REF,
            version=result.scan.scanner_version,
        )
    ]
    if result.dependencies and result.dependencies[0].failure_category is None:
        dependency = result.dependencies[0]
        tools.append(
            Component(
                name=dependency.name,
                type=ComponentType.APPLICATION,
                bom_ref=_OPENSSL_TOOL_REF,
                version=dependency.version,
                properties=_openssl_tool_properties(dependency, reproducible=reproducible),
            )
        )
    bom.metadata.tools = ToolRepository(components=tools)


def _openssl_tool_properties(
    dependency: OpenSSLDependency, *, reproducible: bool = False
) -> list[Property]:
    """Carry the local OpenSSL capability flags (and path) onto the tool component.

    The CBOM kept only openssl's version, dropping the flags JSON's dependencies[]
    carries. Those flags decide whether a "no hybrid found" result is a real negative
    or a prober blind-spot: a consumer can't trust the inventory without them (#151).
    The absolute local path is host-specific, so it is omitted in reproducible mode so
    two hosts observing identical crypto produce the same digest (#162/#147 audit).
    """
    properties = [
        Property(name="qureddy:collector.role", value="local-probe-runtime"),
        Property(
            name="qureddy:openssl.supports_tls13_groups",
            value=str(dependency.supports_tls13_groups).lower(),
        ),
        Property(
            name="qureddy:openssl.supports_x25519mlkem768",
            value=str(dependency.supports_x25519mlkem768).lower(),
        ),
    ]
    if dependency.path is not None and not reproducible:
        properties.append(Property(name="qureddy:openssl.path", value=dependency.path))
    return properties


def _add_scan_status_properties(bom: Bom, result: ScanResult) -> None:
    """Mirror scan.status/readiness/failure_category onto bom.metadata.properties.

    `bom.metadata.properties` is the standard CycloneDX extension point.
    Without this, a CBOM from a hard-failed scan (e.g. tls_handshake_failed)
    is structurally indistinguishable from a successful-but-sparse one —
    both can contain a real, valid certificate component (the certificate
    probe in cli.py runs independently of the main scan's forced-group
    probes and can succeed even when they fail), and there was previously
    no field anywhere in the CBOM itself recording that the scan failed.
    A consumer that stores/forwards only the CBOM JSON (no external exit
    code) had no way to tell these apart (issue #195).

    The readiness verdict is qureddy's headline conclusion and is carried in
    `--format json`; emitting it here keeps the CBOM self-describing so a
    consumer sees what qureddy concluded without re-deriving it (issue #132).
    """
    bom.metadata.properties.add(Property(name="qureddy:scan.status", value=result.scan.status))
    bom.metadata.properties.add(
        Property(name="qureddy:scan.readiness", value=result.summary.readiness.value)
    )
    if result.summary.failure_category is not None:
        bom.metadata.properties.add(
            Property(
                name="qureddy:scan.failure_category",
                value=result.summary.failure_category.value,
            )
        )


def _add_scan_target_metadata(bom: Bom, result: ScanResult, *, reproducible: bool = False) -> None:
    """Carry scan-identity/timing and structured target fields as metadata.properties.

    JSON exposes these; the CBOM previously kept only the emission timestamp and a
    `host:port` component name, so a CBOM-only consumer lost the scan id, timing,
    attempt count, and (critically) the SNI that determined what was actually
    probed (#152). In ``reproducible`` mode the per-run scan id and start/finish
    times are omitted so the output is content-addressable (#162).
    """
    scan = result.scan
    target = result.target
    pairs: list[tuple[str, str]] = [
        ("qureddy:scan.scanner_name", scan.scanner_name),
        ("qureddy:target.original_input", target.original_input),
        ("qureddy:target.host", target.host),
        ("qureddy:target.port", str(target.port)),
        ("qureddy:target.scheme", target.scheme),
        ("qureddy:target.locator", target.locator),
    ]
    if not reproducible:
        # total_attempts can vary with transient retries, so it is per-run too.
        pairs = [
            ("qureddy:scan.id", scan.scan_id),
            ("qureddy:scan.total_attempts", str(scan.total_attempts)),
            ("qureddy:scan.started_at", scan.started_at.isoformat()),
            ("qureddy:scan.completed_at", scan.completed_at.isoformat()),
            *pairs,
        ]
    if target.sni is not None:
        pairs.append(("qureddy:target.sni", target.sni))
    for name, value in pairs:
        bom.metadata.properties.add(Property(name=name, value=value))


def _add_evidence_provenance(bom: Bom, result: ScanResult, *, reproducible: bool) -> None:
    """Attach the scan's evidence/provenance trail as namespaced metadata properties (#149).

    JSON carries `evidence[]` (source, observation_type, probe_role, and the probe_result
    command/return_code/hashes), but the CBOM dropped all of it and so could not answer
    "how do you know?". Emit one indexed block per evidence record, in deterministic scan
    order, so a CBOM consumer can audit/reproduce each observation without also parsing the
    JSON. The per-run probe duration is omitted in reproducible mode (#162).
    """
    for index, evidence in enumerate(result.evidence):
        # Zero-padded so the property names sort lexicographically in scan order
        # (evidence.02 before evidence.10), matching how CycloneDX serializes them (#147).
        prefix = f"qureddy:evidence.{index:02d}"
        pairs: list[tuple[str, str | None]] = [
            (f"{prefix}.type", evidence.evidence_type),
            (f"{prefix}.observation", evidence.observation_type.value),
            (f"{prefix}.source", evidence.source),
            (f"{prefix}.protocol_version", evidence.protocol_version),
            (f"{prefix}.cipher_suite", evidence.cipher_suite),
            (f"{prefix}.negotiated_group", evidence.negotiated_group),
            (f"{prefix}.probe_role", evidence.probe_role.value if evidence.probe_role else None),
            (f"{prefix}.expected_group", evidence.expected_group),
        ]
        probe = evidence.probe_result
        if probe is not None:
            command = " ".join([probe.command.executable, *probe.command.args])
            pairs.extend(
                [
                    (f"{prefix}.command_sha256", hashlib.sha256(command.encode()).hexdigest()),
                    (f"{prefix}.return_code", str(probe.return_code)),
                    (f"{prefix}.stdout_sha256", probe.stdout_sha256),
                    (f"{prefix}.stderr_sha256", probe.stderr_sha256),
                    (f"{prefix}.attempt_number", str(probe.attempt_number)),
                ]
            )
            if not reproducible:
                pairs.append((f"{prefix}.duration_ms", str(probe.duration_ms)))
        for name, value in pairs:
            if value is not None:
                bom.metadata.properties.add(Property(name=name, value=value))


def _add_finding_verdicts(bom: Bom, result: ScanResult) -> None:
    """Carry each finding's verdict (severity/readiness/rule) as metadata properties (#147).

    JSON's findings[] drive the posture; the CBOM previously carried only the top-level
    readiness (#132), so a consumer could not see per-finding severity or which rule fired.
    Emit one indexed block per finding; every field is deterministic (reproducible-safe).
    """
    for index, finding in enumerate(result.findings):
        prefix = f"qureddy:finding.{index:02d}"
        pairs = [
            (f"{prefix}.rule_id", finding.rule_id),
            (f"{prefix}.finding_type", finding.finding_type),
            (f"{prefix}.severity", finding.severity.value),
            (f"{prefix}.readiness", finding.readiness.value),
            (f"{prefix}.title", finding.title),
            (f"{prefix}.confidence", finding.confidence.value),
        ]
        for name, value in pairs:
            bom.metadata.properties.add(Property(name=name, value=value))


# Strongest-signal ordering: a group seen negotiated outranks one merely offered or
# observed on a control probe, so the CBOM records the actual handshake outcome (#150).
_OBSERVATION_RANK: MappingProxyType[ObservationType, int] = MappingProxyType(
    {
        ObservationType.OBSERVED: 0,
        ObservationType.OFFERED: 1,
        ObservationType.NEGOTIATED: 2,
    }
)


def _add_algorithm_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> dict[str, str]:
    """Add one cryptographic asset per unique positively observed group.

    Each component records the strongest observation seen for that group
    (`qureddy:observation`) so a consumer can tell the negotiated group from one
    merely offered or seen on a classical control probe (#150).
    """
    algorithm_refs: dict[str, str] = {}
    groups: dict[str, ObservationType] = {}
    for evidence in result.evidence:
        if evidence.observation_type in _POSITIVE_OBSERVATIONS and evidence.negotiated_group:
            seen = groups.get(evidence.negotiated_group)
            if seen is None or _OBSERVATION_RANK[evidence.observation_type] > _OBSERVATION_RANK[seen]:
                groups[evidence.negotiated_group] = evidence.observation_type
    for group in sorted(groups):
        ref = f"crypto/algorithm/{group.lower()}"
        bom.components.add(
            Component(
                name=group,
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                bom_ref=ref,
                crypto_properties=CryptoProperties(
                    asset_type=CryptoAssetType.ALGORITHM,
                    algorithm_properties=_algorithm_properties(group),
                ),
                properties=[Property(name="qureddy:observation", value=groups[group].value)],
            )
        )
        algorithm_refs[group] = ref
        provides_edges.setdefault(_ENDPOINT_REF, []).append(ref)
    return algorithm_refs


# Classical security strength (bits) of the TLS 1.3 AEAD cipher suites qureddy observes.
# AES-256-GCM and ChaCha20-Poly1305 provide 256-bit symmetric strength; AES-128-GCM, 128.
_CIPHER_SUITE_BITS: MappingProxyType[str, int] = MappingProxyType(
    {
        "TLS_AES_128_GCM_SHA256": 128,
        "TLS_AES_256_GCM_SHA384": 256,
        "TLS_CHACHA20_POLY1305_SHA256": 256,
    }
)


def _add_cipher_suite_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit the negotiated AEAD cipher suite as its own crypto asset (#150).

    JSON carries `evidence.cipher_suite`; the CBOM previously only nested it inside
    `protocolProperties.cipherSuites`, so a core symmetric asset of the connection had
    no standalone component. Each carries the strongest observation seen for it.
    """
    suites: dict[str, ObservationType] = {}
    for evidence in result.evidence:
        if evidence.observation_type in _POSITIVE_OBSERVATIONS and evidence.cipher_suite:
            seen = suites.get(evidence.cipher_suite)
            if seen is None or _OBSERVATION_RANK[evidence.observation_type] > _OBSERVATION_RANK[seen]:
                suites[evidence.cipher_suite] = evidence.observation_type
    for suite in sorted(suites):
        ref = f"crypto/algorithm/{suite.lower()}"
        bits = _CIPHER_SUITE_BITS.get(suite)
        algorithm_properties = (
            AlgorithmProperties(primitive=CryptoPrimitive.AE, classical_security_level=bits)
            if bits is not None
            else None
        )
        bom.components.add(
            Component(
                name=suite,
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                bom_ref=ref,
                crypto_properties=CryptoProperties(
                    asset_type=CryptoAssetType.ALGORITHM,
                    algorithm_properties=algorithm_properties,
                ),
                properties=[Property(name="qureddy:observation", value=suites[suite].value)],
            )
        )
        provides_edges.setdefault(_ENDPOINT_REF, []).append(ref)


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


def _add_protocol_components(
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
        provides_edges.setdefault(_ENDPOINT_REF, []).append(ref)


def _positive_protocol_evidence(result: ScanResult) -> list[Evidence]:
    """Return only positive observations that identify a protocol version."""
    return [
        evidence
        for evidence in result.evidence
        if evidence.observation_type in _POSITIVE_OBSERVATIONS and evidence.protocol_version
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

    Mirrors `_add_algorithm_components`'s per-negotiated-group pattern —
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
            crypto_properties=CryptoProperties(asset_type=CryptoAssetType.ALGORITHM),
        )
    )
    provides_edges.setdefault(_ENDPOINT_REF, []).append(ref)
    return BomRef(value=ref)


def _add_certificate_component(
    bom: Bom, certificate: CertificateObservation, provides_edges: dict[str, list[str]]
) -> None:
    """One certificate component from a real fetched+parsed cert (cert_probe.py).

    `subject_public_key_ref` (pubkey) stays unset pending an OID/key-type
    lookup table (larger, separate work — issue #190) rather than a fake
    reference. The installed library model does not expose CycloneDX 1.7's
    native ``certificateProperties.serialNumber`` field, so the final-byte
    patch adds it after typed serialization.
    """
    ref = _CERTIFICATE_REF
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
    provides_edges.setdefault(_ENDPOINT_REF, []).append(ref)


def _write_with_library_gap_patches(
    bom: Bom,
    provides_edges: dict[str, list[str]],
    certificate_serial: str | None,
    stream: IO[str],
) -> None:
    """Serialize with the library, then fill its two missing 1.7 fields."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*no defined dependencies.*")
        serialized = JsonV1Dot7(bom).output_as_string(indent=2)
    payload = json.loads(serialized)
    for dependency in payload.get("dependencies", []):
        ref = dependency.get("ref")
        if ref in provides_edges:
            dependency["provides"] = sorted(set(provides_edges[ref]))
    if certificate_serial:
        certificate_component = next(
            component
            for component in payload["components"]
            if component.get("bom-ref") == _CERTIFICATE_REF
        )
        certificate_component["cryptoProperties"]["certificateProperties"]["serialNumber"] = (
            certificate_serial
        )
    validate_cbom_semantics(payload)
    # Keep final machine bytes representable on locale-dependent Windows
    # streams. JSON consumers recover the original Unicode from escapes.
    stream.write(json.dumps(payload, indent=2, ensure_ascii=True))
    stream.write("\n")
