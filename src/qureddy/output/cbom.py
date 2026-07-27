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

import json
import re
import sys
import warnings
from datetime import UTC, datetime
from typing import IO, TYPE_CHECKING, Any

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    CertificateProperties,
    CryptoAssetType,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesCipherSuite,
    ProtocolPropertiesType,
)
from cyclonedx.model.tool import ToolRepository
from cyclonedx.output.json import JsonV1Dot7

from qureddy.core.models import ObservationType, ScanResult

if TYPE_CHECKING:
    from qureddy.core.certificate import CertificateObservation

_ENDPOINT_REF = "endpoint"
_QUREDDY_TOOL_REF = "tool/qureddy"
_OPENSSL_TOOL_REF = "tool/openssl"
_CERTIFICATE_REF = "crypto/certificate/leaf"
_POSITIVE_OBSERVATIONS = frozenset(
    {ObservationType.NEGOTIATED, ObservationType.OFFERED, ObservationType.OBSERVED}
)
_SECRET_PATTERNS = (
    re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        re.IGNORECASE,
    ),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_SECRET_FIELD = re.compile(
    r"^(?:access[_ -]?token|refresh[_ -]?token|api[_ -]?key|session[_ -]?key|"
    r"password|credential|secret)$",
    re.IGNORECASE,
)


def render_cbom(
    result: ScanResult,
    stream: IO[str] | None = None,
) -> None:
    """Render typed scan observations as CycloneDX 1.7.

    Issue #239: `stream: IO[str] = sys.stdout` as a default is resolved
    once at function-definition time, not per call — same root cause as
    #237/#238. Resolve at call time instead.
    """
    target_stream = stream if stream is not None else sys.stdout
    bom = Bom()
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
    _add_tool_provenance(bom, result)
    _add_scan_status_properties(bom, result)

    algorithm_refs = _add_algorithm_components(bom, result, provides_edges)
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


def _add_tool_provenance(bom: Bom, result: ScanResult) -> None:
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
                properties=[
                    Property(
                        name="qureddy:collector.role",
                        value="local-probe-runtime",
                    )
                ],
            )
        )
    bom.metadata.tools = ToolRepository(components=tools)


def _add_scan_status_properties(bom: Bom, result: ScanResult) -> None:
    """Mirror scan.status/summary.failure_category onto bom.metadata.properties.

    `bom.metadata.properties` is the standard CycloneDX extension point.
    Without this, a CBOM from a hard-failed scan (e.g. tls_handshake_failed)
    is structurally indistinguishable from a successful-but-sparse one —
    both can contain a real, valid certificate component (the certificate
    probe in cli.py runs independently of the main scan's forced-group
    probes and can succeed even when they fail), and there was previously
    no field anywhere in the CBOM itself recording that the scan failed.
    A consumer that stores/forwards only the CBOM JSON (no external exit
    code) had no way to tell these apart (issue #195).
    """
    bom.metadata.properties.add(Property(name="qureddy:scan.status", value=result.scan.status))
    if result.summary.failure_category is not None:
        bom.metadata.properties.add(
            Property(
                name="qureddy:scan.failure_category",
                value=result.summary.failure_category.value,
            )
        )


def _add_algorithm_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> dict[str, str]:
    """Add one cryptographic asset per unique positively observed group."""
    algorithm_refs: dict[str, str] = {}
    groups = {
        evidence.negotiated_group
        for evidence in result.evidence
        if evidence.observation_type in _POSITIVE_OBSERVATIONS and evidence.negotiated_group
    }
    for group in sorted(groups):
        ref = f"crypto/algorithm/{group.lower()}"
        bom.components.add(
            Component(
                name=group,
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                bom_ref=ref,
                crypto_properties=CryptoProperties(asset_type=CryptoAssetType.ALGORITHM),
            )
        )
        algorithm_refs[group] = ref
        provides_edges.setdefault(_ENDPOINT_REF, []).append(ref)
    return algorithm_refs


def _add_protocol_components(
    bom: Bom,
    result: ScanResult,
    algorithm_refs: dict[str, str],
    provides_edges: dict[str, list[str]],
) -> None:
    """Add one protocol asset per unique observed protocol and version."""
    positive_evidence = [
        evidence
        for evidence in result.evidence
        if evidence.observation_type in _POSITIVE_OBSERVATIONS and evidence.protocol_version
    ]
    protocol_versions: set[tuple[str, str]] = set()
    for evidence in positive_evidence:
        if evidence.protocol_version is not None:
            protocol_versions.add((evidence.protocol, evidence.protocol_version))
    for protocol, protocol_version in sorted(protocol_versions):
        matching = [
            evidence
            for evidence in positive_evidence
            if (evidence.protocol, evidence.protocol_version) == (protocol, protocol_version)
        ]
        cipher_suites = []
        for cipher_suite in sorted(
            {evidence.cipher_suite for evidence in matching if evidence.cipher_suite}
        ):
            group_refs = sorted(
                {
                    algorithm_refs[evidence.negotiated_group]
                    for evidence in matching
                    if evidence.cipher_suite == cipher_suite
                    and evidence.negotiated_group in algorithm_refs
                }
            )
            cipher_suites.append(
                ProtocolPropertiesCipherSuite(
                    name=cipher_suite,
                    algorithms=[BomRef(value=ref) for ref in group_refs] or None,
                )
            )
        ref = f"crypto/protocol/{protocol}-{protocol_version.lower()}"
        bom.components.add(
            Component(
                name=protocol_version,
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                bom_ref=ref,
                crypto_properties=CryptoProperties(
                    asset_type=CryptoAssetType.PROTOCOL,
                    protocol_properties=ProtocolProperties(
                        type=(
                            ProtocolPropertiesType.TLS
                            if protocol == "tls"
                            else ProtocolPropertiesType.SSH
                            if protocol == "ssh"
                            else None
                        ),
                        version=protocol_version,
                        cipher_suites=cipher_suites or None,
                    ),
                ),
            )
        )
        provides_edges.setdefault(_ENDPOINT_REF, []).append(ref)


def _parse_openssl_date(text: str) -> datetime | None:
    """Parse `openssl x509 -dates` output (e.g. "Jul 17 07:18:11 2026 GMT").

    Returns None on anything unparseable rather than raising — a date
    the CBOM can't represent should degrade to "absent from this CBOM",
    not abort rendering the rest of a real, otherwise-valid certificate.
    OpenSSL always reports these in GMT (== UTC); `%Z` doesn't set
    tzinfo on its own in `strptime`, so UTC is attached explicitly to
    satisfy the project's timezone-aware-datetime rule.
    """
    if not text:
        return None
    try:
        return datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
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
    _validate_cbom_semantics(payload)
    # Keep final machine bytes representable on locale-dependent Windows
    # streams. JSON consumers recover the original Unicode from escapes.
    stream.write(json.dumps(payload, indent=2, ensure_ascii=True))
    stream.write("\n")


def _validate_cbom_semantics(payload: dict[str, Any]) -> None:
    """Reject semantic defects that schema validators do not consistently catch."""
    if payload.get("specVersion") != "1.7":
        msg = "CBOM specVersion must be exactly 1.7"
        raise ValueError(msg)

    metadata_component = payload.get("metadata", {}).get("component", {})
    graph_refs = [metadata_component.get("bom-ref")]
    graph_refs.extend(component.get("bom-ref") for component in payload.get("components", []))
    tool_refs = [
        tool.get("bom-ref")
        for tool in payload.get("metadata", {}).get("tools", {}).get("components", [])
    ]
    declared_refs = [ref for ref in (*graph_refs, *tool_refs) if isinstance(ref, str)]
    duplicates = sorted({ref for ref in declared_refs if declared_refs.count(ref) > 1})
    if duplicates:
        msg = f"duplicate bom-ref values: {', '.join(duplicates)}"
        raise ValueError(msg)

    known_refs = {ref for ref in graph_refs if isinstance(ref, str)}
    dangling: set[str] = set()
    for dependency in payload.get("dependencies", []):
        dependency_ref = dependency.get("ref")
        if isinstance(dependency_ref, str) and dependency_ref not in known_refs:
            dangling.add(dependency_ref)
        for edge_name in ("dependsOn", "provides"):
            for ref in dependency.get(edge_name, []):
                if isinstance(ref, str) and ref not in known_refs:
                    dangling.add(ref)
    if dangling:
        msg = f"dangling dependency references: {', '.join(sorted(dangling))}"
        raise ValueError(msg)

    if _contains_secret_like_material(payload):
        msg = "CBOM contains secret-like material"
        raise ValueError(msg)


def _contains_secret_like_material(value: object) -> bool:
    """Detect key blocks, token shapes, and populated secret-named fields."""
    if isinstance(value, dict):
        populated_secret_field = any(
            _SECRET_FIELD.fullmatch(str(key)) and nested not in (None, "", [], {})
            for key, nested in value.items()
        )
        property_name = value.get("name")
        populated_secret_property = (
            isinstance(property_name, str)
            and _SECRET_FIELD.fullmatch(property_name) is not None
            and value.get("value") not in (None, "", [], {})
        )
        return (
            populated_secret_field
            or populated_secret_property
            or any(_contains_secret_like_material(nested) for nested in value.values())
        )
    if isinstance(value, list):
        return any(_contains_secret_like_material(item) for item in value)
    if isinstance(value, str):
        return any(pattern.search(value) for pattern in _SECRET_PATTERNS)
    return False
