# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Render scan observations as a CycloneDX 1.7 CBOM.

The official CycloneDX model is the output contract. QuReddy and its local
OpenSSL runtime are collection-tool provenance under ``metadata.tools``;
neither is attributed to the remote endpoint. The endpoint is the stable
``metadata.component`` root and provides the cryptographic assets QuReddy
positively observed.

The ``qureddy:``-namespaced ``metadata.properties`` emitters live in
``cbom_metadata`` and the CycloneDX crypto-asset component builders live in
``cbom_components``; this module keeps ``render_cbom`` orchestration plus the
library-gap write patches (#171).

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
import sys
import warnings
from typing import IO, TYPE_CHECKING, Any

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.tool import ToolRepository
from cyclonedx.output.json import JsonV1Dot7

from qureddy.core.models import ObservationType, ScanResult
from qureddy.output.cbom_assets import ENDPOINT_REF
from qureddy.output.cbom_components import (
    CERTIFICATE_REF,
    add_algorithm_components,
    add_certificate_component,
    add_cipher_suite_components,
    add_protocol_components,
)
from qureddy.output.cbom_legacy import add_legacy_cipher_components
from qureddy.output.cbom_metadata import (
    add_scan_status_properties,
    add_scan_target_metadata,
    evidence_occurrences,
    finding_annotations,
    openssl_tool_properties,
)
from qureddy.output.cbom_semantics import validate_cbom_semantics
from qureddy.output.cbom_ssh import (
    add_ssh_host_key_components,
    add_ssh_kex_components,
    add_ssh_transport_components,
)

if TYPE_CHECKING:
    from qureddy.core.certificate import CertificateObservation

_QUREDDY_TOOL_REF = "tool/qureddy"
_OPENSSL_TOOL_REF = "tool/openssl"


def render_cbom(
    result: ScanResult,
    stream: IO[str] | None = None,
    *,
    reproducible: bool = False,
    compact: bool = False,
) -> None:
    """Render typed scan observations as CycloneDX 1.7.

    Issue #239: `stream: IO[str] = sys.stdout` as a default is resolved
    once at function-definition time, not per call — same root cause as
    #237/#238. Resolve at call time instead.

    When ``reproducible`` is set, the per-run identity fields (the CycloneDX
    serialNumber and metadata.timestamp, plus the scan id and start/finish
    times) are omitted so the same scan is byte- and digest-reproducible for
    content addressing (#162). The observed crypto content is unchanged.

    When ``compact`` is set the final document is minified to a single line
    (issue #133); the default stays indent=2. Either way exactly one parseable
    CycloneDX document plus a trailing newline is written (issue #30).
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
        bom_ref=ENDPOINT_REF,
    )
    bom.metadata.component = endpoint
    _add_tool_provenance(bom, result, reproducible=reproducible)
    add_scan_status_properties(bom, result)
    add_scan_target_metadata(bom, result, reproducible=reproducible)

    algorithm_refs = add_algorithm_components(bom, result, provides_edges)
    add_ssh_host_key_components(bom, result, provides_edges)
    add_ssh_kex_components(bom, result, provides_edges)
    add_ssh_transport_components(bom, result, provides_edges)
    add_cipher_suite_components(bom, result, provides_edges)
    add_legacy_cipher_components(bom, result, provides_edges)
    add_protocol_components(bom, result, algorithm_refs, provides_edges)
    certificate = _captured_certificate(result)
    if certificate is not None:
        add_certificate_component(bom, certificate, provides_edges)

    bom.register_dependency(endpoint)
    _write_with_library_gap_patches(
        bom,
        provides_edges,
        certificate.serial if certificate is not None else None,
        target_stream,
        result=result,
        reproducible=reproducible,
        compact=compact,
    )


def _observed_certificates(result: ScanResult) -> list[CertificateObservation]:
    """Certificates captured by OBSERVED evidence, in evidence order."""
    return [
        evidence.certificate
        for evidence in result.evidence
        if evidence.observation_type is ObservationType.OBSERVED
        and evidence.certificate is not None
    ]


def _captured_certificate(result: ScanResult) -> CertificateObservation | None:
    """Return the certificate already captured by the scan, never refetch it."""
    observations = _observed_certificates(result)
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
                properties=openssl_tool_properties(dependency, reproducible=reproducible),
            )
        )
    bom.metadata.tools = ToolRepository(components=tools)


def _apply_native_to_component(
    component: dict[str, Any],
    occurrences: dict[str, list[dict[str, str]]],
    verdicts: dict[str, list[dict[str, str]]],
) -> None:
    """Attach evidence occurrences and verdict properties to a single component dict."""
    ref = component.get("bom-ref")
    if ref in occurrences:
        component["evidence"] = {"occurrences": occurrences[ref]}
    if ref in verdicts:
        component.setdefault("properties", []).extend(verdicts[ref])


def _reanchor_annotations(payload: dict[str, Any], annotations: list[dict[str, Any]]) -> None:
    """Re-anchor annotation subjects to the endpoint when their asset has no component.

    A finding's subject asset only exists as a component when the scan also produced its
    evidence; if it doesn't (e.g. a finding with no matching inventory), re-anchor the
    annotation to the endpoint so no subject dangles.
    """
    real_refs = {ENDPOINT_REF} | {c.get("bom-ref") for c in payload.get("components", [])}
    for annotation in annotations:
        annotation["subjects"] = [
            ref if ref in real_refs else ENDPOINT_REF for ref in annotation["subjects"]
        ]
    payload["annotations"] = annotations


def _attach_native_findings(
    payload: dict[str, Any], result: ScanResult, *, reproducible: bool
) -> None:
    """Attach evidence occurrences + verdict properties to components and add annotations.

    The library model does not expose 1.7's ``component.evidence.occurrences`` or top-level
    ``annotations``, so — like the ``provides``/``serialNumber`` gaps — they are patched into
    the serialized dict (#287). Evidence lives on the asset it describes; findings become
    subject-linked annotations; the machine verdict rides as queryable component properties.
    """
    occurrences = evidence_occurrences(result, reproducible=reproducible)
    annotations, verdicts = finding_annotations(result, reproducible=reproducible)

    endpoint = payload.get("metadata", {}).get("component")
    if endpoint:
        _apply_native_to_component(endpoint, occurrences, verdicts)
    for component in payload.get("components", []):
        _apply_native_to_component(component, occurrences, verdicts)
    if annotations:
        _reanchor_annotations(payload, annotations)


def _write_with_library_gap_patches(
    bom: Bom,
    provides_edges: dict[str, list[str]],
    certificate_serial: str | None,
    stream: IO[str],
    *,
    result: ScanResult,
    reproducible: bool = False,
    compact: bool = False,
) -> None:
    """Serialize with the library, then fill the 1.7 fields it does not expose.

    The library serialization is only an intermediate parsed back into a dict,
    so its indentation is irrelevant; the final ``json.dumps`` controls the
    emitted layout — indented by default, single-line minified when ``compact``.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=".*no defined dependencies.*")
        serialized = JsonV1Dot7(bom).output_as_string(indent=2)
    payload = json.loads(serialized)
    _assert_library_serialization_shape(payload, certificate_serial is not None)
    _patch_provides_edges(payload, provides_edges)
    if certificate_serial:
        _patch_certificate_serial(payload, certificate_serial)
    _attach_native_findings(payload, result, reproducible=reproducible)
    validate_cbom_semantics(payload)
    _write_payload(stream, payload, compact=compact)


def _assert_library_serialization_shape(payload: dict[str, Any], has_certificate: bool) -> None:
    """Fail closed if the library's intermediate JSON shape changes (#306).

    The four CycloneDX 1.7 fields patched below are intentionally outside the
    installed library model. This guard turns a library upgrade from silent
    data loss into an actionable test/runtime failure.
    """
    dependencies = payload.get("dependencies", [])
    components = payload.get("components", [])
    _assert_library_collections(dependencies, components)
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("component"), dict):
        raise RuntimeError("cyclonedx-python-lib JSON shape changed: metadata.component")
    if has_certificate:
        _assert_certificate_shape(components)


def _assert_library_collections(dependencies: Any, components: Any) -> None:
    """Validate the collection and reference shapes consumed by gap patches."""
    if not isinstance(dependencies, list) or not isinstance(components, list):
        raise RuntimeError("cyclonedx-python-lib JSON shape changed: dependencies/components")
    if any(
        not isinstance(item, dict) or not isinstance(item.get("ref"), str) for item in dependencies
    ):
        raise RuntimeError("cyclonedx-python-lib JSON shape changed: dependency.ref")
    if any(
        not isinstance(item, dict) or not isinstance(item.get("bom-ref"), str)
        for item in components
    ):
        raise RuntimeError("cyclonedx-python-lib JSON shape changed: component.bom-ref")


def _assert_certificate_shape(components: list[Any]) -> None:
    """Validate the nested certificate path used for serialNumber patching."""
    certificate = next(
        (item for item in components if item.get("bom-ref") == CERTIFICATE_REF), None
    )
    if not isinstance(certificate, dict):
        raise RuntimeError("cyclonedx-python-lib JSON shape changed: certificate component")
    crypto_properties = certificate.get("cryptoProperties")
    certificate_properties = (
        crypto_properties.get("certificateProperties")
        if isinstance(crypto_properties, dict)
        else None
    )
    if not isinstance(certificate_properties, dict):
        raise RuntimeError("cyclonedx-python-lib JSON shape changed: certificateProperties")


def _patch_provides_edges(payload: dict[str, Any], provides_edges: dict[str, list[str]]) -> None:
    """Fill in each dependency's 1.7 ``provides`` edge (library has no such parameter)."""
    for dependency in payload.get("dependencies", []):
        ref = dependency.get("ref")
        if ref in provides_edges:
            dependency["provides"] = sorted(set(provides_edges[ref]))


def _patch_certificate_serial(payload: dict[str, Any], certificate_serial: str) -> None:
    """Fill in the certificate component's 1.7 native ``serialNumber`` field."""
    certificate_component = next(
        component
        for component in payload["components"]
        if component.get("bom-ref") == CERTIFICATE_REF
    )
    certificate_component["cryptoProperties"]["certificateProperties"]["serialNumber"] = (
        certificate_serial
    )


def _write_payload(stream: IO[str], payload: dict[str, Any], *, compact: bool) -> None:
    """Emit the final CBOM bytes plus a trailing newline.

    Keep final machine bytes representable on locale-dependent Windows streams. JSON
    consumers recover the original Unicode from escapes.
    """
    if compact:
        stream.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=True))
    else:
        stream.write(json.dumps(payload, indent=2, ensure_ascii=True))
    stream.write("\n")
