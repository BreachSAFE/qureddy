# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CycloneDX 1.6 CBOM output adapter — MVP 0.3.

Schema decision locked in ADR 0005 (docs/contributors/adr/0005-cbom-schema-source-of-truth.md,
qureddy#61): emit CycloneDX 1.6 verbatim via `cyclonedx-python-lib`'s native model
classes, never a hand-rolled or forked dialect. A CBOM emitted by this module has
been independently validated against the official CycloneDX 1.6 JSON Schema with
zero violations (ADR 0005's Evidence section) and round-trips through Qurum's real
parser, not just this repo's own tests.

Closes the two gaps found when this output was piped through Qurum
(qurum cbom --knowledge): every asset came back with crypto_library_name
and crypto_library_version = UNKNOWN, because the library-linkage graph
was never emitted. Qurum's `_linked_libraries` (src/qurum/cbom.py) looks
for: product --dependsOn--> library component --provides--> crypto asset.
`cyclonedx-python-lib`'s Python API (`Bom.register_dependency`) exposes
`depends_on` but not `provides` — confirmed via `inspect.signature`, this
is a real gap in the library's Python bindings, not an oversight here.
Worked around with a documented, minimal raw-JSON patch for the one
missing edge type rather than avoiding the fix or hand-rolling full BOM
serialization.

ANTIPATTERN ACCEPTED: raw-json-post-processing, because
`cyclonedx-python-lib`'s `Bom.register_dependency` has no `provides`
parameter (confirmed via `inspect.signature(Dependency.__init__)` — only
`ref`/`dependencies` exist) despite `provides` being valid CycloneDX 1.6.
The alternative is hand-rolling BOM serialization ourselves, which is
strictly worse: it reintroduces exactly the schema-drift risk the library
exists to prevent. This patch touches only the one field the library
doesn't expose; everything else stays fully delegated to `JsonV1Dot6`.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from typing import IO, TYPE_CHECKING

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
from cyclonedx.output.json import JsonV1Dot6

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult
    from qureddy.scanners.tls.cert_probe import CertificateInfo

_ENDPOINT_REF = "endpoint"
_LIBRARY_REF = "crypto-library/openssl"


def render_cbom(
    result: ScanResult,
    stream: IO[str] = sys.stdout,
    certificate: CertificateInfo | None = None,
) -> None:
    """Render a ScanResult (+ optional fetched certificate) as a CycloneDX 1.6 CBOM."""
    bom = Bom()
    provides_edges: dict[str, list[str]] = {}

    # The endpoint IS the metadata.component (the "product" this BOM describes),
    # not a separate node — Qurum's dependency traversal starts from
    # metadata.component's own bom-ref, so a disconnected endpoint node never
    # gets found. Confirmed by testing: a separate node left crypto_library_name
    # UNKNOWN even with a correct dependsOn/provides graph elsewhere.
    endpoint = Component(
        name=f"{result.target.host}:{result.target.port}",
        type=ComponentType.APPLICATION,
        bom_ref=_ENDPOINT_REF,
        version=result.scan.scanner_version,
    )
    bom.components.add(endpoint)
    bom.metadata.component = endpoint
    _add_scan_status_properties(bom, result)

    algorithm_refs = _add_algorithm_components(bom, result, provides_edges)
    _add_protocol_components(bom, result, algorithm_refs, provides_edges)
    if certificate is not None:
        _add_certificate_component(bom, certificate, provides_edges)

    if result.dependencies:
        dep = result.dependencies[0]
        library = Component(
            name=dep.name,
            type=ComponentType.LIBRARY,
            bom_ref=_LIBRARY_REF,
            version=dep.version,
        )
        bom.components.add(library)
        bom.register_dependency(endpoint, [library])
        provides_edges[_LIBRARY_REF] = list(provides_edges.get(_LIBRARY_REF, []))

    _write_with_provides(bom, provides_edges, stream)


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
    """One cryptographic-asset component per unique negotiated group. Registers each as provided by the OpenSSL library so Qurum can resolve crypto_library_name."""
    algorithm_refs: dict[str, str] = {}
    for group in sorted({f.negotiated_group for f in result.findings if f.negotiated_group}):
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
        provides_edges.setdefault(_LIBRARY_REF, []).append(ref)
    return algorithm_refs


def _add_protocol_components(
    bom: Bom,
    result: ScanResult,
    algorithm_refs: dict[str, str],
    provides_edges: dict[str, list[str]],
) -> None:
    """One protocol component per unique (protocol, version), cipher suite named from real Evidence.cipher_suite (not a synthetic placeholder)."""
    real_cipher_suite = next((e.cipher_suite for e in result.evidence if e.cipher_suite), None)
    seen: set[tuple[str, str]] = set()
    for finding in result.findings:
        if not finding.protocol_version or (finding.protocol, finding.protocol_version) in seen:
            continue
        seen.add((finding.protocol, finding.protocol_version))

        group_refs = [
            algorithm_refs[f.negotiated_group]
            for f in result.findings
            if f.protocol_version == finding.protocol_version and f.negotiated_group
        ]
        cipher_suites = (
            [
                ProtocolPropertiesCipherSuite(
                    name=real_cipher_suite or f"{finding.protocol_version} negotiated groups",
                    algorithms=[BomRef(value=ref) for ref in group_refs],
                )
            ]
            if group_refs
            else None
        )
        ref = f"crypto/protocol/{finding.protocol}-{finding.protocol_version.lower()}"
        bom.components.add(
            Component(
                name=finding.protocol_version,
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                bom_ref=ref,
                crypto_properties=CryptoProperties(
                    asset_type=CryptoAssetType.PROTOCOL,
                    protocol_properties=ProtocolProperties(
                        type=ProtocolPropertiesType.TLS if finding.protocol == "tls" else None,
                        version=finding.protocol_version,
                        cipher_suites=cipher_suites,
                    ),
                ),
            )
        )
        provides_edges.setdefault(_LIBRARY_REF, []).append(ref)


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
    provides_edges.setdefault(_LIBRARY_REF, []).append(ref)
    return BomRef(value=ref)


def _add_certificate_component(
    bom: Bom, certificate: CertificateInfo, provides_edges: dict[str, list[str]]
) -> None:
    """One certificate component from a real fetched+parsed cert (cert_probe.py).

    `subject_public_key_ref` (pubkey) stays unset pending an OID/key-type
    lookup table (larger, separate work — issue #190) rather than a fake
    reference. `serial` has no home in CycloneDX 1.6's `certificateProperties`
    at all (confirmed: not present in the installed library's schema) — kept
    as a `qureddy:certificate.serial` component property instead of silently
    dropped, same extension-point pattern as `_add_scan_status_properties`.
    """
    ref = "crypto/certificate/leaf"
    sig_alg_ref = _add_signature_algorithm_component(
        bom, certificate.signature_algorithm, provides_edges
    )
    properties = (
        [Property(name="qureddy:certificate.serial", value=certificate.serial)]
        if certificate.serial
        else []
    )
    bom.components.add(
        Component(
            name=certificate.subject,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=ref,
            properties=properties,
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
    provides_edges.setdefault(_LIBRARY_REF, []).append(ref)


def _write_with_provides(bom: Bom, provides_edges: dict[str, list[str]], stream: IO[str]) -> None:
    """Serialize via the library, then patch in `provides` edges the Python API doesn't expose. Documented gap, not a silent hack: see module docstring."""
    payload = json.loads(JsonV1Dot6(bom).output_as_string(indent=2))
    for dependency in payload.get("dependencies", []):
        ref = dependency.get("ref")
        if ref in provides_edges:
            dependency["provides"] = provides_edges[ref]
    stream.write(json.dumps(payload, indent=2))
    stream.write("\n")
