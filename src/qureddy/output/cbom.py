# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CycloneDX 1.6 CBOM output adapter (rapid prototype).

NOT the tracked MVP 0.3 implementation (qureddy#61, which explicitly
requires an ADR before code). This is a local, unmerged prototype on the
`prowler-rapid-prototype` branch to validate the shape of QuReddy-to-CBOM
mapping before that ADR is written. Do not treat this as production-ready
or spec-complete: it maps only what a TLS scan actually observes (protocol
version + negotiated group per finding), not the full CycloneDX crypto
vocabulary (no certificate/key/related-material components yet, since
QuReddy doesn't observe those until MVP 0.2/0.4).
"""

from __future__ import annotations

import sys
from typing import IO, TYPE_CHECKING

from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    CryptoAssetType,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesCipherSuite,
    ProtocolPropertiesType,
)
from cyclonedx.output.json import JsonV1Dot6

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

_PROTOCOL_TYPE_MAP = {
    "tls": ProtocolPropertiesType.TLS,
}


def render_cbom(result: ScanResult, stream: IO[str] = sys.stdout) -> None:
    """Render a ScanResult as a CycloneDX 1.6 CBOM to the given stream.

    Maps each unique (protocol, protocol_version) pair observed across
    findings to one cryptographic-asset protocol component, and each
    unique negotiated_group to one cryptographic-asset algorithm
    component, linked via the protocol's cipher-suite algorithm refs —
    mirroring the structure of the official CycloneDX CBOM examples
    (protocol -> cipherSuite -> algorithms).
    """
    bom = Bom()

    algorithm_refs: dict[str, str] = {}
    for group in sorted({f.negotiated_group for f in result.findings if f.negotiated_group}):
        bom_ref = f"crypto/algorithm/{group.lower()}"
        algo_component = Component(
            name=group,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=bom_ref,
            crypto_properties=CryptoProperties(asset_type=CryptoAssetType.ALGORITHM),
        )
        bom.components.add(algo_component)
        algorithm_refs[group] = bom_ref

    seen_protocols: set[tuple[str, str]] = set()
    for finding in result.findings:
        if not finding.protocol_version:
            continue
        key = (finding.protocol, finding.protocol_version)
        if key in seen_protocols:
            continue
        seen_protocols.add(key)

        cipher_suites = None
        group_refs = [
            algorithm_refs[f.negotiated_group]
            for f in result.findings
            if f.protocol_version == finding.protocol_version and f.negotiated_group
        ]
        if group_refs:
            cipher_suites = [
                ProtocolPropertiesCipherSuite(
                    name=f"{finding.protocol_version} negotiated groups",
                    algorithms=[BomRef(value=ref) for ref in group_refs],
                )
            ]

        proto_component = Component(
            name=finding.protocol_version,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=f"crypto/protocol/{finding.protocol}-{finding.protocol_version.lower()}",
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.PROTOCOL,
                protocol_properties=ProtocolProperties(
                    type=_PROTOCOL_TYPE_MAP.get(finding.protocol),
                    version=finding.protocol_version,
                    cipher_suites=cipher_suites,
                ),
            ),
        )
        bom.components.add(proto_component)

    bom.metadata.component = Component(
        name=f"qureddy-scan-{result.target.host}",
        type=ComponentType.APPLICATION,
        version=result.scan.scanner_version,
    )

    outputter = JsonV1Dot6(bom)
    stream.write(outputter.output_as_string(indent=2))
    stream.write("\n")
