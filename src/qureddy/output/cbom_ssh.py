# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""SSH-specific CycloneDX crypto-asset emission for the CBOM (#143).

Split out of ``cbom_components`` to keep that module under the file-size ceiling.
SSH host keys are signature algorithms, not KEX groups, so ``add_algorithm_components``
deliberately skips ``ssh.hostkey`` evidence and this module emits it instead — the
rendered CBOM is unchanged in intent, only reorganized.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cyclonedx.model import Property
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
)

from qureddy.output.cbom_components import (
    ENDPOINT_REF,
    OBSERVATION_RANK,
    POSITIVE_OBSERVATIONS,
    signature_algorithm_properties,
)
from qureddy.scanners.ssh import classify

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import ObservationType, ScanResult

# CycloneDX cryptoFunctions per KEX primitive: a KEM does keygen/encapsulate/
# decapsulate; a Diffie-Hellman/ECDH key-agreement does keygen; RSA key transport
# (PKE) encapsulates/decapsulates a transported key.
_CRYPTO_FUNCTIONS: dict[str, list[CryptoFunction]] = {
    "kem": [CryptoFunction.KEYGEN, CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE],
    "key-agree": [CryptoFunction.KEYGEN],
    "pke": [CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE],
}


def ssh_kex_algorithm_properties(name: str) -> AlgorithmProperties | None:
    """Structured algorithmProperties for one SSH KEX group (#241).

    A PQ hybrid/standalone KEX (``mlkem768x25519-sha256``, ``mlkem768nistp256-sha256``,
    ``sntrup761x25519-sha512``, the kyber/AWS/OQS variants) becomes the KEM primitive
    carrying its ``nistQuantumSecurityLevel`` so the one PQ-relevant asset is no longer a
    bare component; a classical group is honest key-agreement/key-transport at level 0.
    An unclassifiable name keeps a minimal (empty) algorithmProperties rather than a
    fabricated primitive/level. Classification (name -> primitive/level) lives in the SSH
    ``classify`` module; this only maps it onto the CycloneDX model.
    """
    spec = classify.classify_kex(name)
    if spec is None:
        return None
    return AlgorithmProperties(
        primitive=CryptoPrimitive(spec.primitive),
        parameter_set_identifier=spec.parameter_set_identifier,
        curve=spec.curve,
        crypto_functions=_CRYPTO_FUNCTIONS[spec.primitive],
        nist_quantum_security_level=spec.nist_quantum_security_level,
    )


def add_ssh_kex_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit one crypto-asset component per offered SSH KEX group (#241/#242).

    The SSH scanner records every offered KEX group as ``ssh.kex`` evidence with the
    group name in ``negotiated_group``. The shared TLS-oriented emitter skips SSH KEX
    so this classifies each with the SSH KEX-name classifier: a classical-only endpoint
    now inventories its classical groups (previously zero KEX components) and a hybrid
    endpoint keeps its classical groups alongside the PQ one. Each carries the strongest
    observation seen, mirroring the KEX/cipher/host-key assets.
    """
    groups: dict[str, ObservationType] = {}
    for evidence in result.evidence:
        if (
            evidence.evidence_type == "ssh.kex"
            and evidence.observation_type in POSITIVE_OBSERVATIONS
            and evidence.negotiated_group
        ):
            seen = groups.get(evidence.negotiated_group)
            if seen is None or OBSERVATION_RANK[evidence.observation_type] > OBSERVATION_RANK[seen]:
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
                    algorithm_properties=ssh_kex_algorithm_properties(group),
                ),
                properties=[Property(name="qureddy:observation", value=groups[group].value)],
            )
        )
        provides_edges.setdefault(ENDPOINT_REF, []).append(ref)


def add_ssh_host_key_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit each observed SSH host-key algorithm as a signature crypto asset (#143).

    The SSH scanner records every offered host-key algorithm as ``ssh.hostkey``
    evidence. ``add_algorithm_components`` skips those (host keys are signature
    algorithms, not KEX groups), so without this the CBOM dropped host keys entirely
    — the most security-relevant SSH signal was observed yet absent from the
    inventory. Each host key is classified with the shared signature classifier,
    honestly: every SSH host-key family is classical today (nistQuantumSecurityLevel
    0). Each carries the strongest observation seen, mirroring the KEX/cipher assets.
    """
    host_keys: dict[str, ObservationType] = {}
    for evidence in result.evidence:
        if (
            evidence.evidence_type == "ssh.hostkey"
            and evidence.observation_type in POSITIVE_OBSERVATIONS
            and evidence.negotiated_group
        ):
            seen = host_keys.get(evidence.negotiated_group)
            if seen is None or OBSERVATION_RANK[evidence.observation_type] > OBSERVATION_RANK[seen]:
                host_keys[evidence.negotiated_group] = evidence.observation_type
    for host_key in sorted(host_keys):
        ref = f"crypto/algorithm/{host_key.lower()}"
        bom.components.add(
            Component(
                name=host_key,
                type=ComponentType.CRYPTOGRAPHIC_ASSET,
                bom_ref=ref,
                crypto_properties=CryptoProperties(
                    asset_type=CryptoAssetType.ALGORITHM,
                    algorithm_properties=signature_algorithm_properties(host_key),
                ),
                properties=[Property(name="qureddy:observation", value=host_keys[host_key].value)],
            )
        )
        provides_edges.setdefault(ENDPOINT_REF, []).append(ref)


def _add_transport_component(
    bom: Bom,
    provides_edges: dict[str, list[str]],
    name: str,
    observation: ObservationType,
    primitive: CryptoPrimitive,
) -> None:
    """Add one SSH cipher/MAC as a classical crypto asset (level 0), mirroring host keys."""
    ref = f"crypto/algorithm/{name.lower()}"
    bom.components.add(
        Component(
            name=name,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=ref,
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.ALGORITHM,
                algorithm_properties=AlgorithmProperties(
                    primitive=primitive,
                    nist_quantum_security_level=0,
                ),
            ),
            properties=[Property(name="qureddy:observation", value=observation.value)],
        )
    )
    provides_edges.setdefault(ENDPOINT_REF, []).append(ref)


def add_ssh_transport_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit each offered SSH cipher and MAC as a crypto asset (#243).

    The SSH KEXINIT carries encryption (cipher) and MAC name-lists the scanner now
    records as ``ssh.cipher`` / ``ssh.mac`` evidence; ``add_algorithm_components``
    skips those SSH evidence types, so they were absent from the CBOM while the TLS
    path emits its AEAD cipher-suite asset. Every current SSH cipher/MAC is classical
    (nistQuantumSecurityLevel 0); the CBOM primitive comes from the shared classifier.
    """
    ciphers: dict[str, ObservationType] = {}
    macs: dict[str, ObservationType] = {}
    for evidence in result.evidence:
        if evidence.observation_type not in POSITIVE_OBSERVATIONS or not evidence.negotiated_group:
            continue
        if evidence.evidence_type == "ssh.cipher":
            bucket = ciphers
        elif evidence.evidence_type == "ssh.mac":
            bucket = macs
        else:
            continue
        name = evidence.negotiated_group
        seen = bucket.get(name)
        if seen is None or OBSERVATION_RANK[evidence.observation_type] > OBSERVATION_RANK[seen]:
            bucket[name] = evidence.observation_type
    for name in sorted(ciphers):
        primitive = CryptoPrimitive(classify.cipher_primitive(name))
        _add_transport_component(bom, provides_edges, name, ciphers[name], primitive)
    for name in sorted(macs):
        _add_transport_component(bom, provides_edges, name, macs[name], CryptoPrimitive.MAC)
