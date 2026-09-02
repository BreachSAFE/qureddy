# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""SSH-specific CycloneDX crypto-asset emission for the CBOM (#143).

Split out of ``cbom_components`` to keep that module under the file-size ceiling.
SSH host keys are signature algorithms, not KEX groups, so ``add_algorithm_components``
deliberately skips ``ssh.*`` evidence and these emitters handle it — each through the one
shared ``add_algorithm_assets`` loop (#288), differing only in which evidence they select
and how they classify the algorithmProperties.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cyclonedx.model import Property
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoFunction,
    CryptoPrimitive,
)

from qureddy.core import ssh_algorithms
from qureddy.output.cbom_assets import add_algorithm_assets, select_by_evidence_type
from qureddy.output.cbom_cipher import cipher_algorithm_properties, mac_algorithm_properties
from qureddy.output.cbom_components import signature_algorithm_properties

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component

    from qureddy.core.models import ScanResult


def add_ssh_server_identity_properties(endpoint: Component, result: ScanResult) -> None:
    """Copy the typed SSH server identity onto the CBOM endpoint component."""
    identities = [e for e in result.evidence if e.evidence_type == "ssh.server"]
    if not identities:
        return
    identity = identities[0]
    if identity.server_software is not None:
        endpoint.properties.add(
            Property(name="qureddy:ssh.server.software", value=identity.server_software)
        )
    if identity.server_version is not None:
        endpoint.properties.add(
            Property(name="qureddy:ssh.server.version", value=identity.server_version)
        )


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
    spec = ssh_algorithms.classify_kex(name)
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
    group name in ``negotiated_group``; a classical-only endpoint inventories its
    classical groups and a hybrid endpoint keeps its classical groups alongside the PQ
    one, each carrying the strongest observation seen.
    """
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_by_evidence_type("ssh.kex"),
        algorithm_properties=ssh_kex_algorithm_properties,
    )


def add_ssh_host_key_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit each observed SSH host-key algorithm as a signature crypto asset (#143).

    The SSH scanner records every offered host-key algorithm as ``ssh.hostkey`` evidence;
    ``add_algorithm_components`` skips those (host keys are signature algorithms, not KEX
    groups), so without this the CBOM dropped the most security-relevant SSH signal. Each
    host key is classified with the shared signature classifier — every SSH host-key
    family is classical today (nistQuantumSecurityLevel 0).
    """
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_by_evidence_type("ssh.hostkey"),
        algorithm_properties=signature_algorithm_properties,
    )


def add_ssh_transport_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit each offered SSH cipher and MAC as a crypto asset (#243).

    The SSH KEXINIT carries encryption (cipher) and MAC name-lists the scanner records as
    ``ssh.cipher`` / ``ssh.mac`` evidence; ``add_algorithm_components`` skips those SSH
    evidence types. Every current SSH cipher/MAC is classical (nistQuantumSecurityLevel 0);
    the cipher primitive comes from the shared classifier.
    """
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_by_evidence_type("ssh.cipher"),
        algorithm_properties=cipher_algorithm_properties,
    )
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=select_by_evidence_type("ssh.mac"),
        algorithm_properties=mac_algorithm_properties,
    )
