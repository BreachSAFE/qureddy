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

from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoFunction,
    CryptoPrimitive,
)

from qureddy.output.cbom_assets import add_algorithm_assets
from qureddy.output.cbom_components import signature_algorithm_properties
from qureddy.scanners.ssh import classify

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import ScanResult

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
    group name in ``negotiated_group``; a classical-only endpoint inventories its
    classical groups and a hybrid endpoint keeps its classical groups alongside the PQ
    one, each carrying the strongest observation seen.
    """
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=lambda e: e.negotiated_group if e.evidence_type == "ssh.kex" else None,
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
        select=lambda e: e.negotiated_group if e.evidence_type == "ssh.hostkey" else None,
        algorithm_properties=signature_algorithm_properties,
    )


def _ssh_cipher_bits(name: str) -> int | None:
    """Classical key strength (bits) for an SSH cipher, or None if unknown (#286)."""
    lowered = name.lower()
    if "chacha20" in lowered:
        return 256
    if "3des" in lowered:
        return 112  # 3DES effective strength (NIST SP 800-57)
    for size in (256, 192, 128):
        if f"aes{size}" in lowered or f"aes-{size}" in lowered:
            return size
    return None


def _ssh_cipher_properties(name: str) -> AlgorithmProperties:
    """Build algorithmProperties for an SSH cipher (#286).

    Symmetric ciphers are quantum-resistant, so emit ``classicalSecurityLevel`` — the
    same representation the TLS AEAD cipher suites use — rather than a misleading
    ``nistQuantumSecurityLevel: 0`` that reads as "no quantum resistance". The primitive
    comes from the shared SSH classifier.
    """
    return AlgorithmProperties(
        primitive=CryptoPrimitive(classify.cipher_primitive(name)),
        classical_security_level=_ssh_cipher_bits(name),
    )


def _ssh_mac_properties(_name: str) -> AlgorithmProperties:
    """Build algorithmProperties for an SSH MAC: primitive only (#286).

    A MAC has no meaningful ``classicalSecurityLevel`` in key bits and is not a PQC
    algorithm, so neither level is emitted rather than a misleading ``0``.
    """
    return AlgorithmProperties(primitive=CryptoPrimitive.MAC)


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
        select=lambda e: e.negotiated_group if e.evidence_type == "ssh.cipher" else None,
        algorithm_properties=_ssh_cipher_properties,
    )
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=lambda e: e.negotiated_group if e.evidence_type == "ssh.mac" else None,
        algorithm_properties=_ssh_mac_properties,
    )
