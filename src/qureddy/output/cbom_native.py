# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CycloneDX 1.7 native-field patches for the pinned serializer."""

from __future__ import annotations

from typing import Any

_NATIVE_CURVE_IDS = {
    "curve25519": "other/Curve25519",
    "curve448": "other/Curve448",
    "P-256": "nist/P-256",
    "P-384": "nist/P-384",
    "P-521": "nist/P-521",
}


def _patch_certificate_fields(crypto: dict[str, Any]) -> None:
    certificate = crypto.get("certificateProperties", {})
    related: list[dict[str, str]] = []
    signature_ref = certificate.get("signatureAlgorithmRef")
    subject_key_ref = certificate.get("subjectPublicKeyRef")
    if isinstance(signature_ref, str):
        related.append({"type": "algorithm", "ref": signature_ref})
    if isinstance(subject_key_ref, str):
        related.append({"type": "publicKey", "ref": subject_key_ref})
    if related:
        certificate["relatedCryptographicAssets"] = related


def _patch_protocol_fields(crypto: dict[str, Any]) -> None:
    protocol = crypto.get("protocolProperties", {})
    refs = protocol.get("cryptoRefArray", [])
    if isinstance(refs, list) and refs:
        protocol["relatedCryptographicAssets"] = [
            {"type": "algorithm", "ref": ref} for ref in refs if isinstance(ref, str)
        ]


def _patch_material_fields(crypto: dict[str, Any]) -> None:
    material = crypto.get("relatedCryptoMaterialProperties", {})
    algorithm_ref = material.get("algorithmRef")
    if isinstance(algorithm_ref, str):
        material["relatedCryptographicAssets"] = [{"type": "algorithm", "ref": algorithm_ref}]


def patch_native_crypto_fields(payload: dict[str, Any]) -> None:
    """Add native 1.7 fields while retaining deprecated serializer aliases."""
    for component in payload.get("components", []):
        crypto = component.get("cryptoProperties", {})
        algorithm = crypto.get("algorithmProperties", {})
        native_curve = _NATIVE_CURVE_IDS.get(algorithm.get("curve"))
        if native_curve is not None:
            algorithm["ellipticCurve"] = native_curve
        _patch_certificate_fields(crypto)
        _patch_protocol_fields(crypto)
        _patch_material_fields(crypto)
