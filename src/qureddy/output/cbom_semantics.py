# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Semantic checks applied to final CycloneDX 1.7 bytes."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

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


def validate_cbom_semantics(payload: dict[str, Any]) -> None:
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
    annotation_refs = [annotation.get("bom-ref") for annotation in payload.get("annotations", [])]
    declared_refs = [
        ref for ref in (*graph_refs, *tool_refs, *annotation_refs) if isinstance(ref, str)
    ]
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
    # Also walk the intra-component crypto references the CI conformance harness checks,
    # so a dangling ref fails at runtime, not only in CI (#144).
    dangling.update(ref for ref in _intra_component_crypto_refs(payload) if ref not in known_refs)
    # Every annotation subject must resolve to a real component/endpoint (#287).
    for annotation in payload.get("annotations", []):
        for ref in annotation.get("subjects", []):
            if isinstance(ref, str) and ref not in known_refs:
                dangling.add(ref)
    if dangling:
        msg = f"dangling references: {', '.join(sorted(dangling))}"
        raise ValueError(msg)

    if _contains_secret_like_material(payload):
        msg = "CBOM contains secret-like material"
        raise ValueError(msg)


def _intra_component_crypto_refs(payload: dict[str, Any]) -> Iterator[str]:
    """Yield the crypto references components make.

    A certificate's signatureAlgorithmRef and subjectPublicKeyRef (#313), and each
    protocol's cipherSuites[].algorithms, point at algorithm components.
    """
    for component in payload.get("components", []):
        crypto_properties = component.get("cryptoProperties", {})
        certificate_properties = crypto_properties.get("certificateProperties", {})
        for ref_field in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
            reference = certificate_properties.get(ref_field)
            if isinstance(reference, str):
                yield reference
        for suite in crypto_properties.get("protocolProperties", {}).get("cipherSuites", []):
            for ref in suite.get("algorithms", []):
                if isinstance(ref, str):
                    yield ref


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
