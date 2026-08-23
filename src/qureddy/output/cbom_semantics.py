# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Semantic checks applied to final CycloneDX 1.7 bytes."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from qureddy.core.errors import CbomError

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
# cyclonedx's BomRefDiscriminator names a de-duplicated ref ``BomRef.<float>.<float>`` (#343).
_AUTO_BOM_REF = re.compile(r"^BomRef\.\d")


def _check_bom_ref_integrity(declared_refs: list[str]) -> None:
    """Reject duplicate or non-deterministic auto-generated bom-refs (#343)."""
    duplicates = _duplicate_refs(declared_refs)
    if duplicates:
        msg = f"duplicate bom-ref values: {', '.join(duplicates)}"
        raise CbomError(msg)
    # A literal duplicate bom-ref is silently renamed to a random ``BomRef.<n>.<n>`` by
    # cyclonedx's BomRefDiscriminator at serialization, which erases the duplicate above and
    # makes output non-deterministic (breaks --deterministic). A surviving auto-generated ref is
    # the fingerprint of that class of bug — reject it so it cannot slip past.
    auto_generated = _auto_generated_refs(declared_refs)
    if auto_generated:
        msg = f"non-deterministic auto-generated bom-ref (unresolved duplicate): {auto_generated}"
        raise CbomError(msg)


def _duplicate_refs(declared_refs: list[str]) -> list[str]:
    """Return the sorted set of bom-refs that appear more than once."""
    return sorted({ref for ref in declared_refs if declared_refs.count(ref) > 1})


def _auto_generated_refs(declared_refs: list[str]) -> list[str]:
    """Return the sorted auto-generated ``BomRef.<n>`` refs (unresolved duplicates, #343)."""
    return sorted(ref for ref in declared_refs if _AUTO_BOM_REF.match(ref))


def validate_cbom_semantics(payload: dict[str, Any]) -> None:
    """Reject semantic defects that schema validators do not consistently catch."""
    if payload.get("specVersion") != "1.7":
        msg = "CBOM specVersion must be exactly 1.7"
        raise CbomError(msg)

    graph_refs = _graph_refs(payload)
    _check_bom_ref_integrity(_declared_refs(payload, graph_refs))

    known_refs = _known_refs(graph_refs)
    dangling = _dangling_refs(payload, known_refs)
    if dangling:
        msg = f"dangling references: {', '.join(sorted(dangling))}"
        raise CbomError(msg)

    if _contains_secret_like_material(payload):
        msg = "CBOM contains secret-like material"
        raise CbomError(msg)


def _known_refs(graph_refs: list[Any]) -> set[str]:
    """Return the graph-node bom-refs that are strings (the resolvable reference targets)."""
    return {ref for ref in graph_refs if isinstance(ref, str)}


def _str_values(items: Any) -> Iterator[str]:
    """Yield only the string members of ``items`` (a heterogeneous JSON array)."""
    for item in items:
        if isinstance(item, str):
            yield item


def _graph_refs(payload: dict[str, Any]) -> list[Any]:
    """Collect the metadata-component and component bom-refs (the dependency graph nodes)."""
    metadata_component = payload.get("metadata", {}).get("component", {})
    graph_refs = [metadata_component.get("bom-ref")]
    graph_refs.extend(component.get("bom-ref") for component in payload.get("components", []))
    return graph_refs


def _declared_refs(payload: dict[str, Any], graph_refs: list[Any]) -> list[str]:
    """Collect every declared bom-ref (graph nodes + tool + annotation refs) as strings."""
    tool_refs = [
        tool.get("bom-ref")
        for tool in payload.get("metadata", {}).get("tools", {}).get("components", [])
    ]
    annotation_refs = [annotation.get("bom-ref") for annotation in payload.get("annotations", [])]
    return [ref for ref in (*graph_refs, *tool_refs, *annotation_refs) if isinstance(ref, str)]


def _dangling_refs(payload: dict[str, Any], known_refs: set[str]) -> set[str]:
    """Collect every reference that does not resolve to a known graph node."""
    return {ref for ref in _referenced_refs(payload) if ref not in known_refs}


def _referenced_refs(payload: dict[str, Any]) -> Iterator[str]:
    """Yield every reference the document makes, so a dangling one can be caught.

    Covers dependency ``ref``/``dependsOn``/``provides`` edges, the intra-component crypto
    references the CI conformance harness checks (so a dangling ref fails at runtime, not only
    in CI, #144), and every annotation subject (which must resolve to a real
    component/endpoint, #287).
    """
    for dependency in payload.get("dependencies", []):
        yield from _dependency_refs(dependency)
    yield from _intra_component_crypto_refs(payload)
    for annotation in payload.get("annotations", []):
        yield from _str_values(annotation.get("subjects", []))


def _dependency_refs(dependency: dict[str, Any]) -> Iterator[str]:
    """Yield a dependency node's own ``ref`` and its ``dependsOn``/``provides`` edge refs."""
    dependency_ref = dependency.get("ref")
    if isinstance(dependency_ref, str):
        yield dependency_ref
    for edge_name in ("dependsOn", "provides"):
        yield from _str_values(dependency.get(edge_name, []))


def _intra_component_crypto_refs(payload: dict[str, Any]) -> Iterator[str]:
    """Yield the crypto references components make.

    A certificate's signatureAlgorithmRef and subjectPublicKeyRef (#313), and each
    protocol's cipherSuites[].algorithms, point at algorithm components.
    """
    for component in payload.get("components", []):
        yield from _component_crypto_refs(component)


def _component_crypto_refs(component: dict[str, Any]) -> Iterator[str]:
    """Yield one component's certificate and cipher-suite algorithm references."""
    crypto_properties = component.get("cryptoProperties", {})
    certificate_properties = crypto_properties.get("certificateProperties", {})
    for ref_field in ("signatureAlgorithmRef", "subjectPublicKeyRef"):
        reference = certificate_properties.get(ref_field)
        if isinstance(reference, str):
            yield reference
    for suite in crypto_properties.get("protocolProperties", {}).get("cipherSuites", []):
        yield from _str_values(suite.get("algorithms", []))


def _contains_secret_like_material(value: object) -> bool:
    """Detect key blocks, token shapes, and populated secret-named fields."""
    if isinstance(value, dict):
        return _dict_contains_secret_like_material(value)
    if isinstance(value, list):
        return any(_contains_secret_like_material(item) for item in value)
    if isinstance(value, str):
        return _str_contains_secret(value)
    return False


def _str_contains_secret(value: str) -> bool:
    """Detect a private-key block or token shape inside a string value."""
    return any(pattern.search(value) for pattern in _SECRET_PATTERNS)


def _dict_contains_secret_like_material(value: dict[Any, Any]) -> bool:
    """Detect a populated secret-named field, a secret-named property, or a nested secret."""
    return (
        _has_populated_secret_field(value)
        or _is_populated_secret_property(value)
        or _has_nested_secret(value)
    )


def _has_populated_secret_field(value: dict[Any, Any]) -> bool:
    """Return whether any secret-named key maps to a non-empty value."""
    return any(
        _SECRET_FIELD.fullmatch(str(key)) and nested not in (None, "", [], {})
        for key, nested in value.items()
    )


def _is_populated_secret_property(value: dict[Any, Any]) -> bool:
    """Return whether this is a ``{name, value}`` property whose secret-named name is populated."""
    property_name = value.get("name")
    return (
        isinstance(property_name, str)
        and _SECRET_FIELD.fullmatch(property_name) is not None
        and value.get("value") not in (None, "", [], {})
    )


def _has_nested_secret(value: dict[Any, Any]) -> bool:
    """Return whether any nested value within the dict contains secret-like material."""
    return any(_contains_secret_like_material(nested) for nested in value.values())
