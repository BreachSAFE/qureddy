# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Render scan and CycloneDX projections as deterministic Markdown."""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from typing import IO, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult


MARKDOWN_PROJECTION_VERSION = "2"
CBOM_IDENTITY_FIELDS = ("bomFormat", "specVersion", "serialNumber", "version")
CBOM_SECTION_FIELDS = ("metadata", "components", "dependencies", "annotations")
CBOM_KNOWN_FIELDS = CBOM_IDENTITY_FIELDS + CBOM_SECTION_FIELDS


def _scalar(value: object) -> str:
    """Render one scalar as a single safe Markdown line."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        normalized = " ".join(value.split())
        return normalized if normalized else '""'
    return str(value)


def _write_value(stream: IO[str], path: str, value: object) -> None:
    """Recursively write one mapping value with stable array indexes."""
    if isinstance(value, Mapping):
        _write_mapping(stream, value, path)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if not value:
            stream.write(f"- {path}: []\n")
        for index, item in enumerate(value):
            _write_value(stream, f"{path}[{index}]", item)
    else:
        stream.write(f"- {path}: {_scalar(value)}\n")


def _write_mapping(stream: IO[str], value: Mapping[str, Any], prefix: str = "") -> None:
    """Flatten mappings and sequences into deterministic field/value bullets."""
    for key in value:
        path = f"{prefix}.{key}" if prefix else str(key)
        _write_value(stream, path, value[key])


def _write_section(stream: IO[str], heading: str, value: object) -> None:
    """Write one mapping section, including explicit empty-state output."""
    stream.write(f"## {heading}\n\n")
    if not isinstance(value, Mapping):
        stream.write(f"- value: {_scalar(value)}\n\n")
        return
    if not value:
        stream.write("- value: {}\n\n")
        return
    _write_mapping(stream, value)
    stream.write("\n")


def _write_records(stream: IO[str], heading: str, records: object, label: str) -> None:
    """Write each record under a stable heading for independent retrieval chunks."""
    stream.write(f"## {heading}\n\n")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        stream.write(f"- value: {_scalar(records)}\n\n")
        return
    if not records:
        stream.write(f"No {label.lower()} reported.\n\n")
        return
    for index, record in enumerate(records, start=1):
        stream.write(f"### {label} {index}\n\n")
        if isinstance(record, Mapping):
            _write_mapping(stream, record)
        else:
            stream.write(f"- value: {_scalar(record)}\n")
        stream.write("\n")


def render_scan_markdown(result: ScanResult, stream: IO[str]) -> None:
    """Write the complete typed scan result as retrieval-friendly Markdown."""
    payload = result.model_dump(mode="json")
    stream.write("# QuReddy Scan\n\n")
    stream.write("- document_type: qureddy_scan_markdown\n")
    stream.write(f"- projection_version: qureddyai-scan-v{MARKDOWN_PROJECTION_VERSION}\n")
    stream.write(f"- schema_version: {_scalar(payload.get('schema_version'))}\n\n")
    _write_section(stream, "Run", payload.get("scan"))
    _write_section(stream, "Target", payload.get("target"))
    _write_records(stream, "Dependencies", payload.get("dependencies"), "Dependency")
    _write_records(stream, "Assets", payload.get("assets"), "Asset")
    _write_records(stream, "Findings", payload.get("findings"), "Finding")
    _write_records(stream, "Evidence", payload.get("evidence"), "Evidence")
    _write_section(stream, "Summary", payload.get("summary"))


def render_markdown(result: ScanResult, stream: IO[str] | None = None) -> None:
    """Render scan Markdown to the supplied stream or current stdout."""
    render_scan_markdown(result, stream if stream is not None else sys.stdout)


def render_cbom_markdown(payload: Mapping[str, Any], stream: IO[str]) -> None:
    """Write a generic, CycloneDX-aware Markdown projection of a CBOM payload."""
    stream.write("# QuReddy CBOM\n\n")
    stream.write("- document_type: qureddy_cbom\n")
    stream.write(f"- projection_version: qureddyai-cbom-v{MARKDOWN_PROJECTION_VERSION}\n\n")
    for key in CBOM_IDENTITY_FIELDS:
        if key in payload:
            stream.write(f"- {key}: {_scalar(payload[key])}\n")
    stream.write("\n")
    _write_section(stream, "Metadata", payload.get("metadata"))
    _write_records(stream, "Components", payload.get("components"), "Component")
    _write_records(stream, "Dependencies", payload.get("dependencies"), "Dependency")
    _write_records(stream, "Annotations", payload.get("annotations"), "Annotation")
    additional = {key: value for key, value in payload.items() if key not in CBOM_KNOWN_FIELDS}
    if additional:
        _write_section(stream, "Additional fields", additional)
