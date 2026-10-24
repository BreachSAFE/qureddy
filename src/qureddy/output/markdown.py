# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Render scan and CycloneDX projections as deterministic Markdown.

Data flow::

    ScanResult ──▶ scan.md
         │
         └──────▶ CBOM builder ──▶ CycloneDX payload ──▶ cbom.md

Both projections flatten structured values into stable, retrieval-friendly
bullets.  The renderer owns presentation only; scan policy and CBOM semantics
remain in the typed model and the CycloneDX builder.
"""

from __future__ import annotations

import json
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from typing import IO, TYPE_CHECKING, cast

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult


type JsonValue = (
    bool | int | float | str | bytes | Mapping[str, "JsonValue"] | Sequence["JsonValue"] | None
)

SCAN_MARKDOWN_PROJECTION_VERSION = "qureddy.scan.v3"
CBOM_MARKDOWN_PROJECTION_VERSION = "qureddy.cbom.v3"
CBOM_IDENTITY_FIELDS = ("bomFormat", "specVersion", "serialNumber", "version")
CBOM_SECTION_FIELDS = ("metadata", "components", "dependencies", "annotations")
CBOM_KNOWN_FIELDS = CBOM_IDENTITY_FIELDS + CBOM_SECTION_FIELDS


def _safe_text(value: str) -> str:
    """Keep visible text readable while escaping invisible format controls."""
    normalized = " ".join(value.split())
    if not normalized:
        return '""'
    return "".join(
        f"\\u{ord(character):04x}" if unicodedata.category(character) in {"Cc", "Cf"} else character
        for character in normalized
    )


def _scalar(value: JsonValue) -> str:
    """Render one scalar as a single safe Markdown line."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    # JSON is the canonical scalar representation for values that reach this
    # generic boundary.  A type marker handles extension values without
    # leaking Python repr syntax into a document consumed by another system.
    return json.dumps(
        value,
        ensure_ascii=True,
        default=lambda unsupported: f"<{type(unsupported).__name__}>",
    ).strip('"')


def _write_value(stream: IO[str], path: str, value: JsonValue) -> None:
    """Recursively write one mapping value with stable array indexes."""
    if isinstance(value, Mapping):
        if not value:
            stream.write(f"- {path}: {{}}\n")
            return
        _write_mapping(stream, value, path)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if not value:
            stream.write(f"- {path}: []\n")
        for index, item in enumerate(value):
            _write_value(stream, f"{path}[{index}]", item)
    else:
        stream.write(f"- {path}: {_scalar(value)}\n")


def _path_for_key(prefix: str, key: str) -> str:
    """Build a path that distinguishes literal dotted keys from nesting."""
    component = key if "." not in key and "[" not in key and "]" not in key else json.dumps(key)
    return f"{prefix}.{component}" if prefix else component


def _write_mapping(stream: IO[str], value: Mapping[str, JsonValue], prefix: str = "") -> None:
    """Flatten mappings and sequences into deterministic field/value bullets."""
    for key in value:
        if not isinstance(key, str):
            raise TypeError(f"mapping keys must be strings, got {type(key).__name__}")
        path = _path_for_key(prefix, key)
        _write_value(stream, path, value[key])


def _write_section(stream: IO[str], heading: str, value: JsonValue) -> None:
    """Write one mapping section, including explicit empty-state output."""
    stream.write(f"## {heading}\n\n")
    if value is None:
        stream.write("- value: null\n\n")
        return
    if not isinstance(value, Mapping):
        raise TypeError(f"{heading} must be a mapping, got {type(value).__name__}")
    if not value:
        stream.write("- value: {}\n\n")
        return
    _write_mapping(stream, value)
    stream.write("\n")


def _write_records(stream: IO[str], heading: str, records: JsonValue, label: str) -> None:
    """Write each record under a stable heading for independent retrieval chunks."""
    stream.write(f"## {heading}\n\n")
    if records is None:
        stream.write(f"No {label.lower()} reported.\n\n")
        return
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        raise TypeError(f"{heading} must be a sequence, got {type(records).__name__}")
    if any(not isinstance(record, Mapping) for record in records):
        raise TypeError(f"{heading} records must be mappings")
    if not records:
        stream.write(f"No {label.lower()} reported.\n\n")
        return
    for index, record in enumerate(records, start=1):
        stream.write(f"### {label} {index}\n\n")
        _write_mapping(stream, cast("Mapping[str, JsonValue]", record))
        stream.write("\n")


def render_scan_markdown(result: ScanResult, stream: IO[str]) -> None:
    """Write the complete typed scan result as retrieval-friendly Markdown."""
    payload = result.model_dump(mode="json")
    stream.write("# QuReddy Scan\n\n")
    stream.write("- document_type: qureddy_scan_markdown\n")
    stream.write(f"- projection_version: {SCAN_MARKDOWN_PROJECTION_VERSION}\n")
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


def render_cbom_markdown(payload: Mapping[str, JsonValue], stream: IO[str]) -> None:
    """Write a generic, CycloneDX-aware Markdown projection of a CBOM payload."""
    stream.write("# QuReddy CBOM\n\n")
    stream.write("- document_type: qureddy_cbom_markdown\n")
    stream.write(f"- projection_version: {CBOM_MARKDOWN_PROJECTION_VERSION}\n\n")
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
