# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the bounded Theia artifact-tool boundary."""

from __future__ import annotations

from pathlib import Path

from qureddy.core.contracts import CollectionFailureKind, ScanSource, SourceKind
from qureddy.scanners.artifact.adapter import CbomkitTheiaAdapter


def _source(kind: SourceKind, locator: str) -> ScanSource:
    return ScanSource(kind=kind, locator=locator)


def _tool(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "cbomkit-theia"
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_directory_scan_preserves_valid_cyclonedx_bytes(tmp_path: Path) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(
        tmp_path,
        """if [ \"$1\" = \"--version\" ]; then echo theia-test; exit 0; fi
printf '%s' '{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.7\",\"components\":[]}'""",
    )

    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=2
    )

    assert result.failure is None
    assert result.artifact_cbom == (
        b'{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}'
    )
    assert result.collector_version == "theia-test"


def test_image_scan_rejects_local_path_before_subprocess(tmp_path: Path) -> None:
    tool = _tool(tmp_path, "exit 99")

    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.CONTAINER_IMAGE, str(tmp_path / "not-an-image")), timeout_seconds=2
    )

    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.MALFORMED
    assert "OCI" in result.failure.message


def test_malformed_stdout_is_not_accepted(tmp_path: Path) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(tmp_path, "printf '%s' not-json")

    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=2
    )

    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.MALFORMED
    assert result.artifact_cbom is None


def test_timeout_is_typed_and_bounded(tmp_path: Path) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(tmp_path, "sleep 2")

    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=1
    )

    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.TIMEOUT


def test_nonzero_tool_exit_is_not_a_successful_empty_cbom(tmp_path: Path) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(tmp_path, "echo image backend unavailable >&2; exit 17")

    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=2
    )

    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.EXECUTION
    assert result.artifact_cbom is None


def test_output_limit_is_typed(tmp_path: Path) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(tmp_path, "printf '1234567890'")

    result = CbomkitTheiaAdapter(str(tool), output_limit=4).run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=2
    )

    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.MALFORMED


def test_missing_tool_is_typed() -> None:
    result = CbomkitTheiaAdapter("definitely-not-cbomkit-theia").run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, "."), timeout_seconds=2
    )

    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.UNAVAILABLE
