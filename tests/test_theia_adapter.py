# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the bounded Theia artifact-tool boundary."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from qureddy.core.contracts import CollectionFailureKind, ScanSource, SourceKind
from qureddy.scanners.artifact import adapter as adapter_module
from qureddy.scanners.artifact.adapter import CbomkitTheiaAdapter

if TYPE_CHECKING:
    from qureddy.scanners.common.process import ProcessOutput


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


def test_unsupported_source_is_typed() -> None:
    result = CbomkitTheiaAdapter("definitely-not-cbomkit-theia").run(
        _source(SourceKind.CERTIFICATE, "certificate.pem"), timeout_seconds=2
    )
    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.UNSUPPORTED


def test_resolution_race_is_typed_as_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(tmp_path, "exit 0")
    adapter = CbomkitTheiaAdapter(str(tool))
    adapter.__dict__["_binary"] = None
    monkeypatch.setattr(adapter, "available", lambda: True)
    result = adapter.run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=2
    )
    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.UNAVAILABLE


def test_output_limit_must_be_positive() -> None:
    with pytest.raises(ValueError, match="output_limit"):
        CbomkitTheiaAdapter(output_limit=0)


@pytest.mark.parametrize("locator", ["", " input "])
def test_reference_rejects_empty_or_surrounding_whitespace(tmp_path: Path, locator: str) -> None:
    tool = _tool(tmp_path, "exit 0")
    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.CONTAINER_IMAGE, locator or " "), timeout_seconds=2
    )
    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.MALFORMED


def test_reference_rejects_empty_locator_after_deserialization(tmp_path: Path) -> None:
    source = _source(SourceKind.CONTAINER_IMAGE, "registry.example/image:latest")
    invalid_source = source.model_copy(update={"locator": ""})
    result = CbomkitTheiaAdapter(str(_tool(tmp_path, "exit 0"))).run(
        invalid_source, timeout_seconds=2
    )
    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.MALFORMED


def test_directory_reference_must_be_a_directory(tmp_path: Path) -> None:
    tool = _tool(tmp_path, "exit 0")
    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(tmp_path / "missing")), timeout_seconds=2
    )
    assert result.failure is not None
    assert "not a directory" in result.failure.message


def test_directory_reference_must_be_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(tmp_path, "exit 0")
    adapter = CbomkitTheiaAdapter(str(tool))
    assert adapter.available()
    monkeypatch.setattr(os, "access", lambda *_args: False)
    result = adapter.run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=2
    )
    assert result.failure is not None
    assert "not readable" in result.failure.message


def test_image_reference_success_uses_image_subcommand(tmp_path: Path) -> None:
    tool = _tool(
        tmp_path,
        """if [ \"$1\" = \"--version\" ]; then echo theia-test; exit 0; fi
printf '%s' '{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.7\",\"components\":[]}'""",
    )
    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.CONTAINER_IMAGE, "registry.example/qureddy:latest"), timeout_seconds=2
    )
    assert result.failure is None
    assert result.artifact_cbom is not None


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (b'{"bomFormat":"Other","specVersion":"1.7"}', "not a CycloneDX"),
        (b'{"bomFormat":"CycloneDX"}', "no specVersion"),
    ],
)
def test_valid_json_still_requires_cyclonedx_contract(
    tmp_path: Path, document: bytes, message: str
) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(tmp_path, f"printf '%s' '{document.decode()}'")
    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=2
    )
    assert result.failure is not None
    assert message in result.failure.message


def test_version_probe_oserror_is_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tool = _tool(tmp_path, "exit 0")
    monkeypatch.setattr(
        adapter_module,
        "run_bounded",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("gone")),
    )
    assert CbomkitTheiaAdapter(str(tool)).version == "unknown"


def test_execution_oserror_is_typed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = tmp_path / "input"
    directory.mkdir()
    tool = _tool(tmp_path, "exit 0")

    def fail_process(*_args: object, **_kwargs: object) -> ProcessOutput:
        raise OSError("child unavailable")

    monkeypatch.setattr(adapter_module, "run_bounded", fail_process)
    result = CbomkitTheiaAdapter(str(tool)).run(
        _source(SourceKind.FILESYSTEM_DIRECTORY, str(directory)), timeout_seconds=2
    )
    assert result.failure is not None
    assert result.failure.kind is CollectionFailureKind.EXECUTION
