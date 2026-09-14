# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CLI contract tests for the Theia artifact commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qureddy.cli import app

_RUNNER = CliRunner()
_CBOM = b'{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}'


@pytest.fixture
def theia_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Provide a real executable subprocess that emits a minimal valid CBOM."""
    tool = tmp_path / "cbomkit-theia"
    tool.write_text(f"#!/bin/sh\nprintf '%s' '{_CBOM.decode()}'\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("QUREDDY_THEIA", str(tool))
    monkeypatch.setenv("QUREDDY_THEIA_VERSION", "test")
    return tool


@pytest.mark.parametrize(("command", "reference"), [("dir", "."), ("image", "example:latest")])
def test_artifact_command_emits_only_theia_cbom(
    theia_tool: Path, command: str, reference: str
) -> None:
    """Both commands keep subprocess diagnostics off the machine-output stream."""
    result = _RUNNER.invoke(app, ["scan", command, reference])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == json.loads(_CBOM)


def test_artifact_command_writes_opaque_cbom_bytes(theia_tool: Path, tmp_path: Path) -> None:
    """--output preserves the authoritative Theia document without reserialization."""
    output = tmp_path / "artifact.cdx.json"

    result = _RUNNER.invoke(app, ["scan", "dir", ".", "--output", str(output)])

    assert result.exit_code == 0, result.output
    assert output.read_bytes() == _CBOM


def test_artifact_command_rejects_missing_directory(theia_tool: Path) -> None:
    """The adapter's typed directory validation reaches the CLI as a failed scan."""
    result = _RUNNER.invoke(app, ["scan", "dir", "/definitely/missing"])

    assert result.exit_code == 2
    assert "not a directory" in result.output
