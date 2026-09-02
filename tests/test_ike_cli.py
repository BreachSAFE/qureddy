# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CLI integration tests for the IKE scanner command."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

from typer.testing import CliRunner

from qureddy.cli import app


def _tool(tmp_path: Path) -> str:
    script = tmp_path / "ike_scan_cli_fixture.py"
    script.write_text(
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    print('ike-scan 1.9.5')\n"
        "    raise SystemExit\n"
        "print('Handshake returned (1 transforms) Encr=AES KeyLength=256 Group=14:modp2048')\n"
    )
    if os.name == "nt":
        path = tmp_path / "ike-scan-cli-fixture.cmd"
        path.write_text(f'@"{sys.executable}" "{script}" %*\n')
        return str(path)
    path = tmp_path / "ike-scan-cli-fixture"
    path.write_text(f"#!{sys.executable}\n{script.read_text()}")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_cli_runs_real_tool_and_closes_output_file(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "ike",
            "127.0.0.1",
            "--ike-scan",
            _tool(tmp_path),
            "--format",
            "json",
            "--output",
            str(output),
            "--source-port",
            "500",
            "--timeout",
            "1",
            "--deterministic",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["scan"]["status"] == "completed"
    output.rename(tmp_path / "closed.json")


def test_cli_maps_missing_tool_to_exit_three() -> None:
    result = CliRunner().invoke(
        app,
        ["scan", "ike", "vpn.example", "--ike-scan", "definitely-missing-ike-scan"],
    )
    assert result.exit_code == 3


def test_cli_maps_invalid_target_to_usage_exit() -> None:
    result = CliRunner().invoke(app, ["scan", "ike", "ike://"])
    assert result.exit_code == 4
    assert "invalid target" in result.output
