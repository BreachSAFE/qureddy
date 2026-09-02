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


def _tool(
    tmp_path: Path,
    output: str = "Handshake returned (1 transforms) Encr=AES KeyLength=256 Group=14:modp2048",
) -> str:
    script = tmp_path / "ike_scan_cli_fixture.py"
    script.write_text(
        "import sys\n"
        "if '--version' in sys.argv:\n"
        "    print('ike-scan 1.9.5')\n"
        "    raise SystemExit\n"
        f"print({output!r})\n"
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


def test_silent_ike_cli_has_consistent_json_and_cbom_contract(tmp_path: Path) -> None:
    """Render completed-unknown silence consistently through both document formats."""
    tool = _tool(tmp_path, "")
    for output_format in ("json", "cbom"):
        output = tmp_path / f"silent.{output_format}"
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "ike",
                "127.0.0.1",
                "--ike-scan",
                tool,
                "--format",
                output_format,
                "--output",
                str(output),
                "--deterministic",
                "--quiet",
            ],
        )
        payload = json.loads(output.read_text())

        assert result.exit_code == 0, result.output
        if output_format == "json":
            assert payload["scan"]["status"] == "no_response"
            assert payload["summary"]["readiness"] == "unknown"
            assert payload["summary"]["failure_category"] is None
            args = payload["evidence"][0]["probe_result"]["command"]["args"]
            attempts = int(args[args.index("--retry") + 1])
            initial_seconds = int(args[args.index("--timeout") + 1]) / 1000
            backoff = float(args[args.index("--backoff") + 1])
            scheduled_seconds = sum(
                initial_seconds * backoff**attempt for attempt in range(attempts)
            )
            assert scheduled_seconds <= 8
            assert {
                record["notes"][0]
                for record in payload["evidence"]
                if record["evidence_type"] == "ike.mode.no_response"
            } == {
                "exchange_mode=ikev1_main",
                "exchange_mode=ikev1_aggressive",
                "exchange_mode=ikev2",
            }
        else:
            properties = {item["name"]: item["value"] for item in payload["metadata"]["properties"]}
            assert properties["qureddy:scan.status"] == "no_response"
            assert properties["qureddy:scan.readiness"] == "unknown"


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
