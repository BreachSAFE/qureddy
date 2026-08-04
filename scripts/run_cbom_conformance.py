#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Run the installed-console, schema, independent-CLI, and semantic CBOM gate."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tests.conformance.harness import (  # noqa: E402
    FIXTURE_DIR,
    ROOT,
    independent_cli_errors,
    load_manifest,
    normalized_volatile_fields,
    official_errors,
    semantic_errors,
    sha256,
    verify_independent_cli,
)

_TARGET_FAILURE_EXIT = 2


def parse_args() -> argparse.Namespace:
    """Parse conformance gate arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--cyclonedx-cli", required=True, type=Path)
    parser.add_argument("--tool-asset-key", required=True)
    parser.add_argument("--qureddy-console", required=True, type=Path)
    return parser.parse_args()


def _assert_outcome(actual: list[str], expected_reject: bool, label: str) -> None:
    if bool(actual) is not expected_reject:
        msg = f"{label}: expected reject={expected_reject}, errors={actual!r}"
        raise RuntimeError(msg)


def _validate_fixture_matrix(binary: Path) -> None:
    for name, details in load_manifest()["fixtures"].items():
        path = FIXTURE_DIR / details["kind"] / f"{name}.cbom.json"
        if sha256(path) != details["sha256"]:
            msg = f"{name}: fixture digest mismatch"
            raise RuntimeError(msg)
        payload = json.loads(path.read_text(encoding="utf-8"))
        _assert_outcome(official_errors(payload), details["official_rejects"], f"{name}:schema")
        _assert_outcome(semantic_errors(payload), details["semantic_rejects"], f"{name}:semantic")
        _assert_outcome(
            independent_cli_errors(binary, path),
            details["cli_rejects"],
            f"{name}:cyclonedx-cli",
        )


def _capture_final_bytes(
    console: Path,
    output: Path,
    *,
    openssl: Path,
    target: str,
    expected_exit: int,
) -> dict[str, Any]:
    command = [
        str(console),
        "scan",
        "tls",
        target,
        "--format",
        "cbom",
        "--openssl",
        str(openssl),
    ]
    completed = subprocess.run(  # noqa: S603 - CI supplies the installed console path.
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != expected_exit or completed.stderr:
        msg = (
            f"installed console contract failed: exit={completed.returncode}, "
            f"stderr={completed.stderr!r}"
        )
        raise RuntimeError(msg)
    output.write_text(completed.stdout, encoding="utf-8")
    return cast("dict[str, Any]", json.loads(completed.stdout))


def _validate_installed_console(binary: Path, console: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="qureddy-cbom-conformance-") as directory:
        root = Path(directory)
        first_path = root / "classical-first.cbom.json"
        second_path = root / "classical-second.cbom.json"
        failure_path = root / "failed-target.cbom.json"
        suffix = ".cmd" if os.name == "nt" else ".sh"
        classical_replay = ROOT / f"tests/conformance/shims/openssl_classical_replay{suffix}"
        first = _capture_final_bytes(
            console,
            first_path,
            openssl=classical_replay,
            target="192.0.2.10",
            expected_exit=0,
        )
        second = _capture_final_bytes(
            console,
            second_path,
            openssl=classical_replay,
            target="192.0.2.10",
            expected_exit=0,
        )
        failure = _capture_final_bytes(
            console,
            failure_path,
            openssl=ROOT / f"tests/fixtures/openssl/fake/openssl_connect_refused{suffix}",
            target="192.0.2.1",
            expected_exit=_TARGET_FAILURE_EXIT,
        )
        if normalized_volatile_fields(first) != normalized_volatile_fields(second):
            msg = "installed console output is nondeterministic beyond serialNumber and timestamp"
            raise RuntimeError(msg)
        _assert_positive_inventory(first)
        for path, payload in (
            (first_path, first),
            (second_path, second),
            (failure_path, failure),
        ):
            if errors := official_errors(payload):
                raise RuntimeError(f"{path.name}: official schema errors: {errors!r}")
            if errors := semantic_errors(payload):
                raise RuntimeError(f"{path.name}: semantic errors: {errors!r}")
            if errors := independent_cli_errors(binary, path):
                raise RuntimeError(f"{path.name}: cyclonedx-cli errors: {errors!r}")


def _assert_positive_inventory(payload: dict[str, Any]) -> None:
    component_refs = {component["bom-ref"] for component in payload.get("components", [])}
    if "crypto/algorithm/x25519" not in component_refs:
        msg = "installed positive canary omitted the observed classical algorithm"
        raise RuntimeError(msg)
    dependencies = {entry["ref"]: entry for entry in payload.get("dependencies", [])}
    endpoint = dependencies.get("endpoint", {})
    if "crypto/algorithm/x25519" not in endpoint.get("provides", []):
        msg = "installed positive canary omitted the endpoint provides relationship"
        raise RuntimeError(msg)


def main() -> None:
    """Run the complete fail-closed conformance gate."""
    args = parse_args()
    cyclonedx_cli = args.cyclonedx_cli.resolve(strict=True)
    qureddy_console = args.qureddy_console.resolve(strict=True)
    verify_independent_cli(cyclonedx_cli, args.tool_asset_key)
    _validate_fixture_matrix(cyclonedx_cli)
    _validate_installed_console(cyclonedx_cli, qureddy_console)
    print("CycloneDX 1.7 final-byte conformance: PASS")


if __name__ == "__main__":
    main()
