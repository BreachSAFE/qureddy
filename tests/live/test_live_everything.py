# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Every scan subcommand through the installed CLI, against a live peer.

Four of the nine live files call the scanner in-process. That proves the
scanner and skips everything the CLI owns: argument parsing, the exit-code
contract, stdout purity, and `--output-dir` writing the bundle. `scan wallet`
had that coverage and no other scheme did, so a CLI-level regression in tls,
ssh or ike would reach a release.

One scan per scheme, shared across the assertions, so a peer is probed once.
Each scheme skips when its target is absent and the reason names what to set,
because a lane that cannot reach a peer has measured nothing.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from qureddy.scanners.wallet.profiles import PROFILES

_TIMEOUT_SECONDS = 300
_EXPECTED_FILES = ("scan.json", "scan.cdx.json", "scan.jsonl", "scan.rich.txt")
_SCHEMA = "qureddy.scan.v1"
#: A scan that reached its peer, and a scan that reached it and found something.
#: Both are successful runs; only a usage or internal error is a failure here.
_REACHED = (0, 2)


def _cli() -> str:
    resolved = Path(sys.executable).with_name("qureddy")
    return str(resolved) if resolved.exists() else "qureddy"


def _listening(host: str, port: int) -> bool:
    """Whether a TCP peer answers, so an absent one skips instead of failing."""
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except OSError:
        return False


def _tls_target() -> str:
    return os.environ.get("QUREDDY_CLI_TLS_TARGET", "mozilla.org")


def _ssh_target() -> str:
    return os.environ.get("QUREDDY_CLI_SSH_TARGET", "127.0.0.1:22")


_CASES = {
    "tls": (lambda: ["tls", _tls_target()], lambda: _listening(_tls_target(), 443)),
    "ssh": (
        lambda: ["ssh", _ssh_target()],
        lambda: _listening(_ssh_target().split(":")[0], int(_ssh_target().split(":")[1])),
    ),
    "ike": (
        lambda: ["ike", os.environ.get("QUREDDY_IKE_PUBLIC_TARGET", "")],
        lambda: bool(os.environ.get("QUREDDY_IKE_PUBLIC_TARGET")),
    ),
    "wallet": (
        lambda: ["wallet", next(p.address for p in PROFILES if p.key == "btc-bip173-example")],
        lambda: True,
    ),
}


@pytest.fixture(scope="module")
def bundles(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[int, Path, str]]:
    """One `--output-dir` run per reachable scheme, produced once."""
    produced: dict[str, tuple[int, Path, str]] = {}
    for scheme, (argv, available) in _CASES.items():
        if not available():
            continue
        run_dir = tmp_path_factory.mktemp(f"cli-{scheme}")
        completed = subprocess.run(  # noqa: S603 - resolved binary, list-form argv
            [_cli(), "scan", *argv(), "--output-dir", str(run_dir)],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
        produced[scheme] = (completed.returncode, run_dir, completed.stdout)
    return produced


def _bundle(bundles: dict[str, tuple[int, Path, str]], scheme: str) -> tuple[int, Path, str]:
    if scheme not in bundles:
        pytest.skip(f"no reachable {scheme} peer; set the target for this scheme to run it")
    return bundles[scheme]


@pytest.mark.parametrize("scheme", sorted(_CASES))
def test_the_cli_reaches_its_peer_and_exits_on_the_contract(
    bundles: dict[str, tuple[int, Path, str]], scheme: str
) -> None:
    """0 or 2 is a completed scan. 4 is usage, 70 is internal, and both fail."""
    code, _, _ = _bundle(bundles, scheme)

    assert code in _REACHED, f"scan {scheme} exited {code}"


@pytest.mark.parametrize("scheme", sorted(_CASES))
def test_output_dir_writes_every_projection(
    bundles: dict[str, tuple[int, Path, str]], scheme: str
) -> None:
    """The bundle contract, which only the CLI can be asked for."""
    _, run_dir, _ = _bundle(bundles, scheme)

    for name in _EXPECTED_FILES:
        written = run_dir / name
        assert written.is_file(), f"{scheme}: {name} was not written"
        assert written.stat().st_size > 0, f"{scheme}: {name} is empty"


@pytest.mark.parametrize("scheme", sorted(_CASES))
def test_the_json_projection_carries_the_schema_and_the_target(
    bundles: dict[str, tuple[int, Path, str]], scheme: str
) -> None:
    _, run_dir, _ = _bundle(bundles, scheme)
    document = json.loads((run_dir / "scan.json").read_text(encoding="utf-8"))

    assert document["schema_version"] == _SCHEMA
    assert document["target"]["locator"].startswith(f"{scheme if scheme != 'wallet' else 'btc'}://")
    assert document["scan"]["scanner_name"]


@pytest.mark.parametrize("scheme", sorted(_CASES))
def test_the_jsonl_projection_is_one_object_per_line(
    bundles: dict[str, tuple[int, Path, str]], scheme: str
) -> None:
    """A stream consumer reads it line by line, so a stray blank line breaks it."""
    _, run_dir, _ = _bundle(bundles, scheme)
    lines = (run_dir / "scan.jsonl").read_text(encoding="utf-8").splitlines()

    assert lines
    for line in lines:
        assert json.loads(line)


@pytest.mark.parametrize("scheme", sorted(_CASES))
def test_the_cbom_projection_is_a_cyclonedx_document(
    bundles: dict[str, tuple[int, Path, str]], scheme: str
) -> None:
    _, run_dir, _ = _bundle(bundles, scheme)
    document = json.loads((run_dir / "scan.cdx.json").read_text(encoding="utf-8"))

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.7"
    assert document["components"], f"{scheme}: the CBOM carries no components"


@pytest.mark.parametrize("scheme", sorted(_CASES))
def test_the_bundle_passes_the_cross_format_validator(
    bundles: dict[str, tuple[int, Path, str]], scheme: str
) -> None:
    """The repo's own validator, run on a bundle this CLI produced.

    It checks the machine contracts, the visible Rich contract, and the
    CycloneDX 1.7 oracle without re-scanning, so it answers whether the four
    projections agree rather than whether the command exited zero.
    """
    _, run_dir, _ = _bundle(bundles, scheme)
    document = json.loads((run_dir / "scan.json").read_text(encoding="utf-8"))
    validator = Path(__file__).resolve().parents[2] / "scripts" / "validate_output_bundle.py"
    completed = subprocess.run(  # noqa: S603 - resolved path, list-form argv
        [
            sys.executable,
            str(validator),
            "--run-dir",
            str(run_dir),
            "--scanner",
            document["scan"]["scanner_name"],
            "--target",
            document["target"]["original_input"],
        ],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("scheme", sorted(_CASES))
def test_every_projection_reports_the_same_findings(
    bundles: dict[str, tuple[int, Path, str]], scheme: str
) -> None:
    """Correctness, not exit codes: one scan, four views, one set of facts.

    A projection that drops or invents a finding still exits zero and still
    parses. The only way to catch it is to compare the views against each
    other, which is what one canonical `ScanResult` is supposed to guarantee.
    """
    _, run_dir, _ = _bundle(bundles, scheme)
    document = json.loads((run_dir / "scan.json").read_text(encoding="utf-8"))
    rich = (run_dir / "scan.rich.txt").read_text(encoding="utf-8")
    jsonl = [
        json.loads(line)
        for line in (run_dir / "scan.jsonl").read_text(encoding="utf-8").splitlines()
    ]

    assert document["summary"]["finding_count"] == len(document["findings"])
    assert len(jsonl) >= len(document["findings"]), "the stream drops findings"

    # Every finding id in the canonical document reaches the stream.
    streamed = json.dumps(jsonl)
    for finding in document["findings"]:
        assert finding["finding_type"] in streamed, f"{finding['finding_type']} is absent"

    # The render names the same endpoint and the same severity the data carries.
    assert document["target"]["locator"] in rich
    assert document["summary"]["highest_severity"] in rich.lower()


@pytest.mark.parametrize("scheme", sorted(_CASES))
def test_the_cbom_carries_the_nist_level_the_scan_measured(
    bundles: dict[str, tuple[int, Path, str]], scheme: str
) -> None:
    """The CBOM is the document a consumer grades from, so its level must match.

    `nist_quantum_security_level_max` in the summary and the highest
    `nistQuantumSecurityLevel` across the CBOM's algorithm components describe
    one scan. A disagreement means a consumer and the report reach different
    verdicts from the same run.
    """
    _, run_dir, _ = _bundle(bundles, scheme)
    document = json.loads((run_dir / "scan.json").read_text(encoding="utf-8"))
    cbom = json.loads((run_dir / "scan.cdx.json").read_text(encoding="utf-8"))

    levels = [
        component["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"]
        for component in cbom["components"]
        if component.get("cryptoProperties", {}).get("assetType") == "algorithm"
        and "nistQuantumSecurityLevel"
        in component["cryptoProperties"].get("algorithmProperties", {})
    ]
    measured = document["summary"]["nist_quantum_security_level_max"]
    if measured is None:
        pytest.skip(f"{scheme}: the scan measured no NIST level")

    assert levels, f"{scheme}: the summary reports level {measured} and the CBOM reports none"
    assert max(levels) == measured
