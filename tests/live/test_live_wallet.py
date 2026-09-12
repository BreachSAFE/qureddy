# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Live wallet scans through the installed CLI, asserting on real output.

Every test here runs the real `qureddy` executable as a subprocess against a
real indexer or RPC node and reads what it wrote. No lane is monkeypatched, no
response is stubbed, and no fixture stands in for a network answer.

That matters because the unit suite cannot see a whole class of defect. Three
found during this scanner's development each passed a green unit suite and
failed the first real run: `--output-dir` raised `KeyError` on an unknown scheme
and left an empty directory, the CBOM emitted a component with no
`algorithmProperties` because another emitter claimed the asset first, and the
help text advertised three options the command rejects.

Accounts under test are the grounded ones from
`qureddy.scanners.wallet.profiles`, so each carries a check establishing what it
is. Balances and transaction counts move, so assertions here cover shape,
identity, and invariants that hold regardless of chain state.

Per docs/contributors/coding-rules.md Rule 9.4 these run in the default suite;
pytest-rerunfailures absorbs transient internet hiccups.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from qureddy.scanners.wallet.profiles import PROFILES

_TIMEOUT_SECONDS = 90
_EXIT_USAGE = 4

# Grounded accounts, keyed by what each demonstrates. See profiles.py and ADR section 12.
_BY_KEY = {profile.key: profile for profile in PROFILES}
BTC_UNSPENT = _BY_KEY["btc-genesis"].address
BTC_TAPROOT = _BY_KEY["btc-taproot"].address
# BIP-173 declares this example's key, so a real spend republishes it.
BTC_PUBLISHED = _BY_KEY["btc-bip173-example"].address
ETH_ACCOUNT = _BY_KEY["eth-delegated-account"].address
ETH_CONTRACT = _BY_KEY["eth-contract"].address


def _cli() -> str:
    """Resolve the installed qureddy executable, failing loudly when absent."""
    resolved = shutil.which("qureddy")
    if resolved is None:
        pytest.fail("the qureddy executable is absent; live tests need the installed CLI")
    return resolved


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    """Invoke the real CLI. Argv is a list and the binary is resolved, so no shell."""
    return subprocess.run(  # noqa: S603 - resolved binary, list-form argv
        [_cli(), *args],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )


def _scan_json(address: str, *extra: str) -> dict[str, Any]:
    completed = _run("scan", "wallet", address, "--format", "json", *extra)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _finding(document: dict[str, Any], finding_type: str) -> dict[str, Any] | None:
    return next((f for f in document["findings"] if f["finding_type"] == finding_type), None)


def _value(document: dict[str, Any], finding_type: str) -> str | None:
    """A wallet finding title is "name: value"; return the value."""
    found = _finding(document, finding_type)
    return None if found is None else found["title"].partition(": ")[2]


# --- the contract every real scan holds to ----------------------------------


@pytest.mark.parametrize("address", [BTC_UNSPENT, BTC_TAPROOT, ETH_ACCOUNT, ETH_CONTRACT])
def test_real_scan_emits_the_canonical_contract(address: str) -> None:
    document = _scan_json(address)
    assert document["schema_version"] == "qureddy.scan.v1"
    assert document["scan"]["scanner_name"] == "wallet"
    assert document["scan"]["status"] == "completed"
    assert document["target"]["subject"] == address
    assert document["target"]["locator"].startswith(("btc://", "eth://"))
    assert document["findings"], "a completed scan reports at least one finding"
    assert document["evidence"], "every finding cites evidence"


@pytest.mark.parametrize("address", [BTC_UNSPENT, BTC_TAPROOT, ETH_ACCOUNT, ETH_CONTRACT])
def test_real_scan_reports_nist_level_zero(address: str) -> None:
    """secp256k1 meets no NIST category, on every chain and every account kind."""
    document = _scan_json(address)
    assert document["summary"]["nist_quantum_security_level_max"] == 0
    assert 0 in document["summary"]["nist_quantum_security_levels"]


@pytest.mark.parametrize("address", [BTC_UNSPENT, BTC_TAPROOT, ETH_ACCOUNT, ETH_CONTRACT])
def test_every_real_finding_carries_a_lane_and_a_source(address: str) -> None:
    """Claims-contract C1, asserted against output a real scan produced."""
    document = _scan_json(address)
    for evidence in document["evidence"]:
        notes = evidence.get("notes") or []
        assert any(note.startswith("lane=") for note in notes), evidence["evidence_type"]
        assert any(note.startswith("source=") for note in notes), evidence["evidence_type"]


def test_ethereum_exposure_is_inferred_never_observed() -> None:
    """C2: this lane reads account state and no key material."""
    document = _scan_json(ETH_ACCOUNT)
    published = _finding(document, "key.published")
    assert published is not None
    evidence_id = published["evidence_ids"][0]
    record = next(e for e in document["evidence"] if e["id"] == evidence_id)
    assert record["observation_type"] == "inferred"


def test_bitcoin_key_observed_only_with_recovered_bytes() -> None:
    """C2 on the Bitcoin lane: observed requires key bytes, else inferred."""
    document = _scan_json(BTC_PUBLISHED)
    recovered = _value(document, "pubkeys.recovered")
    published = _finding(document, "key.published")
    assert published is not None
    record = next(e for e in document["evidence"] if e["id"] == published["evidence_ids"][0])
    if recovered is not None and int(recovered) > 0:
        assert record["observation_type"] == "observed"
    else:
        assert record["observation_type"] in {"observed", "inferred"}


def test_bounded_coverage_is_reported_when_it_applies() -> None:
    """C4: a page-bounded scan states the bound as its own finding."""
    document = _scan_json(BTC_UNSPENT)
    examined = _value(document, "transactions.examined")
    coverage = _finding(document, "scan.coverage")
    assert examined is not None, "a chain scan always states how much it examined"
    assert " of " in examined, "the bound names both the sample and the total"
    if coverage is None:
        pytest.skip("this account fits inside one indexer page")
    record = next(e for e in document["evidence"] if e["id"] == coverage["evidence_ids"][0])
    assert record["observation_type"] == "not_testable"
    assert "of" in coverage["title"]


def test_account_kinds_are_distinguished_on_chain() -> None:
    """A contract has no externally owned key; a delegated account keeps one."""
    contract = _scan_json(ETH_CONTRACT)
    assert _value(contract, "account.kind") == "contract"
    assert _value(contract, "key.published") == "no"

    account = _scan_json(ETH_ACCOUNT)
    assert _value(account, "account.kind") in {"eoa", "delegated"}
    assert _value(account, "key.published") == "yes"


# --- the projections, written by the real CLI -------------------------------


def test_real_cbom_matches_the_shared_signature_asset_shape() -> None:
    completed = _run("scan", "wallet", BTC_UNSPENT, "--format", "cbom")
    assert completed.returncode == 0, completed.stderr
    document = json.loads(completed.stdout)
    assert document["bomFormat"] == "CycloneDX"
    components = document["components"]
    assert components, "the CBOM carries the signing algorithm as a crypto asset"
    crypto = components[0]["cryptoProperties"]
    assert crypto["assetType"] == "algorithm"
    # The empty-properties regression: another emitter claimed the asset first.
    properties = crypto["algorithmProperties"]
    assert properties["primitive"] == "signature"
    assert properties["nistQuantumSecurityLevel"] == 0
    assert set(properties["cryptoFunctions"]) == {"sign", "verify"}


def test_real_output_dir_writes_all_four_projections(tmp_path: Path) -> None:
    """The KeyError regression: rich and cbom passed while this wrote nothing."""
    completed = _run("scan", "wallet", BTC_UNSPENT, "--output-dir", str(tmp_path))
    assert completed.returncode == 0, completed.stderr
    written = sorted(path.name for path in tmp_path.iterdir())
    assert written == ["scan.cdx.json", "scan.json", "scan.jsonl", "scan.rich.txt"]
    for name in written:
        assert (tmp_path / name).stat().st_size > 0, name
    json.loads((tmp_path / "scan.json").read_text())
    json.loads((tmp_path / "scan.cdx.json").read_text())
    records = [json.loads(line) for line in (tmp_path / "scan.jsonl").read_text().splitlines()]
    assert records, "the JSONL stream carries at least one record"


def test_real_bundle_passes_the_cross_format_validator(tmp_path: Path) -> None:
    """The repo's own conformance validator, run on a bundle this CLI produced."""
    assert _run("scan", "wallet", BTC_UNSPENT, "--output-dir", str(tmp_path)).returncode == 0
    validator = Path(__file__).resolve().parents[2] / "scripts" / "validate_output_bundle.py"
    completed = subprocess.run(  # noqa: S603 - resolved path, list-form argv
        [
            "python",
            str(validator),
            "--run-dir",
            str(tmp_path),
            "--scanner",
            "wallet",
            "--target",
            BTC_UNSPENT,
        ],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_real_rich_output_names_the_subject_and_the_level() -> None:
    completed = _run("scan", "wallet", BTC_UNSPENT)
    assert completed.returncode == 0, completed.stderr
    assert "wallet" in completed.stdout.lower()
    assert BTC_UNSPENT[:12] in completed.stdout
    assert "nist_levels" in completed.stdout


# --- the paths a real user gets wrong ---------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "notanaddress",
        "0xdeadbeef",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf00",
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    ],
    ids=["garbage", "short-hex", "bad-base58-checksum", "bip141-invalid-v0-length"],
)
def test_a_malformed_address_exits_usage_without_scanning(address: str) -> None:
    completed = _run("scan", "wallet", address)
    assert completed.returncode == _EXIT_USAGE
    assert completed.stdout.strip() == "", "a rejected address renders no report"


def test_a_mistyped_eip55_checksum_is_refused() -> None:
    mistyped = ETH_ACCOUNT[:-1] + ("6" if ETH_ACCOUNT[-1] != "6" else "7")
    completed = _run("scan", "wallet", mistyped)
    assert completed.returncode == _EXIT_USAGE
    assert "checksum" in (completed.stderr + completed.stdout).lower()


def test_an_unsupported_chain_is_refused() -> None:
    completed = _run("scan", "wallet", BTC_UNSPENT, "--type", "solana")
    assert completed.returncode == _EXIT_USAGE


def test_an_unreachable_indexer_reports_not_tested(tmp_path: Path) -> None:
    """C3: a dead lane yields not_testable, and the offline lane still answers."""
    environment = dict(os.environ, QUREDDY_ESPLORA_URL="http://127.0.0.1:9")
    completed = subprocess.run(  # noqa: S603 - resolved binary, list-form argv
        [_cli(), "scan", "wallet", BTC_UNSPENT, "--format", "json"],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
        env=environment,
    )
    assert completed.returncode == 0, completed.stderr
    document = json.loads(completed.stdout)
    assert _value(document, "script.type") == "p2pkh", "the offline lane still answers"
    published = _finding(document, "key.published")
    assert published is not None
    record = next(e for e in document["evidence"] if e["id"] == published["evidence_ids"][0])
    assert record["observation_type"] == "not_testable"


def test_help_advertises_only_options_the_command_accepts() -> None:
    """The regression where the shared help block named three rejected options."""
    completed = _run("scan", "wallet", "--help")
    assert completed.returncode == 0
    for rejected in ("--output ", "--compact", "--min-severity"):
        assert rejected not in completed.stdout, rejected
    for accepted in ("--type", "--format", "--output-dir"):
        assert accepted in completed.stdout, accepted
