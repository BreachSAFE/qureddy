# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""A contract account holds no externally owned key, so it carries no exposure.

Issue #991. `eth_getCode` returning runtime bytecode means the address has no
private key behind it: its owner, upgrade and signer keys sit elsewhere and this
scan never sees them. The verdict said `at_risk` anyway, because the posture
path reads the chain-level fact that Ethereum signs with secp256k1 and never
asks whether this particular account has a key at all.

Live against the real RPC, since the classification depends on what
`eth_getCode` actually returns for these addresses.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qureddy.scanners.wallet.profiles import PROFILES

_BY_KEY = {profile.key: profile for profile in PROFILES}
CONTRACT = _BY_KEY["eth-contract"].address
DELEGATED = _BY_KEY["eth-delegated-account"].address
_TIMEOUT_SECONDS = 90


def _cli() -> str:
    resolved = Path(sys.executable).with_name("qureddy")
    return str(resolved) if resolved.exists() else "qureddy"


def _scan(address: str) -> dict:
    completed = subprocess.run(  # noqa: S603 - resolved binary, list-form argv
        [_cli(), "scan", "wallet", address, "--format", "json"],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT_SECONDS,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _value(document: dict, finding_type: str) -> str | None:
    for finding in document["findings"]:
        if finding["finding_type"] == finding_type:
            return finding["title"].split(": ", 1)[1]
    return None


@pytest.fixture(scope="module")
def contract() -> dict:
    return _scan(CONTRACT)


@pytest.fixture(scope="module")
def delegated() -> dict:
    return _scan(DELEGATED)


def test_the_contract_account_is_classified_as_one(contract: dict) -> None:
    """The premise: without this the rest of the file tests nothing."""
    assert _value(contract, "account.kind") == "contract"
    assert _value(contract, "key.published") == "no"


def test_a_contract_account_carries_no_hndl_exposure(contract: dict) -> None:
    """There is no key at this address for an attacker to harvest."""
    interpretation = contract["summary"]["interpretation"]

    assert interpretation["hndl_exposure"] != "at_risk"


def test_a_contract_account_names_where_its_keys_actually_live(contract: dict) -> None:
    """The exposure moved off-address, and the scan says so rather than going quiet."""
    assert _value(contract, "owner.keys") == "not tested"


def test_a_contract_account_claims_no_classical_authentication(contract: dict) -> None:
    """The axis reads the account's own key, and this account has none."""
    axes = contract["summary"]["interpretation"]["axes"]

    assert axes["authentication"] != "classical"


def test_a_delegated_account_still_reads_at_risk(delegated: dict) -> None:
    """The control. An EIP-7702 account does hold a key, and it is published."""
    assert _value(delegated, "account.kind") == "delegated"
    assert _value(delegated, "key.published") == "yes"
    assert delegated["summary"]["interpretation"]["hndl_exposure"] == "at_risk"
