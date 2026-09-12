# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Ethereum account state. C2 holds: this lane reads no key material."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.vocabulary import Confidence, ObservationType, Readiness, Severity
from qureddy.scanners.wallet import ethereum
from qureddy.scanners.wallet.transport import record_exchanges

if TYPE_CHECKING:  # pragma: no cover - typing only
    from qureddy.scanners.wallet.record import Builder


def record_ethereum(builder: Builder, facts: ethereum.AccountFacts) -> None:
    """Account state. C2 holds: this lane reads no key material."""
    record_exchanges(builder, facts.exchanges)
    if not facts.reachable:
        for name in ("key.published", "account.kind", "account.nonce", "balance"):
            builder.not_tested(name, facts.error or "the RPC lane was unreachable", lane="rpc")
        return
    _record_account_state(builder, facts)
    if facts.kind == ethereum.KIND_CONTRACT:
        _record_contract(builder, facts)
        return
    _record_owned_key(builder, facts)
    builder.not_tested("signatures.examined", "this lane reads account state", lane="rpc")
    builder.not_tested("nonce.reuse", "this lane reads no signature", lane="defect")


def _record_account_state(builder: Builder, facts: ethereum.AccountFacts) -> None:
    """The three values every reachable account has, plus any delegate."""
    builder.record(
        "account.kind",
        facts.kind,
        lane="rpc",
        source="eth_getCode: 0x is an EOA, 23 bytes of 0xef0100 is a delegation, else a contract",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "account.nonce",
        str(facts.nonce),
        lane="rpc",
        source="eth_getTransactionCount, hexadecimal to integer",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "balance",
        f"{facts.balance_ether} ETH",
        lane="rpc",
        source="eth_getBalance, wei divided by 1e18",
        observation=ObservationType.OBSERVED,
    )
    if facts.delegate:
        builder.record(
            "account.delegate",
            facts.delegate,
            lane="rpc",
            source="the 20 bytes following the 0xef0100 delegation prefix",
            observation=ObservationType.OBSERVED,
        )


def _record_contract(builder: Builder, facts: ethereum.AccountFacts) -> None:
    """A contract holds no externally owned key; its owner keys sit elsewhere."""
    builder.record(
        "key.published",
        "no",
        lane="rpc",
        source="eth_getCode returned contract bytecode, so no externally owned key exists",
        observation=ObservationType.INFERRED,
        readiness=Readiness.NOT_APPLICABLE,
        confidence=Confidence.MEDIUM,
        description=(
            f"A contract account of {facts.code_bytes} bytes holds no externally "
            f"owned private key. Its owner, upgrade, and signer keys sit off this "
            f"address and were not tested."
        ),
    )
    builder.not_tested("owner.keys", "owner and upgrade keys are held off this address", lane="rpc")


def _record_owned_key(builder: Builder, facts: ethereum.AccountFacts) -> None:
    """C2: exposure here is INFERRED, since this lane reads no key material."""
    exposed = facts.kind == ethereum.KIND_DELEGATED or facts.nonce > 0
    if exposed:
        reason = (
            "the EIP-7702 delegation was set by a signed authorization"
            if facts.kind == ethereum.KIND_DELEGATED
            else f"the account has sent {facts.nonce} transaction(s)"
        )
        builder.record(
            "key.published",
            "yes",
            lane="rpc",
            source=f"{reason}, so ecrecover yields the key. No key material was read",
            observation=ObservationType.INFERRED,
            severity=Severity.HIGH,
            readiness=Readiness.QUANTUM_VULNERABLE,
            confidence=Confidence.MEDIUM,
            description=(
                f"{reason}, so the public key follows from any such signature through "
                f"ecrecover. The address is keccak256 of that key, so rotating the key "
                f"means abandoning the account. This lane read account state and no key "
                f"material, so the conclusion is inferred."
            ),
        )
    else:
        builder.record(
            "key.published",
            "no",
            lane="rpc",
            source="eth_getTransactionCount is zero, so no signature exists to recover from",
            observation=ObservationType.INFERRED,
            readiness=Readiness.UNKNOWN,
            confidence=Confidence.MEDIUM,
        )
