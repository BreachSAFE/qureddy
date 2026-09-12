# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Ethereum account state over JSON-RPC.

Ethereum signs with secp256k1, the same curve Bitcoin uses, so the CBOM asset is
shared. The exposure shape differs and is wider. An address is the last 20 bytes
of keccak256 of the public key, so the key stays hidden until the account sends
its first transaction. From that point anyone recovers it from the signature with
ecrecover, and because the address derives from the key it cannot be rotated:
securing the account means abandoning it.

This lane reads account state and never key material, so under claims-contract
rule C2 every exposure conclusion it supports is `INFERRED`. The caller records
that; this module reports the state it read.

`QUREDDY_ETH_RPC` replaces the public defaults, so an operator pointing this at
an internal node keeps the queried account inside that boundary.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from qureddy.scanners.wallet.indexer import HttpExchange
from qureddy.scanners.wallet.keccak import eip55

DEFAULT_RPCS: tuple[str, ...] = (
    "https://ethereum-rpc.publicnode.com",
    "https://rpc.ankr.com/eth",
)
ETH_RPC_ENV = "QUREDDY_ETH_RPC"
_USER_AGENT = "qureddy-wallet"
_WEI_PER_ETHER = 10**18
#: Body characters kept in a transcript. Truncation is stated where it applies.
_MAX_BODY_TRACE = 40_000

_ADDRESS_TOTAL_CHARS = 42
_HEX_DIGITS = frozenset("0123456789abcdef")

# EIP-7702 writes `0xef0100 || address` into an account's code slot. That account
# keeps its private key and stays externally owned, so reading any non-empty code
# as a contract reports the most exposed class as keyless. EIP-3541 bans deploying
# code beginning 0xef, so no contract can imitate the indicator.
_DELEGATION_PREFIX = "ef0100"
_DELEGATION_HEX_LEN = 46  # 23 bytes: the 3-byte prefix and a 20-byte address

#: Account kinds this lane distinguishes.
KIND_EOA = "eoa"
KIND_DELEGATED = "delegated"
KIND_CONTRACT = "contract"


@dataclass
class AccountDecoded:
    """What the address string alone establishes."""

    address: str
    checksum_present: bool = False
    error: str = ""

    @property
    def valid(self) -> bool:
        """True when the address parsed and any checksum it carried held."""
        return not self.error


@dataclass
class AccountFacts:
    """Account state read over JSON-RPC."""

    reachable: bool = False
    source: str = ""
    error: str = ""
    kind: str = KIND_EOA
    nonce: int = 0
    balance_wei: int = 0
    code_bytes: int = 0
    delegate: str = ""
    exchanges: list[HttpExchange] = field(default_factory=list)

    @property
    def balance_ether(self) -> str:
        """Balance in ether, from the wei the node reported."""
        return f"{self.balance_wei / _WEI_PER_ETHER:.8f}"


def rpcs() -> tuple[str, ...]:
    """Endpoints to try, in order. An explicit override replaces the defaults."""
    override = os.environ.get(ETH_RPC_ENV, "").strip().rstrip("/")
    return (override,) if override else DEFAULT_RPCS


def looks_like_address(value: str) -> bool:
    """True for a 0x-prefixed 20-byte hex string."""
    candidate = (value or "").strip()
    return (
        len(candidate) == _ADDRESS_TOTAL_CHARS
        and candidate[:2].lower() == "0x"
        and set(candidate[2:].lower()) <= _HEX_DIGITS
    )


def decode(address: str) -> AccountDecoded:
    """Validate an address offline, checking the EIP-55 checksum when one is present."""
    candidate = (address or "").strip()
    if not looks_like_address(candidate):
        return AccountDecoded(
            address=candidate, error="address is not a 0x-prefixed 20-byte hex string"
        )
    body = candidate[2:]
    single_case = body == body.lower() or body == body.upper()
    if single_case:
        # A single-case address is valid and carries no typo protection, so it is
        # normalized to the checksummed form the rest of the scan reports.
        return AccountDecoded(address="0x" + eip55(body), checksum_present=False)
    if eip55(body) != body:
        return AccountDecoded(
            address=candidate,
            checksum_present=True,
            error="EIP-55 checksum does not match, so the address is likely mistyped",
        )
    return AccountDecoded(address=candidate, checksum_present=True)


def classify_code(code: str) -> str:
    """Classify an eth_getCode result as an EOA, a delegation, or a contract."""
    body = (code or "").lower().removeprefix("0x")
    if not body or body == "0":
        return KIND_EOA
    if len(body) == _DELEGATION_HEX_LEN and body.startswith(_DELEGATION_PREFIX):
        return KIND_DELEGATED
    return KIND_CONTRACT


def delegate_of(code: str) -> str:
    """The implementation address a delegation points at, checksummed."""
    body = (code or "").lower().removeprefix("0x")
    if classify_code(code) != KIND_DELEGATED:
        return ""
    return "0x" + eip55(body[len(_DELEGATION_PREFIX) :])


def _rpc(
    url: str,
    method: str,
    params: list[Any],
    timeout: float,
    exchanges: list[HttpExchange] | None = None,
) -> Any:
    """One JSON-RPC call, recording the whole exchange for the transcript.

    The override is operator-controlled, so the scheme is checked before the
    open: `file:` would otherwise turn an endpoint setting into a local-file
    read. Every outcome lands on the `HttpExchange`, a refused scheme included,
    so a reader sees what was attempted.
    """
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    headers = {"Content-Type": "application/json", "User-Agent": _USER_AGENT}
    exchange = HttpExchange(
        method="POST",
        url=url,
        operation=method,
        request_headers=dict(headers),
        request_body=payload,
    )
    if exchanges is not None:
        exchanges.append(exchange)
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        exchange.error = "refused: the scheme is neither http nor https"
        return None
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url, data=payload.encode(), headers=headers
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read()
            exchange.status = getattr(response, "status", 0) or 0
            exchange.reason = getattr(response, "reason", "") or ""
            exchange.response_headers = dict(response.headers.items())
        exchange.response_bytes = len(raw)
        body = json.loads(raw.decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        exchange.status, exchange.error = exc.code, f"HTTP {exc.code}"
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        exchange.error = f"{type(exc).__name__}: {exc}"
        return None
    except ValueError as exc:
        exchange.error = f"the body was not JSON: {exc}"
        return None
    finally:
        exchange.duration_ms = int((time.monotonic() - started) * 1000)
    exchange.body_text = json.dumps(body, indent=2)[:_MAX_BODY_TRACE]
    if not isinstance(body, dict) or "result" not in body:
        return None
    return body["result"]


def _as_int(value: Any) -> int | None:
    """Parse a 0x-prefixed quantity. Returns None when the node sent something else."""
    if not isinstance(value, str) or not value.startswith("0x"):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def fetch(address: str, *, timeout_seconds: float = 12.0) -> AccountFacts:
    """Read account state: code, nonce, balance. Never raises."""
    if not looks_like_address(address):
        return AccountFacts(error="no address supplied")
    last_error = "every configured RPC endpoint was unreachable"
    for url in rpcs():
        host = urllib.parse.urlsplit(url).netloc
        exchanges: list[HttpExchange] = []
        code = _rpc(url, "eth_getCode", [address, "latest"], timeout_seconds, exchanges)
        if not isinstance(code, str):
            last_error = f"{host} did not answer eth_getCode"
            continue
        nonce = _as_int(
            _rpc(url, "eth_getTransactionCount", [address, "latest"], timeout_seconds, exchanges)
        )
        if nonce is None:
            last_error = f"{host} did not answer eth_getTransactionCount"
            continue
        facts = AccountFacts(
            reachable=True,
            source=url,
            kind=classify_code(code),
            nonce=nonce,
            delegate=delegate_of(code),
            code_bytes=max(0, (len(code) - 2) // 2),
            exchanges=exchanges,
        )
        balance = _as_int(
            _rpc(url, "eth_getBalance", [address, "latest"], timeout_seconds, exchanges)
        )
        if balance is None:
            facts.error = "balance was unavailable, so it reads not tested"
        else:
            facts.balance_wei = balance
        return facts
    return AccountFacts(error=last_error)
