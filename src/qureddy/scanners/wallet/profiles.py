# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Grounding for every address compiled into the wallet scanner.

This module is the data form of `docs/architecture/wallet-scanner-adr.md`
section 12, and it exists to satisfy claims-contract rule C6: every address
compiled into the source carries a re-runnable check that establishes what it
is. Acceptance gate G2 is `tests/test_wallet_profiles.py`, which recomputes each
grounding offline from the constants below instead of comparing strings.

The rule has a history. The prototype that preceded this scanner shipped six
demo addresses: five were recalled from model memory and one was an arbitrary
third party's live wallet taken from the mempool. Recall is not a source, and a
public ledger entry is still somebody's account. Both kinds are recorded in
`REMOVED_ADDRESSES` with the reason they went, so neither returns unnoticed.

Two constants carry the key material the checks rest on, and both are quoted in
a public specification: the secp256k1 generator x-coordinate, which is the
witness program of the BIP-350 taproot vector and the body of the BIP-173
example public key, and the block 0 coinbase public key, which hashes to the
genesis address.

Layering: `scanners/wallet` imports `core` and the standard library only. This
module needs neither, so it imports the standard library alone.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

#: secp256k1 generator point x-coordinate (SEC 2 v2, section 2.4.1, curve
#: parameter G). It is the 32-byte witness program of the BIP-350 taproot
#: vector below, and the 32-byte body of the BIP-173 example public key.
SECP256K1_GX: Final = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

#: Block 0 coinbase output public key, uncompressed SEC1 (65 bytes, 0x04 prefix
#: then x then y). The block 0 coinbase pays to a bare P2PK output, so this key
#: has been readable on chain since 2009-01-03.
GENESIS_COINBASE_PUBKEY: Final = (
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6"
    "49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)

#: The public key BIP-173's Examples section declares for all of its examples,
#: compressed SEC1: the 0x02 prefix followed by the generator x-coordinate.
BIP173_EXAMPLE_PUBKEY: Final = f"02{SECP256K1_GX}"


@dataclass(frozen=True)
class AddressProfile:
    """One address compiled into the source, with the check that grounds it.

    Attributes:
        key: Stable identifier for the entry.
        chain: The chain the address belongs to, `bitcoin` or `ethereum`.
        address: The address as it is written in source.
        demonstrates: What the address is carried here to show.
        grounding: The statement a check has to reproduce for the entry to stand.
        check: A command an operator can run to reproduce the grounding live.
            The offline recomputation lives in `tests/test_wallet_profiles.py`;
            this string is the network-reaching form of the same question.
    """

    key: str
    chain: str
    address: str
    demonstrates: str
    grounding: str
    check: str


PROFILES: Final[tuple[AddressProfile, ...]] = (
    AddressProfile(
        key="btc-genesis",
        chain="bitcoin",
        address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        demonstrates=(
            "P2PK output whose public key is on chain, displayed by explorers "
            "under its P2PKH re-encoding"
        ),
        grounding=(
            f"HASH160 of the block 0 coinbase public key {GENESIS_COINBASE_PUBKEY}, "
            f"base58check encoded with version byte 0x00, equals this address"
        ),
        check=(
            "curl -s https://mempool.space/api/tx/$(curl -s "
            "https://mempool.space/api/block/$(curl -s "
            "https://mempool.space/api/block-height/0)/txids | jq -r '.[0]') "
            "| jq -r '.vout[0].scriptpubkey, .vout[0].scriptpubkey_type'"
        ),
    ),
    AddressProfile(
        key="btc-taproot",
        chain="bitcoin",
        address="bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        demonstrates="v1 witness program: the x-only public key is the output itself",
        grounding=(
            f"BIP-350 valid address vector, scriptPubKey 5120{SECP256K1_GX}, "
            f"so the witness program is the secp256k1 generator x-coordinate"
        ),
        check=(
            "curl -s https://raw.githubusercontent.com/bitcoin/bips/master/"
            "bip-0350.mediawiki | grep -i "
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
        ),
    ),
    AddressProfile(
        key="btc-bip173-example",
        chain="bitcoin",
        address="bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        demonstrates="v0 witness program committing to a published key, recoverable from a spend",
        grounding=(
            f"BIP-173 Examples declares the example public key {BIP173_EXAMPLE_PUBKEY}; "
            f"HASH160 of those bytes equals the 20-byte witness program this address encodes"
        ),
        check=(
            "curl -s https://raw.githubusercontent.com/bitcoin/bips/master/"
            "bip-0173.mediawiki | grep -i -e bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 "
            "-e 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ),
    ),
    AddressProfile(
        key="eth-delegated-account",
        chain="ethereum",
        address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        demonstrates="EIP-7702 delegated externally owned account",
        grounding=(
            "ENS registry 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e resolves "
            "namehash('vitalik.eth') to a resolver whose addr() returns this address"
        ),
        check=(
            "cast call 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e "
            "'resolver(bytes32)(address)' $(cast namehash vitalik.eth) "
            "&& cast call <resolver> 'addr(bytes32)(address)' $(cast namehash vitalik.eth)"
        ),
    ),
    AddressProfile(
        key="eth-contract",
        chain="ethereum",
        address="0xdAC17F958D2ee523a2206206994597C13D831ec7",
        demonstrates="contract account, so no externally owned key exists at this address",
        grounding=(
            "eth_call name() returns 'Tether USD', symbol() returns 'USDT', "
            "decimals() returns 6, and eth_getCode returns runtime bytecode"
        ),
        check=(
            "cast call 0xdAC17F958D2ee523a2206206994597C13D831ec7 'name()(string)' "
            "&& cast call 0xdAC17F958D2ee523a2206206994597C13D831ec7 'symbol()(string)' "
            "&& cast call 0xdAC17F958D2ee523a2206206994597C13D831ec7 'decimals()(uint8)'"
        ),
    ),
)

#: Addresses the prototype carried and this scanner refuses, held here so a
#: later edit that reintroduces one fails gate G2 instead of passing quietly.
#: The reasons are the prototype's own removal note, carried over verbatim in
#: substance from `itsqday` `features/wallet/profiles.py`.
REMOVED_ADDRESSES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": (
            "recalled as a P2SH example with no source stating what it is"
        ),
        "bc1qttv968rzhpdha9rtj5k6dzp4s3jfzppdqjjuef": (
            "an arbitrary third party's live wallet taken from /mempool/recent; "
            "a public ledger entry is still that person's account"
        ),
    }
)
