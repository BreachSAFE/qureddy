# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Wallet scanner: account exposure on secp256k1 chains.

Both supported chains sign with secp256k1, which meets no NIST post-quantum
category, so every account carries `nistQuantumSecurityLevel` 0. That value is
constant across the chain. What a scan measures is whether the public key has
been published, because publication is the input Shor's algorithm requires.

The claims contract governing every finding this package emits lives in
`docs/architecture/wallet-scanner-adr.md` section 4. Two rules shape the module
boundaries here:

  An `OBSERVED` finding requires that the scanner read the bytes it reports. A
  conclusion drawn from protocol rules is `INFERRED`. The Ethereum lane reads
  account state and never key material, so its exposure conclusions are always
  the latter.

  Absent evidence is `NOT_TESTABLE`. Each lane below returns a reason on every
  failure path, so a caller reports what went unmeasured in place of a default.

Layering: this package sits under `scanners` and imports `qureddy.core` plus the
standard library only, which `lint-imports` enforces.
"""

from __future__ import annotations

from qureddy.scanners.wallet.address import CURVE, DecodedAddress, decode
from qureddy.scanners.wallet.indexer import ChainFacts, Signature, fetch
from qureddy.scanners.wallet.keccak import eip55, keccak256
from qureddy.scanners.wallet.profiles import PROFILES, AddressProfile

__all__ = [
    "CURVE",
    "PROFILES",
    "AddressProfile",
    "ChainFacts",
    "DecodedAddress",
    "Signature",
    "decode",
    "eip55",
    "fetch",
    "keccak256",
]
