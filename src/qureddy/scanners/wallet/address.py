# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Offline decode of a Bitcoin address into its script class.

This lane reaches no network, so it answers for an air-gapped run and discloses
the queried account to nobody. The chain lane in `indexer.py` adds what only the
ledger knows.

One limit belongs in every consumer's mind: P2PK and bare-multisig outputs carry
no address encoding at all, and explorers display the equivalent P2PKH string for
them. An address alone therefore cannot reveal that its funding output publishes
a public key directly; that requires reading `vout.scriptpubkey_type` from the
chain. Block 0's coinbase is the canonical case, and it is why `key_in_output`
below is a claim about the address form only.

Checksums are validated, so a mistyped address is rejected here instead of
producing a confident answer about an account that does not exist.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3
_MAX_ADDRESS_CHARS = 128
_P2WPKH_PROGRAM_BYTES = 20
_P2WSH_PROGRAM_BYTES = 32
# BIP-141 bounds every witness program to this range; version 0 narrows it further.
_MIN_PROGRAM_BYTES = 2
_MAX_PROGRAM_BYTES = 40
_MAX_WITNESS_VERSION = 16
# base58check: a version byte, a 20-byte hash, and a 4-byte checksum.
_BASE58_MIN_RAW_BYTES = 5
_BASE58_PAYLOAD_BYTES = 21

# base58 version byte -> (script class, network)
_VERSION_BYTES = {
    0x00: ("p2pkh", "mainnet"),
    0x05: ("p2sh", "mainnet"),
    0x6F: ("p2pkh", "testnet"),
    0xC4: ("p2sh", "testnet"),
}
_HRP_NETWORKS = {"bc": "mainnet", "tb": "testnet", "bcrt": "regtest"}

# script class -> (signature scheme, public key readable in the output itself)
_SCRIPT_SCHEMES = {
    "p2pk": ("ECDSA", True),
    "multisig": ("ECDSA", True),
    "p2pkh": ("ECDSA", False),
    "p2sh": ("ECDSA", False),
    "v0_p2wpkh": ("ECDSA", False),
    "v0_p2wsh": ("ECDSA", False),
    "v1_p2tr": ("Schnorr", True),
}

#: Script classes whose output carries a readable public key with no spend.
KEY_IN_OUTPUT_SCRIPTS = frozenset(
    script for script, (_scheme, in_output) in _SCRIPT_SCHEMES.items() if in_output
)

#: Every Bitcoin script class here signs on this curve.
CURVE = "secp256k1"


@dataclass(frozen=True)
class DecodedAddress:
    """What the address string alone establishes.

    `error` carries the rejection reason; when it is set every other field is
    left at its default so a caller cannot read a half-decoded address as fact.
    """

    address: str
    script: str = ""
    network: str = ""
    scheme: str = ""
    curve: str = CURVE
    key_in_output: bool = False
    witness_version: int | None = None
    program_length: int | None = None
    encoding: str = ""
    error: str = ""

    @property
    def valid(self) -> bool:
        """True when the address decoded and every other field carries a read value."""
        return not self.error


def _base58check(value: str) -> bytes | None:
    """Decode base58check, returning the payload when the checksum holds."""
    total = 0
    for char in value:
        index = _BASE58.find(char)
        if index < 0:
            return None
        total = total * 58 + index
    body = total.to_bytes((total.bit_length() + 7) // 8, "big") if total else b""
    raw = b"\x00" * (len(value) - len(value.lstrip("1"))) + body
    if len(raw) < _BASE58_MIN_RAW_BYTES:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return None
    return payload


def _polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit in range(5):
            checksum ^= generator[bit] if ((top >> bit) & 1) else 0
    return checksum


def _expand_hrp(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data: list[int], from_bits: int, to_bits: int) -> list[int] | None:
    accumulator = bits = 0
    out: list[int] = []
    max_value = (1 << to_bits) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((accumulator >> bits) & max_value)
    if bits >= from_bits or ((accumulator << (to_bits - bits)) & max_value):
        return None
    return out


def _bech32_decode(address: str) -> tuple[str, list[int], str] | None:
    """Split a bech32/bech32m address, returning (hrp, data, encoding)."""
    # BIP-173 rejects mixed case, so a mixed-case string is a corruption signal.
    if address != address.lower() and address != address.upper():
        return None
    lowered = address.lower()
    separator = lowered.rfind("1")
    if separator < 1 or separator + 7 > len(lowered):
        return None
    hrp, tail = lowered[:separator], lowered[separator + 1 :]
    data: list[int] = []
    for char in tail:
        index = _BECH32.find(char)
        if index < 0:
            return None
        data.append(index)
    constant = _polymod(_expand_hrp(hrp) + data)
    if constant == _BECH32_CONST:
        return hrp, data[:-6], "bech32"
    if constant == _BECH32M_CONST:
        return hrp, data[:-6], "bech32m"
    return None


def _decode_segwit(address: str, hrp: str, data: list[int], encoding: str) -> DecodedAddress:
    if hrp not in _HRP_NETWORKS or not data:
        return DecodedAddress(address=address, error=f"unknown segwit prefix {hrp!r}")
    version, program = data[0], _convert_bits(data[1:], 5, 8)
    if program is None or not _MIN_PROGRAM_BYTES <= len(program) <= _MAX_PROGRAM_BYTES:
        return DecodedAddress(address=address, error="witness program length is out of range")
    # BIP-141 narrows witness version 0 to exactly 20 or 32 bytes, on top of the
    # generic 2 to 40 range every version shares. The generic gate alone accepts
    # BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P, a 16-byte v0 program that appears in
    # the invalid list of both BIP-173 and BIP-350, and no consensus rule
    # recognises it as spendable.
    if version == 0 and len(program) not in (_P2WPKH_PROGRAM_BYTES, _P2WSH_PROGRAM_BYTES):
        return DecodedAddress(
            address=address,
            error="witness version 0 program must be 20 or 32 bytes (BIP-141)",
        )
    # BIP-350 pairs witness version 0 with bech32 and every later version with
    # bech32m; a crossed pair is a different address than the sender intended.
    version_zero_mismatch = version == 0 and encoding != "bech32"
    later_version_mismatch = version > 0 and encoding != "bech32m"
    if version > _MAX_WITNESS_VERSION or version_zero_mismatch or later_version_mismatch:
        return DecodedAddress(address=address, error="witness version and encoding disagree")
    script = {
        (0, 20): "v0_p2wpkh",
        (0, 32): "v0_p2wsh",
        (1, 32): "v1_p2tr",
    }.get((version, len(program)), f"witness_v{version}")
    sig_scheme, key_in_output = _SCRIPT_SCHEMES.get(script, ("unknown", False))
    return DecodedAddress(
        address=address,
        script=script,
        network=_HRP_NETWORKS[hrp],
        scheme=sig_scheme,
        key_in_output=key_in_output,
        witness_version=version,
        program_length=len(program),
        encoding=encoding,
    )


def _decode_base58check(address: str) -> DecodedAddress:
    """Decode a base58check address into its script class."""
    payload = _base58check(address)
    if payload is None:
        return DecodedAddress(
            address=address, error="address fails both base58check and bech32 decoding"
        )
    if len(payload) != _BASE58_PAYLOAD_BYTES:
        return DecodedAddress(address=address, error="base58 payload length is unexpected")
    script, network = _VERSION_BYTES.get(payload[0], ("", ""))
    if not script:
        return DecodedAddress(
            address=address, error=f"base58 version byte 0x{payload[0]:02x} is unassigned"
        )
    sig_scheme, key_in_output = _SCRIPT_SCHEMES[script]
    return DecodedAddress(
        address=address,
        script=script,
        network=network,
        scheme=sig_scheme,
        key_in_output=key_in_output,
        program_length=_P2WPKH_PROGRAM_BYTES,
        encoding="base58check",
    )


def decode(address: str) -> DecodedAddress:
    """Decode a Bitcoin address offline. Always returns; a rejection sets `error`."""
    candidate = (address or "").strip()
    if not candidate:
        return DecodedAddress(address=candidate, error="address is empty")
    if len(candidate) > _MAX_ADDRESS_CHARS:
        return DecodedAddress(
            address=candidate[:_MAX_ADDRESS_CHARS],
            error=f"address exceeds {_MAX_ADDRESS_CHARS} characters",
        )

    segwit = _bech32_decode(candidate)
    if segwit is not None:
        return _decode_segwit(candidate, *segwit)

    return _decode_base58check(candidate)


def signature_scheme(script: str) -> str:
    """The signature scheme a script class uses, or an empty string when unmapped."""
    return _SCRIPT_SCHEMES.get(script, ("", False))[0]
