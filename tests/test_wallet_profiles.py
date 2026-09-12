# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Gate G2: recompute the grounding of every address compiled into the scanner.

Claims-contract rule C6 in `docs/architecture/wallet-scanner-adr.md` requires a
re-runnable check behind each hard-coded address. A test that compares one
recorded string against another recorded string satisfies nothing, so each test
here derives the address from published key material and compares the result.

Everything is computed from constants. No test in this file reaches the network.

Two primitives are implemented locally instead of imported:

- RIPEMD-160, because OpenSSL 3 moves it into the legacy provider and
  `hashlib.new("ripemd160")` is therefore unavailable on some builds. The
  implementation is checked against the published RIPEMD-160 vectors before any
  address is derived from it.
- bech32 and bech32m decoding, because `address.DecodedAddress` reports the
  witness program length and not its bytes, and because an independent decoder
  keeps the module under test from supplying its own answer (ADR anti-pattern
  A10). `address.decode` is still called directly for the script class,
  witness version, and program length assertions the ADR names.
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
from types import ModuleType

import pytest

from qureddy.scanners.wallet import address
from qureddy.scanners.wallet.profiles import (
    BIP173_EXAMPLE_PUBKEY,
    GENESIS_COINBASE_PUBKEY,
    PROFILES,
    REMOVED_ADDRESSES,
    SECP256K1_GX,
    AddressProfile,
)

_KECCAK_MODULE = "qureddy.scanners.wallet.keccak"
_KECCAK_PRESENT = importlib.util.find_spec(_KECCAK_MODULE) is not None
_ETH_ADDRESS_PATTERN = re.compile(r"0x[0-9a-fA-F]{40}")

# ---------------------------------------------------------------------------
# RIPEMD-160, as specified by Dobbertin, Bosselaers and Preneel in 1996
# ---------------------------------------------------------------------------

_MASK = 0xFFFFFFFF
_RIPEMD_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
_RIPEMD_K = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_RIPEMD_KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)

# The four permutation and rotation tables are laid out 16 to a line, one line
# per round, which is how the specification prints them. Formatting is held off
# so a reader can check a row against the spec.
# fmt: off
_RIPEMD_L = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_RIPEMD_R = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)
_RIPEMD_SL = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_RIPEMD_SR = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)
# fmt: on

#: Published RIPEMD-160 vectors from the reference specification.
_RIPEMD_VECTORS = (
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
)


def _rol(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK


def _ripemd_f(round_index: int, x: int, y: int, z: int) -> int:
    if round_index < 16:
        return x ^ y ^ z
    if round_index < 32:
        return (x & y) | ((_MASK ^ x) & z)
    if round_index < 48:
        return (x | (_MASK ^ y)) ^ z
    if round_index < 64:
        return (x & z) | (y & (_MASK ^ z))
    return x ^ (y | (_MASK ^ z))


def _ripemd_block(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    words = [int.from_bytes(block[i * 4 : i * 4 + 4], "little") for i in range(16)]
    a, b, c, d, e = state
    ar, br, cr, dr, er = state
    for j in range(80):
        left = a + _ripemd_f(j, b, c, d) + words[_RIPEMD_L[j]] + _RIPEMD_K[j // 16]
        t = (_rol(left & _MASK, _RIPEMD_SL[j]) + e) & _MASK
        a, b, c, d, e = e, t, b, _rol(c, 10), d
        right = ar + _ripemd_f(79 - j, br, cr, dr) + words[_RIPEMD_R[j]] + _RIPEMD_KR[j // 16]
        tr = (_rol(right & _MASK, _RIPEMD_SR[j]) + er) & _MASK
        ar, br, cr, dr, er = er, tr, br, _rol(cr, 10), dr
    return (
        (state[1] + c + dr) & _MASK,
        (state[2] + d + er) & _MASK,
        (state[3] + e + ar) & _MASK,
        (state[4] + a + br) & _MASK,
        (state[0] + b + cr) & _MASK,
    )


def _ripemd160(data: bytes) -> bytes:
    padded = data + b"\x80"
    padded += b"\x00" * ((56 - len(padded) % 64) % 64)
    padded += (len(data) * 8).to_bytes(8, "little")
    state = _RIPEMD_INIT
    for offset in range(0, len(padded), 64):
        state = _ripemd_block(state, padded[offset : offset + 64])
    return b"".join(word.to_bytes(4, "little") for word in state)


def _hash160(data: bytes) -> bytes:
    """SHA-256 then RIPEMD-160, the Bitcoin HASH160."""
    return _ripemd160(hashlib.sha256(data).digest())


# ---------------------------------------------------------------------------
# base58check and bech32, implemented here so the assertion is independent
# ---------------------------------------------------------------------------

_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _base58check_encode(payload: bytes) -> str:
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = _BASE58[remainder] + encoded
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + encoded


def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit in range(5):
            checksum ^= generator[bit] if ((top >> bit) & 1) else 0
    return checksum


def _witness_program(bech32_address: str) -> tuple[int, bytes]:
    """Return (witness version, program bytes) for a bech32/bech32m address."""
    lowered = bech32_address.lower()
    separator = lowered.rfind("1")
    hrp, tail = lowered[:separator], lowered[separator + 1 :]
    data = [_BECH32_CHARSET.index(char) for char in tail]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    checksum = _bech32_polymod(expanded + data)
    assert checksum in (_BECH32_CONST, _BECH32M_CONST), (
        f"{bech32_address} fails both bech32 and bech32m checksums"
    )
    accumulator = bits = 0
    program = bytearray()
    for value in data[1:-6]:
        accumulator = (accumulator << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            program.append((accumulator >> bits) & 0xFF)
    return data[0], bytes(program)


def _profile(key: str) -> AddressProfile:
    matches = [entry for entry in PROFILES if entry.key == key]
    assert len(matches) == 1, f"expected exactly one profile keyed {key!r}, found {len(matches)}"
    return matches[0]


def _eip55(address_hex: str, keccak: ModuleType) -> str:
    """Re-checksum an Ethereum address with whatever keccak.py exposes.

    `keccak.eip55` takes the 40-character body and returns it, so the `0x`
    prefix is stripped going in and restored coming out. The `keccak256`
    branch covers the module before it grew the EIP-55 helper.
    """
    body = address_hex.removeprefix("0x").lower()
    checksum = getattr(keccak, "eip55", None)
    if callable(checksum):
        return "0x" + str(checksum(body)).removeprefix("0x")
    digest_of = getattr(keccak, "keccak256", None)
    if not callable(digest_of):
        pytest.skip(f"{_KECCAK_MODULE} exposes neither eip55 nor keccak256")
    digest = bytes(digest_of(body.encode("ascii"))).hex()
    return "0x" + "".join(
        char.upper() if char.isalpha() and int(digest[index], 16) >= 8 else char
        for index, char in enumerate(body)
    )


# ---------------------------------------------------------------------------
# The primitives above are load-bearing, so they are grounded first
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("message", "expected"), _RIPEMD_VECTORS)
def test_local_ripemd160_matches_the_published_vectors(message: bytes, expected: str) -> None:
    assert _ripemd160(message).hex() == expected


# ---------------------------------------------------------------------------
# One test per row of ADR section 12
# ---------------------------------------------------------------------------


def test_genesis_address_is_hash160_of_the_block_0_coinbase_key() -> None:
    key = bytes.fromhex(GENESIS_COINBASE_PUBKEY)
    assert len(key) == 65, "uncompressed SEC1 is 65 bytes"
    assert key[0] == 0x04, "uncompressed SEC1 begins with 0x04"

    recomputed = _base58check_encode(b"\x00" + _hash160(key))

    profile = _profile("btc-genesis")
    assert recomputed == profile.address
    assert recomputed == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    decoded = address.decode(profile.address)
    assert decoded.valid, decoded.error
    assert decoded.script == "p2pkh"
    assert decoded.network == "mainnet"
    assert decoded.encoding == "base58check"


def test_taproot_profile_is_the_bip350_generator_vector() -> None:
    profile = _profile("btc-taproot")
    decoded = address.decode(profile.address)

    assert decoded.valid, decoded.error
    assert decoded.script == "v1_p2tr"
    assert decoded.witness_version == 1
    assert decoded.program_length == 32
    assert decoded.encoding == "bech32m"

    # The grounding names the generator x-coordinate, so the recorded text and
    # the decoded program have to agree with the constant.
    assert SECP256K1_GX in profile.grounding
    version, program = _witness_program(profile.address)
    assert version == 1
    assert program.hex() == SECP256K1_GX
    assert f"5120{SECP256K1_GX}" in profile.grounding


def test_bip173_example_key_hashes_to_the_encoded_witness_program() -> None:
    profile = _profile("btc-bip173-example")
    assert BIP173_EXAMPLE_PUBKEY.startswith("02"), "BIP-173 declares a compressed key"
    assert BIP173_EXAMPLE_PUBKEY.removeprefix("02") == SECP256K1_GX
    assert BIP173_EXAMPLE_PUBKEY in profile.grounding

    key = bytes.fromhex(BIP173_EXAMPLE_PUBKEY)
    assert len(key) == 33, "compressed SEC1 is 33 bytes"

    version, program = _witness_program(profile.address)
    assert version == 0
    assert len(program) == 20
    assert _hash160(key) == program

    decoded = address.decode(profile.address)
    assert decoded.valid, decoded.error
    assert decoded.script == "v0_p2wpkh"
    assert decoded.program_length == 20


# ---------------------------------------------------------------------------
# Rules that hold for every row
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", PROFILES, ids=lambda entry: entry.key)
def test_every_profile_address_decodes_on_its_declared_chain(profile: AddressProfile) -> None:
    assert profile.chain in {"bitcoin", "ethereum"}
    if profile.chain == "bitcoin":
        decoded = address.decode(profile.address)
        assert decoded.valid, f"{profile.address}: {decoded.error}"
        assert decoded.network == "mainnet"
        assert decoded.curve == "secp256k1"
        return
    body = profile.address.removeprefix("0x")
    assert profile.address.startswith("0x")
    assert len(body) == 40
    assert all(char in "0123456789abcdefABCDEF" for char in body)


@pytest.mark.skipif(
    not _KECCAK_PRESENT,
    reason=f"{_KECCAK_MODULE} does not exist yet; the EIP-55 recheck runs once it lands",
)
@pytest.mark.parametrize(
    "profile",
    [entry for entry in PROFILES if entry.chain == "ethereum"],
    ids=lambda entry: entry.key,
)
def test_ethereum_addresses_are_eip55_checksummed(profile: AddressProfile) -> None:
    keccak = importlib.import_module(_KECCAK_MODULE)
    assert _eip55(profile.address, keccak) == profile.address
    # The lowercase form has to re-checksum to the recorded one, which proves
    # the assertion above is recomputing the case and not comparing a string
    # against itself.
    assert _eip55(profile.address.lower(), keccak) == profile.address


@pytest.mark.skipif(
    not _KECCAK_PRESENT,
    reason=f"{_KECCAK_MODULE} does not exist yet; the EIP-55 recheck runs once it lands",
)
def test_ethereum_addresses_quoted_inside_groundings_are_eip55_checksummed() -> None:
    keccak = importlib.import_module(_KECCAK_MODULE)
    quoted = {
        match
        for profile in PROFILES
        for match in _ETH_ADDRESS_PATTERN.findall(f"{profile.grounding} {profile.check}")
    }
    assert quoted, "at least the ENS registry address is quoted in a grounding"
    for candidate in quoted:
        assert _eip55(candidate, keccak) == candidate


@pytest.mark.parametrize("profile", PROFILES, ids=lambda entry: entry.key)
def test_every_profile_carries_a_grounding_and_a_check(profile: AddressProfile) -> None:
    assert profile.key.strip()
    assert profile.address.strip()
    assert profile.demonstrates.strip()
    assert profile.grounding.strip()
    assert profile.check.strip()


def test_profile_keys_and_addresses_are_unique() -> None:
    keys = [entry.key for entry in PROFILES]
    addresses = [entry.address for entry in PROFILES]
    assert len(set(keys)) == len(keys)
    assert len(set(addresses)) == len(addresses)
    assert len(PROFILES) == 5, "ADR section 12 carries five rows"


def test_removed_addresses_stay_out_of_the_profiles() -> None:
    assert len(REMOVED_ADDRESSES) == 2
    compiled = {entry.address for entry in PROFILES}
    for removed, reason in REMOVED_ADDRESSES.items():
        assert removed not in compiled, f"{removed} was removed: {reason}"
        assert reason.strip(), f"{removed} has no recorded reason"
