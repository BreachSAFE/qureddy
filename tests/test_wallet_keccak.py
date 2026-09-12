# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Pin Keccak-256 (Ethereum padding) and the EIP-55 checksum to published values.

Two layers of evidence, because a hash that is wrong in a self-consistent way
still passes a self-consistent test:

1. Published digests and published EIP-55 addresses, written as literals from
   the Keccak specification and EIP-55, compared against the module output.
2. A second Keccak implementation written here from the specification text.
   It derives the rho offsets from the (1, 0) walk and the round constants
   from the degree-8 LFSR, so it shares no table with
   ``qureddy.scanners.wallet.keccak`` and is structured differently (a dict
   keyed by (x, y) against the module's flat lane list). Layer 1 validates
   this reference on short messages; layer 2 then extends that evidence to
   multi-block inputs, where no published digest is on hand, and pins the
   absorb loop and the block-boundary padding cases.

The suite also pins the padding difference itself: Keccak-256 and
``hashlib.sha3_256`` must disagree on every input. A silent swap to
``hashlib`` would break every Ethereum address this scanner reads, and it
would look like a dependency cleanup in review.
"""

from __future__ import annotations

import hashlib

import pytest

from qureddy.scanners.wallet.keccak import eip55, keccak256

_MASK64 = (1 << 64) - 1
_RATE_BYTES = 136

# Keccak-256 digests of the three canonical short messages.
_PUBLISHED_DIGESTS = (
    (b"", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
    (b"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"),
    (b"testing", "5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"),
)

# EIP-55 "Test Cases" section: one all-caps pair, one all-lower pair, and the
# four normal addresses. Each is fed in lowercase so the module has to produce
# the casing, and the published string is the expected output.
_EIP55_VECTORS = (
    "52908400098527886E0F7030069857D2E4169EE7",
    "8617E340B3D01FA5F11F306F4090FD50E238070D",
    "de709f2102306220921060314715629080e2fb77",
    "27b1fdb04752bbc536007a920d24acb045561c26",
    "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
)

# Lengths that straddle every absorb and padding boundary: empty, short, one
# byte under the rate (the merged 0x81 pad byte), exactly the rate (a whole
# extra pad block), one byte over, and several full blocks.
_BOUNDARY_LENGTHS = (0, 1, 135, 136, 137, 200, 271, 272, 273, 1000)


def _deterministic_bytes(length: int) -> bytes:
    """Return a fixed byte string of ``length``, varied enough to move every lane."""
    return bytes((index * 37 + 11) % 256 for index in range(length))


def _rot(value: int, count: int) -> int:
    """Rotate a 64-bit lane left, for the reference implementation below."""
    count %= 64
    return ((value << count) | (value >> (64 - count))) & _MASK64


def _reference_rho_offsets() -> dict[tuple[int, int], int]:
    """Derive the rho offsets from the specification walk instead of a table.

    Start at (1, 0), step (x, y) -> (y, 2x + 3y) mod 5, and give step t the
    offset (t + 1)(t + 2)/2 mod 64. Lane (0, 0) is never visited and has
    offset 0.
    """
    offsets = {(0, 0): 0}
    x, y = 1, 0
    for step in range(24):
        offsets[(x, y)] = ((step + 1) * (step + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return offsets


def _reference_round_constants() -> list[int]:
    """Derive the 24 iota constants from the specification's degree-8 LFSR."""
    constants = []
    register = 1
    for _round in range(24):
        constant = 0
        for bit in range(7):
            register = ((register << 1) ^ ((register >> 7) * 0x71)) % 256
            if register & 2:
                constant ^= 1 << ((1 << bit) - 1)
        constants.append(constant)
    return constants


def _reference_permute(
    state: dict[tuple[int, int], int],
    offsets: dict[tuple[int, int], int],
    constants: list[int],
) -> dict[tuple[int, int], int]:
    """Run Keccak-f[1600] over a state keyed by (x, y), per the specification."""
    grid = [(x, y) for x in range(5) for y in range(5)]
    for constant in constants:
        parity = {}
        for x in range(5):
            parity[x] = state[(x, 0)] ^ state[(x, 1)] ^ state[(x, 2)]
            parity[x] ^= state[(x, 3)] ^ state[(x, 4)]
        column = {x: parity[(x - 1) % 5] ^ _rot(parity[(x + 1) % 5], 1) for x in range(5)}
        state = {(x, y): state[(x, y)] ^ column[x] for x, y in grid}
        state = {(y, (2 * x + 3 * y) % 5): _rot(state[(x, y)], offsets[(x, y)]) for x, y in grid}
        state = {
            (x, y): state[(x, y)] ^ ((state[((x + 1) % 5, y)] ^ _MASK64) & state[((x + 2) % 5, y)])
            for x, y in grid
        }
        state[(0, 0)] ^= constant
    return state


def _reference_keccak256(data: bytes) -> bytes:
    """Hash with an independently written Ethereum-padding Keccak-256 sponge."""
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _RATE_BYTES:
        padded.append(0x00)
    padded[-1] ^= 0x80

    offsets = _reference_rho_offsets()
    constants = _reference_round_constants()
    state = {(x, y): 0 for x in range(5) for y in range(5)}
    for block_start in range(0, len(padded), _RATE_BYTES):
        block = padded[block_start : block_start + _RATE_BYTES]
        for lane in range(_RATE_BYTES // 8):
            chunk = bytes(block[lane * 8 : lane * 8 + 8])
            state[(lane % 5, lane // 5)] ^= int.from_bytes(chunk, "little")
        state = _reference_permute(state, offsets, constants)
    return b"".join(state[(lane % 5, lane // 5)].to_bytes(8, "little") for lane in range(4))


class TestPublishedDigests:
    """The three canonical Keccak-256 vectors, as published, for the module."""

    @pytest.mark.parametrize(("message", "expected"), _PUBLISHED_DIGESTS)
    def test_module_matches_published_digest(self, message: bytes, expected: str) -> None:
        assert keccak256(message).hex() == expected

    @pytest.mark.parametrize(("message", "expected"), _PUBLISHED_DIGESTS)
    def test_reference_matches_published_digest(self, message: bytes, expected: str) -> None:
        """Validate the in-test reference before the multi-block tests rely on it."""
        assert _reference_keccak256(message).hex() == expected

    def test_digest_is_thirty_two_bytes(self) -> None:
        assert len(keccak256(b"abc")) == 32


class TestEthereumPadding:
    """Keccak's 0x01 domain byte against FIPS 202's 0x06.

    If these ever agree, the module has been swapped for hashlib and every
    address, selector, and checksum derived from it is wrong.
    """

    @pytest.mark.parametrize("message", [b"", b"abc", b"testing", _deterministic_bytes(300)])
    def test_differs_from_sha3_256(self, message: bytes) -> None:
        assert keccak256(message) != hashlib.sha3_256(message).digest()

    def test_empty_digest_is_not_the_sha3_empty_digest(self) -> None:
        sha3_empty = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        assert keccak256(b"").hex() != sha3_empty


class TestMultiBlockAbsorb:
    """Inputs past the 136-byte rate, cross-checked against the in-test reference."""

    @pytest.mark.parametrize("length", _BOUNDARY_LENGTHS)
    def test_matches_reference_across_block_boundaries(self, length: int) -> None:
        message = _deterministic_bytes(length)
        assert keccak256(message).hex() == _reference_keccak256(message).hex()

    def test_long_input_spans_several_blocks(self) -> None:
        message = b"qureddy wallet scanner " * 64
        assert len(message) > _RATE_BYTES
        assert keccak256(message).hex() == _reference_keccak256(message).hex()

    def test_one_byte_change_in_a_later_block_changes_the_digest(self) -> None:
        """Pin that block 2 actually reaches the state; a dropped block would tie these."""
        first = bytearray(_deterministic_bytes(300))
        second = bytearray(first)
        second[280] ^= 0x01
        assert keccak256(bytes(first)) != keccak256(bytes(second))


class TestEip55:
    """EIP-55 casing against the addresses published in the EIP."""

    @pytest.mark.parametrize("published", _EIP55_VECTORS)
    def test_published_vector(self, published: str) -> None:
        assert eip55(published.lower()) == published

    def test_vitalik_address(self) -> None:
        body = "d8da6bf26964af9d7eed9e03e53415d37aa96045"
        assert eip55(body) == "d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

    @pytest.mark.parametrize("published", _EIP55_VECTORS)
    def test_idempotent(self, published: str) -> None:
        checksummed = eip55(published.lower())
        assert eip55(checksummed.lower()) == checksummed
        assert eip55(checksummed) == checksummed

    @pytest.mark.parametrize("published", _EIP55_VECTORS)
    def test_casing_is_the_only_change(self, published: str) -> None:
        assert eip55(published.lower()).lower() == published.lower()

    def test_casing_follows_the_digest_nibbles(self) -> None:
        """Recompute the rule here so the test pins EIP-55, not the module's loop."""
        body = "d8da6bf26964af9d7eed9e03e53415d37aa96045"
        digest = _reference_keccak256(body.encode("ascii")).hex()
        expected = "".join(
            char.upper() if int(digest[position], 16) >= 8 else char
            for position, char in enumerate(body)
        )
        assert eip55(body) == expected

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
            "d8da6bf26964af9d7eed9e03e53415d37aa9604",
            "d8da6bf26964af9d7eed9e03e53415d37aa960455",
            "d8da6bf26964af9d7eed9e03e53415d37aa9604g",
            "d8da6bf26964af9d7eed9e03e53415d37aa9604 ",
        ],
    )
    def test_rejects_a_body_that_is_not_forty_hex_characters(self, bad: str) -> None:
        with pytest.raises(ValueError, match="hexadecimal characters"):
            eip55(bad)
