# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Keccak-256 in the Ethereum flavour, and the EIP-55 checksum built on it.

Why the padding differs from SHA-3
----------------------------------
Ethereum froze its hash while Keccak was still the SHA-3 candidate. The
submission appends the domain byte ``0x01`` before the final ``0x80`` bit.
FIPS 202 later changed that byte to ``0x06`` so SHA-3 fixed-output hashing,
SHAKE, and future sponge modes would occupy separate domains. Every Ethereum
address, transaction hash, ABI selector, and EIP-55 checksum already existed
under ``0x01``, so the chain kept the submission padding and the name Keccak.
Rate, capacity, permutation, and round constants are identical in both; the
one padding byte is the whole difference, and it changes every digest.
``hashlib.sha3_256`` computes the FIPS 202 variant, so it answers a different
question and cannot stand in for this function. ``tests/test_wallet_keccak.py``
pins that divergence so a future cleanup cannot quietly swap them.

Why this is Python and not a C extension
----------------------------------------
``pycryptodome``, ``pysha3``, and ``eth-hash[pycryptodome]`` all carry compiled
extension modules, which means per-platform binary wheels and a build toolchain
wherever a wheel is missing. QuReddy ships one pure-Python wheel that installs
on every supported platform, and CODING_RULES Section 13 holds a new runtime
dependency to what the pure-stdlib path cannot do. A scanner hashes a handful
of short addresses per run, behind network latency, so the interpreter cost of
the permutation stays inside the noise.

Boundary
--------
This file sits in the ``scanners`` layer. The import-linter contract in
``pyproject.toml`` allows it to reach down to ``qureddy.core``; it uses the
standard library alone, so it stays clean under the contract by construction.

Flow
----
::

    keccak256(data)
        data ---> pad 0x01 ... 0x80 up to a 136-byte multiple
                    |
                    +--> absorb one block: XOR 17 lanes, run keccak-f[1600]
                    |         keccak-f = 24 x (theta, rho, pi, chi, iota)
                    |
                    +--> squeeze lanes 0..3, little-endian ---> 32 bytes

    eip55(body)
        40 hex chars ---> lower() ---> keccak256(ascii) ---> hex digest
              |                                                  |
              +------ digest nibble i >= 8 upcases char i -------+
"""

from __future__ import annotations

_LANE_COUNT = 25
_LANE_BITS = 64
_LANE_BYTES = _LANE_BITS // 8
_MASK64 = (1 << _LANE_BITS) - 1

#: Keccak-256 rate in bytes: (1600 - 2 * 256) / 8. Seventeen lanes per block.
_RATE_BYTES = 136
_RATE_LANES = _RATE_BYTES // _LANE_BYTES
_DIGEST_BYTES = 32
_DIGEST_LANES = _DIGEST_BYTES // _LANE_BYTES

# The Ethereum domain byte. FIPS 202 SHA3-256 writes 0x06 in this position;
# see the module docstring for why the chain kept the submission value. A
# change here silently invalidates every address this package validates.
_PAD_DOMAIN = 0x01
_PAD_FINAL = 0x80

# Rho rotation offsets in lane order (index = x + 5 * y), from the Keccak
# reference specification, Table 2. Derivable from the (x, y) walk that starts
# at (1, 0) and steps (x, y) -> (y, 2x + 3y) with offset t(t + 1)/2 mod 64;
# the test re-derives them that way instead of copying this table.
_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)  # fmt: skip

# Iota round constants, one per round. Each is the degree-8 LFSR output of the
# reference specification, Section 1.2; the test re-derives the sequence from
# that LFSR so a transcription slip in this table fails a gate.
_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)  # fmt: skip

#: An EIP-55 address body is the 20-byte account rendered as hex, no 0x prefix.
_ADDRESS_HEX_CHARS = 40
_HEX_DIGITS = frozenset("0123456789abcdef")
# EIP-55 upper-cases a hex character when the matching digest nibble is 8 or
# above, which is the same test as "the nibble's high bit is set".
_UPPERCASE_NIBBLE = 8


def _rotl64(value: int, count: int) -> int:
    """Rotate a 64-bit lane left by ``count`` bits."""
    return ((value << count) | (value >> (_LANE_BITS - count))) & _MASK64


def _theta(lanes: list[int]) -> None:
    """Mix each lane with the parity of two neighbouring columns, in place."""
    parity = [
        lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20] for x in range(5)
    ]
    column = [parity[(x - 1) % 5] ^ _rotl64(parity[(x + 1) % 5], 1) for x in range(5)]
    for index in range(_LANE_COUNT):
        # index % 5 recovers the x coordinate of lane index x + 5 * y.
        lanes[index] ^= column[index % 5]


def _rho_pi(lanes: list[int]) -> list[int]:
    """Rotate every lane by its rho offset and move it to its pi position.

    Returns a new state because pi is a permutation of lane positions, and an
    in-place write would overwrite a lane another coordinate still has to read.
    """
    moved = [0] * _LANE_COUNT
    for y in range(5):
        for x in range(5):
            source = x + 5 * y
            moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(lanes[source], _ROTATIONS[source])
    return moved


def _chi(lanes: list[int]) -> None:
    """Apply the only non-linear step, row by row, in place."""
    for y in range(5):
        row = lanes[5 * y : 5 * y + 5]
        for x in range(5):
            # (a ^ _MASK64) is the 64-bit complement; Python's ~ would widen
            # the value to a negative integer of unbounded precision.
            lanes[5 * y + x] = row[x] ^ ((row[(x + 1) % 5] ^ _MASK64) & row[(x + 2) % 5])


def _keccak_f1600(lanes: list[int]) -> None:
    """Run the 24-round Keccak-f[1600] permutation over the state, in place."""
    for round_constant in _ROUND_CONSTANTS:
        _theta(lanes)
        lanes[:] = _rho_pi(lanes)
        _chi(lanes)
        lanes[0] ^= round_constant


def _pad(data: bytes) -> bytes:
    """Append the Ethereum Keccak padding up to a whole number of blocks.

    The tail is ``0x01``, then zeroes, then ``0x80`` set on the final byte. A
    message that already fills the rate gains a whole extra block, and a
    message one byte short of the rate gets the single merged byte ``0x81``.
    """
    padding = _RATE_BYTES - len(data) % _RATE_BYTES
    tail = bytearray(padding)
    tail[0] = _PAD_DOMAIN
    tail[-1] ^= _PAD_FINAL
    return bytes(data) + bytes(tail)


def keccak256(data: bytes) -> bytes:
    """Hash ``data`` with Keccak-256 as Ethereum defines it.

    This is the original Keccak submission padding (``0x01``), which is what
    Ethereum addresses, transaction hashes, ABI selectors, and EIP-55
    checksums are derived under. ``hashlib.sha3_256`` implements the FIPS 202
    padding (``0x06``) and returns a different digest for the same input.

    Args:
        data: Message bytes of any length, including empty.

    Returns:
        The 32-byte digest.
    """
    block = _pad(data)
    lanes = [0] * _LANE_COUNT
    for offset in range(0, len(block), _RATE_BYTES):
        for lane in range(_RATE_LANES):
            start = offset + lane * _LANE_BYTES
            lanes[lane] ^= int.from_bytes(block[start : start + _LANE_BYTES], "little")
        _keccak_f1600(lanes)
    return b"".join(lane.to_bytes(_LANE_BYTES, "little") for lane in lanes[:_DIGEST_LANES])


def eip55(address_hex: str) -> str:
    """Apply the EIP-55 mixed-case checksum to a 40-character address body.

    EIP-55 hides a checksum in the letter casing of an address: hash the
    lowercase hex text as ASCII, then upper-case hex character ``i`` when
    digest nibble ``i`` is 8 or above. Decimal digits carry no case, so a
    mistyped address survives the check roughly one time in 2**(number of
    letters). Wallets that ignore the casing keep working, which is why the
    scheme was adopted after addresses were already in circulation.

    Input casing is discarded before hashing, so the function is idempotent:
    feeding a checksummed address back in returns the same string.

    Args:
        address_hex: The 20-byte account as 40 hex characters, any casing,
            with no ``0x`` prefix.

    Returns:
        The same 40 characters with EIP-55 casing applied.

    Raises:
        ValueError: The input is not exactly 40 hexadecimal characters. A
            caller passing a ``0x`` prefix or a truncated address lands here
            instead of receiving a checksum for an address that does not exist.
    """
    body = address_hex.lower()
    if len(body) != _ADDRESS_HEX_CHARS or any(char not in _HEX_DIGITS for char in body):
        raise ValueError(
            f"expected {_ADDRESS_HEX_CHARS} hexadecimal characters with no 0x prefix, "
            f"got {len(address_hex)} characters"
        )
    digest = keccak256(body.encode("ascii")).hex()
    return "".join(
        char.upper() if int(nibble, 16) >= _UPPERCASE_NIBBLE else char
        for char, nibble in zip(body, digest[:_ADDRESS_HEX_CHARS], strict=True)
    )
