# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Gate G1 of docs/architecture/wallet-scanner-adr.md section 17.

G1 requires that every BIP-173 and BIP-350 valid vector decodes and that every
invalid vector is rejected. The vectors below were copied from the two BIP
source files on 2026-09-12 and are hard-coded here, so this module reaches no
network at collection time or at run time:

* BIP-173, Appendices / Test vectors
  https://raw.githubusercontent.com/bitcoin/bips/master/bip-0173.mediawiki
* BIP-350, Test vectors for Bech32m and for v0-v16 native segwit addresses
  https://raw.githubusercontent.com/bitcoin/bips/master/bip-0350.mediawiki

BIP-350 supersedes BIP-173 for witness version 1 and above, so three addresses
that BIP-173 listed as valid are invalid today and are asserted as rejections.
Each vector block cites its BIP and its section.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from qureddy.scanners.wallet.address import (
    CURVE,
    KEY_IN_OUTPUT_SCRIPTS,
    DecodedAddress,
    decode,
)

# BIP-173 section "Bech32", the data-part character set.
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# The base58 alphabet, Bitcoin ordering, as used by base58check.
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ---------------------------------------------------------------------------
# Bech32 and bech32m strings that carry no supported chain prefix.
#
# These are well-formed under their checksum, so the decoder reaches the
# human-readable part and finds it is neither bc, tb nor bcrt. A wallet decoder
# must reject them: they encode no Bitcoin address. The assertion below is
# therefore "rejected", with the reason naming the prefix.
# ---------------------------------------------------------------------------

# BIP-173, Appendices / Test vectors, "The following strings are valid Bech32".
BIP173_VALID_BECH32_STRINGS = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]

# BIP-350, Test vectors, "The following strings are valid Bech32m".
BIP350_VALID_BECH32M_STRINGS = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]

# ---------------------------------------------------------------------------
# Malformed bech32 and bech32m strings. Every one must be rejected.
# ---------------------------------------------------------------------------

# BIP-173, Appendices / Test vectors, "The following string are not valid
# Bech32". The first three prefix a raw byte to the string, written here as an
# escape so the source file stays ASCII.
BIP173_INVALID_BECH32_STRINGS = [
    ("\x201nwldj5", "HRP character out of range"),
    ("\x7f1axkwrx", "HRP character out of range"),
    ("\x801eym55h", "HRP character out of range"),
    (
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
        "overall max length exceeded",
    ),
    ("pzry9x0s0muk", "no separator character"),
    ("1pzry9x0s0muk", "empty HRP"),
    ("x1b4n0q5v", "invalid data character"),
    ("li1dgmt3", "too short checksum"),
    ("de1lg7wt\xff", "invalid character in checksum"),
    ("A1G7SGD8", "checksum calculated with uppercase form of HRP"),
    ("10a06t8", "empty HRP"),
    ("1qzzfhee", "empty HRP"),
]

# BIP-350, Test vectors, "The following string are not valid Bech32m".
BIP350_INVALID_BECH32M_STRINGS = [
    ("\x201xj0phk", "HRP character out of range"),
    ("\x7f1g6xzxy", "HRP character out of range"),
    ("\x801vctc34", "HRP character out of range"),
    (
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
        "overall max length exceeded",
    ),
    ("qyrz8wqd2c9m", "no separator character"),
    ("1qyrz8wqd2c9m", "empty HRP"),
    ("y1b0jsk6g", "invalid data character"),
    ("lt1igcx5c0", "invalid data character"),
    ("in1muywd", "too short checksum"),
    ("mm1crxm3i", "invalid character in checksum"),
    ("au1s5cgom", "invalid character in checksum"),
    ("M1VUXWEZ", "checksum calculated with uppercase form of HRP"),
    ("16plkw9", "empty HRP"),
    ("1p2gdwpf", "empty HRP"),
]

# ---------------------------------------------------------------------------
# Valid segwit addresses.
#
# BIP-350, "Test vectors for v0-v16 native segregated witness addresses",
# "The following list gives valid segwit addresses and the scriptPubKey that
# they translate to in hex". This list supersedes the BIP-173 one for witness
# version 1 and above. The expected witness version and program length are read
# from the BIP's own scriptPubKey column by _parse_script_pubkey, so the
# expectation comes from the specification instead of from this file.
#
# Columns: address, scriptPubKey hex, script class, network.
# ---------------------------------------------------------------------------
BIP350_VALID_SEGWIT = [
    (
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
        "v0_p2wpkh",
        "mainnet",
    ),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
        "v0_p2wsh",
        "testnet",
    ),
    (
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
        "witness_v1",
        "mainnet",
    ),
    ("BC1SW50QGDZ25J", "6002751e", "witness_v16", "mainnet"),
    (
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "5210751e76e8199196d454941c45d1b3a323",
        "witness_v2",
        "mainnet",
    ),
    (
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        "v0_p2wsh",
        "testnet",
    ),
    (
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
        "v1_p2tr",
        "testnet",
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "v1_p2tr",
        "mainnet",
    ),
]

# BIP-173, Appendices / Test vectors, "The following list gives valid segwit
# addresses". Three of its six entries encode witness version 1, 2 and 16 in
# plain bech32. BIP-350 requires bech32m from version 1 upward, so those three
# are rejections today and the flag below records which.
#
# Columns: address, still valid under BIP-350.
BIP173_SEGWIT_SUPERSEDED = [
    ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", True),
    ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", True),
    ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", False),
    ("BC1SW50QA3JX3S", False),
    ("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", False),
    ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", True),
]

# ---------------------------------------------------------------------------
# Invalid segwit addresses. Every one must be rejected.
#
# The tc1 entries carry a prefix the decoder does not support, so they are
# rejected on the prefix instead of on the encoding. That is the required
# outcome either way: tc is not a Bitcoin chain this decoder answers for.
# ---------------------------------------------------------------------------

# BIP-173, Appendices / Test vectors, "The following list gives invalid segwit
# addresses and the reason for their invalidity".
BIP173_INVALID_SEGWIT = [
    ("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", "invalid human-readable part"),
    ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "invalid checksum"),
    ("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", "invalid witness version"),
    ("bc1rw5uspcuh", "invalid program length"),
    (
        "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
        "invalid program length",
    ),
    (
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "invalid program length for witness version 0 per BIP-141",
    ),
    ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", "mixed case"),
    ("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", "zero padding of more than 4 bits"),
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        "non-zero padding in 8-to-5 conversion",
    ),
    ("bc1gmk9yu", "empty data section"),
]

# BIP-350, "Test vectors for v0-v16 native segregated witness addresses",
# "The following list gives invalid segwit addresses and the reason for their
# invalidity".
BIP350_INVALID_SEGWIT = [
    (
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
        "invalid human-readable part",
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "invalid checksum, bech32 instead of bech32m",
    ),
    (
        "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
        "invalid checksum, bech32 instead of bech32m",
    ),
    (
        "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
        "invalid checksum, bech32 instead of bech32m",
    ),
    (
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
        "invalid checksum, bech32m instead of bech32",
    ),
    (
        "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
        "invalid checksum, bech32m instead of bech32",
    ),
    (
        "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
        "invalid character in checksum",
    ),
    (
        "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
        "invalid witness version",
    ),
    ("bc1pw5dgrnzv", "invalid program length, 1 byte"),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
        "invalid program length, 41 bytes",
    ),
    (
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "invalid program length for witness version 0 per BIP-141",
    ),
    ("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq", "mixed case"),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
        "zero padding of more than 4 bits",
    ),
    (
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "non-zero padding in 8-to-5 conversion",
    ),
    ("bc1gmk9yu", "empty data section"),
]

# ---------------------------------------------------------------------------
# base58check addresses. BIP-173 and BIP-350 carry no base58 vectors, so each
# payload below is documented by its version byte and its provenance, and
# test_base58check_address_reencodes_from_its_documented_payload rebuilds the
# string from that payload.
#
# Columns: address, version byte, 20-byte payload hex, script class, note.
# ---------------------------------------------------------------------------
BASE58CHECK_MAINNET = [
    (
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        0x00,
        "62e907b15cbf27d5425399ebf6f0fb50ebb88f18",
        "p2pkh",
        # Version byte 0x00 is mainnet P2PKH. The payload is the HASH160 of the
        # block 0 coinbase public key, which is the grounding recorded in
        # wallet-scanner-adr.md section 12 for this address.
        "block 0 coinbase key hash",
    ),
    (
        "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
        0x05,
        "bcfeb728b584253d5f3f70bcb780e9ef218a68f4",
        "p2sh",
        # Version byte 0x05 is mainnet P2SH. The payload is the HASH160 of the
        # BIP-141 P2SH-P2WPKH redeemScript
        # 0014751e76e8199196d454941c45d1b3a323f1433bd6, whose key hash is the
        # HASH160 that BIP-173 section Examples documents for the public key
        # 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798.
        "BIP-141 P2SH-P2WPKH script hash",
    ),
]


def _parse_script_pubkey(script_hex: str) -> tuple[int, int]:
    """Read the witness version and program length out of a BIP scriptPubKey."""
    raw = bytes.fromhex(script_hex)
    opcode = raw[0]
    version = 0 if opcode == 0x00 else opcode - 0x50
    push_length = raw[1]
    program = raw[2:]
    assert len(program) == push_length
    return version, len(program)


def _base58check_encode(version: int, payload_hex: str) -> str:
    """Encode a version byte and payload as base58check, sha256 only."""
    body = bytes([version]) + bytes.fromhex(payload_hex)
    raw = body + hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    leading_zeros = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading_zeros + encoded


def _corrupt_one_character(address: str, alphabet: str) -> str:
    """Replace one character near the end with the next one in the alphabet."""
    index = len(address) - 3
    replacement = alphabet[(alphabet.index(address[index]) + 1) % len(alphabet)]
    return address[:index] + replacement + address[index + 1 :]


def _short_id(address: str) -> str:
    """A parametrize id short enough to read in a pytest report."""
    printable = address.encode("unicode_escape").decode("ascii")
    return printable if len(printable) <= 28 else f"{printable[:14]}..{printable[-12:]}"


def _ids(vectors: list[tuple[str, str]]) -> list[str]:
    return [f"{_short_id(address)}-{reason}" for address, reason in vectors]


# ---------------------------------------------------------------------------
# Bech32 and bech32m strings with an unsupported prefix.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "candidate",
    BIP173_VALID_BECH32_STRINGS,
    ids=[_short_id(value) for value in BIP173_VALID_BECH32_STRINGS],
)
def test_bip173_valid_bech32_string_without_a_chain_prefix_is_rejected(candidate: str) -> None:
    result = decode(candidate)
    assert not result.valid
    assert "prefix" in result.error


@pytest.mark.parametrize(
    "candidate",
    BIP350_VALID_BECH32M_STRINGS,
    ids=[_short_id(value) for value in BIP350_VALID_BECH32M_STRINGS],
)
def test_bip350_valid_bech32m_string_without_a_chain_prefix_is_rejected(candidate: str) -> None:
    result = decode(candidate)
    assert not result.valid
    assert "prefix" in result.error


# ---------------------------------------------------------------------------
# Malformed bech32 and bech32m strings.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("candidate", "reason"),
    BIP173_INVALID_BECH32_STRINGS,
    ids=_ids(BIP173_INVALID_BECH32_STRINGS),
)
def test_bip173_invalid_bech32_string_is_rejected(candidate: str, reason: str) -> None:
    result = decode(candidate)
    assert not result.valid, f"BIP-173 rejects this for {reason}"


@pytest.mark.parametrize(
    ("candidate", "reason"),
    BIP350_INVALID_BECH32M_STRINGS,
    ids=_ids(BIP350_INVALID_BECH32M_STRINGS),
)
def test_bip350_invalid_bech32m_string_is_rejected(candidate: str, reason: str) -> None:
    result = decode(candidate)
    assert not result.valid, f"BIP-350 rejects this for {reason}"


# ---------------------------------------------------------------------------
# Valid segwit addresses.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "script_pubkey", "script", "network"),
    BIP350_VALID_SEGWIT,
    ids=[f"{_short_id(row[0])}-{row[2]}" for row in BIP350_VALID_SEGWIT],
)
def test_bip350_valid_segwit_address_decodes(
    address: str, script_pubkey: str, script: str, network: str
) -> None:
    expected_version, expected_length = _parse_script_pubkey(script_pubkey)
    result = decode(address)
    assert result.valid, result.error
    assert result.witness_version == expected_version
    assert result.program_length == expected_length
    assert result.script == script
    assert result.network == network
    assert result.encoding == ("bech32" if expected_version == 0 else "bech32m")
    assert result.curve == CURVE


@pytest.mark.parametrize(
    ("address", "still_valid"),
    BIP173_SEGWIT_SUPERSEDED,
    ids=[
        f"{_short_id(row[0])}-{'valid' if row[1] else 'superseded'}"
        for row in BIP173_SEGWIT_SUPERSEDED
    ],
)
def test_bip173_segwit_address_matches_the_bip350_encoding_rule(
    address: str, still_valid: bool
) -> None:
    result = decode(address)
    assert result.valid is still_valid, result.error


# ---------------------------------------------------------------------------
# Invalid segwit addresses.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "reason"),
    BIP173_INVALID_SEGWIT,
    ids=_ids(BIP173_INVALID_SEGWIT),
)
def test_bip173_invalid_segwit_address_is_rejected(address: str, reason: str) -> None:
    result = decode(address)
    assert not result.valid, f"BIP-173 rejects this for {reason}"


@pytest.mark.parametrize(
    ("address", "reason"),
    BIP350_INVALID_SEGWIT,
    ids=_ids(BIP350_INVALID_SEGWIT),
)
def test_bip350_invalid_segwit_address_is_rejected(address: str, reason: str) -> None:
    result = decode(address)
    assert not result.valid, f"BIP-350 rejects this for {reason}"


# ---------------------------------------------------------------------------
# Witness version and encoding cross-check, BIP-350 section
# "Addresses for segregated witness outputs".
# ---------------------------------------------------------------------------


def test_version_zero_program_encoded_bech32m_is_rejected() -> None:
    # BIP-350 invalid vector, "Invalid checksum (Bech32m instead of Bech32)".
    result = decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh")
    assert not result.valid


def test_version_one_program_encoded_bech32_is_rejected() -> None:
    # BIP-350 invalid vector, "Invalid checksum (Bech32 instead of Bech32m)".
    result = decode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd")
    assert not result.valid


# ---------------------------------------------------------------------------
# base58check.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "version", "payload_hex", "script", "note"),
    BASE58CHECK_MAINNET,
    ids=[row[3] for row in BASE58CHECK_MAINNET],
)
def test_base58check_mainnet_address_decodes(
    address: str, version: int, payload_hex: str, script: str, note: str
) -> None:
    assert len(bytes.fromhex(payload_hex)) == 20, note
    assert version in (0x00, 0x05)
    result = decode(address)
    assert result.valid, result.error
    assert result.script == script
    assert result.network == "mainnet"
    assert result.encoding == "base58check"
    assert result.scheme == "ECDSA"
    assert result.program_length == 20
    assert result.witness_version is None


@pytest.mark.parametrize(
    ("address", "version", "payload_hex"),
    [(row[0], row[1], row[2]) for row in BASE58CHECK_MAINNET],
    ids=[row[3] for row in BASE58CHECK_MAINNET],
)
def test_base58check_address_reencodes_from_its_documented_payload(
    address: str, version: int, payload_hex: str
) -> None:
    assert _base58check_encode(version, payload_hex) == address


# ---------------------------------------------------------------------------
# Checksum corruption, one character per encoding.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "alphabet", "encoding"),
    [
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", BECH32_CHARSET, "bech32"),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            BECH32_CHARSET,
            "bech32m",
        ),
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", BASE58_ALPHABET, "base58check"),
        ("3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN", BASE58_ALPHABET, "base58check"),
    ],
    ids=["bech32-v0", "bech32m-v1", "base58check-p2pkh", "base58check-p2sh"],
)
def test_one_flipped_character_fails_the_checksum(
    address: str, alphabet: str, encoding: str
) -> None:
    assert decode(address).encoding == encoding
    corrupted = _corrupt_one_character(address, alphabet)
    assert corrupted != address
    assert not decode(corrupted).valid


# ---------------------------------------------------------------------------
# Mixed case, BIP-173 section "Bech32": a mixed-case string is invalid.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        # BIP-173 invalid vector, "Mixed case".
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        # BIP-350 invalid vector, "Mixed case".
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        # The BIP-173 valid v0 vector recased, so only the case differs.
        "Bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    ],
    ids=["bip173-mixed-case", "bip350-mixed-case", "recased-valid-vector"],
)
def test_mixed_case_bech32_is_rejected(address: str) -> None:
    assert not decode(address).valid


def test_both_single_case_forms_of_a_valid_address_decode_alike() -> None:
    lower = decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    upper = decode("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
    assert lower.valid
    assert upper.valid
    assert lower.script == upper.script
    assert lower.program_length == upper.program_length
    assert lower.encoding == upper.encoding


# ---------------------------------------------------------------------------
# Empty, whitespace, and oversized input.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "candidate",
    ["", " ", "   ", "\t", "\n", " \t\n "],
    ids=["empty", "one-space", "spaces", "tab", "newline", "mixed-whitespace"],
)
def test_empty_or_whitespace_input_is_rejected(candidate: str) -> None:
    result = decode(candidate)
    assert not result.valid
    assert result.error == "address is empty"


def test_surrounding_whitespace_is_stripped_before_decoding() -> None:
    result = decode("  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  ")
    assert result.valid, result.error
    assert result.address == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


@pytest.mark.parametrize("length", [129, 200, 4096], ids=["129", "200", "4096"])
def test_input_longer_than_128_characters_is_rejected(length: int) -> None:
    result = decode("bc1q" + "q" * (length - 4))
    assert not result.valid
    assert "exceeds 128 characters" in result.error
    # The reported address is truncated to the cap, which is the artefact the
    # error describes.
    assert len(result.address) == 128


def test_input_of_exactly_128_characters_reaches_the_decoder() -> None:
    result = decode("bc1q" + "q" * 124)
    assert not result.valid
    assert "exceeds" not in result.error


# ---------------------------------------------------------------------------
# key_in_output, the claim the ADR section 9 table rests on.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("address", "script", "expected"),
    [
        ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "p2pkh", False),
        ("3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN", "p2sh", False),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "v0_p2wpkh", False),
        (
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
            "v0_p2wsh",
            False,
        ),
        (
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            "v1_p2tr",
            True,
        ),
        (
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            "v1_p2tr",
            True,
        ),
    ],
    ids=["p2pkh", "p2sh", "v0_p2wpkh", "v0_p2wsh", "v1_p2tr-mainnet", "v1_p2tr-testnet"],
)
def test_key_in_output_is_true_only_for_taproot(address: str, script: str, expected: bool) -> None:
    result = decode(address)
    assert result.valid, result.error
    assert result.script == script
    assert result.key_in_output is expected


def test_taproot_is_the_only_key_in_output_script_an_address_can_produce() -> None:
    # p2pk and multisig sit in KEY_IN_OUTPUT_SCRIPTS, and neither carries an
    # address encoding, so no string can decode to them. Only the chain lane
    # reports those, which is the limit the module docstring records.
    addresses = [row[0] for row in BIP350_VALID_SEGWIT]
    addresses += [row[0] for row in BASE58CHECK_MAINNET]
    produced = {decode(address).script for address in addresses if decode(address).valid}
    assert produced & KEY_IN_OUTPUT_SCRIPTS == {"v1_p2tr"}
    assert "p2pk" not in produced
    assert "multisig" not in produced


def test_schnorr_is_reported_for_taproot_and_ecdsa_for_every_other_form() -> None:
    taproot = decode("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
    assert taproot.scheme == "Schnorr"
    for address in (
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
    ):
        assert decode(address).scheme == "ECDSA"


# ---------------------------------------------------------------------------
# A rejection carries no partial decode. DecodedAddress documents this, and a
# caller reading a half-decoded address as fact is the failure it prevents.
# ---------------------------------------------------------------------------

_REJECTED_SOURCES = [
    *BIP173_VALID_BECH32_STRINGS,
    *BIP350_VALID_BECH32M_STRINGS,
    *[row[0] for row in BIP173_INVALID_BECH32_STRINGS],
    *[row[0] for row in BIP350_INVALID_BECH32M_STRINGS],
    *[row[0] for row in BIP173_INVALID_SEGWIT],
    *[row[0] for row in BIP350_INVALID_SEGWIT],
    *[row[0] for row in BIP173_SEGWIT_SUPERSEDED if not row[1]],
    "",
    "   ",
    "bc1q" + "q" * 200,
    "Bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    _corrupt_one_character("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", BASE58_ALPHABET),
    _corrupt_one_character("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", BECH32_CHARSET),
]
# Two vectors appear in both BIP lists, so keep first occurrence order and drop
# the repeat; a duplicate parametrize id reads as a different case.
ALL_REJECTED = list(dict.fromkeys(_REJECTED_SOURCES))

DEFAULTED_FIELDS = [
    field.name
    for field in dataclasses.fields(DecodedAddress)
    if field.name not in ("address", "error")
]


@pytest.mark.parametrize("candidate", ALL_REJECTED, ids=[_short_id(v) for v in ALL_REJECTED])
def test_a_rejected_address_leaves_every_other_field_at_its_default(candidate: str) -> None:
    result = decode(candidate)
    assert not result.valid
    assert result.error
    baseline = DecodedAddress(address=result.address)
    for name in DEFAULTED_FIELDS:
        assert getattr(result, name) == getattr(baseline, name), name


def test_valid_is_the_inverse_of_error() -> None:
    assert decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").valid
    assert not decode("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5").valid
