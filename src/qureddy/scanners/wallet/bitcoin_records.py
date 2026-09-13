# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bitcoin ledger facts, the signing-defect scan, and the coverage bound.

`record_bitcoin_chain` was one 143-line function against a 50-line cap. It is
four jobs: the unreachable path, the key-publication decision, the counts the
ledger holds, and the defects plus the bound C4 requires.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from typing import TYPE_CHECKING

from qureddy.core.vocabulary import Confidence, ObservationType, Readiness, Severity
from qureddy.scanners.wallet.indexer import TICKER_BY_CHAIN
from qureddy.scanners.wallet.record import NOT_TESTED
from qureddy.scanners.wallet.transport import record_exchanges

if TYPE_CHECKING:  # pragma: no cover - typing only
    from qureddy.scanners.wallet.indexer import ChainFacts, Signature
    from qureddy.scanners.wallet.record import Builder

#: Script classes whose output carries a readable public key with no spend.
_KEY_IN_OUTPUT_SCRIPTS = frozenset({"p2pk", "multisig", "v1_p2tr"})

#: Hash-addressed script classes. A P2PK or bare-multisig output paying the same
#: key carries no address, so an address query cannot return it.
_HASH_ADDRESSED_SCRIPTS = frozenset({"p2pkh", "p2sh"})

#: SEC1 encodings the chain lane recovers, named so a reader can parse the bytes.
_SEC1_COMPRESSED = "SEC1-compressed"
_SEC1_UNCOMPRESSED = "SEC1-uncompressed"
_COMPRESSED = ("02", "03")

#: An r value this short implies a nonce small enough to brute force.
_LOW_ENTROPY_R_HEX = 8

# A5: a bound that shapes output is named and reported, never applied silently.
#: Transaction ids listed per defect. The full set stays in the signature evidence.
_DEFECT_TXID_LIMIT = 6
#: Hex characters of r shown in a defect title. The full value is in the description.
_R_TITLE_HEX = 32


def _scan_defects(signatures: list[Signature]) -> list[tuple[str, str, list[str]]]:
    """Nonce reuse and low-entropy nonces. Returns (name, detail, txids) per defect."""
    found: list[tuple[str, str, list[str]]] = []
    counts = Counter(item.r for item in signatures)
    for r_value, count in counts.most_common():
        if count < 2:  # noqa: PLR2004 - a repeat needs two occurrences
            break
        matching = [item.txid for item in signatures if item.r == r_value]
        found.append(
            (
                "nonce.reuse",
                f"r={r_value[:_R_TITLE_HEX]} repeats {count} times",
                matching,
            )
        )
    for item in signatures:
        if len(item.r) <= _LOW_ENTROPY_R_HEX:
            found.append(("nonce.low_entropy", f"r is {len(item.r) // 2} bytes", [item.txid]))
    return found


def record_bitcoin_chain(builder: Builder, facts: ChainFacts, script: str = "") -> None:
    """Facts only the ledger holds, and the coverage bound C4 requires."""
    record_exchanges(builder, facts.exchanges)
    if not facts.reachable:
        for name in (
            "key.published",
            "pubkeys.recovered",
            "signatures.examined",
            "nonce.reuse",
            "balance",
        ):
            builder.not_tested(name, facts.error or "the chain lane was unreachable", lane="chain")
        return

    _record_key_publication(builder, facts, script)
    _record_ledger_counts(builder, facts)
    _record_bitcoin_defects(builder, facts)
    _record_coverage(builder, facts)


def _record_key_publication(builder: Builder, facts: ChainFacts, script: str) -> None:
    """Whether the account's public key is on chain, and how that was established."""
    in_output = _KEY_IN_OUTPUT_SCRIPTS & facts.output_scripts
    if facts.public_keys:
        builder.record(
            "key.published",
            "yes",
            lane="chain",
            source="public key bytes read from vin[].witness or a scriptsig push",
            observation=ObservationType.OBSERVED,
            severity=Severity.HIGH,
            readiness=Readiness.QUANTUM_VULNERABLE,
        )
    elif in_output:
        builder.record(
            "key.published",
            "yes",
            lane="chain",
            source=f"vout[].scriptpubkey_type in {sorted(in_output)}",
            observation=ObservationType.OBSERVED,
            severity=Severity.HIGH,
            readiness=Readiness.QUANTUM_VULNERABLE,
        )
    elif facts.spent_txo_count > 0:
        # C2: a spend publishes the key, and the page examined omitted it.
        builder.record(
            "key.published",
            "yes",
            lane="chain",
            source="chain_stats.spent_txo_count > 0, with no key read in the page examined",
            observation=ObservationType.INFERRED,
            severity=Severity.MEDIUM,
            readiness=Readiness.QUANTUM_VULNERABLE,
            confidence=Confidence.MEDIUM,
        )
    else:
        builder.record(
            "key.published",
            "no",
            lane="chain",
            source="chain_stats.spent_txo_count == 0, so only a hash is on chain",
            observation=ObservationType.OBSERVED,
            readiness=Readiness.UNKNOWN,
        )
        _record_p2pk_blind_spot(builder, script)


#: Every ledger count: the finding name, the value read from `ChainFacts`, and the
#: expression it came from. Nine identical `builder.record` blocks differed only in
#: these three strings, so a reader had to diff them to see what varied. C1 makes
#: the source expression mandatory, and a table is where a mandatory field belongs.
_LEDGER_COUNTS: tuple[tuple[str, Callable[[ChainFacts], str], str], ...] = (
    (
        "pubkeys.recovered",
        lambda f: str(len(f.public_keys)),
        "vin[] pushes matching 02 or 03 plus 32 bytes, or 04 plus 64 bytes",
    ),
    ("outputs.funded", lambda f: str(f.funded_txo_count), "chain_stats.funded_txo_count"),
    ("outputs.spent", lambda f: str(f.spent_txo_count), "chain_stats.spent_txo_count"),
    (
        "transactions.examined",
        lambda f: f"{f.transactions_examined} of {f.tx_count}",
        "len of the returned page over chain_stats plus mempool_stats tx_count",
    ),
    (
        "transactions.confirmed",
        lambda f: str(f.transactions_confirmed),
        "tx[].status.confirmed is true in the returned page",
    ),
    (
        "transactions.mempool",
        lambda f: str(f.transactions_mempool),
        "tx[].status.confirmed absent; this endpoint returns mempool entries first",
    ),
    (
        "inputs.from_this_address",
        lambda f: str(f.inputs_examined),
        "vin[] where prevout.scriptpubkey_address equals the subject",
    ),
    (
        "signatures.examined",
        lambda f: str(len(f.signatures)),
        "DER 0x30 parses in vin[].witness[0] or a scriptsig push",
    ),
    (
        "balance",
        lambda f: f"{f.balance_btc} {TICKER_BY_CHAIN.get(f.chain, 'BTC')}",
        "(chain_stats.funded_txo_sum - chain_stats.spent_txo_sum) / 1e8",
    ),
)


def _record_ledger_counts(builder: Builder, facts: ChainFacts) -> None:
    """The counts the ledger holds, each naming the expression it came from."""
    for name, read, source in _LEDGER_COUNTS:
        builder.record(
            name, read(facts), lane="chain", source=source, observation=ObservationType.OBSERVED
        )
    for key in sorted(facts.public_keys):
        builder.record(
            "pubkey",
            key,
            lane="chain",
            source="vin[].witness[1] or a scriptsig push",
            observation=ObservationType.OBSERVED,
            # The bytes travel as evidence. A public key on a public ledger is
            # already published; withholding it would hide what the scan read.
            public_key=key,
            public_key_format=_SEC1_COMPRESSED if key[:2] in _COMPRESSED else _SEC1_UNCOMPRESSED,
        )


def _record_coverage(builder: Builder, facts: ChainFacts) -> None:
    """C4: a bounded sample carries its own coverage finding."""
    if facts.truncated:
        # C4: the bound is a finding, so a reader sees what went unexamined.
        builder.record(
            "scan.coverage",
            f"{facts.transactions_examined} of {facts.tx_count} transactions",
            lane="chain",
            source="one indexer page, since :last_seen_txid paging is unused",
            observation=ObservationType.NOT_TESTABLE,
            confidence=Confidence.MEDIUM,
            description=(
                f"{facts.transactions_examined} of {facts.tx_count} transactions were "
                f"examined, {facts.transactions_confirmed} confirmed and "
                f"{facts.transactions_mempool} in the mempool. The remainder went "
                f"unexamined, so every count above is bounded by this page."
            ),
        )


def _record_p2pk_blind_spot(builder: Builder, script: str) -> None:
    """Disclose the one exposure an address query structurally cannot see.

    A P2PK or bare-multisig output carries the public key and no address, so
    Esplora sets `scriptpubkey_address` to null and no address query returns it.
    A P2PKH address is the hash re-encoding of the same key, which is how
    explorers display such an output, so a key sitting in the open in a P2PK
    output is invisible to a scan of its P2PKH form.

    Block 0's coinbase is the canonical case: its output is P2PK carrying
    04678afdb0..., and HASH160 of that key base58-encodes to
    1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. Scanning that address reports no
    published key while the key has been readable since 2009.

    Closing this needs the funding transactions walked by txid, which this lane
    does not do. Until then the limit is stated, so `key.published: no` is read
    as what this lane measured and not as a guarantee.
    """
    if script not in _HASH_ADDRESSED_SCRIPTS:
        return
    builder.record(
        "key.p2pk_sibling",
        NOT_TESTED,
        lane="chain",
        source=(
            "a P2PK or bare-multisig output paying this key carries no address, so "
            "scriptpubkey_address is null and no address query returns it"
        ),
        observation=ObservationType.NOT_TESTABLE,
        confidence=Confidence.LOW,
        description=(
            "not tested. A P2PK or bare-multisig output paying the same key carries "
            "no address, so an address query cannot reach it. A key published that "
            "way stays invisible here, which is why the reading above states what "
            "this lane measured and not that the key is unpublished."
        ),
    )


def _record_bitcoin_defects(builder: Builder, facts: ChainFacts) -> None:
    """Signing defects: derivable today, with no quantum computer."""
    if not facts.signatures:
        builder.not_tested(
            "nonce.reuse", "this address published no signature in the page examined", lane="defect"
        )
        return
    defects = _scan_defects(facts.signatures)
    if not defects:
        builder.record(
            "nonce.reuse",
            f"none in {len(facts.signatures)}",
            lane="defect",
            source="Counter over signature r values, with a maximum count of one",
            observation=ObservationType.OBSERVED,
        )
        return
    for name, detail, txids in defects:
        builder.record(
            name,
            detail,
            lane="defect",
            source="Counter over signature r values",
            observation=ObservationType.OBSERVED,
            severity=Severity.CRITICAL,
            readiness=Readiness.CLASSICALLY_WEAK,
            description=(
                f"{detail}, in {', '.join(txids[:_DEFECT_TXID_LIMIT])}"
                + (
                    f" and {len(txids) - _DEFECT_TXID_LIMIT} further transaction(s)"
                    if len(txids) > _DEFECT_TXID_LIMIT
                    else ""
                )
                + ". The private key follows by algebra from data already public, with "
                "no quantum computer. This states derivability and makes no claim that "
                "funds remain. The r value is shown truncated here and in full in the "
                "signature evidence."
            ),
        )
