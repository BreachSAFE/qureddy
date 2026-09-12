# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Assemble a wallet scan into a ScanResult.

Every finding here obeys the claims contract in
`docs/architecture/wallet-scanner-adr.md` section 4. Three rules shape the code:

  C1  a finding names the lane and the expression its value came from, both
      carried in `Evidence.notes` and the finding description.
  C2  `ObservationType.OBSERVED` requires that this scanner read the bytes it
      reports. The Ethereum lane reads account state and never key material, so
      its exposure conclusions are `INFERRED` without exception.
  C3  absent evidence is `NOT_TESTABLE`. An unreachable lane yields that, and a
      `False` stays reserved for a measured negative.
  C4  a bounded sample carries its own coverage finding.

No severity, readiness, or security level is defined here. `core.vocabulary`
already holds those, and secp256k1 meets no NIST category, so every asset this
scanner emits carries level 0.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qureddy.core.contracts import (
    Capability,
    CollectionResult,
    Scanner,
    ScanSource,
    SourceKind,
)
from qureddy.core.ids import new_id
from qureddy.core.models import Asset, Evidence, Finding, ScanResult, ScanTarget
from qureddy.core.vocabulary import (
    WALLET_SIGNATURE_EVIDENCE,
    Confidence,
    ObservationType,
    Readiness,
    Severity,
)
from qureddy.scanners.common.assets import build_endpoint_asset
from qureddy.scanners.common.metadata import build_scan_metadata
from qureddy.scanners.common.posture import build_scan_summary
from qureddy.scanners.wallet import address as btc_address
from qureddy.scanners.wallet import ethereum, indexer

if TYPE_CHECKING:  # pragma: no cover - typing only
    from qureddy.scanners.wallet.indexer import ChainFacts, Signature

#: secp256k1 meets no NIST post-quantum category, so Shor recovers the key outright.
NIST_LEVEL_SECP256K1 = 0
CURVE = "secp256k1"
_PRIMITIVE = "signature"
_KEY_SIZE_BITS = 256

#: Script classes whose output carries a readable public key with no spend.
_KEY_IN_OUTPUT_SCRIPTS = frozenset({"p2pk", "multisig", "v1_p2tr"})

#: An r value this short implies a nonce small enough to brute force.
_LOW_ENTROPY_R_HEX = 8

_NOT_TESTED = "not tested"

# A5: a bound that shapes output is named and reported, never applied silently.
#: Transaction ids listed per defect. The full set stays in the signature evidence.
_DEFECT_TXID_LIMIT = 6
#: Hex characters of r shown in a defect title. The full value is in the description.
_R_TITLE_HEX = 32


def _note(lane: str, source: str) -> tuple[str, ...]:
    """C1: the lane that produced a value and the expression it came from."""
    return (f"lane={lane}", f"source={source}")


class _Builder:
    """Accumulates evidence and findings for one scan, keeping ids consistent."""

    def __init__(self, asset: Asset, protocol: str) -> None:
        self.asset = asset
        self.protocol = protocol
        self.evidence: list[Evidence] = []
        self.findings: list[Finding] = []

    def record(
        self,
        name: str,
        value: str,
        *,
        lane: str,
        source: str,
        observation: ObservationType,
        evidence_type: str | None = None,
        negotiated_group: str | None = None,
        severity: Severity = Severity.INFO,
        readiness: Readiness = Readiness.NOT_APPLICABLE,
        confidence: Confidence = Confidence.HIGH,
        description: str = "",
    ) -> None:
        """Add one observation and the finding that reports it."""
        item = Evidence(
            id=new_id("evidence"),
            asset_id=self.asset.id,
            evidence_type=evidence_type or name,
            observation_type=observation,
            negotiated_group=negotiated_group,
            source=lane,
            protocol=self.protocol,
            algorithm=f"ECDSA-{CURVE}",
            primitive=_PRIMITIVE,
            nist_quantum_security_level=NIST_LEVEL_SECP256K1,
            confidence=confidence,
            notes=_note(lane, source),
        )
        self.evidence.append(item)
        self.findings.append(
            Finding(
                id=new_id("finding"),
                asset_id=self.asset.id,
                evidence_ids=(item.id,),
                rule_id=f"wallet.{name}",
                finding_type=name,
                title=f"{name}: {value}",
                description=description or f"{value}. Read by the {lane} lane from {source}.",
                severity=severity,
                readiness=readiness,
                confidence=confidence,
                protocol=self.protocol,
                algorithm=f"ECDSA-{CURVE}",
                primitive=_PRIMITIVE,
                nist_quantum_security_level=NIST_LEVEL_SECP256K1,
            )
        )

    def not_tested(self, name: str, reason: str, *, lane: str) -> None:
        """C3: record what a lane did not measure, in place of a default."""
        self.record(
            name,
            _NOT_TESTED,
            lane=lane,
            source=reason,
            observation=ObservationType.NOT_TESTABLE,
            confidence=Confidence.LOW,
            description=f"{_NOT_TESTED}. {reason}",
        )


def _record_offline(builder: _Builder, decoded: btc_address.DecodedAddress) -> None:
    """Facts the address string alone establishes."""
    builder.record(
        "algorithm",
        f"{decoded.scheme} {decoded.curve}",
        lane="offline",
        source="address._SCRIPT_SCHEMES[script]",
        observation=ObservationType.OBSERVED,
        readiness=Readiness.QUANTUM_VULNERABLE,
        # Feeds the shared CBOM signature emitter and the NIST rollup, the same
        # seams ssh.hostkey and tls.cert.signature use.
        evidence_type=WALLET_SIGNATURE_EVIDENCE,
        negotiated_group=f"{decoded.scheme}-{decoded.curve}",
    )
    builder.record(
        "nist.quantum_security_level",
        str(NIST_LEVEL_SECP256K1),
        lane="constant",
        source="scanner.NIST_LEVEL_SECP256K1",
        observation=ObservationType.OBSERVED,
        readiness=Readiness.QUANTUM_VULNERABLE,
        description=(
            f"{CURVE} meets no NIST post-quantum category, so Shor recovers the "
            f"private key from a published public key."
        ),
    )
    builder.record(
        "script.type",
        decoded.script,
        lane="offline",
        source="bech32 witness version and program length, or the base58 version byte",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "network",
        decoded.network,
        lane="offline",
        source="bech32 hrp, or the base58 version byte",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "address.encoding",
        decoded.encoding,
        lane="offline",
        source="the checksum that validated",
        observation=ObservationType.OBSERVED,
    )


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


def _record_bitcoin_chain(builder: _Builder, facts: ChainFacts) -> None:
    """Facts only the ledger holds, and the coverage bound C4 requires."""
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

    builder.record(
        "pubkeys.recovered",
        str(len(facts.public_keys)),
        lane="chain",
        source="vin[] pushes matching 02 or 03 plus 32 bytes, or 04 plus 64 bytes",
        observation=ObservationType.OBSERVED,
    )
    for key in sorted(facts.public_keys):
        builder.record(
            "pubkey",
            key,
            lane="chain",
            source="vin[].witness[1] or a scriptsig push",
            observation=ObservationType.OBSERVED,
        )
    builder.record(
        "outputs.funded",
        str(facts.funded_txo_count),
        lane="chain",
        source="chain_stats.funded_txo_count",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "outputs.spent",
        str(facts.spent_txo_count),
        lane="chain",
        source="chain_stats.spent_txo_count",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "transactions.examined",
        f"{facts.transactions_examined} of {facts.tx_count}",
        lane="chain",
        source="len of the returned page over chain_stats plus mempool_stats tx_count",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "transactions.confirmed",
        str(facts.transactions_confirmed),
        lane="chain",
        source="tx[].status.confirmed is true in the returned page",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "transactions.mempool",
        str(facts.transactions_mempool),
        lane="chain",
        source="tx[].status.confirmed absent; this endpoint returns mempool entries first",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "inputs.from_this_address",
        str(facts.inputs_examined),
        lane="chain",
        source="vin[] where prevout.scriptpubkey_address equals the subject",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "signatures.examined",
        str(len(facts.signatures)),
        lane="chain",
        source="DER 0x30 parses in vin[].witness[0] or a scriptsig push",
        observation=ObservationType.OBSERVED,
    )
    builder.record(
        "balance",
        f"{facts.balance_btc} BTC",
        lane="chain",
        source="(chain_stats.funded_txo_sum - chain_stats.spent_txo_sum) / 1e8",
        observation=ObservationType.OBSERVED,
    )

    _record_bitcoin_defects(builder, facts)

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


def _record_bitcoin_defects(builder: _Builder, facts: ChainFacts) -> None:
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


def _record_ethereum(builder: _Builder, facts: ethereum.AccountFacts) -> None:
    """Account state. C2 holds: this lane reads no key material."""
    if not facts.reachable:
        for name in ("key.published", "account.kind", "account.nonce", "balance"):
            builder.not_tested(name, facts.error or "the RPC lane was unreachable", lane="rpc")
        return

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

    if facts.kind == ethereum.KIND_CONTRACT:
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
        builder.not_tested(
            "owner.keys", "owner and upgrade keys are held off this address", lane="rpc"
        )
        return

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
    builder.not_tested("signatures.examined", "this lane reads account state", lane="rpc")
    builder.not_tested("nonce.reuse", "this lane reads no signature", lane="defect")


def _build_result(
    target: ScanTarget, builder: _Builder, started: datetime, protocol: str
) -> ScanResult:
    return ScanResult(
        scan=build_scan_metadata(
            scan_id=new_id("scan"),
            started_at=started,
            scanner_name="wallet",
            status="completed",
            total_attempts=1,
            completed_at=datetime.now(UTC),
        ),
        target=target,
        dependencies=(),
        assets=(builder.asset,),
        evidence=tuple(builder.evidence),
        findings=tuple(builder.findings),
        summary=build_scan_summary(
            target, builder.findings, builder.evidence, None, protocol=protocol
        ),
    )


def scan_wallet(target: ScanTarget, *, timeout_seconds: int = 12) -> ScanResult:
    """Scan one wallet account. Never raises; an unreached lane reports not tested."""
    started = datetime.now(UTC)
    subject = target.subject or ""
    protocol = target.scheme
    asset = build_endpoint_asset(target, asset_type=f"{protocol}.account", protocol=protocol)
    builder = _Builder(asset, protocol)

    if protocol == "eth":
        decoded_eth = ethereum.decode(subject)
        builder.record(
            "algorithm",
            f"ECDSA {CURVE}",
            lane="offline",
            source="every Ethereum account signs on this curve",
            observation=ObservationType.OBSERVED,
            readiness=Readiness.QUANTUM_VULNERABLE,
            evidence_type=WALLET_SIGNATURE_EVIDENCE,
            negotiated_group=f"ECDSA-{CURVE}",
        )
        builder.record(
            "nist.quantum_security_level",
            str(NIST_LEVEL_SECP256K1),
            lane="constant",
            source="scanner.NIST_LEVEL_SECP256K1",
            observation=ObservationType.OBSERVED,
            readiness=Readiness.QUANTUM_VULNERABLE,
        )
        builder.record(
            "address.encoding",
            "eip-55" if decoded_eth.checksum_present else "hex",
            lane="offline",
            source="mixed case implies an EIP-55 checksum",
            observation=ObservationType.OBSERVED,
        )
        _record_ethereum(builder, ethereum.fetch(subject, timeout_seconds=timeout_seconds))
    else:
        decoded_btc = btc_address.decode(subject)
        _record_offline(builder, decoded_btc)
        _record_bitcoin_chain(builder, indexer.fetch(subject, timeout_seconds=timeout_seconds))

    builder.record(
        "chain.pki",
        "none",
        lane="offline",
        source="this chain defines no certificate format",
        observation=ObservationType.OBSERVED,
    )
    return _build_result(target, builder, started, protocol)


class WalletScanner(Scanner[ScanTarget]):
    """Contract adapter for the wallet scan.

    Carries the collector seam as well, so `_execute_scan` accepts it on the same
    terms as the endpoint scanners. A wallet scan runs no external tool, so
    `collect` delegates straight to `scan`.
    """

    scanner_name = "wallet"
    collector_name = "wallet"
    collector_version = "1"
    capabilities = frozenset({Capability.WALLET_ACCOUNT})

    def collect(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Collect one account result through the canonical collector seam."""
        if source.kind is not SourceKind.ENDPOINT or source.protocol not in ("btc", "eth"):
            return CollectionResult(
                collector=self.collector_name,
                collector_version=self.collector_version,
                failure=None,
            )
        raise NotImplementedError(
            "the wallet collector seam needs a ScanSource to ScanTarget parser; "
            "the CLI builds the target directly and calls scan"
        )

    def scan(self, target: ScanTarget, *, timeout_seconds: int = 12) -> ScanResult:
        """Collect wallet evidence for one account."""
        return scan_wallet(target, timeout_seconds=timeout_seconds)
