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

import os
import shutil
import urllib.parse
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qureddy.core.contracts import (
    Capability,
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    Scanner,
    ScanSource,
    SourceKind,
)
from qureddy.core.errors import CertificateParseError, QureddyError
from qureddy.core.ids import new_id
from qureddy.core.models import (
    Asset,
    Evidence,
    Finding,
    ProbeResult,
    ScanResult,
    ScanTarget,
)
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
from qureddy.scanners.tls._cert_findings import evidence_from_certificate
from qureddy.scanners.tls.cert_probe import fetch_certificate_pem, parse_certificate
from qureddy.scanners.tls.openssl_probe import resolve_openssl_path
from qureddy.scanners.tls.openssl_probe._results import build_probe_result
from qureddy.scanners.wallet import address as btc_address
from qureddy.scanners.wallet import ethereum, indexer

if TYPE_CHECKING:  # pragma: no cover - typing only
    from qureddy.scanners.wallet.indexer import ChainFacts, HttpExchange, Signature

#: secp256k1 meets no NIST post-quantum category, so Shor recovers the key outright.
NIST_LEVEL_SECP256K1 = 0
CURVE = "secp256k1"
_PRIMITIVE = "signature"
_KEY_SIZE_BITS = 256

#: Script classes whose output carries a readable public key with no spend.
_KEY_IN_OUTPUT_SCRIPTS = frozenset({"p2pk", "multisig", "v1_p2tr"})

#: Hash-addressed script classes. A P2PK or bare-multisig output paying the same
#: key carries no address, so an address query cannot return it.
_HASH_ADDRESSED_SCRIPTS = frozenset({"p2pkh", "p2sh"})

#: An r value this short implies a nonce small enough to brute force.
_LOW_ENTROPY_R_HEX = 8

_NOT_TESTED = "not tested"
_OPENSSL_ENV = "QUREDDY_OPENSSL"
_HTTP_TIMEOUT_SECONDS = 12
_HTTP_OK = 200
#: Transcript characters kept per exchange. Truncation is stated in the pane.
_TRANSCRIPT_CHARS = 40_000

#: Candidates tried in order until one passes the capability gate unchanged. The
#: gate itself is untouched: a candidate is used only when `resolve_openssl_path`
#: accepts it. PATH alone is unreliable, because a box can carry LibreSSL at
#: /usr/bin/openssl and a 3.6 series build ahead of the 3.5 LTS one, and neither
#: satisfies the platform pin. The Homebrew LTS keg is listed for that reason and
#: is the same candidate the repository's live suite already uses.
_OPENSSL_CANDIDATES: tuple[str, ...] = (
    "/opt/homebrew/opt/openssl@3.5/bin/openssl",
    "/usr/local/opt/openssl@3.5/bin/openssl",
)

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


def _probe_result(exchange: HttpExchange) -> ProbeResult:
    """One HTTP exchange as a ProbeResult, the structure every probe here uses.

    A REST call is a probe like any other: a command went out, bytes came back,
    and it took time. Using `ProbeResult` puts the transcript in `scan.json`
    beside every subprocess probe's, with no structure invented for it.

    `build_probe_result` is the shared builder, so the evidence-integrity
    contract from issue 202 holds here too: each stream's sha256 and excerpt
    derive from one value, which makes the excerpt a verifiable prefix of the
    hashed stream. `stdout` is the curl shaped transcript, the deepest trace
    this lane can produce.
    """
    return build_probe_result(
        args=[exchange.method, exchange.url],
        return_code=exchange.status,
        stdout=exchange.transcript(),
        stderr=exchange.error,
        parser_input="",
        duration_ms=exchange.duration_ms,
        attempt_number=1,
        timeout_seconds=_HTTP_TIMEOUT_SECONDS,
        failure_category=None,
    )


def _record_exchanges(builder: _Builder, facts: ChainFacts) -> None:
    """Attach every HTTP round trip as its own evidence record."""
    for index, exchange in enumerate(facts.exchanges, start=1):
        succeeded = exchange.status == _HTTP_OK and not exchange.error
        item = Evidence(
            id=new_id("evidence"),
            asset_id=builder.asset.id,
            evidence_type="wallet.http",
            observation_type=(
                ObservationType.OBSERVED if succeeded else ObservationType.NO_RESPONSE
            ),
            source="chain",
            protocol=builder.protocol,
            confidence=Confidence.HIGH if succeeded else Confidence.LOW,
            probe_result=_probe_result(exchange),
            notes=(
                "lane=chain",
                f"source=HTTP exchange {index} of {len(facts.exchanges)}",
            ),
        )
        builder.evidence.append(item)


def _record_bitcoin_chain(builder: _Builder, facts: ChainFacts, script: str = "") -> None:
    """Facts only the ledger holds, and the coverage bound C4 requires."""
    _record_exchanges(builder, facts)
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
        _record_p2pk_blind_spot(builder, script)

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


def _record_p2pk_blind_spot(builder: _Builder, script: str) -> None:
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
        _NOT_TESTED,
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


def _resolve_openssl() -> str | None:
    """First OpenSSL the existing capability gate accepts, or None.

    Precedence matches the TLS lane: the environment override first, then the
    known LTS keg locations, then PATH. Each candidate goes through
    `resolve_openssl_path`, so the gate decides and this function only chooses
    what to offer it.
    """
    candidates = [
        os.environ.get(_OPENSSL_ENV),
        *_OPENSSL_CANDIDATES,
        shutil.which("openssl"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return resolve_openssl_path(candidate)
        except QureddyError:
            continue
    return None


def _record_indexer_certificate(builder: _Builder, host: str, port: int) -> None:
    """Record the indexer's TLS certificate, reusing the TLS lane's own probe.

    The endpoint contacted is an ordinary TLS server, so `fetch_certificate_pem`
    and `parse_certificate` apply unchanged and `evidence_from_certificate`
    builds the record. Setting `certificate_pem` also makes `--output-dir` write
    `certificate.pem`, because `_write_certificate_artifact` looks for exactly
    that field.

    This certificate authenticates the API host and says nothing about the
    account, which the finding states. The probe needs an OpenSSL 3.5 LTS
    binary, so an unusable one yields not tested in place of a gap.
    """
    openssl = _resolve_openssl()
    if openssl is None:
        builder.not_tested(
            "indexer.certificate",
            "no OpenSSL on this host passes the capability gate; "
            f"set {_OPENSSL_ENV} to a 3.5 LTS build",
            lane="transport",
        )
        return
    try:
        pem = fetch_certificate_pem(openssl, host, port, host, timeout_seconds=15)
    except QureddyError as exc:
        builder.not_tested("indexer.certificate", str(exc), lane="transport")
        return
    if not pem:
        builder.not_tested(
            "indexer.certificate", "the handshake returned no leaf", lane="transport"
        )
        return
    try:
        certificate = parse_certificate(openssl, pem)
    except (CertificateParseError, QureddyError) as exc:
        builder.not_tested(
            "indexer.certificate", f"the leaf did not parse: {exc}", lane="transport"
        )
        return

    record = evidence_from_certificate(builder.asset, certificate)
    # The TLS builder writes its own note and knows nothing of C1, so the lane
    # and source join it rather than replace it.
    builder.evidence.append(
        record.model_copy(
            update={
                "certificate_pem": pem,
                "notes": (*record.notes, *_note("transport", "openssl s_client leaf")),
            }
        )
    )
    builder.record(
        "indexer.certificate",
        f"{certificate.subject}",
        lane="transport",
        source="openssl s_client leaf, parsed with openssl x509",
        observation=ObservationType.OBSERVED,
        description=(
            f"Issued by {certificate.issuer}, valid to {certificate.not_after}, "
            f"signed with {certificate.signature_algorithm}. This authenticates the "
            f"API host and carries no statement about the account."
        ),
    )


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
        _record_bitcoin_chain(
            builder,
            indexer.fetch(subject, timeout_seconds=timeout_seconds),
            decoded_btc.script,
        )

    _record_indexer_certificate(builder, target.host, target.port)
    builder.record(
        "chain.pki",
        "none",
        lane="offline",
        source="this chain defines no certificate format",
        observation=ObservationType.OBSERVED,
    )
    return _build_result(target, builder, started, protocol)


#: Schemes this collector answers for.
_SCHEMES = frozenset({"btc", "eth"})


def _target_from_source(source: ScanSource, subject: str) -> ScanTarget:
    """Rebuild the ScanTarget a locator plus a subject describe."""
    parts = urllib.parse.urlsplit(source.locator)
    if not parts.hostname or not parts.port:
        msg = f"a wallet locator is scheme://host:port, and this one is {source.locator!r}"
        raise ValueError(msg)
    return ScanTarget(
        original_input=subject,
        host=parts.hostname,
        port=parts.port,
        sni=None,
        scheme=parts.scheme,
        subject=subject,
        locator=f"{parts.scheme}://{parts.hostname}:{parts.port}",
    )


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
        """Collect one account result through the canonical collector seam.

        A wallet source names the endpoint in `locator` and the account in
        `metadata["subject"]`, because an account is not an endpoint and the
        locator grammar is `scheme://host:port`. A source without a subject is
        an unsupported source, reported as such in place of an exception.
        """
        unsupported = source.kind is not SourceKind.ENDPOINT or source.protocol not in _SCHEMES
        if unsupported:
            return self._refuse(
                f"a wallet source is an endpoint on {sorted(_SCHEMES)}, "
                f"and this one is {source.protocol!r} of kind {source.kind.value}"
            )
        subject = source.metadata.get("subject", "")
        if not subject:
            return self._refuse("a wallet source carries the account in metadata['subject']")
        try:
            target = _target_from_source(source, subject)
        except ValueError as exc:
            return self._refuse(str(exc))
        result = self.scan(target, timeout_seconds=timeout_seconds)
        return CollectionResult(
            collector=self.collector_name,
            collector_version=self.collector_version,
            evidence=result.evidence,
            findings=result.findings,
            provenance=result.scan.provenance,
            scan_result=result,
        )

    def _refuse(self, message: str) -> CollectionResult:
        """Report an unusable source as a failure the caller cannot mistake for a scan."""
        return CollectionResult(
            collector=self.collector_name,
            collector_version=self.collector_version,
            failure=CollectionFailure(kind=CollectionFailureKind.UNSUPPORTED, message=message),
        )

    def scan(self, target: ScanTarget, *, timeout_seconds: int = 12) -> ScanResult:
        """Collect wallet evidence for one account."""
        return scan_wallet(target, timeout_seconds=timeout_seconds)
