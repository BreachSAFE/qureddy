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

import urllib.parse
from datetime import UTC, datetime

from qureddy.core.contracts import (
    Capability,
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    Scanner,
    ScanSource,
    SourceKind,
)
from qureddy.core.ids import new_id
from qureddy.core.models import (
    ScanResult,
    ScanTarget,
)
from qureddy.core.vocabulary import (
    WALLET_SIGNATURE_EVIDENCE,
    ObservationType,
    Readiness,
)
from qureddy.scanners.common.assets import build_endpoint_asset
from qureddy.scanners.common.metadata import build_scan_metadata
from qureddy.scanners.common.posture import build_scan_summary
from qureddy.scanners.wallet import address as btc_address
from qureddy.scanners.wallet import ethereum, indexer
from qureddy.scanners.wallet.bitcoin_records import record_bitcoin_chain
from qureddy.scanners.wallet.eth_records import record_ethereum
from qureddy.scanners.wallet.record import CURVE, NIST_LEVEL_SECP256K1, Builder
from qureddy.scanners.wallet.transport import record_indexer_certificate

_KEY_SIZE_BITS = 256

NOT_TESTED = "not tested"
_OPENSSL_ENV = "QUREDDY_OPENSSL"
_HTTP_TIMEOUT_SECONDS = 12
_HTTP_OK = 200
# A5: a bound that shapes output is named and reported, never applied silently.
#: Transaction ids listed per defect. The full set stays in the signature evidence.
_DEFECT_TXID_LIMIT = 6


def _record_offline(builder: Builder, decoded: btc_address.DecodedAddress) -> None:
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
    for name, value in (("chain", decoded.chain), ("network", decoded.network)):
        builder.record(
            name,
            value,
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


def _build_result(
    target: ScanTarget, builder: Builder, started: datetime, protocol: str
) -> ScanResult:
    return ScanResult(
        scan=build_scan_metadata(
            scan_id=new_id("scan"),
            started_at=started,
            scanner_name="wallet",
            status="completed",
            total_attempts=sum(1 for item in builder.evidence if item.probe_result is not None)
            or 1,
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
    builder = Builder(asset, protocol)

    if protocol == "eth":
        _scan_ethereum(builder, subject, timeout_seconds)
    else:
        decoded_btc = btc_address.decode(subject)
        _record_offline(builder, decoded_btc)
        record_bitcoin_chain(
            builder,
            indexer.fetch(subject, chain=decoded_btc.chain, timeout_seconds=timeout_seconds),
            decoded_btc.script,
        )

    record_indexer_certificate(builder, target.host, target.port)
    builder.record(
        "chain.pki",
        "none",
        lane="offline",
        source="this chain defines no certificate format",
        observation=ObservationType.OBSERVED,
    )
    return _build_result(target, builder, started, protocol)


def _scan_ethereum(builder: Builder, subject: str, timeout_seconds: int) -> None:
    """The offline facts an Ethereum address alone establishes, then its account state."""
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
    record_ethereum(builder, ethereum.fetch(subject, timeout_seconds=timeout_seconds))


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
