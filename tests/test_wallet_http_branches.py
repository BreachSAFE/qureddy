# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Deterministic wallet HTTP branches using a real localhost responder.

The public-indexer tests remain in ``tests/live``. This file supplies the
controlled wire failures needed by the unit coverage gate without mocking the
HTTP client or inventing a scanner result.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import ClassVar

import pytest

from qureddy.cli.wallet import _detect_chain, _parse_wallet_target
from qureddy.cli.wallet import _endpoint as _cli_endpoint
from qureddy.core.contracts import ScanSource, SourceKind
from qureddy.core.models import Asset, ScanTarget
from qureddy.scanners.wallet import address as btc_address
from qureddy.scanners.wallet import ethereum, indexer
from qureddy.scanners.wallet.bitcoin_records import record_bitcoin_chain
from qureddy.scanners.wallet.eth_records import record_ethereum
from qureddy.scanners.wallet.indexer import ChainFacts, Signature
from qureddy.scanners.wallet.record import Builder
from qureddy.scanners.wallet.scanner import WalletScanner, _record_offline, _target_from_source


@dataclass(frozen=True)
class _Reply:
    status: int
    body: bytes


class _Responder(http.server.BaseHTTPRequestHandler):
    replies: ClassVar[list[_Reply]] = []

    def _serve(self) -> None:
        reply = type(self).replies.pop(0)
        self.send_response(reply.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply.body)))
        self.end_headers()
        self.wfile.write(reply.body)

    do_GET = _serve  # noqa: N815 - stdlib dispatch name
    do_POST = _serve  # noqa: N815 - stdlib dispatch name

    def log_message(self, *_args: object) -> None:
        """Keep the test responder quiet."""


@contextmanager
def _endpoint(*replies: _Reply) -> Iterator[str]:
    _Responder.replies = list(replies)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Responder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def _setting(name: str, value: str) -> Iterator[None]:
    previous = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def _reply(value: object, status: int = 200) -> _Reply:
    return _Reply(status, json.dumps(value).encode())


def _address_summary() -> dict[str, object]:
    return {"chain_stats": {"tx_count": 1, "funded_txo_count": 1, "funded_txo_sum": 9}}


def test_indexer_http_success_and_unavailable_transaction_page() -> None:
    with (
        _endpoint(_reply(_address_summary()), _Reply(502, b"upstream")) as base,
        _setting(indexer.ESPLORA_URL_ENV, base),
    ):
        facts = indexer.fetch("addr", timeout_seconds=2)
    assert facts.reachable
    assert facts.balance_satoshi == 9
    assert facts.error == "address summary only; the transaction page was unavailable"
    assert len(facts.exchanges) == 2


def test_indexer_http_malformed_summary_and_invalid_json_fail_closed() -> None:
    with _endpoint(_reply([])) as base, _setting(indexer.ESPLORA_URL_ENV, base):
        facts = indexer.fetch("addr", timeout_seconds=2)
    assert not facts.reachable
    assert facts.error.endswith("returned no address summary")

    with _endpoint(_Reply(200, b"not-json")) as base, _setting(indexer.ESPLORA_URL_ENV, base):
        facts = indexer.fetch("addr", timeout_seconds=2)
    assert not facts.reachable
    assert facts.exchanges[0].error.startswith("the body was not JSON")

    with _setting(indexer.ESPLORA_URL_ENV, "http://127.0.0.1:9"):
        facts = indexer.fetch("addr", timeout_seconds=0.1)
    assert not facts.reachable
    assert facts.exchanges[0].error


def test_ethereum_http_success_and_partial_balance() -> None:
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    replies = (_reply({"result": "0x0"}), _reply({"result": "0x1"}), _reply({}))
    with _endpoint(*replies) as base, _setting(ethereum.ETH_RPC_ENV, base):
        facts = ethereum.fetch(address, timeout_seconds=2)
    assert facts.reachable
    assert facts.nonce == 1
    assert facts.error == "balance was unavailable, so it reads not tested"
    assert len(facts.exchanges) == 3


def test_ethereum_http_error_and_invalid_json_are_unreachable() -> None:
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    with _endpoint(_Reply(503, b"down")) as base, _setting(ethereum.ETH_RPC_ENV, base):
        facts = ethereum.fetch(address, timeout_seconds=2)
    assert not facts.reachable
    assert facts.exchanges[0].status == 503

    with _endpoint(_Reply(200, b"not-json")) as base, _setting(ethereum.ETH_RPC_ENV, base):
        facts = ethereum.fetch(address, timeout_seconds=2)
    assert not facts.reachable
    assert "not JSON" in facts.exchanges[0].error


def test_ethereum_value_helpers_cover_invalid_rpc_values() -> None:
    exchange = indexer.HttpExchange("POST", "https://x.test")
    assert ethereum._result_of(exchange, {"result": 4}) == 4  # noqa: SLF001
    assert ethereum._result_of(exchange, {"error": "bad"}) is None  # noqa: SLF001
    assert ethereum._as_int("0x10") == 16  # noqa: SLF001
    assert ethereum._as_int("10") is None  # noqa: SLF001
    assert ethereum._as_int("0xnope") is None  # noqa: SLF001
    assert ethereum.decode("0x" + "a" * 40).address.startswith("0x")


def test_scheme_guard_records_refusal_without_opening_a_file() -> None:
    exchanges: list[indexer.HttpExchange] = []
    assert indexer._get_json("file:///private/no", 1, exchanges) is None  # noqa: SLF001
    assert ethereum._rpc("file:///private/no", "eth_getCode", [], 1, exchanges) is None  # noqa: SLF001
    assert all(exchange.error.startswith("refused:") for exchange in exchanges)


def test_exchange_transcript_covers_request_body_and_failure() -> None:
    exchange = indexer.HttpExchange("POST", "https://x.test/rpc", operation="eth_getCode")
    exchange.request_body = '{"jsonrpc": "2.0"}'
    exchange.error = "connection refused"
    transcript = exchange.transcript()
    assert "> POST /rpc HTTP/1.1" in transcript
    assert '| {"jsonrpc": "2.0"}' in transcript
    assert "FAILED connection refused" in transcript


def test_indexer_summary_and_transaction_harvest_cover_all_record_shapes() -> None:
    facts = indexer.ChainFacts(reachable=True, tx_count=3, spent_txo_count=1)
    transaction = {
        "txid": "tx-1",
        "vout": [
            {"scriptpubkey_address": "addr", "scriptpubkey_type": "p2pkh"},
            {"scriptpubkey_address": "other", "scriptpubkey_type": "p2sh"},
        ],
        "vin": [
            {"prevout": {"scriptpubkey_address": "other"}},
            {"prevout": {"scriptpubkey_address": "addr"}, "witness": [], "scriptsig": "ff"},
        ],
        "status": {"confirmed": True},
    }
    indexer._add_transactions(facts, [transaction], "addr")  # noqa: SLF001
    assert facts.output_scripts == {"p2pkh"}
    assert facts.inputs_examined == 1
    assert facts.truncated
    indexer._add_transactions(facts, {"not": "a list"}, "addr")  # noqa: SLF001
    assert facts.error.startswith("address summary only")


def test_cli_wallet_target_helpers_cover_chain_detection_and_rejection() -> None:
    assert _detect_chain("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045") == "ethereum"
    assert _detect_chain("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") == "bitcoin"
    assert _cli_endpoint("bitcoin")[0]
    target = _parse_wallet_target("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None)
    assert target.scheme == "btc"


def test_scan_wallet_assembles_real_local_chain_evidence() -> None:
    summary = {"chain_stats": {"tx_count": 0, "funded_txo_count": 0, "funded_txo_sum": 0}}
    with _endpoint(_reply(summary), _reply([])) as base, _setting(indexer.ESPLORA_URL_ENV, base):
        target = ScanTarget(
            original_input="1BoatSLRHtKNngkd Kid",  # normalized only by the caller
            host="127.0.0.1",
            port=443,
            sni=None,
            scheme="btc",
            subject="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            locator="btc://127.0.0.1:443",
        )
        result = WalletScanner().scan(target, timeout_seconds=2)
    assert result.scan.scanner_name == "wallet"
    assert result.target.subject == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    assert any(f.finding_type == "script.type" for f in result.findings)


def test_offline_decoder_emits_all_address_facts() -> None:
    decoded = btc_address.decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    builder = _builder()
    _record_offline(builder, decoded)
    names = {finding.finding_type for finding in builder.findings}
    assert {"algorithm", "chain", "network", "script.type", "address.encoding"} <= names


def _builder(protocol: str = "btc") -> Builder:
    asset = Asset(
        id="asset-test",
        asset_type=f"{protocol}.account",
        locator=f"{protocol}://x:1",
        display_name="x",
    )
    return Builder(asset, protocol)


def test_indexer_parsers_cover_script_pushes_and_signature_shapes() -> None:
    assert indexer.parse_der_signature("zz") is None
    assert indexer.parse_der_signature("3006020101020102") == ("01", "02")
    assert indexer.parse_der_signature("3006020101020102ff") == ("01", "02")
    assert indexer.parse_der_signature("3006020000020102") is None
    assert indexer.parse_der_signature("300602010102") is None
    assert indexer.parse_der_signature("3006020101000102") is None
    assert indexer.script_pushes("02aabb") == ["aabb"]
    assert indexer.script_pushes("4c02aabb") == ["aabb"]
    assert indexer.script_pushes("4c02aa") == []
    assert indexer.script_pushes("ff") == []
    assert indexer.looks_like_public_key("02" + "aa" * 32)
    assert indexer.looks_like_public_key("04" + "aa" * 64)
    assert not indexer.looks_like_public_key("aa")


def test_indexer_harvest_records_only_subject_keys_and_signatures() -> None:
    facts = indexer.ChainFacts(reachable=True)
    pubkey = "02" + "aa" * 32
    transaction = {
        "txid": "tx-1",
        "vout": [{"scriptpubkey_address": "addr", "scriptpubkey_type": "p2pkh"}],
        "vin": [
            {"prevout": {"scriptpubkey_address": "other"}},
            {
                "prevout": {"scriptpubkey_address": "addr"},
                "witness": ["3006020101020102", pubkey],
            },
        ],
    }
    indexer._harvest([transaction], "addr", facts)  # noqa: SLF001
    assert facts.output_scripts == {"p2pkh"}
    assert facts.public_keys == {pubkey}
    assert facts.signatures[0].r == "01"
    assert facts.inputs_examined == 1


def test_bitcoin_recorder_covers_key_and_defect_variants() -> None:
    no_key = ChainFacts(reachable=True, chain="bitcoin", spent_txo_count=0)
    builder = _builder()
    record_bitcoin_chain(builder, no_key, "p2pkh")
    assert any(f.finding_type == "key.p2pk_sibling" for f in builder.findings)

    in_output = ChainFacts(reachable=True, output_scripts={"p2pk"}, transactions_examined=1)
    builder = _builder()
    record_bitcoin_chain(builder, in_output)
    assert _finding(builder, "key.published").title.endswith("yes")

    inferred = ChainFacts(reachable=True, spent_txo_count=1)
    builder = _builder()
    record_bitcoin_chain(builder, inferred)
    assert _finding(builder, "key.published").title.endswith("yes")

    signatures = [Signature(str(i), "abcdef01", "02") for i in range(7)]
    signatures += [Signature("low", "01", "02")]
    defects = ChainFacts(reachable=True, signatures=signatures)
    builder = _builder()
    record_bitcoin_chain(builder, defects)
    assert any(f.finding_type == "nonce.low_entropy" for f in builder.findings)
    assert any("further transaction" in f.description for f in builder.findings)


def test_ethereum_recorder_covers_delegate_contract_and_clean_account() -> None:
    delegated = ethereum.AccountFacts(
        reachable=True,
        kind=ethereum.KIND_DELEGATED,
        delegate="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        nonce=0,
        balance_wei=1,
    )
    builder = _builder("eth")
    record_ethereum(builder, delegated)
    assert any(f.finding_type == "account.delegate" for f in builder.findings)

    clean = ethereum.AccountFacts(reachable=True, nonce=0)
    builder = _builder("eth")
    record_ethereum(builder, clean)
    assert _finding(builder, "key.published").title.endswith("no")


def test_wallet_source_contract_rejects_bad_sources_and_accepts_canonical_source() -> None:
    scanner = WalletScanner()
    unsupported = ScanSource(
        kind=SourceKind.CERTIFICATE,
        protocol="btc",
        locator="btc://x:443",
        metadata={"subject": "addr"},
    )
    assert scanner.collect(unsupported, timeout_seconds=1).failure is not None
    missing = ScanSource(
        kind=SourceKind.ENDPOINT,
        protocol="btc",
        locator="btc://x:443",
        metadata={},
    )
    assert scanner.collect(missing, timeout_seconds=1).failure is not None
    with pytest.raises(ValueError, match="scheme://host:port"):
        _target_from_source(
            ScanSource(
                kind=SourceKind.ENDPOINT, protocol="btc", locator="bad", metadata={"subject": "x"}
            ),
            "x",
        )
    source = ScanSource(
        kind=SourceKind.ENDPOINT,
        protocol="btc",
        locator="btc://mempool.space:443",
        metadata={"subject": "addr"},
    )
    target = _target_from_source(source, "addr")
    assert target.locator == "btc://mempool.space:443"


def _finding(builder: Builder, name: str):
    return next(finding for finding in builder.findings if finding.finding_type == name)
