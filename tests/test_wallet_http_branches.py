# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Deterministic wallet HTTP branches using a real localhost responder.

The public-indexer tests remain in ``tests/live``. This file supplies the
controlled wire failures needed by the unit coverage gate without mocking the
HTTP client or inventing a scanner result.
"""

# These tests intentionally exercise private branch helpers and keep compact
# compound assertions around the contract they prove; production lint rules
# remain unchanged.
# ruff: noqa: PLC0415, PT018, SLF001

from __future__ import annotations

import http.server
import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar

import pytest
import typer
from rich.console import Console

from qureddy.cli import wallet as wallet_cli
from qureddy.cli.wallet import _detect_chain, _parse_wallet_target, _validate_address
from qureddy.cli.wallet import _endpoint as _cli_endpoint
from qureddy.core.contracts import ScanSource, SourceKind
from qureddy.core.models import (
    Asset,
    HndlExposure,
    HygieneStatus,
    OutputFormat,
    PqcSupport,
    ScanTarget,
)
from qureddy.core.vocabulary import WALLET_SIGNATURE_EVIDENCE
from qureddy.output.console._nist import nist_categories_table
from qureddy.output.console._tables import _summary_table
from qureddy.scanners.common.evaluation.builder import build_evaluation
from qureddy.scanners.common.evaluation.facts import PostureFacts
from qureddy.scanners.common.signature_posture import (
    protocol_hndl_exposure,
    signature_only_ciso_text,
    signature_only_pqc_axis,
)
from qureddy.scanners.wallet import address as btc_address
from qureddy.scanners.wallet import ethereum, indexer, transport
from qureddy.scanners.wallet.bitcoin_records import record_bitcoin_chain
from qureddy.scanners.wallet.eth_records import record_ethereum
from qureddy.scanners.wallet.indexer import ChainFacts, Signature
from qureddy.scanners.wallet.record import Builder
from qureddy.scanners.wallet.scanner import (
    WalletScanner,
    _build_result,
    _record_offline,
    _target_from_source,
)


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
    assert ethereum._result_of(exchange, {"result": 4}) == 4
    assert ethereum._result_of(exchange, {"error": "bad"}) is None
    assert ethereum._as_int("0x10") == 16
    assert ethereum._as_int("10") is None
    assert ethereum._as_int("0xnope") is None
    assert ethereum.decode("0x" + "a" * 40).address.startswith("0x")


def test_scheme_guard_records_refusal_without_opening_a_file() -> None:
    exchanges: list[indexer.HttpExchange] = []
    assert indexer._get_json("file:///private/no", 1, exchanges) is None
    assert ethereum._rpc("file:///private/no", "eth_getCode", [], 1, exchanges) is None
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
    indexer._add_transactions(facts, [transaction], "addr")
    assert facts.output_scripts == {"p2pkh"}
    assert facts.inputs_examined == 1
    assert facts.truncated
    indexer._add_transactions(facts, {"not": "a list"}, "addr")
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
    indexer._harvest([transaction], "addr", facts)
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


def test_cli_wallet_validation_rejects_empty_type_and_mismatched_addresses() -> None:
    with pytest.raises(typer.Exit):
        _parse_wallet_target("   ", None)
    with pytest.raises(typer.Exit):
        _parse_wallet_target("1A1zP1eP5Gefi2DMPTfTL5SLmv7DivfNa", "dogecoin")
    with pytest.raises(typer.Exit):
        _validate_address("not-an-ethereum-address", "ethereum")
    with pytest.raises(typer.Exit):
        _validate_address("not-a-bitcoin-address", "bitcoin")
    with pytest.raises(typer.Exit):
        _validate_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "bitcoin")


def test_cli_wallet_endpoint_defaults_and_missing_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(indexer, "bases", lambda _chain: ("http://127.0.0.1/api",))
    assert _cli_endpoint("bitcoin") == ("127.0.0.1", 80)
    monkeypatch.setattr(indexer, "bases", lambda _chain: ("http:///api",))
    with pytest.raises(typer.Exit):
        _parse_wallet_target("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bitcoin")
    assert _validate_address("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "ethereum")
    with pytest.raises(typer.Exit):
        _validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "litecoin")


def test_wallet_scan_eth_path_and_source_contract_success(monkeypatch: pytest.MonkeyPatch) -> None:
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    replies = (_reply({"result": "0x0"}), _reply({"result": "0x1"}), _reply({"result": "0x0"}))
    monkeypatch.setattr(
        "qureddy.scanners.wallet.scanner.record_indexer_certificate", lambda *_: None
    )
    with _endpoint(*replies) as base, _setting(ethereum.ETH_RPC_ENV, base):
        target = ScanTarget(
            original_input=address,
            host="127.0.0.1",
            port=443,
            sni=None,
            scheme="eth",
            subject=address,
            locator="eth://127.0.0.1:443",
        )
        result = WalletScanner().scan(target, timeout_seconds=2)
    assert any(f.finding_type == "account.kind" for f in result.findings)
    source = ScanSource(
        kind=SourceKind.ENDPOINT,
        protocol="eth",
        locator="eth://127.0.0.1:443",
        metadata={"subject": address},
    )
    monkeypatch.setattr(WalletScanner, "scan", lambda self, target, timeout_seconds: result)
    collected = WalletScanner().collect(source, timeout_seconds=1)
    assert collected.scan_result is result


def test_wallet_renderers_show_wallet_and_nist_rows() -> None:
    facts = indexer.ChainFacts(reachable=True, chain="bitcoin")
    builder = _builder()
    record_bitcoin_chain(builder, facts, "p2pkh")
    target = ScanTarget(
        original_input="addr",
        host="x",
        port=443,
        sni=None,
        scheme="btc",
        subject="addr",
        locator="btc://x:443",
    )
    result = _build_result(target, builder, datetime.now(UTC), "btc")
    summary = _summary_table(result)
    console = Console(record=True, width=120)
    console.print(summary)
    rendered = console.export_text()
    assert "subject" in rendered and "key_published" in rendered and "balance" in rendered
    evidence = result.evidence[0].model_copy(
        update={
            "evidence_type": WALLET_SIGNATURE_EVIDENCE,
            "nist_quantum_security_level": 0,
            "algorithm": "ECDSA secp256k1",
        }
    )
    assert nist_categories_table(result.model_copy(update={"evidence": (evidence,)})) is not None


def test_cli_wallet_command_wires_machine_render_and_propagates_scan_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_result = _build_result(
        ScanTarget(
            original_input="addr",
            host="x",
            port=443,
            sni=None,
            scheme="btc",
            subject="addr",
            locator="btc://x:443",
        ),
        _builder(),
        datetime.now(UTC),
        "btc",
    )
    calls: list[object] = []
    monkeypatch.setattr(wallet_cli, "_prepare_output_dir", lambda *args: calls.append("dir"))
    monkeypatch.setattr(wallet_cli, "start_run_logging", lambda **kwargs: calls.append("log"))
    monkeypatch.setattr(wallet_cli, "_execute_scan", lambda *args, **kwargs: (target_result, 0))
    monkeypatch.setattr(wallet_cli, "_render", lambda *args, **kwargs: calls.append("render"))
    wallet_cli.scan_wallet_cmd(
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None, OutputFormat.JSON, None, 0
    )
    assert calls == ["log", "dir", "render"]
    monkeypatch.setattr(wallet_cli, "_execute_scan", lambda *args, **kwargs: (target_result, 2))
    with pytest.raises(typer.Exit) as exc_info:
        wallet_cli.scan_wallet_cmd(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None, OutputFormat.RICH, None, 0
        )
    assert exc_info.value.exit_code == 2


def test_wallet_recorders_cover_unreachable_contract_and_all_bitcoin_count_rows() -> None:
    unreachable = indexer.ChainFacts(reachable=False, error="offline")
    builder = _builder()
    record_bitcoin_chain(builder, unreachable)
    assert _finding(builder, "balance").title.endswith("not tested")

    p2pk = indexer.ChainFacts(reachable=True, output_scripts={"p2pk"}, tx_count=2)
    builder = _builder()
    record_bitcoin_chain(builder, p2pk)
    assert _finding(builder, "key.published").title.endswith("yes")

    full = indexer.ChainFacts(
        reachable=True,
        public_keys={"04" + "aa" * 64},
        signatures=[Signature("tx", "abcdef", "01")],
        tx_count=2,
        transactions_examined=1,
        truncated=True,
    )
    builder = _builder()
    record_bitcoin_chain(builder, full)
    assert (
        next(e for e in builder.evidence if e.public_key).public_key_format == "SEC1-uncompressed"
    )
    assert _finding(builder, "scan.coverage")
    clean = indexer.ChainFacts(reachable=True, signatures=[Signature("tx", "abcdef0123", "01")])
    builder = _builder()
    record_bitcoin_chain(builder, clean)
    assert _finding(builder, "nonce.reuse").title.endswith("none in 1")


def test_ethereum_recorder_covers_unreachable_contract_and_owned_key() -> None:
    builder = _builder("eth")
    record_ethereum(builder, ethereum.AccountFacts(error="rpc down"))
    assert _finding(builder, "balance").title.endswith("not tested")
    builder = _builder("eth")
    record_ethereum(
        builder, ethereum.AccountFacts(reachable=True, kind=ethereum.KIND_CONTRACT, code_bytes=3)
    )
    assert _finding(builder, "owner.keys").title.endswith("not tested")
    builder = _builder("eth")
    record_ethereum(builder, ethereum.AccountFacts(reachable=True, nonce=1, balance_wei=1))
    assert _finding(builder, "key.published").title.endswith("yes")


def test_wallet_address_and_indexer_edge_parsers() -> None:
    assert btc_address._base58check("1") is None
    assert btc_address._convert_bits([32], 5, 8) is None
    assert btc_address.decode("bc1").error
    assert indexer.parse_der_signature("3006020101020100") is None
    assert indexer.script_pushes("4c02aa") == []
    assert indexer.script_pushes("zz") == []
    assert indexer.fetch("").error == "no address supplied"
    original_base58 = btc_address._base58check
    try:
        btc_address._base58check = lambda _value: b"short"  # type: ignore[assignment]
        assert btc_address._decode_base58check("x").error == "base58 payload length is unexpected"
        btc_address._base58check = lambda _value: bytes([255]) + b"x" * 20  # type: ignore[assignment]
        assert "unassigned" in btc_address._decode_base58check("x").error
    finally:
        btc_address._base58check = original_base58  # type: ignore[assignment]
    assert btc_address.signature_scheme("unknown") == ""


def test_signature_and_evaluation_edges_are_explicit() -> None:
    assert signature_only_pqc_axis(protocol="btc", signature_classical=True) == (
        PqcSupport.CLASSICAL_ONLY_OBSERVED,
        __import__("qureddy.core.models", fromlist=["AxisStatus"]).AxisStatus.CLASSICAL,
    )
    assert signature_only_ciso_text(protocol="btc", account_without_key=True)
    assert (
        protocol_hndl_exposure(protocol="btc", not_testable=False, signature_classical=True)
        is HndlExposure.AT_RISK
    )
    assert (
        protocol_hndl_exposure(protocol="tls", not_testable=False, signature_classical=False)
        is None
    )
    assert build_evaluation(
        PostureFacts(
            protocol="tls",
            support=PqcSupport.CLASSICAL_ONLY_OBSERVED,
            hndl_exposure=HndlExposure.UNKNOWN,
            hygiene_status=HygieneStatus.UNKNOWN,
        )
    ).summary.startswith("Only classical TLS")


def test_evaluation_builder_handles_no_key_and_unknown_axes() -> None:
    facts = PostureFacts(
        protocol="btc",
        support=PqcSupport.CLASSICAL_ONLY_OBSERVED,
        hndl_exposure=HndlExposure.AT_RISK,
        hygiene_status=HygieneStatus.UNKNOWN,
        account_without_key=True,
    )
    evaluation = build_evaluation(facts)
    assert "no key" in evaluation.summary.lower()
    assert "no key" in evaluation.protection.lower()
    assert "owner" in evaluation.recommended_action.lower()


def test_ethereum_decode_delegation_and_rpc_failure_edges() -> None:
    decoded = ethereum.decode("0x" + "A" * 40)
    assert decoded.valid and not decoded.checksum_present
    bad = ethereum.decode("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96044")
    assert not bad.valid
    code = "0xef0100" + "11" * 20
    assert ethereum.classify_code(code) == ethereum.KIND_DELEGATED
    assert ethereum.delegate_of(code).startswith("0x")
    assert ethereum.delegate_of("0x00") == ""
    assert ethereum.fetch("").error == "no address supplied"
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    with _endpoint(_reply({"result": None})) as base, _setting(ethereum.ETH_RPC_ENV, base):
        facts = ethereum.fetch(address, timeout_seconds=2)
    assert not facts.reachable and "eth_getCode" in facts.error
    with (
        _endpoint(_reply({"result": "0x0"}), _reply({"result": "bad"})) as base,
        _setting(ethereum.ETH_RPC_ENV, base),
    ):
        facts = ethereum.fetch(address, timeout_seconds=2)
    assert not facts.reachable and "eth_getTransactionCount" in facts.error
    exchanges: list[indexer.HttpExchange] = []
    assert ethereum._rpc("http://127.0.0.1:9", "eth_getCode", [], 0.1, exchanges) is None


def test_wallet_table_marks_not_tested_values() -> None:
    builder = _builder()
    builder.not_tested("balance", "offline", lane="chain")
    target = ScanTarget(
        original_input="addr",
        host="x",
        port=443,
        sni=None,
        scheme="btc",
        subject="addr",
        locator="btc://x:443",
    )
    result = _build_result(target, builder, datetime.now(UTC), "btc")
    console = Console(record=True, width=120)
    console.print(_summary_table(result))
    assert "not tested" in console.export_text()


def test_transport_resolution_and_certificate_failures_are_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "_OPENSSL_CANDIDATES", ())
    monkeypatch.setattr(transport.shutil, "which", lambda _name: None)
    monkeypatch.delenv(transport._OPENSSL_ENV, raising=False)
    assert transport._resolve_openssl() is None
    builder = _builder()
    transport.record_indexer_certificate(builder, "x", 443)
    assert _finding(builder, "indexer.certificate").title.endswith("not tested")
    monkeypatch.setattr(
        transport,
        "resolve_openssl_path",
        lambda _path: (_ for _ in ()).throw(transport.QureddyError("bad binary")),
    )
    monkeypatch.setattr(transport, "_OPENSSL_CANDIDATES", ("/bad",))
    monkeypatch.setenv(transport._OPENSSL_ENV, "/also-bad")
    assert transport._resolve_openssl() is None
    monkeypatch.setattr(transport, "_resolve_openssl", lambda: "openssl")
    monkeypatch.setattr(transport, "fetch_certificate_pem", lambda *args, **kwargs: "")
    builder = _builder()
    transport.record_indexer_certificate(builder, "x", 443)
    assert _finding(builder, "indexer.certificate")
    from qureddy.scanners.tls.cert_probe import CertificateInfo

    certificate = CertificateInfo(
        "subject",
        "issuer",
        "before",
        "after",
        "serial",
        "sha256WithRSAEncryption",
        "RSA",
        False,
        False,
        "RSA",
        2048,
    )
    monkeypatch.setattr(transport, "parse_certificate", lambda *args, **kwargs: certificate)
    monkeypatch.setattr(transport, "_resolve_openssl", lambda: "openssl")
    monkeypatch.setattr(transport, "fetch_certificate_pem", lambda *args, **kwargs: "PEM")
    builder = _builder()
    transport.record_indexer_certificate(builder, "x", 443)
    assert _finding(builder, "indexer.certificate")
    monkeypatch.setattr(
        transport,
        "fetch_certificate_pem",
        lambda *args, **kwargs: (_ for _ in ()).throw(transport.QureddyError("down")),
    )
    builder = _builder()
    transport.record_indexer_certificate(builder, "x", 443)
    assert _finding(builder, "indexer.certificate")
    monkeypatch.setattr(transport, "fetch_certificate_pem", lambda *args, **kwargs: "PEM")
    monkeypatch.setattr(
        transport,
        "parse_certificate",
        lambda *args, **kwargs: (_ for _ in ()).throw(transport.CertificateParseError("bad")),
    )
    builder = _builder()
    transport.record_indexer_certificate(builder, "x", 443)
    assert _finding(builder, "indexer.certificate")


def test_wallet_source_contract_rejects_malformed_locator() -> None:
    source = ScanSource(
        kind=SourceKind.ENDPOINT, protocol="btc", locator="btc://x", metadata={"subject": "addr"}
    )
    result = WalletScanner().collect(source, timeout_seconds=1)
    assert result.failure is not None and "scheme://host:port" in result.failure.message


def _finding(builder: Builder, name: str):
    return next(finding for finding in builder.findings if finding.finding_type == name)
