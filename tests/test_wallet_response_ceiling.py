# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The wallet HTTP lanes cap what they read, not just what they keep.

`_MAX_BODY_TRACE` bounds the transcript after the body is already resident, so
it caps what is kept and not what is allocated. An indexer is an
operator-controlled endpoint read unauthenticated, so the read needs its own
ceiling. Issue #1004.

These run against a real HTTP server on localhost rather than a stubbed socket:
the behaviour under test is what `urlopen` hands back, including a chunked
response that declares no length.
"""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from qureddy.scanners.wallet import ethereum, indexer
from qureddy.scanners.wallet.indexer import _MAX_RESPONSE_BYTES

_OVERSIZE = _MAX_RESPONSE_BYTES + 1024
_REFUSAL = "read ceiling"


class _Oversize(http.server.BaseHTTPRequestHandler):
    """Answer any request with a body past the ceiling, length undeclared."""

    protocol_version = "HTTP/1.1"

    def _serve(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        chunk = b"a" * 64_000
        sent = 0
        while sent < _OVERSIZE:
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            sent += len(chunk)
        self.wfile.write(b"0\r\n\r\n")

    # BaseHTTPRequestHandler dispatches on these exact names, so the casing is
    # the stdlib's contract rather than a style choice.
    do_GET = _serve  # noqa: N815
    do_POST = _serve  # noqa: N815

    def log_message(self, *_: object) -> None:
        """Keep the test output readable."""


@contextmanager
def _oversize_server() -> Iterator[str]:
    server = http.server.HTTPServer(("127.0.0.1", 0), _Oversize)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_the_chain_lane_refuses_a_body_past_the_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _oversize_server() as base:
        monkeypatch.setenv(indexer.ESPLORA_URL_ENV, base)
        facts = indexer.fetch("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", timeout_seconds=30)

    assert not facts.reachable, "an oversized body is not a chain answer"
    assert facts.exchanges, "the refusal is still an attempt, and it is evidence"
    assert any(_REFUSAL in exchange.error for exchange in facts.exchanges)


def test_the_rpc_lane_refuses_a_body_past_the_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One reader serves both lanes, so the ceiling cannot hold on only one."""
    with _oversize_server() as base:
        monkeypatch.setenv(ethereum.ETH_RPC_ENV, base)
        facts = ethereum.fetch("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", timeout_seconds=30)

    assert not facts.reachable
    assert facts.exchanges
    assert any(_REFUSAL in exchange.error for exchange in facts.exchanges)


def test_the_refusal_states_the_ceiling_it_applied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A5: a bound that shapes output names itself."""
    with _oversize_server() as base:
        monkeypatch.setenv(indexer.ESPLORA_URL_ENV, base)
        facts = indexer.fetch("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", timeout_seconds=30)

    refused = next(exchange for exchange in facts.exchanges if _REFUSAL in exchange.error)
    assert str(_MAX_RESPONSE_BYTES) in refused.error
    assert refused.response_bytes > _MAX_RESPONSE_BYTES


def test_the_ceiling_bounds_the_read_and_not_only_the_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The allocation is the point, so one byte past the ceiling is all that lands.

    Refusing after `response.read()` still holds the whole body in memory, and
    such a check passes this file's other tests, which is why this one measures
    the bytes. The server sends 1024 past the ceiling: a bounded read records
    exactly one over, an unbounded read records all 1024.
    """
    with _oversize_server() as base:
        monkeypatch.setenv(indexer.ESPLORA_URL_ENV, base)
        facts = indexer.fetch("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", timeout_seconds=30)

    refused = next(exchange for exchange in facts.exchanges if _REFUSAL in exchange.error)
    assert refused.response_bytes == _MAX_RESPONSE_BYTES + 1
