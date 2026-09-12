# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Esplora REST client for the Bitcoin wallet lane.

Blockstream's Esplora schema is served by `blockstream.info` and `mempool.space`
alike, so one client covers both plus any self-hosted instance. Point
`QUREDDY_ESPLORA_URL` at your own node to keep the queried account inside your
boundary; that setting replaces the public defaults so a failed lookup stays
inside the boundary instead of falling back to a third party.

Two documented behaviours shape the code:

`GET /address/:address/txs` returns, per Esplora's API.md, "up to 50 mempool
transactions plus the first 25 confirmed transactions", mempool first. A
client-side slice of that array would mix confirmed and unconfirmed history
under one count, so the whole returned page is kept and the two are counted
apart. Deeper history needs the `:last_seen_txid` parameter, which this lane
leaves unused, so coverage is the first page and `truncated` records it.

A probe outcome is data. Every failure path returns `ChainFacts` with
`reachable=False` and a reason, so a caller reports `not_testable` instead of
inventing an answer.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

# A third party serves this JSON, so its shape is established by isinstance checks at
# each use rather than by a static type. Naming that here keeps the dynamism at the
# boundary where the bytes arrive, in place of spreading ignores through the readers.
Json = Any
JsonObject = dict[str, Any]

DEFAULT_BASES: tuple[str, ...] = (
    "https://mempool.space/api",
    "https://blockstream.info/api",
)
ESPLORA_URL_ENV = "QUREDDY_ESPLORA_URL"
_USER_AGENT = "qureddy-wallet"
_SATOSHI_PER_BTC = 100_000_000
#: Body characters kept in a transcript. Truncation is stated where it applies.
_MAX_BODY_TRACE = 40_000

# A compressed SEC1 point is 33 bytes prefixed 02 or 03; uncompressed is 65 prefixed 04.
_COMPRESSED_PREFIXES = ("02", "03")
_COMPRESSED_HEX_LEN = 66
_UNCOMPRESSED_HEX_LEN = 130
_DER_SEQUENCE = 0x30
_DER_MIN_BYTES = 8  # SEQUENCE, length, two INTEGER headers, and a byte of r and s each
_DER_INTEGER = 0x02
_PUSHDATA1 = 0x4C
_MAX_DIRECT_PUSH = 75


@dataclass
class HttpExchange:
    """One HTTP round trip, kept whole so a reader can check the scan after the fact.

    This is the REST lane's equivalent of `openssl s_client -msg`: the request
    line and headers sent, the status line and headers received, the timing, and
    the body that was parsed. It travels as a `ProbeResult` on the evidence, so
    it uses the same structure every subprocess probe in this engine already
    uses.
    """

    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    status: int = 0
    reason: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    duration_ms: int = 0
    response_bytes: int = 0
    body_text: str = ""
    error: str = ""

    @property
    def host(self) -> str:
        """Host and port of the endpoint contacted."""
        return urllib.parse.urlsplit(self.url).netloc

    @property
    def path(self) -> str:
        """Request path with its query, as it went on the wire."""
        parts = urllib.parse.urlsplit(self.url)
        return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")

    def transcript(self) -> str:
        """Curl -v shaped: `>` lines sent, `<` lines received, `|` body."""
        lines = [f"* {self.method} {self.url}", f"* Connected to {self.host}"]
        lines.append(f"> {self.method} {self.path} HTTP/1.1")
        lines.append(f"> Host: {self.host}")
        lines += [f"> {name}: {value}" for name, value in self.request_headers.items()]
        lines.append(">")
        if self.error:
            lines.append(f"* FAILED {self.error}")
            return "\n".join(lines)
        lines.append(f"< HTTP/1.1 {self.status} {self.reason}".rstrip())
        lines += [f"< {name}: {value}" for name, value in self.response_headers.items()]
        lines.append("<")
        lines.append(f"* received {self.response_bytes} bytes in {self.duration_ms}ms")
        if self.body_text:
            lines += [f"| {line}" for line in self.body_text.splitlines()]
        return "\n".join(lines)


@dataclass(frozen=True)
class Signature:
    """One ECDSA signature lifted from a spend input. `r` is the reuse key."""

    txid: str
    r: str
    s: str


@dataclass
class ChainFacts:
    """What the ledger reports about one address."""

    reachable: bool = False
    source: str = ""
    error: str = ""
    tx_count: int = 0
    funded_txo_count: int = 0
    spent_txo_count: int = 0
    balance_satoshi: int = 0
    output_scripts: set[str] = field(default_factory=set)
    public_keys: set[str] = field(default_factory=set)
    signatures: list[Signature] = field(default_factory=list)
    exchanges: list[HttpExchange] = field(default_factory=list)
    transactions_examined: int = 0
    transactions_confirmed: int = 0
    transactions_mempool: int = 0
    inputs_examined: int = 0
    truncated: bool = False

    @property
    def balance_btc(self) -> str:
        """Confirmed balance in BTC. Mempool movement is excluded."""
        return f"{self.balance_satoshi / _SATOSHI_PER_BTC:.8f}"


def bases() -> tuple[str, ...]:
    """Indexers to try, in order. An explicit override replaces the defaults."""
    override = os.environ.get(ESPLORA_URL_ENV, "").strip().rstrip("/")
    return (override,) if override else DEFAULT_BASES


def _get_json(url: str, timeout: float, exchanges: list[HttpExchange] | None = None) -> Json:
    """GET one JSON document, recording the whole exchange for the transcript.

    Both the override and the defaults are operator-controlled strings, so the
    scheme is checked before the open: `file:` would otherwise turn an indexer
    setting into a local-file read. Every outcome, including a refused scheme,
    lands on the `HttpExchange` so a reader sees what was attempted.
    """
    headers = {"User-Agent": _USER_AGENT}
    exchange = HttpExchange(method="GET", url=url, request_headers=dict(headers))
    if exchanges is not None:
        exchanges.append(exchange)
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        exchange.error = "refused: the scheme is neither http nor https"
        return None
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - scheme checked
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read()
            exchange.status = getattr(response, "status", 0) or 0
            exchange.reason = getattr(response, "reason", "") or ""
            exchange.response_headers = dict(response.headers.items())
        exchange.response_bytes = len(raw)
        decoded: Json = json.loads(raw.decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        exchange.status, exchange.error = exc.code, f"HTTP {exc.code}"
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        exchange.error = f"{type(exc).__name__}: {exc}"
        return None
    except ValueError as exc:
        exchange.error = f"the body was not JSON: {exc}"
        return None
    finally:
        exchange.duration_ms = int((time.monotonic() - started) * 1000)
    exchange.body_text = json.dumps(decoded, indent=2)[:_MAX_BODY_TRACE]
    return decoded


def parse_der_signature(value: str) -> tuple[str, str] | None:
    """Split a DER ECDSA signature into (r, s). A trailing sighash byte is tolerated."""
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return None
    if len(raw) < _DER_MIN_BYTES or raw[0] != _DER_SEQUENCE or raw[2] != _DER_INTEGER:
        return None
    r_length = raw[3]
    if 4 + r_length + 2 > len(raw) or raw[4 + r_length] != _DER_INTEGER:
        return None
    s_length = raw[5 + r_length]
    r_value = raw[4 : 4 + r_length].lstrip(b"\x00")
    s_value = raw[6 + r_length : 6 + r_length + s_length].lstrip(b"\x00")
    if not r_value or not s_value:
        return None
    return r_value.hex(), s_value.hex()


def script_pushes(script_hex: str) -> list[str]:
    """Data pushes from a scriptSig, covering the opcodes a spend actually uses."""
    try:
        raw = bytes.fromhex(script_hex)
    except ValueError:
        return []
    out: list[str] = []
    index = 0
    while index < len(raw):
        opcode = raw[index]
        index += 1
        if 1 <= opcode <= _MAX_DIRECT_PUSH:
            length = opcode
        elif opcode == _PUSHDATA1 and index < len(raw):
            length, index = raw[index], index + 1
        else:
            # Anything else is script logic; stop rather than mis-read it as data.
            return out
        if index + length > len(raw):
            return out
        out.append(raw[index : index + length].hex())
        index += length
    return out


def looks_like_public_key(value: str) -> bool:
    """True for a SEC1 encoded secp256k1 point in compressed or uncompressed form."""
    compressed = len(value) == _COMPRESSED_HEX_LEN and value[:2] in _COMPRESSED_PREFIXES
    uncompressed = len(value) == _UNCOMPRESSED_HEX_LEN and value[:2] == "04"
    return compressed or uncompressed


def _harvest(transactions: list[JsonObject], address: str, facts: ChainFacts) -> None:
    """Read script classes, published public keys and signatures out of a page."""
    for transaction in transactions:
        for output in transaction.get("vout") or []:
            if output.get("scriptpubkey_address") == address:
                script = output.get("scriptpubkey_type")
                if script:
                    facts.output_scripts.add(script)
        for spend_input in transaction.get("vin", []):
            previous = spend_input.get("prevout") or {}
            if previous.get("scriptpubkey_address") != address:
                continue
            # Only this address's own inputs can carry its signatures.
            facts.inputs_examined += 1
            items = list(spend_input.get("witness") or [])
            items += script_pushes(spend_input.get("scriptsig", "") or "")
            for item in items:
                if looks_like_public_key(item):
                    facts.public_keys.add(item)
                    continue
                parsed = parse_der_signature(item)
                if parsed is not None:
                    facts.signatures.append(
                        Signature(txid=transaction.get("txid", ""), r=parsed[0], s=parsed[1])
                    )


def fetch(address: str, *, timeout_seconds: float = 12.0) -> ChainFacts:
    """Query the chain lane for one address. Never raises."""
    if not address:
        return ChainFacts(error="no address supplied")
    last_error = "every configured indexer was unreachable"
    for base in bases():
        exchanges: list[HttpExchange] = []
        summary = _get_json(f"{base}/address/{address}", timeout_seconds, exchanges)
        if not isinstance(summary, dict) or "chain_stats" not in summary:
            last_error = f"{base} returned no address summary"
            continue
        chain_stats = summary.get("chain_stats") or {}
        mempool_stats = summary.get("mempool_stats") or {}
        facts = ChainFacts(
            reachable=True,
            source=base,
            tx_count=int(chain_stats.get("tx_count", 0)) + int(mempool_stats.get("tx_count", 0)),
            funded_txo_count=int(chain_stats.get("funded_txo_count", 0)),
            spent_txo_count=int(chain_stats.get("spent_txo_count", 0)),
            balance_satoshi=int(chain_stats.get("funded_txo_sum", 0))
            - int(chain_stats.get("spent_txo_sum", 0)),
            exchanges=exchanges,
        )
        transactions = _get_json(f"{base}/address/{address}/txs", timeout_seconds, exchanges)
        if isinstance(transactions, list):
            facts.transactions_examined = len(transactions)
            facts.transactions_confirmed = sum(
                1 for tx in transactions if (tx.get("status") or {}).get("confirmed")
            )
            facts.transactions_mempool = facts.transactions_examined - facts.transactions_confirmed
            facts.truncated = facts.tx_count > facts.transactions_examined
            _harvest(transactions, address, facts)
        else:
            facts.error = "address summary only; the transaction page was unavailable"
        return facts
    return ChainFacts(error=last_error)
