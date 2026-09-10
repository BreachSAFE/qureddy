# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bounded native selection of TLS suites excluded by OpenSSL (#700).

The ownership boundary is intentionally small:

    OpenSSL candidate names
              │ excluded reviewed wire IDs only
              ▼
    one-suite ClientHello ──► bounded TLS record reader
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                 exact ServerHello  peer alert   malformed/
                 suite ID           rejection    timeout/EOF
                         │            │            │
                         ▼            ▼            ▼
                    accepted     conclusive     unknown

The selector sends one deliberately minimal ClientHello and stops at the first
complete ServerHello. It does not perform key exchange or certificate
verification; a selected suite ID is the only positive fact it owns. The
one-suite offer is the critical invariant: a ServerHello selecting anything
else cannot be attributed to the attempted weak suite.

The transport is direct TLS only. STARTTLS is deliberately left to the existing
OpenSSL path until the application-protocol prologue contract is separately
defined. The caller reuses ``LegacyProtocolResult`` so all existing evidence,
finding, JSON, JSONL, Rich, and CBOM projections remain on the canonical path.
"""

from __future__ import annotations

import socket
import struct
import time
from contextlib import suppress
from dataclasses import dataclass

_MAX_RECORDS = 8
_MAX_RECORD_BYTES = 16 * 1024
_TLS_RECORD_HEADER = 5
_HANDSHAKE_HEADER = 4
_SERVER_HELLO = 2
_ALERT = 21
_HANDSHAKE = 22
_MIN_SERVER_HELLO_BODY = 38


@dataclass(frozen=True, slots=True)
class NativeSuite:
    """Reviewed wire identity for one legacy TLS suite."""

    name: str
    wire_id: int


_EXCLUDED_SUITES: tuple[NativeSuite, ...] = (
    NativeSuite("RC4-MD5", 0x0004),
    NativeSuite("RC4-SHA", 0x0005),
    NativeSuite("DES-CBC3-SHA", 0x000A),
    NativeSuite("DES-CBC-SHA", 0x0015),
)

_TLS_VERSIONS = {"TLSv1": 0x0301, "TLSv1.1": 0x0302, "TLSv1.2": 0x0303}


def _client_hello(host: str, sni: str | None, version: int, suite_id: int) -> bytes:
    """Build a minimal TLS ClientHello offering exactly one suite."""
    random = b"Q" * 32
    server_name = (sni or host).encode("idna")
    sni_name = b"\x00" + struct.pack(">H", len(server_name)) + server_name
    extension = (
        struct.pack(">HH", 0, len(sni_name) + 2) + struct.pack(">H", len(sni_name)) + sni_name
    )
    body = (
        struct.pack(">H", version)
        + random
        + b"\x00"
        + struct.pack(">H", 2)
        + struct.pack(">H", suite_id)
    )
    body += b"\x01\x00" + struct.pack(">H", len(extension)) + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def _server_hello_suite(handshake: bytes) -> int | None:
    """Return the ServerHello suite ID, or None for incomplete/other data."""
    if len(handshake) < _HANDSHAKE_HEADER or handshake[0] != _SERVER_HELLO:
        return None
    length = int.from_bytes(handshake[1:4], "big")
    if length != len(handshake) - _HANDSHAKE_HEADER or length < _MIN_SERVER_HELLO_BODY:
        return None
    body = memoryview(handshake)[_HANDSHAKE_HEADER:]
    session_len = body[34]
    suite_offset = 35 + session_len
    if suite_offset + 2 > len(body):
        return None
    return int.from_bytes(body[suite_offset : suite_offset + 2], "big")


def _read_record(sock: socket.socket) -> tuple[int, bytes] | None:
    """Read one bounded TLS record, returning None for malformed input."""
    header = sock.recv(_TLS_RECORD_HEADER)
    if len(header) != _TLS_RECORD_HEADER:
        return None
    content_type, _record_version, length = struct.unpack(">BHH", header)
    if length > _MAX_RECORD_BYTES:
        return None
    payload = bytearray()
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return None
        payload.extend(chunk)
    return content_type, bytes(payload)


def _read_selected_suite(
    sock: socket.socket,
    suite_id: int,
    deadline: float,
) -> tuple[bool, bool]:
    """Read records until exact selection, alert, or bounded uncertainty."""
    handshake = bytearray()
    for _ in range(_MAX_RECORDS):
        record = _read_record(sock)
        if record is None:
            return False, False
        content_type, payload = record
        if content_type == _ALERT:
            return False, True
        if content_type != _HANDSHAKE:
            return False, False
        handshake.extend(payload)
        if len(handshake) < _HANDSHAKE_HEADER:
            continue
        message_length = int.from_bytes(handshake[1:4], "big") + _HANDSHAKE_HEADER
        if len(handshake) < message_length:
            if time.monotonic() >= deadline:
                return False, False
            continue
        selected = _server_hello_suite(bytes(handshake[:message_length]))
        return selected == suite_id, selected is not None and selected == suite_id
    return False, False


def select_excluded_suite(
    host: str,
    port: int,
    sni: str | None,
    protocol_version: str,
    suite: NativeSuite,
    *,
    timeout_seconds: int,
) -> tuple[bool, bool]:
    """Return ``(selected, conclusive)`` for one exact suite offer.

    Any timeout, malformed record, unexpected suite, EOF, or socket failure is
    inconclusive. A valid ServerHello selecting another suite is also
    inconclusive because it violates the one-suite offer invariant.
    """
    version = _TLS_VERSIONS[protocol_version]
    deadline = time.monotonic() + timeout_seconds
    result = (False, False)
    with suppress(OSError, TimeoutError):
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            sock.sendall(_client_hello(host, sni, version, suite.wire_id))
            result = _read_selected_suite(sock, suite.wire_id, deadline)
    return result


def probe_excluded_suites(
    host: str,
    port: int,
    sni: str | None,
    protocol_version: str,
    *,
    timeout_seconds: int,
) -> tuple[tuple[str, ...], bool]:
    """Probe reviewed suites for direct TLS and return accepted names/incompleteness."""
    accepted: list[str] = []
    incomplete = False
    for suite in _EXCLUDED_SUITES:
        selected, conclusive = select_excluded_suite(
            host, port, sni, protocol_version, suite, timeout_seconds=timeout_seconds
        )
        if selected:
            accepted.append(suite.name)
        elif not conclusive:
            incomplete = True
    return tuple(accepted), incomplete


__all__ = ["NativeSuite", "probe_excluded_suites", "select_excluded_suite"]
